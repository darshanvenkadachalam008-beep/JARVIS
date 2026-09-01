// credential_provider/AlertQueue.cpp
#include "AlertQueue.h"
#include <shlwapi.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

struct WorkerParams {
    AlertQueueEntry entry;
    BOOL bSuccess;
};

static DWORD WINAPI QueueWorkerThread(LPVOID lpParam) {
    WorkerParams* pParams = (WorkerParams*)lpParam;
    if (pParams) {
        pParams->bSuccess = AlertQueue::WriteEventInternal(pParams->entry);
    }
    return 0;
}

std::wstring AlertQueue::GetCurrentIsoTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, 64, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::wstring(buf);
}

BOOL AlertQueue::GetEntropySecret(DATA_BLOB* pEntropyBlob) {
    if (!pEntropyBlob) return FALSE;
    pEntropyBlob->pbData = NULL;
    pEntropyBlob->cbData = 0;

    HKEY hKey = NULL;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REGISTRY_SECURITY_KEY, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        return FALSE; // Missing registry key -> fail closed
    }

    DWORD dwType = REG_BINARY;
    DWORD cbData = 0;
    status = RegQueryValueExW(hKey, REGISTRY_ENTROPY_VAL, NULL, &dwType, NULL, &cbData);
    if (status != ERROR_SUCCESS || cbData == 0) {
        RegCloseKey(hKey);
        return FALSE;
    }

    std::vector<BYTE> encData(cbData);
    status = RegQueryValueExW(hKey, REGISTRY_ENTROPY_VAL, NULL, &dwType, encData.data(), &cbData);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        return FALSE;
    }

    // Unprotect using DPAPI Local Machine scope
    DATA_BLOB cipherBlob;
    cipherBlob.pbData = encData.data();
    cipherBlob.cbData = cbData;

    DATA_BLOB plainBlob = { 0 };
    if (!CryptUnprotectData(&cipherBlob, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &plainBlob)) {
        return FALSE; // Corrupted or unreadable entropy -> fail closed
    }

    *pEntropyBlob = plainBlob;
    return TRUE;
}

BOOL AlertQueue::ProvisionEntropySecret() {
    // Generate 32 cryptographically random bytes
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    BYTE rawSecret[32];
    if (!CryptGenRandom(hProv, sizeof(rawSecret), rawSecret)) {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    CryptReleaseContext(hProv, 0);

    // Encrypt with DPAPI Local Machine scope
    DATA_BLOB plainBlob;
    plainBlob.pbData = rawSecret;
    plainBlob.cbData = sizeof(rawSecret);

    DATA_BLOB cipherBlob = { 0 };
    if (!CryptProtectData(&plainBlob, L"JarvisColdBootEntropy", NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &cipherBlob)) {
        return FALSE;
    }

    // Write to HKLM\SOFTWARE\JarvisSecurity\ColdBootEntropy
    HKEY hKey = NULL;
    DWORD dwDisposition = 0;
    LSTATUS status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        REGISTRY_SECURITY_KEY,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY,
        NULL,
        &hKey,
        &dwDisposition
    );

    if (status != ERROR_SUCCESS) {
        if (cipherBlob.pbData) LocalFree(cipherBlob.pbData);
        return FALSE;
    }

    status = RegSetValueExW(
        hKey,
        REGISTRY_ENTROPY_VAL,
        0,
        REG_BINARY,
        cipherBlob.pbData,
        cipherBlob.cbData
    );

    RegCloseKey(hKey);
    if (cipherBlob.pbData) LocalFree(cipherBlob.pbData);
    return (status == ERROR_SUCCESS);
}

static std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

BOOL AlertQueue::WriteEventInternal(const AlertQueueEntry& entry) {
    // 1. Fetch DPAPI entropy secret (fail closed if missing)
    DATA_BLOB entropyBlob = { 0 };
    if (!GetEntropySecret(&entropyBlob)) {
        return FALSE; // Silent fallback: entropy missing or invalid
    }

    // 2. Format JSON event line
    std::ostringstream ss;
    ss << "{\"timestamp\":\"" << WStringToString(entry.timestampIso) << "\","
       << "\"event_type\":\"" << WStringToString(entry.eventType) << "\","
       << "\"attempt_count\":" << entry.attemptCount << ","
       << "\"layer\":\"" << WStringToString(entry.layer) << "\","
       << "\"domain\":\"" << WStringToString(entry.domain) << "\","
       << "\"username\":\"" << WStringToString(entry.username) << "\"}\n";
    std::string jsonLine = ss.str();

    // 3. Ensure target directory exists
    CreateDirectoryW(QUEUE_DIR_PATH, NULL);

    // 4. Read existing decrypted payload if file exists, or start fresh
    std::string accumulatedData;
    HANDLE hFile = CreateFileW(
        QUEUE_FILE_PATH,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD dwSize = GetFileSize(hFile, NULL);
        if (dwSize > 0 && dwSize < 1048576) { // Max 1MB queue bounds
            std::vector<BYTE> cipherBuffer(dwSize);
            DWORD dwRead = 0;
            if (ReadFile(hFile, cipherBuffer.data(), dwSize, &dwRead, NULL) && dwRead == dwSize) {
                DATA_BLOB inBlob;
                inBlob.pbData = cipherBuffer.data();
                inBlob.cbData = dwRead;

                DATA_BLOB outBlob = { 0 };
                if (CryptUnprotectData(&inBlob, NULL, &entropyBlob, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &outBlob)) {
                    if (outBlob.pbData && outBlob.cbData > 0) {
                        accumulatedData.assign((char*)outBlob.pbData, outBlob.cbData);
                    }
                    if (outBlob.pbData) LocalFree(outBlob.pbData);
                }
            }
        }
        CloseHandle(hFile);
    }

    // Append new event line
    accumulatedData += jsonLine;

    // 5. Encrypt complete accumulated queue using DPAPI Machine Scope + Entropy
    DATA_BLOB plainBlob;
    plainBlob.pbData = (BYTE*)accumulatedData.data();
    plainBlob.cbData = (DWORD)accumulatedData.size();

    DATA_BLOB encryptedBlob = { 0 };
    BOOL bEncrypted = CryptProtectData(
        &plainBlob,
        L"JarvisColdBootAlertQueue",
        &entropyBlob,
        NULL,
        NULL,
        CRYPTPROTECT_LOCAL_MACHINE,
        &encryptedBlob
    );

    // Free entropy memory
    if (entropyBlob.pbData) {
        SecureZeroMemory(entropyBlob.pbData, entropyBlob.cbData);
        LocalFree(entropyBlob.pbData);
    }

    if (!bEncrypted || !encryptedBlob.pbData) {
        return FALSE;
    }

    // 6. Write encrypted buffer atomically
    hFile = CreateFileW(
        QUEUE_FILE_PATH,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        LocalFree(encryptedBlob.pbData);
        return FALSE;
    }

    DWORD dwWritten = 0;
    BOOL bWriteOk = WriteFile(hFile, encryptedBlob.pbData, encryptedBlob.cbData, &dwWritten, NULL);
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    LocalFree(encryptedBlob.pbData);

    return bWriteOk && (dwWritten == encryptedBlob.cbData);
}

BOOL AlertQueue::QueueEventNonBlocking(
    const std::wstring& eventType,
    DWORD attemptCount,
    const std::wstring& layer,
    const std::wstring& domain,
    const std::wstring& username
) {
    WorkerParams params;
    params.entry.timestampIso = GetCurrentIsoTimestamp();
    params.entry.eventType = eventType;
    params.entry.attemptCount = attemptCount;
    params.entry.layer = layer;
    params.entry.domain = domain;
    params.entry.username = username;
    params.bSuccess = FALSE;

    HANDLE hThread = CreateThread(NULL, 0, QueueWorkerThread, &params, 0, NULL);
    if (!hThread) {
        return FALSE; // Cannot spawn worker -> fail closed immediately
    }

    // Bound execution with strict 1.8s timeout
    DWORD dwWait = WaitForSingleObject(hThread, IO_TIMEOUT_MS);
    if (dwWait == WAIT_TIMEOUT) {
        // Hard timeout expired — do not block LogonUI
        CloseHandle(hThread);
        return FALSE;
    }

    CloseHandle(hThread);
    return params.bSuccess;
}
