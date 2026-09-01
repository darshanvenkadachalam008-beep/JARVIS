// credential_provider/dllmain.cpp
// COM In-Process Server Registration & Lifecycle Management
#include <windows.h>
#include <unknwn.h>
#include <shlwapi.h>
#include "guid.h"
#include "JarvisCredentialProvider.h"
#include "AlertQueue.h"

#pragma comment(lib, "shlwapi.lib")

static HINSTANCE g_hInst = NULL;
static LONG g_cDllRef = 0;

static const WCHAR s_szClsidStr[] = L"{A9B8C7D6-E5F4-4A3B-8C1D-0E9F8A7B6C5D}";
static const WCHAR s_szProviderName[] = L"JarvisCredentialProvider";

// ── Class Factory ──────────────────────────────────────────────────────────

class CClassFactory : public IClassFactory {
public:
    CClassFactory() : _cRef(1) {}
    virtual ~CClassFactory() {}

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        static const QITAB qit[] = {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef() {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release() {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0) {
            delete this;
        }
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) {
        if (pUnkOuter != NULL) return CLASS_E_NOAGGREGATION;
        CJarvisCredentialProvider* pProvider = new CJarvisCredentialProvider();
        if (!pProvider) return E_OUTOFMEMORY;
        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL bLock) {
        if (bLock) InterlockedIncrement(&g_cDllRef);
        else InterlockedDecrement(&g_cDllRef);
        return S_OK;
    }

private:
    LONG _cRef;
};

// ── DLL Entry Point ────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        g_hInst = hInstance;
        DisableThreadLibraryCalls(hInstance);
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() {
    return (g_cDllRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    *ppv = NULL;

    if (IsEqualCLSID(rclsid, CLSID_JarvisCredentialProvider)) {
        CClassFactory* pFactory = new CClassFactory();
        if (!pFactory) return E_OUTOFMEMORY;
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }

    return CLASS_E_CLASSNOTAVAILABLE;
}

// ── Registration (DllRegisterServer & DllUnregisterServer) ─────────────────

STDAPI DllRegisterServer() {
    WCHAR szModule[MAX_PATH];
    if (GetModuleFileNameW(g_hInst, szModule, MAX_PATH) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // 1. Register CLSID in HKCR\CLSID\{A9B8C7D6-E5F4-4A3B-8C1D-0E9F8A7B6C5D}
    WCHAR szClsidKey[256];
    swprintf_s(szClsidKey, 256, L"CLSID\\%s", s_szClsidStr);

    HKEY hKey = NULL;
    LSTATUS status = RegCreateKeyExW(HKEY_CLASSES_ROOT, szClsidKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)s_szProviderName, (DWORD)((wcslen(s_szProviderName) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    // InprocServer32
    WCHAR szInprocKey[256];
    swprintf_s(szInprocKey, 256, L"CLSID\\%s\\InprocServer32", s_szClsidStr);
    status = RegCreateKeyExW(HKEY_CLASSES_ROOT, szInprocKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)szModule, (DWORD)((wcslen(szModule) + 1) * sizeof(WCHAR)));
    const WCHAR szModel[] = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (const BYTE*)szModel, (DWORD)((wcslen(szModel) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    // 2. Register Credential Provider in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{GUID}
    WCHAR szProviderKey[512];
    swprintf_s(szProviderKey, 512, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", s_szClsidStr);
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szProviderKey, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)s_szProviderName, (DWORD)((wcslen(s_szProviderName) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    // 3. Provision random DPAPI machine entropy in HKLM\SOFTWARE\JarvisSecurity\ColdBootEntropy
    AlertQueue::ProvisionEntropySecret();

    return S_OK;
}

STDAPI DllUnregisterServer() {
    // 1. Remove from Credential Providers
    WCHAR szProviderKey[512];
    swprintf_s(szProviderKey, 512, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", s_szClsidStr);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, szProviderKey, KEY_WOW64_64KEY, 0);

    // 2. Remove CLSID
    WCHAR szInprocKey[256];
    swprintf_s(szInprocKey, 256, L"CLSID\\%s\\InprocServer32", s_szClsidStr);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, szInprocKey);

    WCHAR szClsidKey[256];
    swprintf_s(szClsidKey, 256, L"CLSID\\%s", s_szClsidStr);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, szClsidKey);

    // 3. Remove JarvisSecurity registry root if empty
    HKEY hSecKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\JarvisSecurity", 0, KEY_WRITE | KEY_WOW64_64KEY, &hSecKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hSecKey, L"ColdBootEntropy");
        RegCloseKey(hSecKey);
        RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\JarvisSecurity", KEY_WOW64_64KEY, 0);
    }

    return S_OK;
}
