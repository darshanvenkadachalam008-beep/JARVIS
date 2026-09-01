// credential_provider/SessionTracker.cpp
#include "SessionTracker.h"
#include <wtsapi32.h>
#include <sddl.h>

#pragma comment(lib, "wtsapi32.lib")

static HANDLE OpenOrCreateSessionMapping(JarvisSessionState** ppState) {
    if (!ppState) return NULL;
    *ppState = NULL;

    // Explicit security descriptor restricting write/full access exclusively to NT AUTHORITY\SYSTEM
    SECURITY_ATTRIBUTES sa = { 0 };
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    // D:(A;;GA;;;SY) -> Only SYSTEM has Generic All access (no user/admin process can write/tamper)
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)",
            SDDL_REVISION_1,
            &pSD,
            NULL)) {
        sa.lpSecurityDescriptor = pSD;
    }

    HANDLE hMap = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        sa.lpSecurityDescriptor ? &sa : NULL,
        PAGE_READWRITE,
        0,
        sizeof(JarvisSessionState),
        SESSION_MAPPING_NAME
    );

    if (pSD) {
        LocalFree(pSD);
    }

    if (!hMap) {
        hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, SESSION_MAPPING_NAME);
    }

    if (!hMap) return NULL;

    JarvisSessionState* pState = (JarvisSessionState*)MapViewOfFile(
        hMap,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(JarvisSessionState)
    );

    if (!pState) {
        CloseHandle(hMap);
        return NULL;
    }

    *ppState = pState;
    return hMap;
}

DWORD SessionTracker::GetCurrentLogonSessionId() {
    DWORD dwSessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);
    return dwSessionId;
}

DWORD SessionTracker::GetDuressAttemptCount() {
    JarvisSessionState* pState = NULL;
    HANDLE hMap = OpenOrCreateSessionMapping(&pState);
    if (!hMap || !pState) return 0;

    DWORD dwCurrentSession = GetCurrentLogonSessionId();
    DWORD count = 0;

    if (pState->dwSessionId == dwCurrentSession) {
        count = pState->dwDuressAttempts;
    } else {
        // Stale session detected: reset state for the new session
        pState->dwSessionId = dwCurrentSession;
        pState->dwDuressAttempts = 0;
        pState->bLockedOut = FALSE;
        pState->dwLastEventTime = GetTickCount();
        count = 0;
    }

    UnmapViewOfFile(pState);
    CloseHandle(hMap);
    return count;
}

DWORD SessionTracker::IncrementDuressAttempt() {
    JarvisSessionState* pState = NULL;
    HANDLE hMap = OpenOrCreateSessionMapping(&pState);
    if (!hMap || !pState) return 1;

    DWORD dwCurrentSession = GetCurrentLogonSessionId();
    if (pState->dwSessionId != dwCurrentSession) {
        // Stale session detected: reset before incrementing for current session
        pState->dwSessionId = dwCurrentSession;
        pState->dwDuressAttempts = 0;
        pState->bLockedOut = FALSE;
    }

    pState->dwDuressAttempts++;
    pState->dwLastEventTime = GetTickCount();

    if (pState->dwDuressAttempts >= MAX_DURESS_ATTEMPTS) {
        pState->bLockedOut = TRUE;
    }

    DWORD result = pState->dwDuressAttempts;
    UnmapViewOfFile(pState);
    CloseHandle(hMap);
    return result;
}

BOOL SessionTracker::IsSessionLockedOut() {
    JarvisSessionState* pState = NULL;
    HANDLE hMap = OpenOrCreateSessionMapping(&pState);
    if (!hMap || !pState) return FALSE;

    DWORD dwCurrentSession = GetCurrentLogonSessionId();
    BOOL locked = FALSE;

    if (pState->dwSessionId == dwCurrentSession) {
        locked = pState->bLockedOut || (pState->dwDuressAttempts >= MAX_DURESS_ATTEMPTS);
    } else {
        // Stale session detected: reset and clear lockout for the new session
        pState->dwSessionId = dwCurrentSession;
        pState->dwDuressAttempts = 0;
        pState->bLockedOut = FALSE;
        pState->dwLastEventTime = GetTickCount();
        locked = FALSE;
    }

    UnmapViewOfFile(pState);
    CloseHandle(hMap);
    return locked;
}

void SessionTracker::ResetSessionState() {
    JarvisSessionState* pState = NULL;
    HANDLE hMap = OpenOrCreateSessionMapping(&pState);
    if (!hMap || !pState) return;

    pState->dwSessionId = GetCurrentLogonSessionId();
    pState->dwDuressAttempts = 0;
    pState->bLockedOut = FALSE;
    pState->dwLastEventTime = GetTickCount();

    UnmapViewOfFile(pState);
    CloseHandle(hMap);
}
