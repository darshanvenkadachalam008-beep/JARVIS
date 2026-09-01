// credential_provider/SessionTracker.h
// Session-persistent attempt tracker across Cancel/tile recreation
#pragma once

#include <windows.h>

#define MAX_DURESS_ATTEMPTS 3
#define SESSION_MAPPING_NAME L"Global\\JarvisColdBoot_SessionState"

struct JarvisSessionState {
    DWORD dwSessionId;
    DWORD dwDuressAttempts;
    BOOL  bLockedOut;
    DWORD dwLastEventTime;
};

class SessionTracker {
public:
    static DWORD GetCurrentLogonSessionId();
    static DWORD GetDuressAttemptCount();
    static DWORD IncrementDuressAttempt();
    static BOOL IsSessionLockedOut();
    static void ResetSessionState();
};
