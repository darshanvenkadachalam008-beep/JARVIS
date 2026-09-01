// credential_provider/AlertQueue.h
// Pre-Network Encrypted Alert Queue with Bounded Non-Blocking I/O
#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>

#define QUEUE_DIR_PATH L"C:\\ProgramData\\JarvisSecurity"
#define QUEUE_FILE_PATH L"C:\\ProgramData\\JarvisSecurity\\boot_alert_queue.enc"
#define REGISTRY_SECURITY_KEY L"SOFTWARE\\JarvisSecurity"
#define REGISTRY_ENTROPY_VAL L"ColdBootEntropy"
#define IO_TIMEOUT_MS 1800

struct AlertQueueEntry {
    std::wstring timestampIso;
    std::wstring eventType;
    DWORD attemptCount;
    std::wstring layer;
    std::wstring domain;
    std::wstring username;
};

class AlertQueue {
public:
    // Write an event entry to the encrypted queue file using bounded timeout worker
    static BOOL QueueEventNonBlocking(
        const std::wstring& eventType,
        DWORD attemptCount,
        const std::wstring& layer,
        const std::wstring& domain,
        const std::wstring& username
    );

    // Synchronous internal writer (invoked inside timeout-bounded worker thread)
    static BOOL WriteEventInternal(const AlertQueueEntry& entry);

    // Retrieve machine-scope entropy from registry; returns FALSE if missing/corrupted
    static BOOL GetEntropySecret(DATA_BLOB* pEntropyBlob);

    // Provision install-time entropy into registry
    static BOOL ProvisionEntropySecret();

    // Helper to format ISO 8601 UTC timestamp
    static std::wstring GetCurrentIsoTimestamp();
};
