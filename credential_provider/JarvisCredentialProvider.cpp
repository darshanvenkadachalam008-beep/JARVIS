// credential_provider/JarvisCredentialProvider.cpp
#include "JarvisCredentialProvider.h"
#include <shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "secur32.lib")

// ── Field Descriptors ──────────────────────────────────────────────────────
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFields[] = {
    { JFI_TILE_IMAGE,      CPFT_TILE_IMAGE,    L"JARVIS Cold-Boot" },
    { JFI_LABEL,           CPFT_LARGE_TEXT,    L"JARVIS Secure Cold-Boot Access" },
    { JFI_USERNAME,        CPFT_EDIT_TEXT,     L"Username" },
    { JFI_PASSWORD,        CPFT_PASSWORD_TEXT, L"Password" },
    { JFI_DURESS_LABEL,    CPFT_SMALL_TEXT,    L"Fallback / Duress Code" },
    { JFI_DURESS_PASSWORD, CPFT_PASSWORD_TEXT, L"Secondary Passcode" },
    { JFI_SUBMIT_BUTTON,   CPFT_SUBMIT_BUTTON, L"Submit" },
};

// ── CJarvisCredentialProvider Implementation ───────────────────────────────

CJarvisCredentialProvider::CJarvisCredentialProvider()
    : _cRef(1),
      _cpus(CPUS_INVALID),
      _dwFlags(0),
      _pcpe(NULL),
      _upAdviseContext(0),
      _pCredential(NULL),
      _bScenarioSupported(FALSE) {
}

CJarvisCredentialProvider::~CJarvisCredentialProvider() {
    if (_pCredential) {
        _pCredential->Release();
        _pCredential = NULL;
    }
}

IFACEMETHODIMP CJarvisCredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(CJarvisCredentialProvider, ICredentialProvider),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

IFACEMETHODIMP_(ULONG) CJarvisCredentialProvider::AddRef() {
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CJarvisCredentialProvider::Release() {
    LONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

IFACEMETHODIMP CJarvisCredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) {
    _cpus = cpus;
    _dwFlags = dwFlags;

    // Hard Constraint: ONLY CPUS_LOGON and CPUS_UNLOCK_WORKSTATION
    // Never active for UAC elevation, CredUI, or password changes
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION) {
        _bScenarioSupported = TRUE;
        if (!_pCredential) {
            _pCredential = new CJarvisCredential(this);
        }
        return S_OK;
    }

    _bScenarioSupported = FALSE;
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredentialProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredentialProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) {
    if (_pcpe) {
        _pcpe->Release();
    }
    _pcpe = pcpe;
    _upAdviseContext = upAdviseContext;
    if (_pcpe) {
        _pcpe->AddRef();
    }
    return S_OK;
}

IFACEMETHODIMP CJarvisCredentialProvider::UnAdvise() {
    if (_pcpe) {
        _pcpe->Release();
        _pcpe = NULL;
    }
    _upAdviseContext = 0;
    return S_OK;
}

IFACEMETHODIMP CJarvisCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) return E_INVALIDARG;
    *pdwCount = JFI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CJarvisCredentialProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (dwIndex >= JFI_NUM_FIELDS || !ppcpfd) {
        return E_INVALIDARG;
    }

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pcpfd) return E_OUTOFMEMORY;

    pcpfd->dwFieldID = s_rgFields[dwIndex].dwFieldID;
    pcpfd->cpft = s_rgFields[dwIndex].cpft;
    SHStrDupW(s_rgFields[dwIndex].pszLabel, &pcpfd->pszLabel);

    *ppcpfd = pcpfd;
    return S_OK;
}

IFACEMETHODIMP CJarvisCredentialProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) {
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) {
        return E_INVALIDARG;
    }

    // Safety Invariant: Native Windows tile retains default focus
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    if (!_bScenarioSupported) {
        *pdwCount = 0;
        return S_OK;
    }

    // If session is locked out (>= 3 attempts), show 0 credentials to silently yield focus
    if (SessionTracker::IsSessionLockedOut()) {
        *pdwCount = 0;
        return S_OK;
    }

    *pdwCount = 1;
    return S_OK;
}

IFACEMETHODIMP CJarvisCredentialProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (dwIndex != 0 || !_pCredential || !ppcpc) {
        return E_INVALIDARG;
    }

    *ppcpc = _pCredential;
    (*ppcpc)->AddRef();
    return S_OK;
}

// ── CJarvisCredential Implementation ───────────────────────────────────────

CJarvisCredential::CJarvisCredential(CJarvisCredentialProvider* pProvider)
    : _cRef(1),
      _pProvider(pProvider),
      _pcpce(NULL),
      _pszUsername(NULL),
      _pszPassword(NULL),
      _pszDuressPassword(NULL),
      _bDuressModeActive(FALSE),
      _bSessionLocked(FALSE),
      _dwAttemptCount(0) {
    _dwAttemptCount = SessionTracker::GetDuressAttemptCount();
    _bSessionLocked = SessionTracker::IsSessionLockedOut();
}

CJarvisCredential::~CJarvisCredential() {
    if (_pszUsername) CoTaskMemFree(_pszUsername);
    if (_pszPassword) {
        SecureZeroMemory(_pszPassword, wcslen(_pszPassword) * sizeof(WCHAR));
        CoTaskMemFree(_pszPassword);
    }
    if (_pszDuressPassword) {
        SecureZeroMemory(_pszDuressPassword, wcslen(_pszDuressPassword) * sizeof(WCHAR));
        CoTaskMemFree(_pszDuressPassword);
    }
    if (_pcpce) _pcpce->Release();
}

IFACEMETHODIMP CJarvisCredential::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(CJarvisCredential, ICredentialProviderCredential),
        QITABENT(CJarvisCredential, ICredentialProviderCredential2),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

IFACEMETHODIMP_(ULONG) CJarvisCredential::AddRef() {
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CJarvisCredential::Release() {
    LONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

IFACEMETHODIMP CJarvisCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    if (_pcpce) _pcpce->Release();
    _pcpce = pcpce;
    if (_pcpce) _pcpce->AddRef();
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::UnAdvise() {
    if (_pcpce) {
        _pcpce->Release();
        _pcpce = NULL;
    }
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::SetSelected(BOOL* pbAutoLogon) {
    if (pbAutoLogon) *pbAutoLogon = FALSE;
    _dwAttemptCount = SessionTracker::GetDuressAttemptCount();
    _bSessionLocked = SessionTracker::IsSessionLockedOut();
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::SetDeselected() {
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    if (!pcpfs || !pcpfis) return E_INVALIDARG;

    if (_bSessionLocked) {
        // Locked out: hide editable fields
        if (dwFieldID == JFI_LABEL) {
            *pcpfs = CPFS_DISPLAY_IN_BOTH;
            *pcpfis = CPFIS_NONE;
        } else {
            *pcpfs = CPFS_HIDDEN;
            *pcpfis = CPFIS_NONE;
        }
        return S_OK;
    }

    switch (dwFieldID) {
    case JFI_TILE_IMAGE:
    case JFI_LABEL:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case JFI_USERNAME:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
    case JFI_PASSWORD:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_FOCUSED;
        break;
    case JFI_DURESS_LABEL:
    case JFI_DURESS_PASSWORD:
        *pcpfs = _bDuressModeActive ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
        *pcpfis = _bDuressModeActive ? CPFIS_FOCUSED : CPFIS_NONE;
        break;
    case JFI_SUBMIT_BUTTON:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
    default:
        *pcpfs = CPFS_HIDDEN;
        *pcpfis = CPFIS_NONE;
        break;
    }
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppsz) {
    if (!ppsz) return E_INVALIDARG;
    *ppsz = NULL;

    switch (dwFieldID) {
    case JFI_LABEL:
        if (_bSessionLocked) {
            return SHStrDupW(L"⚠️ Maximum attempts exceeded. Please use standard Windows login.", ppsz);
        } else if (_bDuressModeActive) {
            return SHStrDupW(L"⚠️ Primary authentication failed. Enter fallback authorization code:", ppsz);
        } else {
            return SHStrDupW(L"JARVIS Secure Cold-Boot Access", ppsz);
        }
    case JFI_DURESS_LABEL:
        return SHStrDupW(L"Secondary / Duress Passcode:", ppsz);
    case JFI_USERNAME:
        if (_pszUsername) return SHStrDupW(_pszUsername, ppsz);
        return SHStrDupW(L"", ppsz);
    default:
        return E_INVALIDARG;
    }
}

IFACEMETHODIMP CJarvisCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) {
    if (!phbmp) return E_INVALIDARG;
    *phbmp = NULL;
    // Tile icon can be generated or left default
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppszLabel) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) {
    if (!pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = _bDuressModeActive ? JFI_DURESS_PASSWORD : JFI_PASSWORD;
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppszItem) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::SetStringValue(DWORD dwFieldID, LPCWSTR psz) {
    switch (dwFieldID) {
    case JFI_USERNAME:
        if (_pszUsername) CoTaskMemFree(_pszUsername);
        return SHStrDupW(psz ? psz : L"", &_pszUsername);
    case JFI_PASSWORD:
        if (_pszPassword) {
            SecureZeroMemory(_pszPassword, wcslen(_pszPassword) * sizeof(WCHAR));
            CoTaskMemFree(_pszPassword);
        }
        return SHStrDupW(psz ? psz : L"", &_pszPassword);
    case JFI_DURESS_PASSWORD:
        if (_pszDuressPassword) {
            SecureZeroMemory(_pszDuressPassword, wcslen(_pszDuressPassword) * sizeof(WCHAR));
            CoTaskMemFree(_pszDuressPassword);
        }
        return SHStrDupW(psz ? psz : L"", &_pszDuressPassword);
    default:
        return S_OK;
    }
}

IFACEMETHODIMP CJarvisCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::CommandLinkClicked(DWORD dwFieldID) {
    return E_NOTIMPL;
}

IFACEMETHODIMP CJarvisCredential::GetUserSid(LPWSTR* ppszSid) {
    return E_NOTIMPL;
}

HRESULT CJarvisCredential::PackageKerberosAuthBuffer(
    LPCWSTR pszDomain,
    LPCWSTR pszUsername,
    LPCWSTR pszPassword,
    BYTE** ppbAuthBuffer,
    DWORD* pcbAuthBuffer
) {
    if (!ppbAuthBuffer || !pcbAuthBuffer) return E_INVALIDARG;
    *ppbAuthBuffer = NULL;
    *pcbAuthBuffer = 0;

    DWORD cbDomain = (DWORD)(wcslen(pszDomain) * sizeof(WCHAR));
    DWORD cbUser = (DWORD)(wcslen(pszUsername) * sizeof(WCHAR));
    DWORD cbPass = (DWORD)(wcslen(pszPassword) * sizeof(WCHAR));

    DWORD cbTotal = sizeof(KERB_INTERACTIVE_LOGON) + cbDomain + cbUser + cbPass;
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer) return E_OUTOFMEMORY;
    ZeroMemory(pBuffer, cbTotal);

    KERB_INTERACTIVE_LOGON* pLogon = (KERB_INTERACTIVE_LOGON*)pBuffer;
    pLogon->MessageType = KerbInteractiveLogon;

    BYTE* pRunning = pBuffer + sizeof(KERB_INTERACTIVE_LOGON);

    // Domain
    pLogon->LogonDomainName.Length = (USHORT)cbDomain;
    pLogon->LogonDomainName.MaximumLength = (USHORT)cbDomain;
    pLogon->LogonDomainName.Buffer = (PWSTR)pRunning;
    CopyMemory(pRunning, pszDomain, cbDomain);
    pRunning += cbDomain;

    // Username
    pLogon->UserName.Length = (USHORT)cbUser;
    pLogon->UserName.MaximumLength = (USHORT)cbUser;
    pLogon->UserName.Buffer = (PWSTR)pRunning;
    CopyMemory(pRunning, pszUsername, cbUser);
    pRunning += cbUser;

    // Password
    pLogon->Password.Length = (USHORT)cbPass;
    pLogon->Password.MaximumLength = (USHORT)cbPass;
    pLogon->Password.Buffer = (PWSTR)pRunning;
    CopyMemory(pRunning, pszPassword, cbPass);

    *ppbAuthBuffer = pBuffer;
    *pcbAuthBuffer = cbTotal;
    return S_OK;
}

IFACEMETHODIMP CJarvisCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
) {
    if (!pcpgsr || !pcpcs) return E_INVALIDARG;
    *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

    if (_bSessionLocked) {
        if (ppszOptionalStatusText) {
            SHStrDupW(L"Session locked. Use native Windows login.", ppszOptionalStatusText);
        }
        if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_OK;
    }

    LPCWSTR pszUser = _pszUsername ? _pszUsername : L"";
    LPCWSTR pszPass = _bDuressModeActive ? (_pszDuressPassword ? _pszDuressPassword : L"") : (_pszPassword ? _pszPassword : L"");

    // Split domain\username if present
    WCHAR szDomain[256] = L".";
    WCHAR szAccount[256] = { 0 };
    LPCWSTR pSlash = wcschr(pszUser, L'\\');
    if (pSlash) {
        wcsncpy_s(szDomain, 256, pszUser, pSlash - pszUser);
        wcsncpy_s(szAccount, 256, pSlash + 1, _TRUNCATE);
    } else {
        wcsncpy_s(szAccount, 256, pszUser, _TRUNCATE);
    }

    HANDLE hLsa = NULL;
    LsaConnectUntrusted(&hLsa);
    ULONG ulAuthPackage = 0;
    LSA_STRING pkgName;
    char szNegotiate[] = "Negotiate";
    pkgName.Buffer = szNegotiate;
    pkgName.Length = (USHORT)strlen(szNegotiate);
    pkgName.MaximumLength = (USHORT)sizeof(szNegotiate);
    if (hLsa) {
        LsaLookupAuthenticationPackage(hLsa, &pkgName, &ulAuthPackage);
        LsaDeregisterLogonProcess(hLsa);
    }

    BYTE* pAuthBuffer = NULL;
    DWORD cbAuthBuffer = 0;
    HRESULT hr = PackageKerberosAuthBuffer(szDomain, szAccount, pszPass, &pAuthBuffer, &cbAuthBuffer);
    if (FAILED(hr)) return hr;

    pcpcs->clsidCredentialProvider = CLSID_JarvisCredentialProvider;
    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->cbSerialization = cbAuthBuffer;
    pcpcs->rgbSerialization = pAuthBuffer;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

void CJarvisCredential::ShowDuressPrompt() {
    _bDuressModeActive = TRUE;
    if (_pcpce) {
        _pcpce->SetFieldState(this, JFI_DURESS_LABEL, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pcpce->SetFieldState(this, JFI_DURESS_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pcpce->SetFieldString(this, JFI_LABEL, L"⚠️ Primary authentication failed. Enter fallback authorization code:");
        _pcpce->SetFieldInteractiveState(this, JFI_DURESS_PASSWORD, CPFIS_FOCUSED);
        _pcpce->SetFieldSubmitButton(this, JFI_SUBMIT_BUTTON, JFI_DURESS_PASSWORD);
    }
}

IFACEMETHODIMP CJarvisCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    LPWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
) {
    std::wstring user = _pszUsername ? _pszUsername : L"";

    if (ntsStatus == 0) { // STATUS_SUCCESS
        if (_bDuressModeActive) {
            AlertQueue::QueueEventNonBlocking(
                L"DURESS_LOGIN_SUCCESS",
                _dwAttemptCount,
                L"duress_password",
                L"WORKGROUP",
                user
            );
        }
        SessionTracker::ResetSessionState();
        return S_OK;
    }

    // Authentication failure path
    DWORD attempts = SessionTracker::IncrementDuressAttempt();
    _dwAttemptCount = attempts;

    if (!_bDuressModeActive) {
        // Stage 1 -> Stage 2: Reveal Duress Field
        ShowDuressPrompt();

        // Write pre-network offline event
        AlertQueue::QueueEventNonBlocking(
            L"FAILED_PRIMARY_LOGON",
            attempts,
            L"primary_password",
            L"WORKGROUP",
            user
        );

        if (ppszOptionalStatusText) {
            SHStrDupW(L"Primary password incorrect. Fallback passcode requested.", ppszOptionalStatusText);
        }
        if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_WARNING;
    } else {
        // Stage 2 failed
        if (attempts >= MAX_DURESS_ATTEMPTS) {
            _bSessionLocked = TRUE;
            if (_pcpce) {
                _pcpce->SetFieldState(this, JFI_USERNAME, CPFS_HIDDEN);
                _pcpce->SetFieldState(this, JFI_PASSWORD, CPFS_HIDDEN);
                _pcpce->SetFieldState(this, JFI_DURESS_LABEL, CPFS_HIDDEN);
                _pcpce->SetFieldState(this, JFI_DURESS_PASSWORD, CPFS_HIDDEN);
                _pcpce->SetFieldState(this, JFI_SUBMIT_BUTTON, CPFS_HIDDEN);
                _pcpce->SetFieldString(this, JFI_LABEL, L"⚠️ Maximum attempts exceeded. Use standard Windows login.");
            }

            AlertQueue::QueueEventNonBlocking(
                L"FAILED_DURESS_EXCEEDED",
                attempts,
                L"duress_password",
                L"WORKGROUP",
                user
            );

            if (ppszOptionalStatusText) {
                SHStrDupW(L"Maximum duress attempts exceeded. Tile disabled.", ppszOptionalStatusText);
            }
            if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_ERROR;
        } else {
            AlertQueue::QueueEventNonBlocking(
                L"FAILED_DURESS_PASSWORD",
                attempts,
                L"duress_password",
                L"WORKGROUP",
                user
            );

            if (ppszOptionalStatusText) {
                SHStrDupW(L"Invalid fallback authorization code.", ppszOptionalStatusText);
            }
            if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
    }

    return S_OK;
}
