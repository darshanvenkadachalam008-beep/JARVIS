// credential_provider/JarvisCredentialProvider.h
// Full Implementation of ICredentialProvider and ICredentialProviderCredential2
#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include "guid.h"
#include "SessionTracker.h"
#include "AlertQueue.h"

enum JARVIS_FIELD_ID {
    JFI_TILE_IMAGE = 0,
    JFI_LABEL = 1,
    JFI_USERNAME = 2,
    JFI_PASSWORD = 3,
    JFI_DURESS_LABEL = 4,
    JFI_DURESS_PASSWORD = 5,
    JFI_SUBMIT_BUTTON = 6,
    JFI_NUM_FIELDS = 7
};

class CJarvisCredential;

class CJarvisCredentialProvider : public ICredentialProvider {
public:
    CJarvisCredentialProvider();
    virtual ~CJarvisCredentialProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

private:
    long _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    DWORD _dwFlags;
    ICredentialProviderEvents* _pcpe;
    UINT_PTR _upAdviseContext;
    CJarvisCredential* _pCredential;
    BOOL _bScenarioSupported;
};

class CJarvisCredential : public ICredentialProviderCredential2 {
public:
    CJarvisCredential(CJarvisCredentialProvider* pProvider);
    virtual ~CJarvisCredential();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR psz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(LPWSTR* ppszSid);

    void ShowDuressPrompt();

private:
    long _cRef;
    CJarvisCredentialProvider* _pProvider;
    ICredentialProviderCredentialEvents* _pcpce;

    PWSTR _pszUsername;
    PWSTR _pszPassword;
    PWSTR _pszDuressPassword;

    BOOL _bDuressModeActive;
    BOOL _bSessionLocked;
    DWORD _dwAttemptCount;

    HRESULT PackageKerberosAuthBuffer(
        LPCWSTR pszDomain,
        LPCWSTR pszUsername,
        LPCWSTR pszPassword,
        BYTE** ppbAuthBuffer,
        DWORD* pcbAuthBuffer
    );
};
