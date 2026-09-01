@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  JARVIS Cold-Boot Credential Provider -- Automated Build ^& Sign Script
echo =====================================================================

:: 1. Verify VM Test-Signing Prerequisites
echo [*] Checking Windows Test-Signing status...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$opt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SystemStartOptions' -ErrorAction SilentlyContinue).SystemStartOptions; if ($opt -and $opt -like '*TESTSIGNING*') { Write-Host '  [OK] Windows Test-Signing mode is ACTIVE.' -ForegroundColor Green } else { Write-Host '  [WARNING] Test-Signing is NOT active. On your disposable VM, run:' -ForegroundColor Yellow; Write-Host '    bcdedit /set testsigning on' -ForegroundColor Cyan; Write-Host '  and reboot before testing Credential Provider DLL loading.' -ForegroundColor Yellow }"

:: 2. Locate MSVC Compiler
set "VCVARS="
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)

if defined VCVARS (
    echo [*] Initializing MSVC x64 build environment from: !VCVARS!
    call "!VCVARS!" >nul 2>&1
) else (
    where cl.exe >nul 2>&1
    if errorlevel 1 (
        echo [!] MSVC cl.exe compiler not found in PATH or standard VS locations.
        echo     Please run this script from the 'x64 Native Tools Command Prompt for VS'.
        goto :GEN_CERT
    )
)

:: 3. Compile x64 COM In-Process DLL
echo [*] Compiling JarvisCredentialProvider.dll (x64)...
cl.exe /nologo /W4 /EHsc /O2 /MD /LD ^
    JarvisCredentialProvider.cpp ^
    AlertQueue.cpp ^
    SessionTracker.cpp ^
    dllmain.cpp ^
    /DEF:JarvisCredentialProvider.def ^
    /link /OUT:JarvisCredentialProvider.dll ^
    advapi32.lib crypt32.lib shlwapi.lib secur32.lib wtsapi32.lib ole32.lib user32.lib

if errorlevel 1 (
    echo [!] Compilation failed.
    exit /b 1
)
echo   [OK] Binary compiled successfully: JarvisCredentialProvider.dll

:: 4. Generate Certificate & Sign DLL
echo [*] Code-signing JarvisCredentialProvider.dll with self-signed certificate...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$certName = 'JarvisColdBootCert'; " ^
  "$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like \"*$certName*\" } | Select-Object -First 1; " ^
  "if (-not $cert) { " ^
  "    Write-Host '  Creating self-signed code-signing certificate in CurrentUser store...' -ForegroundColor Cyan; " ^
  "    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject \"CN=$certName\" -CertStoreLocation Cert:\CurrentUser\My; " ^
  "} " ^
  "try { " ^
  "    $rootUserStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser'); " ^
  "    $rootUserStore.Open('ReadWrite'); " ^
  "    $rootUserStore.Add($cert); " ^
  "    $rootUserStore.Close(); " ^
  "    $pubUserStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'CurrentUser'); " ^
  "    $pubUserStore.Open('ReadWrite'); " ^
  "    $pubUserStore.Add($cert); " ^
  "    $pubUserStore.Close(); " ^
  "} catch {} " ^
  "try { " ^
  "    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); " ^
  "    $rootStore.Open('ReadWrite'); " ^
  "    $rootStore.Add($cert); " ^
  "    $rootStore.Close(); " ^
  "    $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine'); " ^
  "    $pubStore.Open('ReadWrite'); " ^
  "    $pubStore.Add($cert); " ^
  "    $pubStore.Close(); " ^
  "    Write-Host '  [OK] Certificate installed into LocalMachine Root and TrustedPublisher stores.' -ForegroundColor Green; " ^
  "} catch { " ^
  "    Write-Host '  [INFO] LocalMachine store import requires elevation; cert active in CurrentUser store.' -ForegroundColor Yellow; " ^
  "} " ^
  "if ($cert -and (Test-Path 'JarvisCredentialProvider.dll')) { " ^
  "    $sigResult = Set-AuthenticodeSignature -FilePath 'JarvisCredentialProvider.dll' -Certificate $cert -HashAlgorithm SHA256; " ^
  "    Write-Host \"  Signature Status: $($sigResult.Status)\" -ForegroundColor Green; " ^
  "}"

echo =====================================================================
echo  Build complete!
echo =====================================================================
