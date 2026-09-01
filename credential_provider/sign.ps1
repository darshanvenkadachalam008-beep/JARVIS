# credential_provider/sign.ps1
$certName = "JarvisColdBootCert"
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$certName*" } | Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating self-signed code-signing certificate..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$certName" -CertStoreLocation Cert:\CurrentUser\My
}

if ($cert -and (Test-Path "JarvisCredentialProvider.dll")) {
    $sig = Set-AuthenticodeSignature -FilePath "JarvisCredentialProvider.dll" -Certificate $cert -HashAlgorithm SHA256
    Write-Host "Signature Status: $($sig.Status)" -ForegroundColor Green
    $ver = Get-AuthenticodeSignature -FilePath "JarvisCredentialProvider.dll"
    Write-Host "Subject: $($ver.SignerCertificate.Subject)"
    Write-Host "Thumbprint: $($ver.SignerCertificate.Thumbprint)"
}
