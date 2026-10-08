<#
.SYNOPSIS
    Makes a Vault PKI mount a subordinate CA of the local ADCS CA (adcs.md, steps 1-4).

.DESCRIPTION
    Run on the ADCS server, in an elevated PowerShell, with a Vault token that
    can manage the PKI mount (VAULT_TOKEN set, or "vault login" done first).

    1. Enables and tunes the Vault PKI mount.
    2. Generates the intermediate CSR in Vault (written as ASCII: certreq
       rejects the UTF-16 files Windows PowerShell's ">" produces).
    3. Submits it to the local CA with the SubCA template, approves the
       pending request (unless -NoAutoApprove) and retrieves the certificate.
    4. Imports the certificate plus its ADCS parent chain into Vault.
    5. Sets the AIA/CRL URLs from VAULT_ADDR and VAULT_NAMESPACE, enables
       auto-tidy, and creates the workstation role.
    6. Optionally publishes the Vault CA into Active Directory.

    Safe to re-run: a mount that already has a signed issuer skips straight
    to step 5. With -NoAutoApprove, approve the request in the CA console and
    re-run with -RequestId to continue.

.EXAMPLE
    $env:VAULT_ADDR      = "https://<cluster>.<id>.z1.hashicorp.cloud:8200"
    $env:VAULT_NAMESPACE = "admin"
    vault login
    .\Setup-VaultSubCA.ps1 -AllowedDomains corp.example.com -PublishToAD

.EXAMPLE
    # Request left pending for a CA manager to approve; continue afterwards:
    .\Setup-VaultSubCA.ps1 -AllowedDomains corp.example.com -NoAutoApprove
    .\Setup-VaultSubCA.ps1 -AllowedDomains corp.example.com -RequestId 42
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]] $AllowedDomains,

    [string] $VaultAddr      = $env:VAULT_ADDR,
    [string] $VaultNamespace = $env:VAULT_NAMESPACE,
    [string] $Mount          = "pki_adcs",
    [string] $CommonName     = "Corp Vault Issuing CA",
    [int]    $KeyBits        = 4096,
    [string] $MaxLeaseTtl    = "8760h",

    # "<host>\<CA name>". Defaults to the CA installed on this server.
    [string] $CAConfig,
    [string] $Template       = "SubCA",
    [int]    $RequestId,
    [switch] $NoAutoApprove,

    [string] $RoleName       = "workstation",
    [string] $RoleTtl        = "720h",
    [switch] $ServerAuth,

    [switch] $PublishToAD,
    [switch] $PublishNTAuth,
    [switch] $Force,

    [string] $WorkDir        = (Join-Path $PWD "vault-subca")
)

$ErrorActionPreference = "Stop"

function Write-Step([string] $Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Runs a native command, echoes nothing, returns stdout lines, throws on failure.
function Invoke-Native([string] $Exe, [string[]] $Arguments) {
    $out = & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe $($Arguments -join ' ') failed (exit $LASTEXITCODE):`n$($out -join "`n")"
    }
    return $out
}

function ConvertTo-Pem([System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert) {
    $b64 = [Convert]::ToBase64String($Cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----"
}

# --- Preflight ---------------------------------------------------------------
foreach ($exe in "vault", "certreq", "certutil") {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { throw "$exe not found in PATH." }
}
if (-not $VaultAddr) { throw "Set VAULT_ADDR or pass -VaultAddr." }
$env:VAULT_ADDR = $VaultAddr.TrimEnd("/")
if ($VaultNamespace) { $env:VAULT_NAMESPACE = $VaultNamespace.Trim("/") }

Invoke-Native vault @("token", "lookup", "-format=json") | Out-Null

if (-not $CAConfig) {
    $caName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction SilentlyContinue).Active
    if (-not $caName) { throw "No local CA found. Run on the ADCS server or pass -CAConfig '<host>\<CA name>'." }
    $CAConfig = "$([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)\$caName"
}
Write-Step "Vault $env:VAULT_ADDR (namespace: $(if ($env:VAULT_NAMESPACE) { $env:VAULT_NAMESPACE } else { 'root' })), CA $CAConfig"

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$csrPath   = Join-Path $WorkDir "$Mount.csr"
$certPath  = Join-Path $WorkDir "vault-int.cer"
$chainPath = Join-Path $WorkDir "chain.pem"

# --- 1. PKI mount ------------------------------------------------------------
$mounts = (Invoke-Native vault @("secrets", "list", "-format=json")) -join "`n" | ConvertFrom-Json
if ($mounts.PSObject.Properties.Name -contains "$Mount/") {
    Write-Step "Mount $Mount already enabled"
} else {
    Write-Step "Enabling PKI mount $Mount"
    Invoke-Native vault @("secrets", "enable", "-path=$Mount", "pki") | Out-Null
}
Invoke-Native vault @("secrets", "tune", "-max-lease-ttl=$MaxLeaseTtl", $Mount) | Out-Null

# An issuer only exists once a signed intermediate has been imported.
# (Windows PowerShell turns redirected stderr into errors under "Stop".)
$ErrorActionPreference = "Continue"
& vault list -format=json "$Mount/issuers" 2>$null | Out-Null
$hasIssuer = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = "Stop"

if ($hasIssuer -and -not $Force) {
    Write-Step "$Mount already has a signed issuer; skipping CSR and signing (use -Force to redo)"
} else {
    # certreq only writes the certificate once the request is issued, so a
    # leftover file from an earlier run must not be mistaken for this one.
    Remove-Item $certPath -ErrorAction SilentlyContinue

    # --- 2. CSR ----------------------------------------------------------------
    if ($RequestId) {
        Write-Step "Resuming request $RequestId"
    } else {
        Write-Step "Generating intermediate CSR ($CommonName, RSA $KeyBits)"
        $csr = Invoke-Native vault @("write", "-field=csr", "$Mount/intermediate/generate/internal",
            "common_name=$CommonName", "key_type=rsa", "key_bits=$KeyBits")
        Set-Content -Path $csrPath -Value $csr -Encoding Ascii
        Invoke-Native certutil @("-dump", $csrPath) | Out-Null   # fails here rather than in certreq if the CSR is bad

        # --- 3. Submit to ADCS -------------------------------------------------
        $templates = Invoke-Native certutil @("-config", $CAConfig, "-CATemplates")
        if (-not ($templates -match "^\s*$([regex]::Escape($Template)):")) {
            throw "Template '$Template' is not published on $CAConfig. Add it with: certutil -SetCATemplates +$Template"
        }

        Write-Step "Submitting CSR to $CAConfig with template $Template"
        $submit = & certreq -q -f -config $CAConfig -submit -attrib "CertificateTemplate:$Template" $csrPath $certPath
        $submitText = $submit -join "`n"
        if ($submitText -notmatch 'RequestId:\s*"?(\d+)') { throw "certreq -submit failed:`n$submitText" }
        $RequestId = [int] $Matches[1]
        Write-Host "    RequestId $RequestId"
    }

    if (-not (Test-Path $certPath)) {
        if ($NoAutoApprove) {
            Write-Step "Request $RequestId left for approval"
            Write-Host "    Approve it in the Certification Authority console, then run:"
            Write-Host "    .\Setup-VaultSubCA.ps1 -AllowedDomains $($AllowedDomains -join ',') -RequestId $RequestId"
            return
        }
        Write-Step "Approving request $RequestId"
        & certutil -config $CAConfig -resubmit $RequestId | Out-Null   # no-op error if it is already issued

        Write-Step "Retrieving certificate"
        $retrieve = & certreq -q -f -config $CAConfig -retrieve $RequestId $certPath
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $certPath)) {
            throw "Could not retrieve request $RequestId (still pending or denied?):`n$($retrieve -join "`n")"
        }
    }

    # --- 4. Import signed intermediate + ADCS chain into Vault ---------------
    $intCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certPath
    Write-Step "Issued: $($intCert.Subject), valid until $($intCert.NotAfter)"

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    [void] $chain.Build($intCert)
    $pems = @($chain.ChainElements | ForEach-Object { ConvertTo-Pem $_.Certificate })
    if ($pems.Count -lt 2) { throw "Could not build the ADCS chain for $($intCert.Subject); is the ADCS root in the local trust store?" }
    Set-Content -Path $chainPath -Value ($pems -join "`r`n") -Encoding Ascii
    Write-Host "    Chain: $($chain.ChainElements.Count) certificates -> $chainPath"

    Write-Step "Importing signed intermediate into $Mount"
    Invoke-Native vault @("write", "$Mount/intermediate/set-signed", "certificate=@$chainPath") | Out-Null
}

# --- 5. URLs, tidy, role -------------------------------------------------------
$pkiUrl = "$env:VAULT_ADDR/v1/" + $(if ($env:VAULT_NAMESPACE) { "$env:VAULT_NAMESPACE/" }) + $Mount
Write-Step "Setting AIA/CRL URLs to $pkiUrl/{ca,crl}"
Invoke-Native vault @("write", "$Mount/config/urls",
    "issuing_certificates=$pkiUrl/ca", "crl_distribution_points=$pkiUrl/crl") | Out-Null
Invoke-Native vault @("write", "$Mount/config/auto-tidy",
    "enabled=true", "tidy_cert_store=true", "tidy_revoked_certs=true") | Out-Null

$eku = if ($ServerAuth) { "ClientAuth,ServerAuth" } else { "ClientAuth" }
Write-Step "Writing role $Mount/roles/$RoleName (domains: $($AllowedDomains -join ', '); EKU: $eku)"
Invoke-Native vault @("write", "$Mount/roles/$RoleName",
    "allowed_domains=$($AllowedDomains -join ',')", "allow_subdomains=true",
    "key_type=rsa", "key_bits=2048",
    "key_usage=DigitalSignature,KeyEncipherment", "ext_key_usage=$eku",
    "ttl=$RoleTtl", "max_ttl=$RoleTtl") | Out-Null

# --- 6. Active Directory -------------------------------------------------------
if ($PublishToAD -or $PublishNTAuth) {
    if (-not (Test-Path $certPath)) {
        Invoke-Native vault @("read", "-field=certificate", "$Mount/cert/ca") | Set-Content -Path $certPath -Encoding Ascii
    }
    if ($PublishToAD) {
        Write-Step "Publishing Vault CA to AD (SubCA container); needs Enterprise Admin"
        Invoke-Native certutil @("-dspublish", "-f", $certPath, "SubCA") | Out-Null
    }
    if ($PublishNTAuth) {
        Write-Step "Publishing Vault CA to NTAuth; needs Enterprise Admin"
        Invoke-Native certutil @("-dspublish", "-f", $certPath, "NTAuthCA") | Out-Null
    }
}

Write-Step "Done. Issue a test certificate with:"
Write-Host "    vault write $Mount/issue/$RoleName common_name=<host>.$($AllowedDomains[0]) alt_names=<host>.$($AllowedDomains[0])"
