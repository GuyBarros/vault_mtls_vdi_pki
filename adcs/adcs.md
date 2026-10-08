The approach that works is to make Vault a subordinate (intermediate) CA under your ADCS root. Vault then issues the workstation certificates, and Windows trusts them because the chain ends at the ADCS root that is already distributed through Active Directory.

One thing to settle first: what does "ADCS recognises" mean for you?

    Trusted by domain machines. This is what the setup below gives you.
    Recorded in the ADCS database, under ADCS templates and autoenrollment. Vault can't do this. Only certificates that ADCS issues itself show up there. If that's what you need, keep using ADCS autoenrollment and put Vault elsewhere.

Steps 1–4 are automated by [adcs/Setup-VaultSubCA.ps1](adcs/Setup-VaultSubCA.ps1). Run it in an elevated PowerShell on the ADCS server after `vault login`:
```powershell
$env:VAULT_ADDR      = "https://<cluster>.<id>.z1.hashicorp.cloud:8200"
$env:VAULT_NAMESPACE = "admin"
.\adcs\Setup-VaultSubCA.ps1 -AllowedDomains corp.example.com -PublishToAD
```
The manual steps below show what it does.

1. Create the Vault intermediate and get it signed by ADCS

All commands in this guide run in PowerShell on the ADCS server.
```powershell
$env:VAULT_ADDR      = "https://<cluster>.<id>.z1.hashicorp.cloud:8200"
$env:VAULT_NAMESPACE = "admin"   # HCP Vault Dedicated; omit for the root namespace

vault secrets enable -path=pki_adcs pki
vault secrets tune -max-lease-ttl=8760h pki_adcs

# -field avoids jq, and Out-File -Encoding ascii avoids the UTF-16 file that
# Windows PowerShell's ">" writes, which certreq rejects with
# "ASN1 bad tag value met. 0x8009310b (CRYPT_E_ASN1_BADTAG)".
vault write -field=csr pki_adcs/intermediate/generate/internal `
  "common_name=Corp Vault Issuing CA" key_type=rsa key_bits=4096 |
  Out-File -Encoding ascii pki_adcs.csr

certutil -dump pki_adcs.csr   # must parse and show CN=Corp Vault Issuing CA
```
Submit the CSR against the built-in SubCA template. HashiCorp's support article uses this same certreq approach.
```powershell
certreq -submit -attrib "CertificateTemplate:SubCA" pki_adcs.csr vault-int.cer
# SubCA requests usually go to "pending". Approve the request, then retrieve it:
certutil -resubmit <RequestId>
certreq -retrieve <RequestId> vault-int.cer
```
Import the certificate into Vault with the ADCS root appended so Vault holds the full chain. certreq saves Base64 (PEM), so only the root needs converting:
```powershell
# Quoted: PowerShell would otherwise split -ca.cert into "-ca" and ".cert".
certutil "-ca.cert" adcs-root.der
certutil -encode adcs-root.der adcs-root.pem
# If this ADCS CA is itself a subordinate, append its parent CA certificate(s) too.
Get-Content vault-int.cer, adcs-root.pem | Set-Content -Encoding ascii chain.pem
vault write pki_adcs/intermediate/set-signed certificate=@chain.pem
```
2. Make revocation checking work for Windows

Windows checks CRLs and AIA. If workstations can't reach those URLs, certificate validation fails in ways that are hard to diagnose. The URLs below are built from the VAULT_ADDR and VAULT_NAMESPACE set in step 1, so they must be addresses the workstations can reach:
```powershell
# The namespace is part of the URL path (/v1/admin/...); none for the root namespace.
$pkiUrl = "$env:VAULT_ADDR/v1/" + $(if ($env:VAULT_NAMESPACE) { "$env:VAULT_NAMESPACE/" }) + "pki_adcs"

vault write pki_adcs/config/urls `
  "issuing_certificates=$pkiUrl/ca" `
  "crl_distribution_points=$pkiUrl/crl"
vault read pki_adcs/config/urls   # check the URLs before issuing any certificates
vault write pki_adcs/config/auto-tidy enabled=true tidy_cert_store=true tidy_revoked_certs=true
```
3. Publish the Vault CA into Active Directory

Run these as an Enterprise Admin:
```powershell

certutil -dspublish -f vault-int.cer SubCA       # distributes the intermediate to domain machines
certutil -dspublish -f vault-int.cer NTAuthCA    # needed only if the certificates authenticate to AD
```
You need the NTAuth entry for smart card or PKINIT logon, and often for 802.1X through NPS, where the certificate is mapped to the computer account.
4. Create a role that mirrors the "Workstation Authentication" template
```powershell
vault write pki_adcs/roles/workstation `
  allowed_domains="corp.example.com" allow_subdomains=true `
  key_type=rsa key_bits=2048 `
  key_usage="DigitalSignature,KeyEncipherment" `
  ext_key_usage="ClientAuth" `
  max_ttl=720h ttl=720h
```
Issue certificates with the machine's FQDN as both the CN and the DNS SAN. Add ServerAuth to ext_key_usage if the workstations also host TLS endpoints.
5. Get the certificates onto the workstations

You have a few options:

    Vault Agent on Windows with a pkiCert template renders the certificate and handles renewal. Follow the render with certutil -importpfx (or Import-PfxCertificate) into Cert:\LocalMachine\My.
   
    A Python script with hvac authenticates the machine (AppRole or cert auth), calls pki_adcs/issue/workstation, builds a PFX with cryptography, and imports it.
    ACME. Vault PKI exposes an ACME endpoint, and a Windows ACME client such as win-acme can use it. This is less common for client certificates.

Gotchas to check

    Strong certificate mapping (KB5014754). Domain controllers now enforce strong mapping for certificate-based authentication. ADCS embeds the computer's SID in the certificate, and Vault can't add that SID extension. If these certificates are used to authenticate to AD, you'll need explicit altSecurityIdentities mappings on the computer objects, or you should let ADCS issue those particular certificates.
    Template-specific policies. Vault doesn't add the Microsoft certificate-template extension. Any policy that matches on a specific template name or OID, such as some NPS or Intune rules, won't match Vault-issued certificates.
    Lifetime. The SubCA validity that ADCS grants caps what Vault can issue, so plan the intermediate rotation ahead of time.

If it helps, I can write the Python hvac enrollment script for the workstations, including PFX creation and import into the machine store.

