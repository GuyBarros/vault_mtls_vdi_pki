#!/usr/bin/env python3
"""
HashiCorp Vault workstation certificate enrollment for Windows.

Issues a machine certificate from a Vault PKI intermediate CA that is
subordinate to an ADCS root, and installs it into Cert:\\LocalMachine\\My
so Windows (and anything chaining to the AD-published root) trusts it.

Flow
----
1. Check the machine store for an existing Vault-issued certificate. If it is
   still valid for longer than --renew-days, exit without changes.
2. Authenticate to Vault with AppRole (role_id + secret_id).
3. Call <mount>/issue/<role> with the machine FQDN as CN and DNS SAN.
4. Build a PFX in memory with a random one-time password (3DES/SHA1 so every
   supported Windows version can import it).
5. Import with Import-PfxCertificate (private key non-exportable), set a
   FriendlyName for tracking, and add any intermediate CAs to LocalMachine\\CA.
6. Optionally remove superseded Vault-issued certificates.

Requirements
------------
    pip install hvac cryptography
    Run elevated (Administrator / SYSTEM): writing to LocalMachine needs it.

Example
-------
    python vault_workstation_enroll.py ^
        --vault-addr https://vault.corp.example.com:8200 ^
        --role-id-file C:\\ProgramData\\VaultEnroll\\role_id ^
        --secret-id-file C:\\ProgramData\\VaultEnroll\\secret_id ^
        --ca-cert C:\\ProgramData\\VaultEnroll\\vault-ca.pem ^
        --remove-old

Run it daily as a scheduled task under SYSTEM:
    schtasks /Create /TN "Vault Workstation Enroll" /RU SYSTEM /SC DAILY /ST 03:00 ^
        /TR "C:\\Python312\\python.exe C:\\ProgramData\\VaultEnroll\\vault_workstation_enroll.py --remove-old ..."

Exit codes: 0 = success or no renewal needed, 1 = error, 2 = dry run would enroll.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import logging
import os
import secrets
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import hvac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

LOG = logging.getLogger("vault-enroll")
DEFAULT_FRIENDLY_NAME = "Vault Workstation Authentication"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    vault_addr: str
    namespace: str | None
    ca_cert: str | None
    approle_mount: str
    role_id: str
    secret_id: str
    pki_mount: str
    pki_role: str
    common_name: str
    alt_names: list[str]
    ttl: str | None
    renew_days: int
    friendly_name: str
    remove_old: bool
    force: bool
    dry_run: bool


def _read_secret(value: str | None, file_path: str | None, env: str, label: str) -> str:
    """Resolve a secret from a file, an argument, or an environment variable (in that order)."""
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    if value:
        return value.strip()
    if os.environ.get(env):
        return os.environ[env].strip()
    raise SystemExit(f"Missing {label}: use --{label}-file, --{label}, or set {env}")


def parse_args(argv: list[str] | None = None) -> Config:
    p = argparse.ArgumentParser(description="Enroll a workstation certificate from HashiCorp Vault PKI.")
    p.add_argument("--vault-addr", default=os.environ.get("VAULT_ADDR"), help="Vault address (or VAULT_ADDR)")
    p.add_argument("--namespace", default=os.environ.get("VAULT_NAMESPACE"), help="Vault Enterprise namespace")
    p.add_argument("--ca-cert", default=os.environ.get("VAULT_CACERT"), help="PEM bundle to verify Vault's TLS cert")
    p.add_argument("--approle-mount", default="approle", help="AppRole auth mount path")
    p.add_argument("--role-id"), p.add_argument("--role-id-file")
    p.add_argument("--secret-id"), p.add_argument("--secret-id-file")
    p.add_argument("--pki-mount", default="pki_adcs", help="PKI secrets engine mount")
    p.add_argument("--pki-role", default="workstation", help="PKI role name")
    p.add_argument("--common-name", default=None, help="Defaults to this machine's FQDN")
    p.add_argument("--alt-names", default="", help="Extra comma-separated DNS SANs")
    p.add_argument("--ttl", default=None, help="Requested TTL, e.g. 8760h (role max_ttl applies)")
    p.add_argument("--renew-days", type=int, default=30, help="Renew when fewer than N days remain")
    p.add_argument("--friendly-name", default=DEFAULT_FRIENDLY_NAME, help="FriendlyName used to track Vault certs")
    p.add_argument("--remove-old", action="store_true", help="Delete superseded Vault-issued certs after import")
    p.add_argument("--force", action="store_true", help="Enroll even if a valid cert exists")
    p.add_argument("--dry-run", action="store_true", help="Check state only, change nothing")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if not a.vault_addr:
        raise SystemExit("Missing --vault-addr (or VAULT_ADDR)")

    cn = (a.common_name or socket.getfqdn()).lower()
    if "." not in cn:
        raise SystemExit(f"'{cn}' is not an FQDN; is the machine domain-joined? Use --common-name.")

    return Config(
        vault_addr=a.vault_addr,
        namespace=a.namespace,
        ca_cert=a.ca_cert,
        approle_mount=a.approle_mount,
        role_id=_read_secret(a.role_id, a.role_id_file, "VAULT_ROLE_ID", "role-id"),
        secret_id=_read_secret(a.secret_id, a.secret_id_file, "VAULT_SECRET_ID", "secret-id"),
        pki_mount=a.pki_mount,
        pki_role=a.pki_role,
        common_name=cn,
        alt_names=[n.strip().lower() for n in a.alt_names.split(",") if n.strip()],
        ttl=a.ttl,
        renew_days=a.renew_days,
        friendly_name=a.friendly_name,
        remove_old=a.remove_old,
        force=a.force,
        dry_run=a.dry_run,
    )


# --------------------------------------------------------------------------- #
# PowerShell helpers
# --------------------------------------------------------------------------- #
def run_ps(script: str, env_extra: dict[str, str] | None = None) -> str:
    """Run a PowerShell snippet and return stdout. Secrets travel via env, never argv."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, env=env, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PowerShell failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def find_existing(friendly_name: str, common_name: str) -> list[dict]:
    """Return Vault-issued certs in LocalMachine\\My for this CN, newest first."""
    script = f"""
$fn = {_ps_quote(friendly_name)}; $cn = {_ps_quote(common_name)}
$items = @(Get-ChildItem Cert:\\LocalMachine\\My |
  Where-Object {{ $_.FriendlyName -eq $fn -and $_.Subject -match ('CN=' + [regex]::Escape($cn)) }} |
  Sort-Object NotAfter -Descending |
  ForEach-Object {{ [pscustomobject]@{{ Thumbprint = $_.Thumbprint;
                                       NotAfter = $_.NotAfter.ToUniversalTime().ToString('o') }} }})
# -InputObject keeps a one-element result as a JSON array on Windows PowerShell 5.1.
ConvertTo-Json -InputObject $items -Compress
"""
    out = run_ps(script)
    return json.loads(out) if out else []


def import_pfx(pfx_bytes: bytes, password: str, friendly_name: str) -> str:
    """Import a PFX into LocalMachine\\My (key non-exportable), set FriendlyName, return thumbprint."""
    with tempfile.TemporaryDirectory(prefix="vault-enroll-") as tmp:
        pfx_path = Path(tmp) / "cert.pfx"
        pfx_path.write_bytes(pfx_bytes)
        try:
            script = f"""
$pw = ConvertTo-SecureString -String $env:VAULT_ENROLL_PFX_PW -AsPlainText -Force
$c = Import-PfxCertificate -FilePath {_ps_quote(str(pfx_path))} `
       -CertStoreLocation Cert:\\LocalMachine\\My -Password $pw
$leaf = $c | Where-Object {{ $_.HasPrivateKey }} | Select-Object -First 1
$leaf.FriendlyName = {_ps_quote(friendly_name)}
$leaf.Thumbprint
"""
            return run_ps(script, {"VAULT_ENROLL_PFX_PW": password}).splitlines()[-1].strip()
        finally:
            # Overwrite before the directory is removed.
            pfx_path.write_bytes(b"\0" * len(pfx_bytes))


def import_intermediates(cas: list[x509.Certificate]) -> None:
    """Add intermediate CAs to LocalMachine\\CA if missing (roots come from AD, not from here)."""
    for ca in cas:
        if ca.subject == ca.issuer:
            continue  # self-signed root: trust is distributed by AD Group Policy
        thumb = ca.fingerprint(hashes.SHA1()).hex().upper()
        der_b64 = base64.b64encode(ca.public_bytes(serialization.Encoding.DER)).decode()
        script = f"""
if (-not (Test-Path Cert:\\LocalMachine\\CA\\{thumb})) {{
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('CA','LocalMachine')
  $store.Open('ReadWrite')
  $store.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
      [Convert]::FromBase64String('{der_b64}')))
  $store.Close(); 'added'
}}
"""
        if run_ps(script) == "added":
            LOG.info("Added intermediate CA %s to LocalMachine\\CA", ca.subject.rfc4514_string())


def remove_certs(thumbprints: list[str]) -> None:
    for t in thumbprints:
        run_ps(f"Remove-Item -Path Cert:\\LocalMachine\\My\\{t} -DeleteKey")
        LOG.info("Removed superseded certificate %s", t)


# --------------------------------------------------------------------------- #
# Vault and crypto
# --------------------------------------------------------------------------- #
def vault_login(cfg: Config) -> hvac.Client:
    verify: bool | str = cfg.ca_cert if cfg.ca_cert else True
    client = hvac.Client(url=cfg.vault_addr, namespace=cfg.namespace, verify=verify)
    client.auth.approle.login(role_id=cfg.role_id, secret_id=cfg.secret_id, mount_point=cfg.approle_mount)
    if not client.is_authenticated():
        raise RuntimeError("Vault AppRole login failed")
    LOG.info("Authenticated to Vault at %s", cfg.vault_addr)
    return client


def issue_cert(client: hvac.Client, cfg: Config) -> dict:
    params: dict[str, str] = {"format": "pem", "private_key_format": "pkcs8"}
    sans = [n for n in cfg.alt_names if n != cfg.common_name]
    if sans:
        params["alt_names"] = ",".join(sans)
    if cfg.ttl:
        params["ttl"] = cfg.ttl
    resp = client.secrets.pki.generate_certificate(
        name=cfg.pki_role, common_name=cfg.common_name,
        extra_params=params, mount_point=cfg.pki_mount,
    )
    data = resp["data"]
    LOG.info("Issued certificate serial %s for %s", data["serial_number"], cfg.common_name)
    return data


def build_pfx(data: dict, friendly_name: str) -> tuple[bytes, str, list[x509.Certificate]]:
    """Build a Windows-compatible PFX from a Vault issue response."""
    leaf = x509.load_pem_x509_certificate(data["certificate"].encode())
    key = serialization.load_pem_private_key(data["private_key"].encode(), password=None)
    chain_pem = data.get("ca_chain") or [data["issuing_ca"]]
    cas = [x509.load_pem_x509_certificate(c.encode()) for c in chain_pem]

    password = secrets.token_urlsafe(32)
    # 3DES + SHA1 MAC: the format every supported Windows build imports reliably.
    enc = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(), key=key, cert=leaf, cas=None, encryption_algorithm=enc,
    )
    return pfx, password, cas


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def needs_renewal(existing: list[dict], renew_days: int) -> bool:
    if not existing:
        LOG.info("No Vault-issued certificate found in LocalMachine\\My")
        return True
    not_after = dt.datetime.fromisoformat(existing[0]["NotAfter"].replace("Z", "+00:00"))
    remaining = not_after - dt.datetime.now(dt.timezone.utc)
    LOG.info("Current certificate %s expires %s (%d days left)",
             existing[0]["Thumbprint"], not_after.isoformat(), remaining.days)
    return remaining < dt.timedelta(days=renew_days)


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(argv)
    if sys.platform != "win32" and not cfg.dry_run:
        LOG.error("This script installs into the Windows certificate store; run it on Windows.")
        return 1

    try:
        existing = find_existing(cfg.friendly_name, cfg.common_name) if sys.platform == "win32" else []
        if not cfg.force and not needs_renewal(existing, cfg.renew_days):
            LOG.info("No renewal needed")
            return 0
        if cfg.dry_run:
            LOG.info("Dry run: would enroll %s from %s/issue/%s", cfg.common_name, cfg.pki_mount, cfg.pki_role)
            return 2

        client = vault_login(cfg)
        data = issue_cert(client, cfg)
        pfx, password, cas = build_pfx(data, cfg.friendly_name)
        thumbprint = import_pfx(pfx, password, cfg.friendly_name)
        LOG.info("Installed certificate %s into LocalMachine\\My", thumbprint)
        import_intermediates(cas)

        if cfg.remove_old:
            remove_certs([c["Thumbprint"] for c in existing if c["Thumbprint"] != thumbprint])

        client.auth.token.revoke_self()  # don't leave a live token behind
        return 0
    except hvac.exceptions.VaultError as e:
        LOG.error("Vault error: %s", e)
    except Exception as e:  # noqa: BLE001 - top-level guard for scheduled runs
        LOG.exception("Enrollment failed: %s", e)
    return 1


if __name__ == "__main__":
    sys.exit(main())