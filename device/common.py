"""Shared helpers for the host-device scripts.

Configuration comes from environment variables so the same scripts work
against any Vault / gateway:

    VAULT_ADDR            Vault address (required)
    VAULT_TOKEN           admin token (provision / list / revoke only)
    VAULT_CACERT          CA bundle for Vault's TLS cert (optional)
    VAULT_NAMESPACE       default: admin (HCP Vault Dedicated); "" for root
    DT_PKI_ROOT_MOUNT     default: pki-demo-root
    DT_PKI_DEVICES_MOUNT  default: pki-devices
    DT_APPROLE_MOUNT      default: approle-devices
    DT_DEVICE_DOMAIN      default: devices.demo.local
    DT_GATEWAY_URL        default: https://vdi.demo.local:8443
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import hvac
import requests
import urllib3

BASE_DIR = Path(__file__).resolve().parent
DEVICES_DIR = BASE_DIR / "devices"
TRUST_DIR = BASE_DIR / "trust"

PKI_ROOT_MOUNT = os.environ.get("DT_PKI_ROOT_MOUNT", "pki-demo-root")
PKI_DEVICES_MOUNT = os.environ.get("DT_PKI_DEVICES_MOUNT", "pki-devices")
APPROLE_MOUNT = os.environ.get("DT_APPROLE_MOUNT", "approle-devices")
APPROLE_ROLE = "host-enrollment"
DEVICE_ROLE = "host-device"
DEVICE_DOMAIN = os.environ.get("DT_DEVICE_DOMAIN", "devices.demo.local")
GATEWAY_URL = os.environ.get("DT_GATEWAY_URL", "https://vdi.demo.local:8443")


# --------------------------------------------------------------------------
# Terminal output (black / white with Vault yellow accents)
# --------------------------------------------------------------------------

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def vault(text: str) -> str:
    return _c("38;5;220;1", text)


def bold(text: str) -> str:
    return _c("1", text)


def dim(text: str) -> str:
    return _c("2", text)


def ok(text: str) -> str:
    return _c("32;1", text)


def bad(text: str) -> str:
    return _c("31;1", text)


def banner(title: str) -> None:
    print(vault("▌") + " " + bold(title))


def fail(message: str, code: int = 1) -> None:
    print(bad("✖ ") + message, file=sys.stderr)
    sys.exit(code)


# --------------------------------------------------------------------------
# Vault
# --------------------------------------------------------------------------


def vault_addr() -> str:
    addr = os.environ.get("VAULT_ADDR")
    if not addr:
        fail("VAULT_ADDR is not set.")
    return addr.rstrip("/")


def vault_verify() -> str | bool:
    return os.environ.get("VAULT_CACERT") or True


def vault_namespace() -> str | None:
    """HCP Vault Dedicated puts everything under the "admin" namespace."""
    return os.environ.get("VAULT_NAMESPACE", "admin").strip("/") or None


def vault_client(
    token: str | None = None,
    *,
    require_token: bool = False,
    addr: str | None = None,
    namespace: str | None = None,
) -> hvac.Client:
    token = token if token is not None else os.environ.get("VAULT_TOKEN")
    if require_token and not token:
        fail("VAULT_TOKEN is not set. This step is performed by the security admin / MDM persona.")
    return hvac.Client(
        url=addr or vault_addr(),
        token=token,
        namespace=namespace if namespace is not None else vault_namespace(),
        verify=vault_verify(),
    )


def root_ca_path() -> Path:
    """Root CA used to verify the gateway's server cert. Fetched once from
    Vault's unauthenticated CA endpoint and cached under device/trust/."""
    path = TRUST_DIR / "root-ca.pem"
    if not path.exists():
        TRUST_DIR.mkdir(parents=True, exist_ok=True)
        url = f"{vault_addr()}/v1/{PKI_ROOT_MOUNT}/ca/pem"
        headers = {"X-Vault-Namespace": ns} if (ns := vault_namespace()) else {}
        resp = requests.get(url, headers=headers, verify=vault_verify(), timeout=10)
        resp.raise_for_status()
        path.write_text(resp.text.strip() + "\n")
    return path


# --------------------------------------------------------------------------
# Device identity on disk
# --------------------------------------------------------------------------


def fqdn(device_id: str) -> str:
    return f"{device_id}.{DEVICE_DOMAIN}"


def device_dir(device_id: str, *, create: bool = False) -> Path:
    path = DEVICES_DIR / device_id
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


# --------------------------------------------------------------------------
# Gateway probe
# --------------------------------------------------------------------------


@dataclass
class GatewayResult:
    allowed: bool
    reason: str
    identity: dict | None = None


def probe_gateway(
    gateway_url: str,
    cert: tuple[str, str] | None,
    verify: str | bool,
) -> GatewayResult:
    """Open a brand-new TLS connection to the gateway and report whether the
    device was let through. A fresh connection every time means a revoked
    certificate is re-checked rather than riding on an existing session."""
    if verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = gateway_url.rstrip("/") + "/__device"
    with requests.Session() as session:
        try:
            resp = session.get(
                url,
                cert=cert,
                verify=verify,
                timeout=8,
                headers={"Connection": "close"},
            )
        except requests.exceptions.SSLError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                # The *device* could not verify the *gateway*. Not a device-trust
                # verdict: usually a stale trust/root-ca.pem or a name/IP mismatch.
                return GatewayResult(False, "could not verify the gateway's server certificate "
                                            f"({_short(exc)}); check device/trust/root-ca.pem and the gateway hostname/IP SANs")
            return GatewayResult(False, f"TLS handshake rejected ({_short(exc)})")
        except requests.exceptions.ConnectionError as exc:
            return GatewayResult(False, f"gateway unreachable ({_short(exc)})")

    verdict = resp.headers.get("X-Device-Verify", "")
    if resp.status_code == 200:
        try:
            ident = resp.json()
        except ValueError:
            ident = None
        if ident and ident.get("verify") == "SUCCESS":
            return GatewayResult(True, "SUCCESS", ident)
        return GatewayResult(False, f"unexpected response: {resp.text[:120]}")
    if resp.status_code == 403:
        if verdict == "NONE":
            verdict = "NONE (no device certificate presented)"
        return GatewayResult(False, verdict or "403 Forbidden")
    return GatewayResult(False, f"HTTP {resp.status_code} {verdict}".strip())


def print_gateway_result(label: str, result: GatewayResult) -> None:
    if result.allowed:
        ident = result.identity or {}
        print(f"{ok('✔ ALLOWED')}  {bold(label)}")
        print(dim(f"   subject : {ident.get('subject')}"))
        print(dim(f"   issuer  : {ident.get('issuer')}"))
        print(dim(f"   serial  : {ident.get('serial')}   expires {ident.get('not_after')}"))
        print(dim("   → VDI session may be brokered (user SSO happens next)"))
    else:
        print(f"{bad('✖ BLOCKED')}  {bold(label)}")
        print(dim(f"   reason  : {result.reason}"))
        print(dim("   → no desktop: this host is not known to the organization"))


def _short(exc: Exception) -> str:
    """Pull the human-meaningful bit out of a nested requests/urllib3 error."""
    import re

    text = str(exc)
    match = re.search(r"\[SSL[^\]]*\]\s*([^()'\"]+)", text)
    if match:
        return match.group(0).strip()
    for marker in ("Connection refused", "Name or service not known", "timed out", "Remote end closed"):
        if marker in text:
            return marker
    return text[:100]
