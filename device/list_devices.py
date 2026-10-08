#!/usr/bin/env python3
"""Persona: security admin. Inventory of every device identity Vault issued.

    python list_devices.py
"""

from __future__ import annotations

from datetime import datetime, timezone

import hvac
from cryptography import x509

from common import PKI_DEVICES_MOUNT, bad, banner, bold, dim, ok, vault_client


def main() -> None:
    client = vault_client(require_token=True)
    banner(f"Device identities issued by {PKI_DEVICES_MOUNT}")

    try:
        serials = client.secrets.pki.list_certificates(mount_point=PKI_DEVICES_MOUNT)["data"]["keys"]
    except hvac.exceptions.InvalidPath:
        serials = []

    now = datetime.now(timezone.utc)
    rows = []
    for serial in serials:
        data = client.secrets.pki.read_certificate(serial, mount_point=PKI_DEVICES_MOUNT)["data"]
        cert = x509.load_pem_x509_certificate(data["certificate"].encode())
        if _is_ca(cert):
            continue  # skip CA certificates
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        name = cn[0].value if cn else "?"
        if data.get("revocation_time"):
            status = bad("revoked")
        elif cert.not_valid_after_utc < now:
            status = dim("expired")
        else:
            status = ok("trusted")  # all three labels are 7 chars, so alignment survives colouring
        rows.append((name, serial, cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M"), status))

    if not rows:
        print(dim("   no devices enrolled yet"))
        return
    width = max(len(r[0]) for r in rows)
    print(bold(f"   {'DEVICE'.ljust(width)}  {'EXPIRES (UTC)'.ljust(16)}  STATUS   SERIAL"))
    for name, serial, expires, status in sorted(rows):
        print(f"   {name.ljust(width)}  {expires.ljust(16)}  {status}  {dim(serial)}")


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


if __name__ == "__main__":
    main()
