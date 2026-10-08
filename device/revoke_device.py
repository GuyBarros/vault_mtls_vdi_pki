#!/usr/bin/env python3
"""Persona: security admin, responding to a lost or stolen laptop.

Revokes the device certificate in Vault. The gateway's CRL sidecar picks up
the new CRL within seconds and NGINX hot-reloads: the host is cut off long
before its certificate would have expired.

    python revoke_device.py laptop-0042
    python revoke_device.py --serial 1a:2b:...      # revoke by serial directly
"""

from __future__ import annotations

import argparse

from common import (
    PKI_DEVICES_MOUNT,
    banner,
    bold,
    device_dir,
    dim,
    fail,
    load_json,
    ok,
    vault_client,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("device_id", nargs="?")
    target.add_argument("--serial")
    args = parser.parse_args()

    if args.serial:
        serial, label = args.serial, args.serial
    else:
        meta_path = device_dir(args.device_id.lower()) / "metadata.json"
        if not meta_path.exists():
            fail(f"No enrollment record for {args.device_id}.")
        meta = load_json(meta_path)
        if meta.get("forged"):
            fail("That is a forged identity: Vault never issued it, so there is nothing to revoke.")
        serial, label = meta["serial_number"], meta["fqdn"]

    banner(f"Revoking {label}")
    client = vault_client(require_token=True)
    resp = client.secrets.pki.revoke_certificate(serial, mount_point=PKI_DEVICES_MOUNT)
    revoked_at = (resp or {}).get("data", {}).get("revocation_time_rfc3339", "now")

    print(ok("✔ ") + f"serial {bold(serial)} revoked in Vault at {revoked_at}")
    print(dim("   Vault rebuilt the CRL; the gateway picks it up on its next refresh (≈5s)."))


if __name__ == "__main__":
    main()
