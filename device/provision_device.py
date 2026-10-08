#!/usr/bin/env python3
"""Persona: security admin / MDM.

Registers a host as "known to the organization" by minting a single-use,
response-wrapped bootstrap credential for it. In production this is what
Intune / Jamf (or your imaging pipeline) would deliver to the device.

    python provision_device.py laptop-0042
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone

from common import (
    APPROLE_MOUNT,
    APPROLE_ROLE,
    banner,
    bold,
    device_dir,
    dim,
    fqdn,
    ok,
    fail,
    vault_addr,
    vault_client,
    vault_namespace,
    write_private,
)

DEVICE_ID_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("device_id", help="asset tag / hostname, e.g. laptop-0042")
    parser.add_argument("--wrap-ttl", default="15m", help="how long the bootstrap credential can be unwrapped (default 15m)")
    args = parser.parse_args()

    device_id = args.device_id.lower()
    if not DEVICE_ID_RE.match(device_id):
        fail("device_id must be a DNS label: lowercase letters, digits and hyphens.")

    banner(f"Provisioning {fqdn(device_id)}")
    client = vault_client(require_token=True)

    role_id = client.auth.approle.read_role_id(APPROLE_ROLE, mount_point=APPROLE_MOUNT)["data"]["role_id"]
    wrapped = client.auth.approle.generate_secret_id(
        APPROLE_ROLE,
        metadata={"device_id": device_id},
        wrap_ttl=args.wrap_ttl,
        mount_point=APPROLE_MOUNT,
    )
    wrap_info = wrapped["wrap_info"]

    bootstrap = {
        "device_id": device_id,
        "vault_addr": vault_addr(),
        "vault_namespace": vault_namespace() or "",
        "role_id": role_id,
        "wrapped_secret_id": wrap_info["token"],
        "wrap_expires": wrap_info.get("creation_time"),
        "provisioned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path = device_dir(device_id, create=True) / "bootstrap.json"
    write_private(path, json.dumps(bootstrap, indent=2).encode())

    print(ok("✔ ") + f"bootstrap credential written to {bold(str(path))}")
    print(dim(f"   role_id           : {role_id}"))
    print(dim(f"   wrapped secret_id : {wrap_info['token'][:12]}…  (single use, unwrap within {args.wrap_ttl})"))
    print(dim("   The Secret ID itself never appears on screen or on disk in clear text."))
    print(f"\nNext, on the device:  {bold(f'python enroll_device.py {device_id}')}")


if __name__ == "__main__":
    main()
