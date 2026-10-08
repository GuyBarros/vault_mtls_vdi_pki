#!/usr/bin/env python3
"""Persona: the host device trying to start a VDI session.

Opens a fresh mTLS connection to the gateway and shows whether the host is
let through to the VDI broker.

    python access_gateway.py --device laptop-0042          # known host
    python access_gateway.py --no-cert                     # unmanaged host
    python access_gateway.py --device laptop-0042-rogue    # forged cert
    python access_gateway.py --device laptop-0042 --watch 2   # keep probing (revocation demo)
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime

from common import (
    GATEWAY_URL,
    banner,
    device_dir,
    dim,
    fail,
    print_gateway_result,
    probe_gateway,
    root_ca_path,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    who = parser.add_mutually_exclusive_group(required=True)
    who.add_argument("--device", help="device id whose certificate to present")
    who.add_argument("--no-cert", action="store_true", help="present no certificate at all")
    who.add_argument("--cert", help="explicit client cert PEM (use with --key)")
    parser.add_argument("--key", help="explicit client key PEM")
    parser.add_argument("--gateway", default=GATEWAY_URL, help=f"gateway URL (default {GATEWAY_URL})")
    parser.add_argument("--insecure", action="store_true", help="do not verify the gateway's server certificate")
    parser.add_argument("--watch", type=float, metavar="SECONDS", help="repeat every N seconds until Ctrl-C")
    args = parser.parse_args()

    if args.device:
        ddir = device_dir(args.device.lower())
        cert = (str(ddir / "cert.pem"), str(ddir / "key.pem"))
        if not (ddir / "cert.pem").exists():
            fail(f"{args.device} has no certificate. Enroll it first (or it was never provisioned).")
        label = args.device.lower()
    elif args.cert:
        if not args.key:
            fail("--cert needs --key")
        cert = (args.cert, args.key)
        label = args.cert
    else:
        cert = None
        label = "unmanaged host (no certificate)"

    verify = False if args.insecure else str(root_ca_path())

    banner(f"Requesting a VDI session at {args.gateway}")
    while True:
        result = probe_gateway(args.gateway, cert, verify)
        if args.watch:
            print(dim(datetime.now().strftime("%H:%M:%S")), end="  ")
        print_gateway_result(label, result)
        if not args.watch:
            raise SystemExit(0 if result.allowed else 2)
        try:
            time.sleep(args.watch)
        except KeyboardInterrupt:
            print()
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
