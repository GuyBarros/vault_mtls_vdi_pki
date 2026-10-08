#!/usr/bin/env python3
"""Persona: an attacker / unmanaged machine impersonating a known host.

Builds a look-alike identity for an existing device: a fake CA with the SAME
name as the real Vault device CA, signing a cert with the SAME common name as
the real device. Then it tries the gateway.

It fails because trust comes from the issuer's key, not from names.

    python rogue_device.py laptop-0042
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common import (
    GATEWAY_URL,
    banner,
    device_dir,
    dim,
    fqdn,
    print_gateway_result,
    probe_gateway,
    root_ca_path,
    write_private,
)


def _issuer_name_of_real_device(device_id: str) -> x509.Name:
    meta_path = device_dir(device_id) / "metadata.json"
    if meta_path.exists():
        cert = x509.load_pem_x509_certificate((device_dir(device_id) / "cert.pem").read_bytes())
        return cert.issuer
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Device Trust Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Device Trust Demo Host Device CA"),
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("device_id", help="the legitimate device to impersonate")
    parser.add_argument("--gateway", default=GATEWAY_URL)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    victim = args.device_id.lower()
    rogue_id = f"{victim}-rogue"
    name = fqdn(victim)
    now = datetime.now(timezone.utc)

    banner(f"Forging an identity for {name}")

    ca_name = _issuer_name_of_real_device(victim)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    rdir = device_dir(rogue_id, create=True)
    write_private(rdir / "key.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (rdir / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (rdir / "fake-ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (rdir / "metadata.json").write_text(json.dumps({"forged": True, "impersonating": name}, indent=2))

    print(dim(f"   subject : CN={name}                    (identical to the real device)"))
    print(dim(f"   issuer  : {ca_name.rfc4514_string()}   (identical name, different key)"))
    print()

    verify = False if args.insecure else str(root_ca_path())
    print_gateway_result(f"{rogue_id} (forged)", probe_gateway(args.gateway, (str(rdir / "cert.pem"), str(rdir / "key.pem")), verify))


if __name__ == "__main__":
    main()
