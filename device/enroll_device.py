#!/usr/bin/env python3
"""Persona: the host device.

Turns the one-time bootstrap credential into a device certificate:

  1. unwrap the Secret ID (fails if anyone else already unwrapped it)
  2. log in to Vault with AppRole
  3. generate the private key LOCALLY and send only a CSR
     (in production the key is generated inside the TPM and never exported)
  4. Vault signs it with the host-device role: client-auth only, short TTL

    python enroll_device.py laptop-0042
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

import hvac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from common import (
    APPROLE_MOUNT,
    DEVICE_ROLE,
    PKI_DEVICES_MOUNT,
    banner,
    bold,
    device_dir,
    dim,
    fail,
    fqdn,
    load_json,
    ok,
    root_ca_path,
    vault,
    vault_client,
    vault_namespace,
    write_private,
)


def build_p12(name: str, key, cert: x509.Certificate, issuing_ca: x509.Certificate, password: str) -> bytes:
    # Legacy-compatible PKCS#12 encryption so the bundle imports cleanly into
    # macOS Keychain, Windows cert store and browsers.
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    return pkcs12.serialize_key_and_certificates(name.encode(), key, cert, [issuing_ca], encryption)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("device_id")
    parser.add_argument("--ttl", default=None, help="requested cert TTL, e.g. 72h or 5m (defaults to the role TTL)")
    parser.add_argument("--p12-password", default="demo", help="password for the browser-importable .p12 (default: demo)")
    args = parser.parse_args()

    device_id = args.device_id.lower()
    ddir = device_dir(device_id)
    bootstrap_path = ddir / "bootstrap.json"
    if not bootstrap_path.exists():
        fail(f"No bootstrap credential for {device_id}. Run provision_device.py first (this host is not known yet).")
    bootstrap = load_json(bootstrap_path)
    name = fqdn(device_id)

    banner(f"Enrolling {name}")

    # The bootstrap file says which Vault / namespace issued it, so the laptop
    # needs no Vault configuration of its own.
    namespace = bootstrap.get("vault_namespace", vault_namespace() or "")

    # 1. Unwrap the one-time Secret ID ---------------------------------------
    try:
        # Authenticate *as* the wrapping token: that is all it is good for.
        unwrapper = vault_client(token=bootstrap["wrapped_secret_id"], addr=bootstrap["vault_addr"],
                                 namespace=namespace)
        secret_id = unwrapper.sys.unwrap()["data"]["secret_id"]
    except hvac.exceptions.VaultError as exc:
        fail(f"Bootstrap credential rejected ({exc}). It was already used, expired, or tampered with.")
    print(ok("✔ ") + "bootstrap credential unwrapped (it is now burned)")

    # 2. Log in -----------------------------------------------------------------
    client = vault_client(token="", addr=bootstrap["vault_addr"], namespace=namespace)
    client.auth.approle.login(bootstrap["role_id"], secret_id, mount_point=APPROLE_MOUNT)
    print(ok("✔ ") + f"authenticated to Vault via AppRole ({APPROLE_MOUNT})")

    # 3. Key + CSR, generated on the device -------------------------------------
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    print(ok("✔ ") + "EC P-256 key generated locally " + dim("(TPM in production); only the CSR leaves the device"))

    # 4. Vault signs ------------------------------------------------------------
    extra = {"ttl": args.ttl} if args.ttl else {}
    data = client.secrets.pki.sign_certificate(
        DEVICE_ROLE,
        csr.public_bytes(serialization.Encoding.PEM).decode(),
        name,
        extra_params=extra,
        mount_point=PKI_DEVICES_MOUNT,
    )["data"]

    cert = x509.load_pem_x509_certificate(data["certificate"].encode())
    issuing_ca = x509.load_pem_x509_certificate(data["issuing_ca"].encode())

    write_private(ddir / "key.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (ddir / "cert.pem").write_text(data["certificate"].strip() + "\n")
    (ddir / "chain.pem").write_text(
        data["issuing_ca"].strip() + "\n" + root_ca_path().read_text().strip() + "\n")
    write_private(ddir / "device.p12", build_p12(name, key, cert, issuing_ca, args.p12_password))

    meta = {
        "device_id": device_id,
        "fqdn": name,
        "serial_number": data["serial_number"],
        "not_after": cert.not_valid_after_utc.isoformat(),
        "issuer": cert.issuer.rfc4514_string(),
        "enrolled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (ddir / "metadata.json").write_text(json.dumps(meta, indent=2))
    bootstrap_path.unlink()

    print(ok("✔ ") + "device certificate issued by " + vault("HashiCorp Vault"))
    print(dim(f"   subject : CN={name}"))
    print(dim(f"   issuer  : {meta['issuer']}"))
    print(dim(f"   serial  : {meta['serial_number']}"))
    print(dim(f"   expires : {meta['not_after']}"))
    print(dim(f"   files   : {ddir}/{{cert,key,chain}}.pem, device.p12 (password: {args.p12_password})"))
    print(f"\nNext:  {bold(f'python access_gateway.py --device {device_id}')}")


if __name__ == "__main__":
    main()
