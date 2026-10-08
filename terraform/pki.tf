locals {
  hour_s = 3600
  year_s = 8760 * local.hour_s

  # Base for the AIA / CRL / OCSP URLs embedded in certificates. Clients that
  # follow these URLs cannot send an X-Vault-Namespace header, so the namespace
  # goes in the path: <addr>/v1/admin/<mount>/crl
  vault_api = var.vault_namespace == "" ? "${var.vault_public_addr}/v1" : "${var.vault_public_addr}/v1/${trim(var.vault_namespace, "/")}"
}

# ---------------------------------------------------------------------------
# Root CA (demo only: in production the root normally lives offline / in an HSM)
# ---------------------------------------------------------------------------

resource "vault_mount" "root" {
  path                  = var.pki_root_mount
  type                  = "pki"
  description           = "Device trust demo: root CA"
  max_lease_ttl_seconds = 10 * local.year_s
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend      = vault_mount.root.path
  type         = "internal"
  common_name  = "${var.org_name} Root CA"
  organization = var.org_name
  ttl          = tostring(10 * local.year_s)
  key_type     = "ec"
  key_bits     = 384
  issuer_name  = "demo-root"
}

resource "vault_pki_secret_backend_config_urls" "root" {
  backend                 = vault_mount.root.path
  issuing_certificates    = ["${local.vault_api}/${vault_mount.root.path}/ca"]
  crl_distribution_points = ["${local.vault_api}/${vault_mount.root.path}/crl"]
}

# ---------------------------------------------------------------------------
# Intermediate CA for HOST DEVICES (client certificates only)
# A dedicated intermediate means the gateway trusts *only* device certs:
# a user cert or a service cert from another issuer can never substitute.
# ---------------------------------------------------------------------------

resource "vault_mount" "devices" {
  path                  = var.pki_devices_mount
  type                  = "pki"
  description           = "Device trust demo: host device intermediate CA"
  max_lease_ttl_seconds = 5 * local.year_s
}

resource "vault_pki_secret_backend_intermediate_cert_request" "devices" {
  backend      = vault_mount.devices.path
  type         = "internal"
  common_name  = "${var.org_name} Host Device CA"
  organization = var.org_name
  key_type     = "ec"
  key_bits     = 256
}

resource "vault_pki_secret_backend_root_sign_intermediate" "devices" {
  backend      = vault_mount.root.path
  csr          = vault_pki_secret_backend_intermediate_cert_request.devices.csr
  common_name  = "${var.org_name} Host Device CA"
  organization = var.org_name
  ttl          = tostring(5 * local.year_s)
  format       = "pem"

  depends_on = [vault_pki_secret_backend_root_cert.root]
}

resource "vault_pki_secret_backend_intermediate_set_signed" "devices" {
  backend     = vault_mount.devices.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.devices.certificate
}

resource "vault_pki_secret_backend_config_urls" "devices" {
  backend                 = vault_mount.devices.path
  issuing_certificates    = ["${local.vault_api}/${vault_mount.devices.path}/ca"]
  crl_distribution_points = ["${local.vault_api}/${vault_mount.devices.path}/crl"]
  ocsp_servers            = ["${local.vault_api}/${vault_mount.devices.path}/ocsp"]
}

resource "vault_pki_secret_backend_role" "host_device" {
  backend = vault_mount.devices.path
  name    = "host-device"

  # Identity: <device-id>.devices.demo.local, nothing else.
  allowed_domains    = [var.device_domain]
  allow_subdomains   = true
  allow_bare_domains = false
  allow_glob_domains = false
  allow_localhost    = false
  allow_ip_sans      = false
  enforce_hostnames  = true
  require_cn         = true

  # Client authentication only: a device cert can never be used as a server cert.
  client_flag = true
  server_flag = false

  key_type = "ec"
  key_bits = 256

  ttl     = tostring(var.device_cert_ttl_hours * local.hour_s)
  max_ttl = tostring(var.device_cert_max_ttl_hours * local.hour_s)

  # Keep issued certs in storage so they can be listed (inventory) and revoked by serial.
  no_store = false

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.devices]
}

# ---------------------------------------------------------------------------
# Intermediate CA for the VDI GATEWAY (server certificate, issued to Nomad)
# ---------------------------------------------------------------------------

resource "vault_mount" "gateway" {
  path                  = var.pki_gateway_mount
  type                  = "pki"
  description           = "Device trust demo: gateway server intermediate CA"
  max_lease_ttl_seconds = 5 * local.year_s
}

resource "vault_pki_secret_backend_intermediate_cert_request" "gateway" {
  backend      = vault_mount.gateway.path
  type         = "internal"
  common_name  = "${var.org_name} Gateway CA"
  organization = var.org_name
  key_type     = "ec"
  key_bits     = 256
}

resource "vault_pki_secret_backend_root_sign_intermediate" "gateway" {
  backend      = vault_mount.root.path
  csr          = vault_pki_secret_backend_intermediate_cert_request.gateway.csr
  common_name  = "${var.org_name} Gateway CA"
  organization = var.org_name
  ttl          = tostring(5 * local.year_s)
  format       = "pem"

  depends_on = [vault_pki_secret_backend_root_cert.root]
}

resource "vault_pki_secret_backend_intermediate_set_signed" "gateway" {
  backend     = vault_mount.gateway.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.gateway.certificate
}

resource "vault_pki_secret_backend_role" "gateway" {
  backend = vault_mount.gateway.path
  name    = "gateway"

  allowed_domains    = [var.gateway_domain]
  allow_subdomains   = true
  allow_bare_domains = true
  allow_ip_sans      = true
  enforce_hostnames  = true

  server_flag = true
  client_flag = false

  key_type = "ec"
  key_bits = 256

  ttl     = tostring(72 * local.hour_s)
  max_ttl = tostring(168 * local.hour_s)

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.gateway]
}
