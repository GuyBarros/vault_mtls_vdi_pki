variable "vault_public_addr" {
  description = "Address of Vault as seen by devices and the Nomad client (embedded in the CRL / issuing-certificate URLs of issued certs)."
  type        = string
}

variable "vault_namespace" {
  description = "Vault namespace everything is created in. HCP Vault Dedicated uses \"admin\"; set \"\" for the root namespace of a self-managed Vault."
  type        = string
  default     = "admin"
}

# ---------------------------------------------------------------------------
# PKI layout
# ---------------------------------------------------------------------------

variable "pki_root_mount" {
  description = "Mount path of the demo root CA."
  type        = string
  default     = "pki-demo-root"
}

variable "pki_devices_mount" {
  description = "Mount path of the intermediate CA that issues host device (client) certificates."
  type        = string
  default     = "pki-devices"
}

variable "pki_gateway_mount" {
  description = "Mount path of the intermediate CA that issues the VDI gateway (server) certificate."
  type        = string
  default     = "pki-gateway"
}

variable "org_name" {
  description = "Organization name placed in CA subjects."
  type        = string
  default     = "Device Trust Demo"
}

variable "device_domain" {
  description = "Domain under which every device identity is issued, e.g. laptop-0042.devices.demo.local."
  type        = string
  default     = "devices.demo.local"
}

variable "device_cert_ttl_hours" {
  description = "Default TTL of a device certificate, in hours. Hosts are persistent, so days rather than hours."
  type        = number
  default     = 72
}

variable "device_cert_max_ttl_hours" {
  description = "Maximum TTL of a device certificate, in hours."
  type        = number
  default     = 720
}

variable "gateway_domain" {
  description = "Domain the VDI gateway certificate is issued for, e.g. vdi.demo.local."
  type        = string
  default     = "vdi.demo.local"
}

# ---------------------------------------------------------------------------
# Device enrollment (simulates MDM handing a one-time bootstrap credential)
# ---------------------------------------------------------------------------

variable "approle_mount" {
  description = "Mount path of the AppRole auth method used for device enrollment."
  type        = string
  default     = "approle-devices"
}

# ---------------------------------------------------------------------------
# Nomad workload identity
# ---------------------------------------------------------------------------

variable "create_nomad_jwt_auth" {
  description = "Create the JWT auth method for Nomad workload identities. Set false if Nomad is already integrated with this Vault (for example via `nomad setup vault`); the demo role is then added to the existing mount."
  type        = bool
  default     = true
}

variable "nomad_jwt_auth_path" {
  description = "Path of the JWT auth method that trusts Nomad workload identities. Must match `jwt_auth_backend_path` in the Nomad agent vault block."
  type        = string
  default     = "jwt-nomad"
}

variable "nomad_jwks_url" {
  description = "Nomad JWKS URL reachable from Vault, e.g. https://nomad.example.com:4646/.well-known/jwks.json. Only used when create_nomad_jwt_auth = true."
  type        = string
  default     = ""
}

variable "nomad_jwks_ca_pem" {
  description = "Optional CA PEM that signed Nomad's HTTPS certificate (needed when Nomad uses a private CA)."
  type        = string
  default     = ""
}

variable "nomad_namespace" {
  description = "Nomad namespace the demo job runs in."
  type        = string
  default     = "default"
}

variable "nomad_job_id" {
  description = "Nomad job ID of the demo. Only this job can use the Vault role."
  type        = string
  default     = "device-trust-vdi"
}

variable "nomad_vault_role" {
  description = "Name of the Vault JWT role the demo job uses (job `vault { role = ... }`)."
  type        = string
  default     = "device-trust-vdi"
}

variable "kv_mount" {
  description = "KV v2 mount that holds the demo's application secrets."
  type        = string
  default     = "kv-device-trust"
}
