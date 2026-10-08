# ---------------------------------------------------------------------------
# Device enrollment: AppRole
#
# Stands in for MDM-driven enrollment. An admin (or the MDM pipeline) mints a
# single-use, response-wrapped Secret ID per device; the device unwraps it once,
# logs in, and may only *sign* a CSR against the host-device role.
# In production you would typically swap this for Vault Enterprise SCEP/EST
# fed by Intune/Jamf, or the cert auth method backed by an existing TPM identity.
# ---------------------------------------------------------------------------

resource "vault_auth_backend" "devices" {
  type        = "approle"
  path        = var.approle_mount
  description = "Device trust demo: host enrollment"
}

resource "vault_approle_auth_backend_role" "host_enrollment" {
  backend   = vault_auth_backend.devices.path
  role_name = "host-enrollment"

  token_policies = [vault_policy.device_enroll.name]
  token_ttl      = 900 # 15 minutes: long enough to enroll, nothing more
  token_max_ttl  = 900

  bind_secret_id     = true
  secret_id_num_uses = 1    # a bootstrap credential works exactly once
  secret_id_ttl      = 3600 # and only for an hour
}

# ---------------------------------------------------------------------------
# Nomad workload identity: JWT auth
# The gateway task authenticates with its own Nomad-signed identity, so no
# Vault token is ever stored in the job or on the Nomad client.
# ---------------------------------------------------------------------------

resource "vault_jwt_auth_backend" "nomad" {
  count = var.create_nomad_jwt_auth ? 1 : 0

  path               = var.nomad_jwt_auth_path
  type               = "jwt"
  description        = "Nomad workload identities"
  jwks_url           = var.nomad_jwks_url
  jwks_ca_pem        = var.nomad_jwks_ca_pem == "" ? null : var.nomad_jwks_ca_pem
  jwt_supported_algs = ["RS256", "EdDSA"]

  lifecycle {
    precondition {
      condition     = var.nomad_jwks_url != ""
      error_message = "Set nomad_jwks_url when create_nomad_jwt_auth = true."
    }
  }
}

resource "vault_jwt_auth_backend_role" "device_trust_vdi" {
  backend   = var.create_nomad_jwt_auth ? vault_jwt_auth_backend.nomad[0].path : var.nomad_jwt_auth_path
  role_name = var.nomad_vault_role
  role_type = "jwt"

  bound_audiences = ["vault.io"]
  bound_claims = {
    nomad_namespace = var.nomad_namespace
    nomad_job_id    = var.nomad_job_id
  }

  user_claim              = "/nomad_job_id"
  user_claim_json_pointer = true
  claim_mappings = {
    nomad_namespace = "nomad_namespace"
    nomad_job_id    = "nomad_job_id"
    nomad_task      = "nomad_task"
  }

  token_type             = "service"
  token_policies         = [vault_policy.nomad_workload.name]
  token_period           = 1800
  token_explicit_max_ttl = 0
}
