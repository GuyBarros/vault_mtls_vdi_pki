output "root_ca_pem" {
  description = "Root CA certificate. Devices use it to verify the gateway's server certificate."
  value       = vault_pki_secret_backend_root_cert.root.certificate
}

output "device_ca_pem" {
  description = "Host device intermediate CA certificate."
  value       = vault_pki_secret_backend_root_sign_intermediate.devices.certificate
}

output "nomad_job_vars" {
  description = "Variables to pass to the Nomad job so it matches this Vault configuration."
  value = {
    vault_namespace   = var.vault_namespace
    vault_role        = vault_jwt_auth_backend_role.device_trust_vdi.role_name
    pki_root_mount    = vault_mount.root.path
    pki_devices_mount = vault_mount.devices.path
    pki_gateway_mount = vault_mount.gateway.path
    kv_mount          = vault_mount.kv.path
    gateway_hostname  = var.gateway_domain
  }
}

output "device_script_env" {
  description = "Environment for the Python device scripts (export these before running them)."
  value       = <<-EOT
    export VAULT_NAMESPACE=${var.vault_namespace}
    export DT_PKI_ROOT_MOUNT=${vault_mount.root.path}
    export DT_PKI_DEVICES_MOUNT=${vault_mount.devices.path}
    export DT_APPROLE_MOUNT=${vault_auth_backend.devices.path}
    export DT_DEVICE_DOMAIN=${var.device_domain}
  EOT
}
