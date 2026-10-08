# What an enrolling device may do: sign its own CSR. Nothing else.
# (`sign` rather than `issue` means the private key is generated on the device
#  and never travels to Vault.)
resource "vault_policy" "device_enroll" {
  name   = "device-trust-enroll"
  policy = <<-EOT
    path "${var.pki_devices_mount}/sign/host-device" {
      capabilities = ["create", "update"]
    }
  EOT
}

# What the Nomad job may do: read the CA certs it must trust, issue its own
# server certificate, and read its database password.
resource "vault_policy" "nomad_workload" {
  name   = "device-trust-vdi-workload"
  policy = <<-EOT
    path "${var.pki_root_mount}/cert/ca" {
      capabilities = ["read"]
    }

    path "${var.pki_devices_mount}/cert/ca" {
      capabilities = ["read"]
    }

    path "${var.pki_gateway_mount}/issue/gateway" {
      capabilities = ["create", "update"]
    }

    path "${var.kv_mount}/data/guacamole" {
      capabilities = ["read"]
    }
  EOT
}

# For the presenter (the "security admin / MDM" persona): provision bootstrap
# credentials, inventory devices, revoke a lost one. Attach this to the token
# you run the device/ scripts with, or just use an admin token in a lab.
resource "vault_policy" "device_admin" {
  name   = "device-trust-admin"
  policy = <<-EOT
    path "auth/${var.approle_mount}/role/host-enrollment/role-id" {
      capabilities = ["read"]
    }

    path "auth/${var.approle_mount}/role/host-enrollment/secret-id" {
      capabilities = ["create", "update"]
    }

    path "${var.pki_devices_mount}/certs" {
      capabilities = ["list"]
    }

    path "${var.pki_devices_mount}/cert/*" {
      capabilities = ["read"]
    }

    path "${var.pki_devices_mount}/revoke" {
      capabilities = ["create", "update"]
    }
  EOT
}
