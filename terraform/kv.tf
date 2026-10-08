resource "vault_mount" "kv" {
  path        = var.kv_mount
  type        = "kv"
  options     = { version = "2" }
  description = "Device trust demo: application secrets"
}

resource "random_password" "guacamole_db" {
  length  = 32
  special = false
}

resource "vault_kv_secret_v2" "guacamole" {
  mount = vault_mount.kv.path
  name  = "guacamole"
  data_json = jsonencode({
    db_name     = "guacamole_db"
    db_username = "guacamole_user"
    db_password = random_password.guacamole_db.result
  })
}
