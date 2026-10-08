terraform {
  required_version = ">= 1.5.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

# Authentication comes from the standard environment variables:
#   VAULT_ADDR, VAULT_TOKEN (and VAULT_CACERT if needed).
# Everything is created inside var.vault_namespace ("admin" on HCP Vault Dedicated).
provider "vault" {
  namespace = var.vault_namespace == "" ? null : var.vault_namespace
}
