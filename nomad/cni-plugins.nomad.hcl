# -----------------------------------------------------------------------------
# One-shot installer for the CNI reference plugins on every Nomad client.
#
# device-trust-vdi uses bridge networking, which Nomad only allows on clients
# that fingerprint ${attr.plugins.cni.version.bridge}. This sysbatch job runs
# once on each Linux client that is still missing it, installs the plugins,
# enables bridge netfilter, then has systemd restart Nomad so the new plugins
# are fingerprinted. Running allocations survive a client restart.
#
# Requires the raw_exec driver on the clients (it needs root on the host):
#   plugin "raw_exec" { config { enabled = true } }
#
#   nomad job run cni-plugins.nomad.hcl
# -----------------------------------------------------------------------------

variable "datacenters" {
  type    = list(string)
  default = ["eu-west-2a", "eu-west-2b", "eu-west-2c", "eu-west-2"]
}

variable "cni_version" {
  type    = string
  default = "v1.6.2"
}

variable "cni_path" {
  description = "Must match the client's cni_path (Nomad default: /opt/cni/bin)."
  type        = string
  default     = "/opt/cni/bin"
}

job "cni-plugins" {
  datacenters = var.datacenters
  type        = "sysbatch"

  meta {
    demo = "vault-device-trust-vdi"
  }

  constraint {
    attribute = "${attr.kernel.name}"
    value     = "linux"
  }

  # Only target clients that don't have the plugins yet, so re-running the
  # job is a no-op on clients that are already done.
  constraint {
    attribute = "${attr.plugins.cni.version.bridge}"
    operator  = "is_not_set"
  }

  group "install" {
    restart {
      attempts = 2
      interval = "5m"
      delay    = "15s"
      mode     = "fail"
    }

    task "install-cni" {
      driver = "raw_exec"

      config {
        command = "/bin/sh"
        args    = ["local/install-cni.sh"]
      }

      env {
        CNI_VERSION = var.cni_version
        CNI_PATH    = var.cni_path
      }

      template {
        destination = "local/install-cni.sh"
        perms       = "0755"
        data        = <<-EOF
          #!/bin/sh
          set -eu

          case "$(uname -m)" in
            x86_64)        ARCH=amd64 ;;
            aarch64|arm64) ARCH=arm64 ;;
            *) echo "cni: unsupported architecture $(uname -m)" >&2; exit 1 ;;
          esac

          TGZ="cni-plugins-linux-$ARCH-$CNI_VERSION.tgz"
          URL="https://github.com/containernetworking/plugins/releases/download/$CNI_VERSION/$TGZ"
          WORK="$NOMAD_TASK_DIR/dl"
          mkdir -p "$WORK"
          cd "$WORK"

          echo "cni: downloading $TGZ"
          curl -fsSL -o "$TGZ"        "$URL"
          curl -fsSL -o "$TGZ.sha256" "$URL.sha256"
          sha256sum -c "$TGZ.sha256"

          mkdir -p "$CNI_PATH"
          tar -C "$CNI_PATH" -xzf "$TGZ"
          echo "cni: installed into $CNI_PATH"
          ls "$CNI_PATH"

          # Bridged traffic must traverse iptables for Nomad's port mappings.
          modprobe br_netfilter
          echo br_netfilter > /etc/modules-load.d/nomad-cni.conf
          printf '%s\n' \
            'net.bridge.bridge-nf-call-arptables = 1' \
            'net.bridge.bridge-nf-call-ip6tables = 1' \
            'net.bridge.bridge-nf-call-iptables  = 1' \
            > /etc/sysctl.d/99-nomad-cni.conf
          sysctl --system > /dev/null
          echo "cni: bridge netfilter enabled"

          # Restart Nomad from a transient systemd unit, outside this task's
          # process tree, so the task can finish cleanly before the agent goes.
          systemd-run --unit="nomad-cni-restart-$(date +%s)" --on-active=15 \
            /bin/systemctl restart nomad
          echo "cni: nomad restart scheduled in 15s"
        EOF
      }

      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
