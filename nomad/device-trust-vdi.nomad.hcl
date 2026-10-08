# -----------------------------------------------------------------------------
# Device-trusted VDI on HashiCorp Nomad
#
#   Host device ──mTLS (Vault-issued device cert)──▶ gateway (NGINX)
#                                                     │  verified only?
#                                                     ▼
#                                         Apache Guacamole ─▶ guacd ─▶ desktop (RDP)
#
# Everything runs in ONE allocation with bridge networking, so the tasks talk
# to each other over localhost and only the gateway port is exposed.
#
# Vault is used for:
#   * the gateway's server certificate        (pkiCert, auto-renewed)
#   * the device CA chain the gateway trusts  (secret read)
#   * the device + root CRLs                  (unauthenticated CRL endpoints)
#   * the Guacamole DB password               (KV v2)
# via Nomad workload identity (JWT auth): no Vault token in the job.
# -----------------------------------------------------------------------------

variable "datacenters" {
  type    = list(string)
  default =  ["eu-west-2a","eu-west-2b","eu-west-2c","eu-west-2"]
}

variable "vault_addr" {
  description = "Vault address reachable from the Nomad client; used by the CRL sync sidecar."
  type        = string
}

variable "vault_namespace" {
  description = "Vault namespace the demo lives in (\"admin\" on HCP Vault Dedicated, \"\" for root). Used by the CRL sync sidecar; templates use the namespace from the Nomad agent's vault block."
  type        = string
  default     = "admin"
}

variable "vault_ca_pem" {
  description = "Optional CA PEM for Vault's TLS certificate (if Vault uses a private CA)."
  type        = string
  default     = ""
}

variable "vault_tls_skip_verify" {
  description = "Lab only: skip TLS verification when fetching CRLs from Vault."
  type        = bool
  default     = false
}

variable "crl_sync_doh_url" {
  description = "Optional DNS-over-HTTPS resolver for the CRL sync sidecar, for clients where port 53 is blocked from the bridge network (e.g. \"https://1.1.1.1/dns-query\")."
  type        = string
  default     = ""
}

variable "vault_role" {
  type    = string
  default = "device-trust-vdi"
}

variable "pki_root_mount" {
  type    = string
  default = "pki-demo-root"
}

variable "pki_devices_mount" {
  type    = string
  default = "pki-devices"
}

variable "pki_gateway_mount" {
  type    = string
  default = "pki-gateway"
}

variable "kv_mount" {
  type    = string
  default = "kv-device-trust"
}

variable "gateway_hostname" {
  description = "Name devices use to reach the gateway (must sit under gateway_domain in Vault)."
  type        = string
  default     = "vdi.demo.local"
}

variable "gateway_ip_sans" {
  description = "Comma-separated IPs to put in the gateway certificate (e.g. the Nomad client IP)."
  type        = string
  default     = "127.0.0.1"
}

variable "gateway_port" {
  description = "Static host port the gateway listens on."
  type        = number
  default     = 8443
}

variable "crl_refresh_seconds" {
  description = "How often the gateway pulls fresh CRLs from Vault."
  type        = number
  default     = 5
}

variable "images" {
  type = map(string)
  default = {
    gateway   = "nginx:1.27-alpine"
    crl_sync  = "curlimages/curl:8.10.1"
    guacamole = "guacamole/guacamole:1.6.0"
    guacd     = "guacamole/guacd:1.6.0"
    postgres  = "postgres:16-alpine"
    desktop   = "scottyhardy/docker-remote-desktop:latest"
  }
}

job "device-trust-vdi" {
  datacenters = var.datacenters
  type        = "service"

  meta {
    demo = "vault-device-trust-vdi"
  }

  group "vdi" {
    count = 1

    network {
      mode     = "bridge"
      hostname = "corp-desktop-01"

      port "https" {
        static = var.gateway_port
        to     = 443
      }
    }

    service {
      name     = "device-trust-gateway"
      port     = "https"
      provider = "consul"
      tags     = ["mtls", "vdi"]

      # A TCP check: an HTTP check would be (correctly) rejected without a device cert.
      check {
        type     = "tcp"
        interval = "10s"
        timeout  = "2s"
      }
    }

    restart {
      attempts = 5
      interval = "5m"
      delay    = "10s"
      mode     = "delay"
    }

    # =========================================================================
    # PRESTART: extract the Guacamole DB schema from the Guacamole image
    # =========================================================================
    task "guac-schema" {
      driver = "docker"
      user   = "root"

      lifecycle {
        hook    = "prestart"
        sidecar = false
      }

      config {
        image      = var.images["guacamole"]
        entrypoint = ["/bin/sh", "-c"]
        args = [
          "mkdir -p /alloc/data/initdb && /opt/guacamole/bin/initdb.sh --postgresql > /alloc/data/initdb/001-guacamole-schema.sql && echo schema extracted",
        ]
      }

      resources {
        cpu    = 200
        memory = 256
      }
    }

    # =========================================================================
    # SIDECAR: keep the device + root CRLs fresh in /alloc/data/crl.pem
    # This is what makes "revoke in Vault" cut a device off within seconds.
    # =========================================================================
    task "crl-sync" {
      driver = "docker"
      user   = "root"

      lifecycle {
        hook    = "prestart"
        sidecar = true
      }

      config {
        image      = var.images["crl_sync"]
        entrypoint = ["/bin/sh", "/local/crl-sync.sh"]
      }

      env {
        VAULT_ADDR    = var.vault_addr
        NS_PREFIX     = var.vault_namespace == "" ? "" : "${trim(var.vault_namespace, "/")}/"
        ROOT_MOUNT    = var.pki_root_mount
        DEVICES_MOUNT = var.pki_devices_mount
        INTERVAL      = var.crl_refresh_seconds
        CURL_EXTRA    = join(" ", compact([var.vault_tls_skip_verify ? "--insecure" : "", var.crl_sync_doh_url == "" ? "" : "--doh-url ${var.crl_sync_doh_url}"]))
      }

      template {
        destination = "local/vault-ca.pem"
        # Template data cannot be empty, so render a placeholder when unset.
        data = var.vault_ca_pem == "" ? "# no custom Vault CA configured\n" : var.vault_ca_pem
      }

      template {
        destination = "local/crl-sync.sh"
        perms       = "0755"
        data        = <<-EOF
          #!/bin/sh
          # Pulls the root and device-intermediate CRLs from Vault and publishes
          # them atomically for the gateway. NGINX needs a CRL for every CA in
          # the chain, so both are bundled.
          set -u
          OUT=/alloc/data/crl.pem
          CURL="curl -fsS --max-time 5 $CURL_EXTRA"
          if grep -q "BEGIN CERTIFICATE" /local/vault-ca.pem 2>/dev/null; then CURL="$CURL --cacert /local/vault-ca.pem"; fi

          echo "crl-sync: polling $VAULT_ADDR/v1/$NS_PREFIX every $INTERVAL s"
          while true; do
            if $CURL "$VAULT_ADDR/v1/$NS_PREFIX$ROOT_MOUNT/crl/pem"    -o /tmp/root.crl && \
               $CURL "$VAULT_ADDR/v1/$NS_PREFIX$DEVICES_MOUNT/crl/pem" -o /tmp/devices.crl && \
               grep -q "BEGIN X509 CRL" /tmp/root.crl && \
               grep -q "BEGIN X509 CRL" /tmp/devices.crl; then
              { cat /tmp/root.crl; echo; cat /tmp/devices.crl; echo; } > /tmp/crl.new
              if ! cmp -s /tmp/crl.new "$OUT"; then
                cp /tmp/crl.new "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
                echo "crl-sync: $(date -u +%H:%M:%S) CRL updated"
              fi
            else
              echo "crl-sync: $(date -u +%H:%M:%S) failed to fetch CRLs from Vault" >&2
            fi
            sleep "$INTERVAL"
          done
        EOF
      }

      resources {
        cpu    = 50
        memory = 32
      }
    }

    # =========================================================================
    # GATEWAY: NGINX enforcing device mTLS in front of Guacamole
    # =========================================================================
    task "gateway" {
      driver = "docker"

      config {
        image      = var.images["gateway"]
        entrypoint = ["/bin/sh", "/local/start-gateway.sh"]
        ports      = ["https"]
      }

      vault {
        role = var.vault_role
      }

      identity {
        name = "vault_default"
        aud  = ["vault.io"]
        ttl  = "1h"
      }

      # --- Server certificate for the gateway, issued by Vault ---------------
      # Cert, CA and key in ONE file so they always match (NGINX accepts a
      # combined PEM for both ssl_certificate and ssl_certificate_key).
      template {
        destination   = "secrets/gateway.pem"
        perms         = "0600"
        change_mode   = "script"
        change_script {
          command = "/usr/sbin/nginx"
          args    = ["-s", "reload", "-c", "/local/nginx.conf"]
        }
        data = <<-EOF
          {{- with pkiCert "${var.pki_gateway_mount}/issue/gateway" "common_name=${var.gateway_hostname}" "ip_sans=${var.gateway_ip_sans}" "ttl=72h" }}
          {{ .Cert }}
          {{ .CA }}
          {{ .Key }}
          {{- end }}
        EOF
      }

      # --- The ONLY CA the gateway accepts client certs from -----------------
      template {
        destination   = "local/device-trust-ca.pem"
        change_mode   = "script"
        change_script {
          command = "/usr/sbin/nginx"
          args    = ["-s", "reload", "-c", "/local/nginx.conf"]
        }
        data = <<-EOF
          {{- with secret "${var.pki_devices_mount}/cert/ca" }}
          {{ .Data.certificate }}
          {{- end }}
          {{- with secret "${var.pki_root_mount}/cert/ca" }}
          {{ .Data.certificate }}
          {{- end }}
        EOF
      }

      template {
        destination = "local/start-gateway.sh"
        perms       = "0755"
        data        = <<-EOF
          #!/bin/sh
          # Starts NGINX once the first CRL bundle exists, then hot-reloads
          # NGINX whenever the CRL changes (i.e. a device was revoked).
          set -u
          CRL=/alloc/data/crl.pem
          CONF=/local/nginx.conf

          echo "gateway: waiting for CRL bundle from crl-sync..."
          until [ -s "$CRL" ]; do sleep 1; done

          nginx -c "$CONF" -g 'daemon off;' &
          NGINX_PID=$!
          trap 'kill -TERM "$NGINX_PID" 2>/dev/null; wait "$NGINX_PID"; exit 0' TERM INT

          last=$(md5sum "$CRL" | cut -d' ' -f1)
          while kill -0 "$NGINX_PID" 2>/dev/null; do
            sleep 1
            cur=$(md5sum "$CRL" | cut -d' ' -f1)
            if [ "$cur" != "$last" ]; then
              if nginx -t -q -c "$CONF"; then
                nginx -s reload -c "$CONF"
                echo "gateway: $(date -u +%H:%M:%S) CRL changed, NGINX reloaded"
                last="$cur"
              fi
            fi
          done
          wait "$NGINX_PID"
        EOF
      }

      template {
        destination = "local/nginx.conf"
        change_mode = "script"
        change_script {
          command = "/usr/sbin/nginx"
          args    = ["-s", "reload", "-c", "/local/nginx.conf"]
        }
        data = <<-EOF
          worker_processes 1;
          pid /tmp/nginx.pid;
          error_log /dev/stderr notice;

          events { worker_connections 1024; }

          http {
            include /etc/nginx/mime.types;
            server_tokens off;

            log_format device '$remote_addr verify="$ssl_client_verify" device="$ssl_client_s_dn" serial=$ssl_client_serial "$request" $status';
            access_log /dev/stdout device;

            map $http_upgrade $connection_upgrade {
              default upgrade;
              ''      close;
            }

            server {
              listen 443 ssl;
              server_name ${var.gateway_hostname};

              ssl_certificate     /secrets/gateway.pem;
              ssl_certificate_key /secrets/gateway.pem;
              ssl_protocols       TLSv1.2 TLSv1.3;

              # ---- Device trust ----------------------------------------------
              # Only certs chaining to the Vault host-device intermediate pass.
              ssl_client_certificate /local/device-trust-ca.pem;
              ssl_verify_client      on;
              ssl_verify_depth       2;
              ssl_crl                /alloc/data/crl.pem;

              # Force a full certificate check on every new connection, so a
              # revoked device cannot ride on a resumed TLS session.
              ssl_session_cache   off;
              ssl_session_tickets off;
              keepalive_timeout   5s;

              # No / bad / revoked cert -> branded 403 instead of NGINX's 400.
              error_page 495 496 =403 /_device_blocked.html;

              location = /_device_blocked.html {
                internal;
                root /local/html;
                ssi  on;
                add_header X-Device-Verify $ssl_client_verify always;
                add_header Cache-Control "no-store" always;
              }

              # Lightweight identity probe used by the device scripts.
              location = /__device {
                default_type application/json;
                add_header Cache-Control "no-store" always;
                return 200 '{"verify":"$ssl_client_verify","subject":"$ssl_client_s_dn","issuer":"$ssl_client_i_dn","serial":"$ssl_client_serial","not_after":"$ssl_client_v_end"}\n';
              }

              location / {
                proxy_pass         http://127.0.0.1:8080;
                proxy_http_version 1.1;
                proxy_buffering    off;
                proxy_read_timeout 1h;

                proxy_set_header Upgrade           $http_upgrade;
                proxy_set_header Connection        $connection_upgrade;
                proxy_set_header Host              $host;
                proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto https;

                # Verified device identity, for the app / audit trail.
                proxy_set_header X-Device-Verify $ssl_client_verify;
                proxy_set_header X-Device-DN     $ssl_client_s_dn;
                proxy_set_header X-Device-Serial $ssl_client_serial;

                add_header X-Device-Verify $ssl_client_verify always;
              }
            }
          }
        EOF
      }

      template {
        destination = "local/html/_device_blocked.html"
        data        = <<-EOF
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Unknown device</title>
            <style>
              :root { --bg:#000; --fg:#fff; --muted:#b2b6bd; --vault:#FFD814; --line:#3b3d45; }
              * { box-sizing:border-box; }
              body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
                     background:var(--bg); color:var(--fg);
                     font-family: "HashiCorp Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
              main { width:min(640px, 100% - 32px); border:1px solid var(--line); border-radius:8px; padding:40px; }
              .tag { display:inline-block; background:var(--vault); color:#000; font-weight:600; font-size:13px;
                     padding:4px 10px; border-radius:4px; letter-spacing:.02em; }
              h1 { font-size:32px; line-height:1.2; margin:20px 0 12px; font-weight:600; }
              p  { color:var(--muted); line-height:1.6; margin:0 0 16px; }
              code { display:block; background:#15181e; border:1px solid var(--line); border-radius:6px;
                     padding:12px 14px; color:var(--fg); font-family: ui-monospace, Menlo, Consolas, monospace;
                     font-size:14px; overflow-wrap:anywhere; }
            </style>
          </head>
          <body>
            <main>
              <span class="tag">Vault device trust</span>
              <h1>This device is not known to the organization</h1>
              <p>Virtual desktops can only be started from a managed host that holds a valid, unrevoked device certificate issued by HashiCorp Vault.</p>
              <p>Gateway verification result:</p>
              <code><!--# echo var="ssl_client_verify" default="NONE" --></code>
            </main>
          </body>
          </html>
        EOF
      }

      resources {
        cpu    = 100
        memory = 128
      }
    }

    # =========================================================================
    # DATABASE for Guacamole (ephemeral: re-initialized on every deploy)
    # =========================================================================
    task "postgres" {
      driver = "docker"

      config {
        image      = var.images["postgres"]
        entrypoint = ["/bin/sh", "-c"]
        args = [
          "cp /alloc/data/initdb/*.sql /local/*.sql /docker-entrypoint-initdb.d/ && exec docker-entrypoint.sh postgres -c listen_addresses=127.0.0.1",
        ]
      }

      vault {
        role = var.vault_role
      }

      identity {
        name = "vault_default"
        aud  = ["vault.io"]
        ttl  = "1h"
      }

      template {
        destination = "secrets/db.env"
        env         = true
        data        = <<-EOF
          {{- with secret "${var.kv_mount}/data/guacamole" }}
          POSTGRES_DB={{ .Data.data.db_name }}
          POSTGRES_USER={{ .Data.data.db_username }}
          POSTGRES_PASSWORD={{ .Data.data.db_password }}
          {{- end }}
        EOF
      }

      # Pre-load a demo desktop connection so the story flows straight from
      # "device verified" to "desktop on screen".
      template {
        destination = "local/002-demo-connection.sql"
        data        = <<-EOF
          INSERT INTO guacamole_connection (connection_name, protocol)
          VALUES ('Corporate desktop (Ubuntu XFCE)', 'rdp');

          INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
          SELECT connection_id, p.name, p.value
          FROM guacamole_connection,
               (VALUES ('hostname',    '127.0.0.1'),
                       ('port',        '3389'),
                       ('username',    'ubuntu'),
                       ('password',    'ubuntu'),
                       ('security',    'any'),
                       ('ignore-cert', 'true'),
                       ('resize-method', 'display-update')) AS p(name, value)
          WHERE connection_name = 'Corporate desktop (Ubuntu XFCE)';

          INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
          SELECT e.entity_id, c.connection_id, 'READ'
          FROM guacamole_entity e, guacamole_connection c
          WHERE e.name = 'guacadmin' AND e.type = 'USER'
            AND c.connection_name = 'Corporate desktop (Ubuntu XFCE)';
        EOF
      }

      resources {
        cpu    = 200
        memory = 256
      }
    }

    # =========================================================================
    # VDI: Apache Guacamole (web broker) + guacd (protocol proxy)
    # =========================================================================
    task "guacd" {
      driver = "docker"

      config {
        image = var.images["guacd"]
      }

      resources {
        cpu    = 300
        memory = 256
      }
    }

    task "guacamole" {
      driver = "docker"

      config {
        image = var.images["guacamole"]
      }

      vault {
        role = var.vault_role
      }

      identity {
        name = "vault_default"
        aud  = ["vault.io"]
        ttl  = "1h"
      }

      env {
        GUACD_HOSTNAME          = "127.0.0.1"
        GUACD_PORT              = "4822"
        POSTGRESQL_HOSTNAME     = "127.0.0.1"
        POSTGRESQL_PORT         = "5432"
        WEBAPP_CONTEXT          = "ROOT"
        REMOTE_IP_VALVE_ENABLED = "true"
      }

      template {
        destination = "secrets/guacamole.env"
        env         = true
        data        = <<-EOF
          {{- with secret "${var.kv_mount}/data/guacamole" }}
          POSTGRESQL_DATABASE={{ .Data.data.db_name }}
          POSTGRESQL_USERNAME={{ .Data.data.db_username }}
          POSTGRESQL_PASSWORD={{ .Data.data.db_password }}
          {{- end }}
        EOF
      }

      resources {
        cpu    = 500
        memory = 768
      }
    }

    # =========================================================================
    # The virtual desktop itself (Ubuntu + XFCE over RDP)
    # =========================================================================
    task "desktop" {
      driver = "docker"

      config {
        # hostname is set on the group network: Docker rejects a per-task
        # hostname when the container joins the shared bridge namespace.
        image = var.images["desktop"]
      }

      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }
}
