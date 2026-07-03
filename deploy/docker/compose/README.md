# Certhub server with Docker Compose

This example starts PostgreSQL, runs Certhub migrations, and starts the
Certhub server image. It can run in local HTTP mode or direct HTTPS mode with a
server-managed Let's Encrypt certificate.

The Compose file bind-mounts `server.yaml` directly into the scratch-based
server image. Keep secrets in `.env` and reference them from `server.yaml` with
the documented `*_env` fields; operators are responsible for not placing
secrets directly in the server config file.

## First run

Copy the example environment file and replace the placeholder values:

```bash
cp deploy/docker/compose/example.env deploy/docker/compose/.env
docker run --rm ghcr.io/torob/certhub-server:0.1.0 generate-encryption-key
```

Set `CERTHUB_ENCRYPTION_KEY` in `deploy/docker/compose/.env` to the generated
value and choose a strong `CERTHUB_POSTGRES_PASSWORD`.

Start the default local HTTP stack:

```bash
cd deploy/docker/compose
docker compose --env-file .env up -d
```

The web UI and API listen on `http://localhost:8080` by default.

## Bootstrap an admin

After PostgreSQL and migrations are ready, create the first admin user:

```bash
cd deploy/docker/compose
printf '%s\n' 'change-this-admin-password' | \
  docker compose --env-file .env run --rm -T server \
    bootstrap create-admin \
    --config /etc/certhub/server.yaml \
    --email admin@example.com \
    --display-name "Admin" \
    --password-stdin
```

When `auth.password.2fa_required` is `true`, the command prints a terminal QR
code and one-time TOTP provisioning URI for the admin account.

## Direct HTTPS With Certhub Certificate

Use this flow when the Certhub container should serve HTTPS itself. Before
starting, make sure the public DNS name points to this host and that the host
port in `.env` is reachable by users:

```bash
CERTHUB_SERVER_PORT=443
```

Edit `deploy/docker/compose/server.yaml` and enable HTTPS plus
self-certificate sync:

```yaml
http:
  bind_addr: ":8080"
  require_https: true
  trusted_proxy_cidrs: []
server:
  public_hostname: "certhub.example.com"
tls:
  cert_file: "/var/lib/certhub/tls/current/fullchain.pem"
  key_file: "/var/lib/certhub/tls/current/privkey.pem"
self_certificate:
  sync_enabled: true
  output_dir: "/var/lib/certhub/tls"
  issuer: "letsencrypt_prod"
  key_type: "ecdsa-p256"
```

Run migrations:

```bash
cd deploy/docker/compose
docker compose --env-file .env run --rm migrate
```

Create the admin user if you have not already done so, then create the ACME
issuer. Use the Let's Encrypt staging directory first for a dry run, or use the
production directory shown here for a trusted certificate:

```bash
docker compose --env-file .env run --rm server \
  bootstrap create-issuer \
  --config /etc/certhub/server.yaml \
  --name letsencrypt_prod \
  --environment production \
  --directory-url https://acme-v02.api.letsencrypt.org/directory \
  --contact-email admin@example.com \
  --default
```

Create a DNS provider that can write DNS-01 challenge records for the public
hostname's zone. Cloudflare credentials use `api_token`:

```bash
printf '%s\n' '{"api_token":"cloudflare-api-token"}' | \
  docker compose --env-file .env run --rm -T server \
    bootstrap create-dns-provider \
    --config /etc/certhub/server.yaml \
    --name cloudflare_main \
    --type cloudflare \
    --zone-mode manual \
    --credentials-stdin
```

Add the DNS zone that contains `server.public_hostname`:

```bash
docker compose --env-file .env run --rm server \
  bootstrap add-dns-provider-zone \
  --config /etc/certhub/server.yaml \
  --dns-provider cloudflare_main \
  --zone example.com
```

For ArvanCloud, use `--type arvancloud` and credential JSON shaped like
`{"api_key":"Apikey ..."}`.

Certhub checks DNS-01 TXT propagation before asking the issuer to validate a
challenge. By default, each provider type uses the system resolver:

```yaml
dns:
  propagation_resolvers:
    cloudflare:
      type: system
```

To use a regular DNS resolver for all Cloudflare-backed challenges:

```yaml
dns:
  propagation_resolvers:
    cloudflare:
      type: dns
      endpoint: "1.1.1.1:53"
```

To use DNS-over-HTTPS through a named proxy:

```yaml
outbound_http:
  proxies:
    corp_proxy:
      url_env: "CERTHUB_CORP_PROXY_URL"
dns:
  propagation_resolvers:
    cloudflare:
      type: doh
      endpoint: "https://cloudflare-dns.com/dns-query"
      proxy: "corp_proxy"
```

To use DNS-over-TLS through a named proxy:

```yaml
outbound_http:
  proxies:
    corp_proxy:
      url_env: "CERTHUB_CORP_PROXY_URL"
dns:
  propagation_resolvers:
    cloudflare:
      type: dot
      endpoint: "1.1.1.1:853"
      tls_server_name: "cloudflare-dns.com"
      proxy: "corp_proxy"
```

Start the server in HTTPS mode:

```bash
docker compose --env-file .env up -d server
docker compose --env-file .env logs -f server
```

The first start is allowed even though
`/var/lib/certhub/tls/current/fullchain.pem` and `privkey.pem` do
not exist yet. Certhub creates the reserved server certificate, completes the
ACME DNS-01 flow through the configured DNS provider, writes the certificate
material into the TLS data directory, and begins serving HTTPS on the configured
host port.

If issuance has completed but `/readyz` still reports pending TLS material,
wait for `self_certificate.sync_interval_seconds` or restart the server to
trigger a startup sync immediately:

```bash
docker compose --env-file .env restart server
```

For an operator-provided certificate, place the certificate and private key in
the `server-data` volume under `/var/lib/certhub/tls`, set `tls.cert_file` and
`tls.key_file` to those paths, and leave `self_certificate.sync_enabled: false`.

After issuance succeeds:

```bash
curl https://certhub.example.com/readyz
```

If you used the Let's Encrypt staging directory, the certificate will not be
browser-trusted. Create a production issuer, set `self_certificate.issuer` to
that issuer name, and recreate the server.

## Updating config

Edit `deploy/docker/compose/server.yaml`, then recreate the server:

```bash
cd deploy/docker/compose
docker compose --env-file .env up -d --force-recreate server
```

Run migrations again when upgrading Certhub or applying a build that may include
database migrations:

```bash
docker compose --env-file .env run --rm migrate
```

For deployments behind an external HTTPS reverse proxy, terminate TLS at the
proxy instead of using the direct HTTPS flow above. Set `http.require_https:
true`, configure `http.trusted_proxy_cidrs` for the proxy network, and set
`server.public_hostname` to the public Certhub hostname.
