# Certhub server with Docker Compose

This example starts PostgreSQL, runs Certhub migrations, and starts the
Certhub server image. It can run in local HTTP mode or direct HTTPS mode with a
server-managed Let's Encrypt certificate.

The server validates config file ownership and permissions at startup. The
`config-init` service copies the checked-in `server.yaml` template into a named
volume owned by uid `65532` with mode `0600`, which matches the scratch-based
server image. It also prepares the writable self-certificate volume used by
direct HTTPS mode.

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
  cert_file: "/var/lib/certhub/self-certificate/current/fullchain.pem"
  key_file: "/var/lib/certhub/self-certificate/current/privkey.pem"
self_certificate:
  sync_enabled: true
  output_dir: "/var/lib/certhub/self-certificate"
  issuer: "letsencrypt_prod"
  key_type: "ecdsa-p256"
```

Refresh the secure config copy and run migrations:

```bash
cd deploy/docker/compose
docker compose --env-file .env run --rm config-init
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

Start the server in HTTPS mode:

```bash
docker compose --env-file .env up -d server
docker compose --env-file .env logs -f server
```

The first start is allowed even though
`/var/lib/certhub/self-certificate/current/fullchain.pem` and `privkey.pem` do
not exist yet. Certhub creates the reserved server certificate, completes the
ACME DNS-01 flow through the configured DNS provider, writes the certificate
material into the self-certificate volume, and begins serving HTTPS on the
configured host port.

If issuance has completed but `/readyz` still reports pending TLS material,
wait for `self_certificate.sync_interval_seconds` or restart the server to
trigger a startup sync immediately:

```bash
docker compose --env-file .env restart server
```

After issuance succeeds:

```bash
curl https://certhub.example.com/readyz
```

If you used the Let's Encrypt staging directory, the certificate will not be
browser-trusted. Create a production issuer, set `self_certificate.issuer` to
that issuer name, refresh config, and recreate the server.

## Updating config

Edit `deploy/docker/compose/server.yaml`, refresh the secure copy in the named
volume, then recreate the server:

```bash
cd deploy/docker/compose
docker compose --env-file .env run --rm config-init
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
