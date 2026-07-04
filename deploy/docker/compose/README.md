# Certhub server with Docker Compose

This Compose setup runs PostgreSQL and the Certhub server. Keep secrets in
`.env`; `server.yaml` reads them through environment variable references.

## Setup

Create the environment file and replace the placeholder values:

```bash
cd deploy/docker/compose
cp example.env .env
docker run --rm ghcr.io/torob/certhub-server:0.1.0 generate-encryption-key
```

Set `CERTHUB_ENCRYPTION_KEY` in `.env` to the generated value and choose a
strong `CERTHUB_POSTGRES_PASSWORD`.

Edit `server.yaml` and set `server.public_hostname` to the public DNS name for
this host.

## Bootstrap

Run bootstrap interactively. Do not pass `-T`; prompts need a TTY. Values
provided as flags are reused, and missing values are prompted.

```bash
docker compose --env-file .env run --rm server bootstrap create-admin --interactive
docker compose --env-file .env run --rm server bootstrap create-issuer --interactive
docker compose --env-file .env run --rm server bootstrap create-dns-provider --interactive
docker compose --env-file .env run --rm server bootstrap add-dns-provider-zone --interactive
```

For DNS provider setup, paste the raw Cloudflare API token or ArvanCloud API key
when prompted. Do not wrap it in JSON.

For the issuer, use Let's Encrypt staging first if you want a dry run:

```text
https://acme-staging-v02.api.letsencrypt.org/directory
```

Use production when ready for a trusted certificate:

```text
https://acme-v02.api.letsencrypt.org/directory
```

## Start

Start the Certhub server:

```bash
docker compose --env-file .env up -d server
docker compose --env-file .env logs -f server
```

The server applies pending migrations before it starts. The first start can
succeed before certificate files exist; Certhub creates the server certificate
through DNS-01 and writes it under the `server-data` volume.

## Useful Commands

```bash
docker compose --env-file .env ps
docker compose --env-file .env logs -f postgres
docker compose --env-file .env restart server
docker compose --env-file .env down
```

To inspect command help:

```bash
docker compose --env-file .env run --rm server --help
docker compose --env-file .env run --rm server bootstrap --help
```
