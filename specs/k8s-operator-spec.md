# Certhub Kubernetes Operator Spec

## Summary

Certhub Kubernetes operator syncs certificates from the Certhub backend API into Kubernetes TLS Secrets. It gives Kubernetes workloads a native way to consume company-managed Let's Encrypt certificates without embedding ACME, DNS provider credentials, or private keys in application code.

The operator is a Certhub API client. It does not talk to Let's Encrypt, Cloudflare, or ArvanCloud directly.

The operator authenticates to Certhub as a Certhub Application using an Application token. Human Users interact with Kubernetes by creating or updating `CerthubCertificate` resources, while Certhub audit events record the Certhub Application as the backend authenticated identity.

## Technology Choices

- Implementation language: Go.
- Runtime: Kubernetes controller/operator.
- Persistence: Kubernetes custom resources and Secrets only; Certhub remains the certificate source of truth.

## Goals

- Allow Kubernetes users to create Certhub certificates through Kubernetes custom resources.
- Sync ready certificate material into Kubernetes TLS Secrets.
- Keep Secrets updated across renewal and key rotation.
- Expose clear status conditions for pending, ready, failed, and unauthorized states.
- Avoid storing DNS provider credentials in Kubernetes clusters.

## Non-Goals

- The operator does not implement ACME.
- The operator does not manage DNS challenge records.
- The operator does not replace cert-manager for non-Certhub issuers.
- The operator does not issue self-signed certificates.

## Custom Resource

Primary CRD:

```text
CerthubCertificate
```

Example:

```yaml
apiVersion: certs.torob.dev/v1alpha1
kind: CerthubCertificate
metadata:
  name: gateway-tls
  namespace: gateway
spec:
  domains:
    - api.torob.dev
    - "*.torob.dev"
  secretName: gateway-tls
  keyType: ecdsa-p256
  issuer: letsencrypt_production
  secretDeletionPolicy: Retain
```

Spec fields:

- `domains`: required list of requested certificate SANs.
- `secretName`: required target Kubernetes Secret name.
- `keyType`: optional, default `ecdsa-p256`.
- `issuer`: optional. When omitted, the operator omits issuer from Certhub requests and the backend selects the single active default issuer.
- `secretDeletionPolicy`: optional enum `Retain` or `Delete`, default `Retain`. Controls what happens to an operator-owned target Secret when the `CerthubCertificate` is deleted.

CRD validation:

- `domains`: non-empty list; each item must match the backend `certificate_identifier` validation after backend normalization. The operator may prevalidate but the backend remains authoritative.
- `secretName`: valid Kubernetes Secret name using Kubernetes DNS label validation.
- `keyType`: enum `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384`.
- `issuer`: backend `machine_name` validation.
- `secretDeletionPolicy`: enum `Retain` or `Delete`.
- All spec strings reject leading/trailing whitespace and control characters.

Status fields:

- `phase`: `Pending`, `ValidatingDNS`, `Issuing`, `Ready`, `Failed`.
- `certificateId`.
- `observedDomains`.
- `notBefore`.
- `notAfter`.
- `renewalTime`.
- `message`.
- `conditions`.

Conditions:

- `Accepted`
- `Ready`
- `SecretSynced`
- `AuthorizationFailed`
- `IssuanceFailed`
- `CertificateRevoked`

## Kubernetes Secret

The operator writes a standard Kubernetes TLS Secret:

```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: gateway-tls
  namespace: gateway
  labels:
    app.kubernetes.io/managed-by: certhub-operator
    certhub.torob.dev/certhub-certificate-name: gateway-tls
  annotations:
    certhub.torob.dev/owner-uid: <certhub-certificate-uid>
data:
  tls.crt: <base64 fullchain.pem>
  tls.key: <base64 privkey.pem>
```

Annotations:

```text
certhub.torob.dev/certificate-id
certhub.torob.dev/not-after
certhub.torob.dev/fingerprint-sha256
certhub.torob.dev/material-etag
certhub.torob.dev/owner-uid
```

Required management labels:

```text
app.kubernetes.io/managed-by=certhub-operator
certhub.torob.dev/certhub-certificate-name=<cr-name>
```

The operator owns only Secrets referenced by `CerthubCertificate` resources in the same namespace.

Mutation and deletion require all ownership checks to pass:

- Secret namespace equals the CR namespace.
- Secret name equals `spec.secretName`.
- `certhub.torob.dev/owner-uid` equals the current CR UID.
- Required management labels are present and match the current CR.
- If an owner reference exists, it points to the current CR UID.
- Secret type is `kubernetes.io/tls`, or absent only before initial creation.

## Authentication

The operator authenticates to Certhub using a Certhub Application token stored in a Kubernetes Secret. If the Certhub Application has trusted source CIDRs configured, the operator pod's effective source IP, after any trusted proxy processing by Certhub, must be inside one of those CIDRs.

Transport rules:

- `CERTHUB_URL` must use `https://` by default.
- The operator must verify Certhub TLS certificates by default.
- The operator must not provide silent `insecure_skip_verify` behavior.
- If a future local-development HTTP/TLS override is added, it must be explicit deployment configuration and must not be enabled by default.
- The operator must not forward `Authorization` headers when following redirects to a different host, port, or scheme.

Operator deployment configuration:

```text
CERTHUB_URL
CERTHUB_TOKEN_SECRET_NAME
CERTHUB_TOKEN_SECRET_KEY
```

The Certhub Application used by the operator must have domain scopes for every DNS name that Kubernetes users are allowed to create through that operator instance. The Application token has no separate Certhub roles or permissions.

Application trusted source CIDRs do not replace the Application token. The operator always sends the token and never attempts to spoof `Forwarded` or `X-Forwarded-For` headers.

Human User permissions in Certhub do not authorize the operator's backend calls. If a human User should be restricted from creating Kubernetes certificates, enforce that through Kubernetes RBAC on `CerthubCertificate` resources and through the operator Application's Certhub domain scopes.

The Kubernetes ServiceAccount used by the operator pod is only for Kubernetes API RBAC and is separate from the Certhub Application.

## Reconcile Flow

1. Watch `CerthubCertificate` resources.
2. Normalize desired certificate criteria locally for stable comparison.
3. Read existing target Secret, if present, and use `certhub.torob.dev/material-etag` as `If-None-Match`.
4. Call `POST /v1/sync/certificates/tls-material` with the Certhub Application token, CR criteria, and optional `If-None-Match`.
5. If backend returns `204 No Content`, leave the target Secret unchanged and update CR status/conditions as synced.
6. If backend returns `200 OK`, write or update the target TLS Secret, including `certhub.torob.dev/material-etag`, and update CR status.
7. If backend returns `404 certificate_not_found`, call `POST /v1/sync/certificates` with the same criteria, store `certificateId` when present for observability, and requeue.
8. If backend returns `409 certificate_not_ready`, do not call `POST /v1/sync/certificates`; record the returned status metadata and requeue.
9. If backend returns `409 certificate_issuance_failed`, set a failed condition with backend failure metadata and stop retrying until the backend Certificate is repaired through a User lifecycle action in Certhub or the CR criteria changes to a different certificate identity.
10. If backend returns `409 certificate_no_active_version`, set a failed condition and stop retrying until the backend Certificate is reissued through a User lifecycle action in Certhub or the CR criteria changes to a different certificate identity.
11. On each later reconcile, retry `POST /v1/sync/certificates/tls-material` with the same CR criteria and latest stored `material_etag`.
12. Update CR status and conditions.

Manual retry:

- A User may request retry by changing annotation `certhub.torob.dev/retry-id` on the `CerthubCertificate`.
- Any changed non-empty retry ID causes the operator to clear locally latched failures caused by local Secret writes, backend retryable states, or transient backend/network errors, then re-run the normal criteria-based material retrieval flow.
- Retry ID does not repair backend terminal `certificate_issuance_failed` state. That state requires a User lifecycle action in the Certhub web UI or a CR criteria change that maps to a different certificate identity.
- Retry annotation handling must not call any backend ID-based lifecycle endpoint. The operator still uses only `/v1/sync/...`.

The operator must not create duplicate Certificates for repeated reconciles. It calls `POST /v1/sync/certificates` only after `404 certificate_not_found`, relies on backend idempotency, and stores the Certificate ID in status for observability only. `409 certificate_no_active_version` is terminal until User reissue or criteria change. Backend certificate readiness checking and material retrieval are always criteria-based.

Each backend request should include an `X-Request-ID` correlation ID tied to the current reconcile ID.

## Renewal Behavior

The backend is responsible for renewing certificates. The operator is responsible for keeping Kubernetes Secrets current.

The operator should periodically inspect managed certificates and refresh Secrets when:

- Latest valid certificate version changes.
- Certificate fingerprint changes.
- `not_after` changes.
- Backend reports the certificate is renewing or ready with newer material.
- Backend reports `certificate_no_active_version`; the operator should keep the existing Kubernetes Secret unchanged and wait for User reissue or criteria change.
- CR spec changes and maps to a different certificate identity.

Default resync interval:

```text
6 hours
```

## Failure Behavior

If backend returns `domain_not_authorized`:

- Set condition `AuthorizationFailed=True`.
- Set phase `Failed`.
- Do not retry aggressively.

If backend returns transient errors:

- Requeue with exponential backoff.
- Preserve last known good Secret if one exists.

If TLS material cannot be fetched:

- Set condition `SecretSynced=False`.
- Requeue with backoff.

If Secret update fails:

- Set condition `SecretSynced=False`.
- Requeue with backoff.

Delete behavior:

- Default `secretDeletionPolicy=Retain` leaves the target Secret in place when the `CerthubCertificate` is deleted.
- `secretDeletionPolicy=Delete` deletes only a Secret that the operator can prove it owns through the required labels, `certhub.torob.dev/owner-uid`, same-namespace/name checks, and owner reference UID checks when present.
- Finalizers are required only when needed to honor `secretDeletionPolicy=Delete` safely.
- The operator must never delete, clear, or rewrite an unowned Secret, a Secret with an owner-reference UID mismatch, or a Secret missing the expected management labels/annotations.
- Deleting the Kubernetes CR never deletes or revokes the Certhub backend Certificate. It only affects the local Kubernetes Secret according to `secretDeletionPolicy`.

The operator must parse the backend standard error envelope and branch on `error.code`. When backend sets `retryable=true`, the operator should requeue using `Retry-After` or `error.retry_after_seconds` when present. It must not branch on free-form message text.

## Observability

The operator should expose:

- Liveness and readiness probes.
- Prometheus metrics for reconcile count, reconcile duration, backend request count by error code, Secret sync count, and current CR conditions.
- Structured logs with namespace, resource name, Certificate ID when known, backend error code, reconcile ID, and result.

Logs and metrics must not include private keys, raw Application tokens, or full certificate material.

## RBAC

Operator Kubernetes permissions:

- Read/write `CerthubCertificate` resources and status.
- Read the Kubernetes Secret containing the Certhub Application token.
- Read/write Kubernetes Secrets in watched namespaces.
- Emit Kubernetes Events.

The operator should support namespace-scoped and cluster-scoped deployment modes.

## Events

The operator should emit Kubernetes Events:

- `CertificateCreated`
- `CertificatePending`
- `CertificateReady`
- `SecretSynced`
- `AuthorizationFailed`
- `IssuanceFailed`
- `CertificateRevoked`
- `BackendUnavailable`

## API Integration

Required backend endpoints:

- `POST /v1/sync/certificates`
- `POST /v1/sync/certificates/tls-material`

The operator does not need direct access to issuer, DNS provider, User admin, Application admin, or audit APIs.

## Tests

Required operator scenarios:

- New CR creates a backend Certificate with the Certhub Application token.
- Ready backend response creates a Kubernetes TLS Secret with `certhub.torob.dev/material-etag`.
- Operator fetches certificate material by CR criteria, not by Certificate ID.
- Pending backend response updates status and requeues.
- Failed authorization sets `AuthorizationFailed` and does not create a Secret.
- Changing `certhub.torob.dev/retry-id` clears local/transient latched failed conditions and retries the normal `/v1/sync/...` flow without using backend ID-based lifecycle endpoints.
- Changing `certhub.torob.dev/retry-id` does not clear terminal backend `certificate_issuance_failed` until Certhub is repaired through a User lifecycle action or CR criteria changes.
- `403 application_source_ip_denied` sets `AuthorizationFailed` and reports that the operator source IP is outside the Certhub Application trusted source CIDRs.
- Operator rejects plain HTTP Certhub URLs by default, verifies TLS certificates, and does not forward Authorization headers across redirects to different hosts, ports, or schemes.
- The operator never logs or emits Kubernetes Events containing raw Application tokens, Authorization headers, private keys, certificate PEM, backend material JSON, or Secret data.
- Existing Secret is updated when backend certificate material changes.
- Existing Secret is left unchanged when backend returns `204 No Content` for a matching stored `material_etag`.
- Existing Secret is preserved unchanged when authorization fails, backend is unavailable, material is not ready, issuance fails, or a Secret update write fails before commit.
- Existing Secret is preserved unchanged when backend reports `certificate_no_active_version`; status records the terminal backend state and no stale Secret rewrite occurs.
- Existing target Secrets that are not owned or explicitly managed by the matching `CerthubCertificate` are not overwritten.
- Owner-reference UID mismatch, `certhub.torob.dev/owner-uid` mismatch, missing required management labels, or conflicting Secret type causes a failed condition instead of mutating the existing Secret.
- Deleting a CR with default `secretDeletionPolicy=Retain` leaves the target Secret unchanged and does not require a finalizer.
- Deleting a CR with `secretDeletionPolicy=Delete` deletes only an owned target Secret after owner UID, labels, annotations, namespace, name, and Secret type checks pass.
- Deleting a CR never calls Certhub certificate revoke/delete APIs.
- Operator writes only the referenced same-namespace target Secret and never writes Secrets in namespaces not selected by its deployment mode and RBAC.
- Operator refuses CRs whose `secretName` targets another namespace by path-like, URL-like, or annotation-driven indirection.
- Operator does not copy Application tokens into managed TLS Secrets, CR status, annotations, labels, metrics, or Events.
- Operator reads the Certhub Application token only from the configured Secret name/key and never lists, watches, copies, or logs unrelated Kubernetes Secrets.
- Operator never sends `Forwarded`, `X-Forwarded-For`, or other headers that attempt to claim a different source IP.
- Managed Secret contains only expected TLS data keys and non-secret Certhub annotations; status contains no private key or PEM material.
- Managed Secret owner references, labels, and annotations cannot point at objects outside the CR namespace or include raw certificate material, private keys, Application tokens, or backend material JSON.
- Status messages and Kubernetes Events sanitize backend failure messages before storing them in the Kubernetes API.
- Repeated reconciles do not create duplicate logical Certificates.
- Backend outage preserves existing Secret and retries with backoff.
- Retryable backend errors use `Retry-After` or `retry_after_seconds` for requeue timing.
- Operator logs and metrics include backend error codes without leaking Application tokens or certificate material.
- Operator RBAC manifests grant only the needed verbs for `CerthubCertificate`, status updates, Events, the configured Application-token Secret, and managed TLS Secrets.
- RBAC tests verify the operator ServiceAccount cannot read unrelated Secrets, cannot write Secrets outside watched namespaces, cannot update CR specs, and cannot access issuer, DNS provider, User, Application admin, or audit APIs.
- Multi-namespace and single-namespace deployment tests verify Secret writes are constrained by the selected deployment mode and fail closed when RBAC denies access.
- Delete/finalizer tests verify the operator never deletes or clears an unowned Secret and never logs Secret data during cleanup.
- CR spec change requests a new certificate identity and syncs new material.
