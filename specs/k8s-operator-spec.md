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
- `secretName`: required immutable target Kubernetes Secret name. Moving to a
  different target requires a new `CerthubCertificate` resource.
- `keyType`: optional, default `ecdsa-p256`.
- `issuer`: optional. When omitted, the operator omits issuer from Certhub requests and the backend selects the single active default issuer.
- `secretDeletionPolicy`: optional enum `Retain` or `Delete`, default `Retain`. Controls what happens to an operator-owned target Secret when the `CerthubCertificate` is deleted.

CRD validation:

- `domains`: non-empty list; each item must match the backend `certificate_identifier` validation after backend normalization. The operator may prevalidate but the backend remains authoritative.
- `secretName`: valid Kubernetes Secret name using Kubernetes DNS label validation.
- `secretName` updates are rejected by a CEL transition rule requiring
  `self == oldSelf`. Installing this rule during a CRD-first upgrade permits
  unchanged updates of existing objects while preventing an old
  owner-referenced Secret from becoming unreachable through the mutable spec.
- `keyType`: enum `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384`.
- `issuer`: backend `machine_name` validation.
- `secretDeletionPolicy`: enum `Retain` or `Delete`.
- All spec strings reject leading/trailing whitespace and control characters.

Status fields:

- `observedGeneration`: the `metadata.generation` reconciled by every persisted
  status update.
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
  ownerReferences:
    - apiVersion: certs.torob.dev/v1alpha1
      kind: CerthubCertificate
      name: gateway-tls
      uid: <certhub-certificate-uid>
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
- The managed owner reference uses API version
  `certs.torob.dev/v1alpha1`, kind `CerthubCertificate`, and the current CR name
  and UID. An owner reference for a different CerthubCertificate is an
  ownership conflict.
- Secret type is `kubernetes.io/tls`, or absent only before initial creation.

Every newly created managed Secret includes the matching owner reference.
Existing managed Secrets without that reference are patched in place only
after the cleanup finalizer has been persisted on the Certificate. Migration
must preserve the Secret UID, TLS data, type, labels, annotations, and all
metadata other than the expected owner-reference change.

## Authentication

The operator authenticates to Certhub using a Certhub Application token from
the `CERTHUB_TOKEN` environment variable. The Helm chart injects this variable
from a Kubernetes Secret in the operator pod's release namespace using
`secretKeyRef`; the operator does not fetch its token through the Kubernetes
API. If the Certhub Application has trusted source CIDRs configured, the
operator pod's effective source IP, after any trusted proxy processing by
Certhub, must be inside one of those CIDRs.

Transport rules:

- `CERTHUB_URL` must use `https://` by default.
- The operator must verify Certhub TLS certificates by default.
- The operator must not provide silent `insecure_skip_verify` behavior.
- If a future local-development HTTP/TLS override is added, it must be explicit deployment configuration and must not be enabled by default.
- The operator must not forward `Authorization` headers when following redirects to a different host, port, or scheme.

Operator deployment configuration:

```text
CERTHUB_URL
CERTHUB_TOKEN
WATCH_NAMESPACES
```

`CERTHUB_TOKEN` is required and must be a valid Certhub Application token.
The chart keeps only `certhub.tokenSecretName` and
`certhub.tokenSecretKey` as Secret-reference settings. The Secret must be in
the Helm release namespace, and token rotation requires an operator pod
restart.

`WATCH_NAMESPACES` is a comma-separated list of exact Kubernetes namespaces.
The operator lists and watches each configured namespace independently. An
empty list selects all namespaces for a cluster-scoped deployment. Helm
namespaced deployments expand an empty `watchNamespaces` value to the release
namespace before starting the operator.

## Command

The operator binary runs the controller with:

```bash
certhub-operator run
```

Help behavior:

- `certhub-operator --help`, `certhub-operator help`, `certhub-operator run --help`, and `certhub-operator help run` must print command-specific help to stdout and exit `0`.
- Help output must include the deployment environment variables needed to configure the operator.
- Help paths must not load Kubernetes in-cluster config, read Kubernetes Secrets, validate required environment variables, contact Certhub, or start controller loops.
- Unknown commands or unexpected positional arguments must exit with invalid-arguments code `2`.

The Certhub Application used by the operator must have domain scopes for every DNS name that Kubernetes users are allowed to create through that operator instance. The Application token has no separate Certhub roles or permissions.

Application trusted source CIDRs do not replace the Application token. The operator always sends the token and never attempts to spoof `Forwarded` or `X-Forwarded-For` headers.

Human User permissions in Certhub do not authorize the operator's backend calls. If a human User should be restricted from creating Kubernetes certificates, enforce that through Kubernetes RBAC on `CerthubCertificate` resources and through the operator Application's Certhub domain scopes.

The Kubernetes ServiceAccount used by the operator pod is only for Kubernetes API RBAC and is separate from the Certhub Application.

Permission to create or update a `CerthubCertificate` authorizes selecting any
valid same-namespace target Secret name at creation. Admission rejects later
changes to `spec.secretName`. The operator never targets another namespace and
never overwrites or deletes a Secret that fails its ownership checks.

## Reconcile Flow

1. Watch `CerthubCertificate` resources.
2. For every valid, non-deleting resource, persist the cleanup finalizer before
   creating a Secret or adding its owner reference. Stop reconciliation if the
   finalizer patch fails.
3. Normalize desired certificate criteria locally for stable comparison.
4. Read the existing target Secret, if present. After ownership validation,
   migrate a managed Secret that lacks the owner reference with an in-place,
   resource-version-guarded metadata patch. Never attach the owner reference
   until step 2 is observable through the Kubernetes API.
5. Use `certhub.torob.dev/material-etag` as `If-None-Match`.
6. Call `POST /v1/sync/certificates/tls-material` with the Certhub Application token, CR criteria, and optional `If-None-Match`.
7. If backend returns `204 No Content`, leave certificate material unchanged and update CR status/conditions as synced; owner-reference migration may still update metadata.
8. If backend returns `200 OK`, create or update the target TLS Secret with the matching owner reference and `certhub.torob.dev/material-etag`, then update CR status.
9. If backend returns `404 certificate_not_found`, call `POST /v1/sync/certificates` with the same criteria, store `certificateId` when present for observability, and requeue.
10. If backend returns `409 certificate_not_ready`, do not call `POST /v1/sync/certificates`; record the returned status metadata and requeue.
11. If backend returns `409 certificate_issuance_failed`, set a failed condition with backend failure metadata and stop retrying until the backend Certificate is repaired through a User lifecycle action in Certhub or the CR criteria changes to a different certificate identity.
12. If backend returns `409 certificate_no_active_version`, set a failed condition and stop retrying until the backend Certificate is reissued through a User lifecycle action in Certhub or the CR criteria changes to a different certificate identity.
13. On each later reconcile, retry `POST /v1/sync/certificates/tls-material` with the same CR criteria and latest stored `material_etag`.
14. Persist status and conditions with `status.observedGeneration` equal to the
    `metadata.generation` that produced them.

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
- Mutable certificate-criteria fields in the CR spec change and map to a
  different certificate identity; `secretName` remains immutable.

Default resync interval:

```text
6 hours
```

The minimum configurable resync interval is 30 seconds. Status-only watch
updates do not trigger reconciliation, and an unchanged effective status is
not written back to Kubernetes or re-emitted as an Event.

## Failure Behavior

If backend returns `domain_not_authorized`:

- Set condition `AuthorizationFailed=True`.
- Set phase `Failed`.
- Do not retry aggressively.
- Replay-safe Certhub and Kubernetes reads use configurable per-request retries (`CERTHUB_HTTP_RETRY_MAX_ATTEMPTS`, `CERTHUB_HTTP_RETRY_INITIAL_BACKOFF`, and `CERTHUB_HTTP_RETRY_MAX_BACKOFF`) defaulting to five attempts with 1s-to-8s jittered exponential backoff. Ambiguous mutations remain reconciliation-driven.

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

- The cleanup finalizer is required on every valid, non-deleting Certificate so
  Kubernetes garbage collection cannot race either deletion policy.
- Default `secretDeletionPolicy=Retain` verifies Secret ownership and removes
  the matching Certificate owner reference with a resource-version-guarded
  metadata patch. Only after that patch succeeds, the owned Secret is confirmed
  to have no matching reference, or the target Secret is confirmed absent may
  the operator release the finalizer. The retained Secret keeps the same UID
  and data.
- `secretDeletionPolicy=Delete` deletes only a Secret that the operator can
  prove it owns through the required labels,
  `certhub.torob.dev/owner-uid`, Secret type, and same-namespace/name checks. If
  a CerthubCertificate owner reference is present, it must match the current
  CR. Deletion uses both UID and resource-version preconditions; only confirmed
  deletion or absence permits finalizer release.
- A policy transition changes the cleanup action selected when deletion begins
  but never permits finalizer release before that action completes.
- Owner-reference mutation, Secret deletion, ownership verification, or
  finalizer patch failures leave the finalizer in place and are retried.
- The operator must never delete, clear, or rewrite an unowned Secret, a Secret with an owner-reference UID mismatch, or a Secret missing the expected management labels/annotations.
- Deleting the Kubernetes CR never deletes or revokes the Certhub backend Certificate. It only affects the local Kubernetes Secret according to `secretDeletionPolicy`.

The operator must parse the backend standard error envelope and branch on `error.code`. When backend sets `retryable=true`, the operator should requeue using `Retry-After` or `error.retry_after_seconds` when present. It must not branch on free-form message text.

## Observability

The operator should expose:

- Liveness and readiness probes.
- Prometheus metrics for reconcile count, reconcile duration, backend request count by error code, Secret sync count, and current CR conditions.
- Structured logs with namespace, resource name, Certificate ID when known, backend error code, reconcile ID, and result.

Logs and metrics must not include private keys, raw Application tokens, or full certificate material.

## Upgrades and Argo CD

The CRD must be applied explicitly before upgrading the operator because Helm
does not update files in a chart's `crds/` directory. The updated CRD adds the
optional integer `status.observedGeneration`; only after that schema is
accepted may an operator that writes the field start. Upgrading from `v0.10.0`
then adds owner references to existing managed Secrets in place, after each
Certificate finalizer is persisted.

The chart packages, but does not install or own, an `argocd-cm` health
customization. Platform administrators merge it into their existing Argo CD
configuration. Health is mapped as follows:

- `Healthy`: `status.observedGeneration` equals `metadata.generation` and the
  current conditions include both `Ready=True` and `SecretSynced=True`.
- `Degraded`: current-generation terminal `phase: Failed`.
- `Progressing`: status is absent or stale, the Certificate is pending,
  validating, or issuing, or either readiness condition is incomplete.

The Secret's matching Kubernetes owner reference makes it a child of the
Certificate in the Argo CD resource tree. Restrictive AppProjects must allow
both `certs.torob.dev/CerthubCertificate` and core-group `Secret` resources in
their `namespaceResourceWhitelist`.

## RBAC

Operator Kubernetes permissions:

- Read/list/watch `CerthubCertificate` resources, patch the main resource only
  for cleanup finalizers, and update status through the status subresource.
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
- Existing Secret data and certificate metadata are left unchanged when the backend returns `204 No Content` for a matching stored `material_etag`; owner-reference migration may still patch Kubernetes metadata.
- Existing Secret is preserved unchanged when authorization fails, backend is unavailable, material is not ready, issuance fails, or a Secret update write fails before commit.
- Existing Secret is preserved unchanged when backend reports `certificate_no_active_version`; status records the terminal backend state and no stale Secret rewrite occurs.
- Existing target Secrets that are not owned or explicitly managed by the matching `CerthubCertificate` are not overwritten.
- Owner-reference UID mismatch, `certhub.torob.dev/owner-uid` mismatch, missing required management labels, or conflicting Secret type causes a failed condition instead of mutating the existing Secret.
- Every valid live CR persists its finalizer before a managed Secret is created
  or gains the matching owner reference; finalizer patch failure prevents both
  operations.
- Newly created managed Secrets have the matching owner reference. An owned
  `v0.10.0` Secret without one gains it through an in-place metadata patch
  without changing UID, data, type, labels, or annotations, including when the
  backend returns `204 No Content`.
- Deleting a CR with default `secretDeletionPolicy=Retain` removes the matching
  owner reference before releasing the finalizer and preserves the same Secret
  UID and data.
- Deleting a CR with `secretDeletionPolicy=Delete` deletes only an owned target
  Secret with UID and resource-version preconditions before releasing the
  finalizer.
- Cleanup and finalizer-patch failure matrices prove that the finalizer remains
  until the selected retention or deletion action is complete.
- Policy transitions, ownership conflicts, and repeated reconciles preserve
  ordering and are idempotent.
- CRD admission accepts unchanged `spec.secretName` values on resources that
  predate the transition rule and rejects attempts to change the target name,
  so no previously owner-referenced Secret can be orphaned from cleanup.
- Deleting a CR never calls Certhub certificate revoke/delete APIs.
- Operator writes only the referenced same-namespace target Secret and never writes Secrets in namespaces not selected by its deployment mode and RBAC.
- Operator refuses CRs whose `secretName` targets another namespace by path-like, URL-like, or annotation-driven indirection.
- Operator does not copy Application tokens into managed TLS Secrets, CR status, annotations, labels, metrics, or Events.
- Operator reads the Certhub Application token only from `CERTHUB_TOKEN`, which the chart injects from a same-namespace Secret. It never reads that token through the Kubernetes API, lists Secrets, or watches Secrets.
- Operator never sends `Forwarded`, `X-Forwarded-For`, or other headers that attempt to claim a different source IP.
- Managed Secret contains only expected TLS data keys and non-secret Certhub annotations; status contains no private key or PEM material.
- Managed Secret labels, annotations, and owner references cannot point at
  objects outside the CR namespace or include raw certificate material,
  private keys, Application tokens, or backend material JSON.
- Every persisted status reports the current reconciled
  `status.observedGeneration`.
- Argo CD health fixtures cover absent and stale status, pending, DNS
  validation, issuing, failed, incompletely synced Ready, and fully synced
  Ready states; only the final state is `Healthy`.
- Status messages and Kubernetes Events sanitize backend failure messages before storing them in the Kubernetes API.
- Repeated reconciles do not create duplicate logical Certificates.
- Backend outage preserves existing Secret and retries with backoff.
- Retryable backend errors use `Retry-After` or `retry_after_seconds` for requeue timing.
- Operator logs and metrics include backend error codes without leaking Application tokens or certificate material.
- Operator RBAC manifests grant only the needed verbs for `CerthubCertificate`, status updates, Events, the configured Application-token Secret, and named Secret operations in watched namespaces; Secret list and watch remain forbidden.
- RBAC tests verify equivalent permissions in every selected namespace, no Secret access outside watched namespaces, no main-resource update permission, finalizer-only main-resource patches in the implementation, and no access to issuer, DNS provider, User, Application admin, or audit APIs.
- Multi-namespace and single-namespace deployment tests verify independent list/watch behavior, partial-failure isolation, and Secret writes constrained by the selected deployment mode.
- Delete/finalizer tests verify the operator never deletes or clears an unowned Secret and never logs Secret data during cleanup.
- A mutable certificate-criteria spec change requests a new certificate
  identity and syncs new material without changing the immutable Secret target.
