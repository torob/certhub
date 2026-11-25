# Certhub Operator Helm Chart

This chart deploys the Certhub Kubernetes certificate sync operator. The
operator watches `CerthubCertificate` resources and writes their certificate
material to same-namespace Kubernetes TLS Secrets selected by each resource.

## Prerequisites

- Kubernetes 1.25 or newer with CRD CEL validation rules enabled.
- Helm 3.
- A Certhub Application token stored in a Kubernetes Secret.
- An HTTPS Certhub server URL.

The Certhub URL has no production-safe default and must be supplied for every
installation.

## Install

Create the namespace and token Secret without placing the Application token in
Helm values:

```bash
kubectl create namespace certhub-system
printf '%s' "$CERTHUB_TOKEN" |
  kubectl create secret generic certhub-token \
    --namespace certhub-system \
    --from-file=token=/dev/stdin
```

Create a values file:

```yaml
certhub:
  url: https://certhub.example.com
```

Install the release:

```bash
helm upgrade --install certhub-operator \
  oci://ghcr.io/torob/charts/certhub-operator \
  --namespace certhub-system \
  --create-namespace \
  --values operator-values.yaml
```

When `image.tag` is empty, the chart uses its `appVersion`, which keeps the
default operator image aligned with the chart release. `image.digest` can pin a
specific image digest; it cannot be combined with an explicit tag.

## Namespace scope

| Mode | `clusterScoped` | `watchNamespaces` | Access |
| --- | --- | --- | --- |
| Release namespace | `false` | `[]` | Role in the Helm release namespace |
| Selected namespaces | `false` | `[apps, staging]` | One Role and RoleBinding in each namespace |
| All namespaces | `true` | `[]` | ClusterRole and ClusterRoleBinding |

`clusterScoped=true` with a nonempty `watchNamespaces` list is rejected because
it would grant cluster-wide permissions to an operator that watches only some
namespaces.

## Token Secret

The token Secret must be in the Helm release namespace, regardless of which
namespaces the operator watches. The chart injects the selected key into the
pod as `CERTHUB_TOKEN` using a Kubernetes `secretKeyRef`; the operator does not
read this Secret through the Kubernetes API and receives no token-specific
RBAC.

Configure a non-default Secret or key with `certhub.tokenSecretName` and
`certhub.tokenSecretKey`. Kubernetes will not start the container while the
referenced Secret or key is missing. Restart the operator pod after rotating
the token.

## Private CA for the Certhub server

The operator image trusts the public CAs in its
`/etc/ssl/certs/ca-certificates.crt` bundle. If the Certhub server uses a
certificate from a private CA, store the PEM CA certificates in a ConfigMap or
Secret in the Helm release namespace and reference it:

```bash
kubectl create configmap certhub-private-ca \
  --namespace certhub-system \
  --from-file=ca.crt=private-ca.pem
```

```yaml
certhub:
  url: https://certhub.internal.example
  caBundle:
    configMapName: certhub-private-ca
    key: ca.crt
```

Use `certhub.caBundle.secretName` instead of `configMapName` for a Secret; set
only one of them. The chart mounts only the selected key read-only at
`/etc/certhub/ca-bundle/ca.crt` and sets:

```text
SSL_CERT_DIR=/etc/ssl/certs:/etc/pki/tls/certs:/etc/certhub/ca-bundle
```

Go loads the image CA bundle file and every PEM file in these directories, so
the public CAs stay trusted and the private CAs are added. The first two
directories are the Go defaults. The chart does not set `SSL_CERT_FILE`:
that variable replaces the default CA bundle file, so the public CAs would stay
trusted only through the directory list. The added CAs are trusted for
every TLS connection of the operator process, including the Kubernetes API
connection. Kubernetes will not start the container while the referenced
ConfigMap, Secret, or key is missing. The operator reads the trust store once,
so restart the operator pod after you change the CA certificates.

## Extra environment variables and volumes

`extraEnv`, `extraVolumes`, and `extraVolumeMounts` take standard Kubernetes
`EnvVar`, `Volume`, and `VolumeMount` lists. They are empty by default and add
nothing to the Deployment. The chart appends `extraEnv` after its own
variables and rejects an entry that redefines a variable the chart sets (see
`values.yaml`), including `SSL_CERT_DIR` when `certhub.caBundle` is set.
Without `certhub.caBundle`, you can manage trust yourself with these values:

```yaml
extraEnv:
  - name: SSL_CERT_DIR
    value: /etc/ssl/certs:/etc/custom-certs
extraVolumes:
  - name: custom-certs
    configMap:
      name: custom-certs
extraVolumeMounts:
  - name: custom-certs
    mountPath: /etc/custom-certs
    readOnly: true
```

The container root filesystem is read-only. Mount writable paths explicitly.

## Target Secret permissions

Each `CerthubCertificate` chooses its target through `spec.secretName`. The
operator always uses the resource's own namespace; there is no cross-namespace
target field. Users authorized to create or update `CerthubCertificate`
resources are therefore trusted to choose certificate Secret names in that
namespace.

`spec.secretName` is immutable after creation. This guarantees that every
managed Secret remains discoverable through the deleting
Certificate's single target name. To move certificate material to another
Secret, create a new `CerthubCertificate` with the new target, update consumers,
and then delete the old resource under its selected deletion policy.

The generated RBAC grants Secret create, get, update, patch, and delete
throughout each watched namespace without granting Secret list or watch.
Existing Secrets are mutated or deleted only after their type, owner UID,
labels, annotations, namespace, and name pass the operator's ownership checks.
Cluster-scoped mode grants these target-Secret permissions across all
namespaces.

The operator patches the main `CerthubCertificate` resource only to add or
remove its cleanup finalizer. Kubernetes CRDs do not expose a separate
`/finalizers` REST endpoint, so the generated RBAC grants main-resource
`patch` but does not grant main-resource `update`. The finalizer is persisted
on every valid, non-deleting Certificate before the operator creates a Secret
or attaches the Certificate owner reference to an existing Secret.

Every managed TLS Secret carries the management labels and the
`certhub.torob.dev/owner-uid` annotation. Only Secrets of a Certificate with
`secretDeletionPolicy: Delete` also carry an owner reference to their
`CerthubCertificate`, which makes them visible as a child in Kubernetes
resource graphs, including the Argo CD resource tree. `Retain` Secrets have no
owner reference: Kubernetes foreground deletion, which Argo CD prune uses by
default, deletes all dependents while the owner still exists, before the
operator can react, and the finalizer cannot prevent that. The operator adds
or removes the owner reference in place when the policy changes. During
deletion the finalizer makes both deletion policies explicit and ordered:

- `Retain` verifies ownership, removes a remaining matching Certificate owner
  reference (for example from an older operator version), and then releases
  the finalizer. The Secret remains in place.
- `Delete` verifies ownership and deletes the Secret with UID and resource
  version preconditions before releasing the finalizer.

If either cleanup operation fails, the finalizer remains so Kubernetes cannot
bypass the selected policy. Existing managed Secrets are patched in place to
match the policy after the finalizer is persisted; that patch does not replace
the Secret or rewrite its TLS material. If you change a Certificate from
`Delete` to `Retain`, wait until the operator has reconciled the change before
you delete the Certificate with foreground propagation.

Set `rbac.create=false` to supply all RBAC resources outside the chart. Set
`serviceAccount.create=false` and `serviceAccount.name` to use an existing
ServiceAccount.

## Breaking value changes

The singular `watchNamespace` value has been replaced by `watchNamespaces`,
`managedSecretNames` and `certhub.tokenSecretNamespace` have been removed, and
the token Secret must move to the Helm release namespace. Remove the old
allowlist and convert a custom namespace during upgrade:

```yaml
watchNamespaces:
  - apps
```

The operator environment now uses comma-separated `WATCH_NAMESPACES` and reads
the Application token directly from `CERTHUB_TOKEN`. `WATCH_NAMESPACE`,
`CERTHUB_ALLOWED_SECRET_NAMES`, and the three `CERTHUB_TOKEN_SECRET_*`
variables are rejected.

## Metrics

The operator exposes `/metrics`, `/healthz`, and `/readyz` on the configured
metrics port. A ClusterIP Service is enabled by default. Service annotations and
labels can be set under `metrics.service`.

An optional Prometheus Operator `ServiceMonitor` is available:

```yaml
metrics:
  service:
    enabled: true
  serviceMonitor:
    enabled: true
    additionalLabels:
      release: kube-prometheus-stack
```

The Prometheus Operator CRDs must already exist before enabling this option.

## Network policy

The chart can render one namespaced policy that selects only this release's
operator pod. Choose either the Kubernetes or Cilium provider and supply native
rules for that provider:

```yaml
networkPolicy:
  enabled: true
  provider: kubernetes
  kubernetes:
    ingress: []
    egress:
      - to:
          - namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: certhub-system
            podSelector:
              matchLabels:
                app.kubernetes.io/name: certhub-server
        ports:
          - protocol: TCP
            port: 8080
```

For both providers, a null or omitted direction is left out of the policy, an
explicit `[]` renders an empty rule list, and `- {}` renders one empty native
rule. Under [Kubernetes NetworkPolicy
semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
an empty rule `{}` allows all traffic in that direction. Kubernetes and Cilium
rules have provider-specific fields and semantics; the chart passes the
selected provider's lists through unchanged.

The chart does not add implicit rules for DNS, the Kubernetes API, Certhub, or
metrics. Enabling egress isolation without rules that allow DNS resolution, the
Kubernetes API, and the configured Certhub endpoint will prevent the operator
from working. Add every required connection explicitly.

Only the selected provider is rendered. The Kubernetes provider creates a
`networking.k8s.io/v1` `NetworkPolicy`; the Cilium provider creates a namespaced
`cilium.io/v2` `CiliumNetworkPolicy`. Cilium and its CRDs must already be
installed before enabling the Cilium provider. The chart does not install
Cilium CRDs or create cluster-wide Cilium policies.

## Availability and upgrades

The operator currently has no leader election. The chart therefore enforces one
replica and uses the Deployment `Recreate` strategy so an upgrade cannot run two
reconcilers simultaneously. Existing TLS Secrets remain available during the
brief operator restart.

Helm installs files under `crds/` only when the CRD does not already exist; it
does not upgrade an existing CRD. When a release changes the
`CerthubCertificate` schema, apply the shipped CRD before upgrading the chart:

```bash
kubectl apply --server-side \
  -f deploy/helm/certhub-operator/crds/certs.torob.dev_certhubcertificates.yaml
```

Review CRD changes before applying them, particularly changes to served or
storage versions.

For this release, applying the CRD first is required because the operator
writes `status.observedGeneration` and relies on admission enforcement of the
immutable `spec.secretName`. The CEL transition rule permits unchanged updates
of existing `v0.10.0` resources while rejecting later target-name changes.
Wait for the CRD update to succeed before upgrading the operator Deployment.
Existing `v0.10.0` Secrets are then adopted in place; their UID and TLS data
are preserved.

## Argo CD health and resource tree

The packaged `argocd/argocd-cm-patch.yaml` adds a health assessment for
`certs.torob.dev/CerthubCertificate`. It reports:

- `Healthy` only when `status.observedGeneration` equals
  `metadata.generation` and both `Ready=True` and `SecretSynced=True` exist.
- `Degraded` for a current-generation terminal `phase: Failed`.
- `Progressing` for missing or stale status, validation and issuance phases,
  and incomplete Secret synchronization.

The Certhub operator chart deliberately does not own `argocd-cm`. Have the
Argo CD administrator review and merge the packaged data key into the existing
ConfigMap, for example:

```bash
kubectl --namespace argocd patch configmap argocd-cm \
  --type merge \
  --patch-file deploy/helm/certhub-operator/argocd/argocd-cm-patch.yaml
```

Restarting Argo CD is not normally required because it watches its ConfigMap.
The customization can be checked locally with the Argo CD `v3.4.2` CLI:

```bash
ARGOCD_BIN=/path/to/argocd-v3.4.2 test/argocd-health/check.sh
```

For `secretDeletionPolicy: Delete`, the generated Secret appears beneath its
Certificate after the operator adds the Kubernetes owner reference. `Retain`
Secrets have no owner reference and do not appear beneath the Certificate. When an AppProject uses a restrictive
`namespaceResourceWhitelist`, allow both the custom resource and core
Secrets:

```yaml
namespaceResourceWhitelist:
  - group: certs.torob.dev
    kind: CerthubCertificate
  - group: ""
    kind: Secret
```

## Selected values

| Value | Default | Description |
| --- | --- | --- |
| `revisionHistoryLimit` | `3` | Number of old Deployment ReplicaSets to retain |
| `image.tag` | `""` | Explicit image tag; empty uses chart `appVersion` |
| `image.digest` | `""` | Optional `sha256:` image digest |
| `clusterScoped` | `false` | Watch all namespaces and create cluster RBAC |
| `watchNamespaces` | `[]` | Exact namespaces to watch; empty uses the release namespace |
| `certhub.url` | `""` | Required absolute HTTPS Certhub URL |
| `certhub.tokenSecretName` | `certhub-token` | Token Secret in the Helm release namespace |
| `certhub.tokenSecretKey` | `token` | Application-token key in the token Secret |
| `certhub.resyncInterval` | `6h` | Requeue interval of a ready Certificate and period of the safety-net namespace list; minimum `30s` |
| `certhub.reconcileBackoff` | `1m` | Base of the per-Certificate exponential failure backoff (capped at 32x and at `resyncInterval`) and poll interval while issuance is pending without `Retry-After` |
| `certhub.caBundle.configMapName` | `""` | ConfigMap in the release namespace with additional PEM CA certificates to trust |
| `certhub.caBundle.secretName` | `""` | Secret in the release namespace with additional PEM CA certificates; exclusive with `configMapName` |
| `certhub.caBundle.key` | `ca.crt` | Key in the CA ConfigMap or Secret |
| `metrics.service.enabled` | `true` | Create the metrics Service |
| `metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor |
| `networkPolicy.enabled` | `false` | Create a policy selecting the operator pod |
| `networkPolicy.provider` | `cilium` | Policy backend: `kubernetes` or `cilium` |
| `networkPolicy.<provider>.ingress` | `null` | Native ingress rule list |
| `networkPolicy.<provider>.egress` | `null` | Native egress rule list |
| `resources` | `{}` | Operator resource requests and limits |
| `extraEnv` | `[]` | Additional operator container environment variables |
| `extraVolumes` | `[]` | Additional pod volumes |
| `extraVolumeMounts` | `[]` | Additional operator container volume mounts |

See `values.yaml` and `values.schema.json` for the complete interface and
validation rules.
