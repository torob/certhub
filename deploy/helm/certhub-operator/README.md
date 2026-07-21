# Certhub Operator Helm Chart

This chart deploys the Certhub Kubernetes certificate sync operator. The
operator watches `CerthubCertificate` resources and writes their certificate
material to same-namespace Kubernetes TLS Secrets selected by each resource.

## Prerequisites

- Kubernetes with the `apiextensions.k8s.io/v1` CRD API.
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

## Target Secret permissions

Each `CerthubCertificate` chooses its target through `spec.secretName`. The
operator always uses the resource's own namespace; there is no cross-namespace
target field. Users authorized to create or update `CerthubCertificate`
resources are therefore trusted to choose certificate Secret names in that
namespace.

The generated RBAC grants Secret create, get, update, patch, and delete
throughout each watched namespace without granting Secret list or watch.
Existing Secrets are mutated or deleted only after their type, owner UID,
labels, annotations, namespace, and name pass the operator's ownership checks.
Cluster-scoped mode grants these target-Secret permissions across all
namespaces.

The operator patches the main `CerthubCertificate` resource only to add or
remove its cleanup finalizer. Kubernetes CRDs do not expose a separate
`/finalizers` REST endpoint, so the generated RBAC grants main-resource
`patch` but does not grant main-resource `update`.

Managed TLS Secrets have no Kubernetes owner reference. The default
`secretDeletionPolicy: Retain` therefore leaves the Secret in place when its
`CerthubCertificate` is removed. `secretDeletionPolicy: Delete` uses an
operator finalizer and explicit ownership-checked deletion. Existing managed
Secrets with legacy owner references are migrated during reconciliation.
After upgrading from an older chart, allow the operator to reconcile existing
resources before deleting a `Retain` resource so the legacy reference is
removed before Kubernetes garbage collection can act.

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

## Selected values

| Value | Default | Description |
| --- | --- | --- |
| `image.tag` | `""` | Explicit image tag; empty uses chart `appVersion` |
| `image.digest` | `""` | Optional `sha256:` image digest |
| `clusterScoped` | `false` | Watch all namespaces and create cluster RBAC |
| `watchNamespaces` | `[]` | Exact namespaces to watch; empty uses the release namespace |
| `certhub.url` | `""` | Required absolute HTTPS Certhub URL |
| `certhub.tokenSecretName` | `certhub-token` | Token Secret in the Helm release namespace |
| `certhub.tokenSecretKey` | `token` | Application-token key in the token Secret |
| `certhub.resyncInterval` | `6h` | Periodic resync interval; minimum `30s` |
| `metrics.service.enabled` | `true` | Create the metrics Service |
| `metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor |
| `networkPolicy.enabled` | `false` | Create a policy selecting the operator pod |
| `networkPolicy.provider` | `cilium` | Policy backend: `kubernetes` or `cilium` |
| `networkPolicy.<provider>.ingress` | `null` | Native ingress rule list |
| `networkPolicy.<provider>.egress` | `null` | Native egress rule list |
| `resources` | `{}` | Operator resource requests and limits |

See `values.yaml` and `values.schema.json` for the complete interface and
validation rules.
