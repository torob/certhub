package operator

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
)

func TestExternalKubernetesSecretSyncWithRealAPI(t *testing.T) {
	if os.Getenv("CERTHUB_EXTERNAL_K8S_SECRET_SYNC") != "1" {
		t.Skip("set CERTHUB_EXTERNAL_K8S_SECRET_SYNC=1 to run real Kubernetes Secret sync validation")
	}
	kubectl := strings.TrimSpace(os.Getenv("KUBECTL_BIN"))
	if kubectl == "" {
		kubectl = "kubectl"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ensureExternalKubernetesCRD(ctx, t, kubectl)
	namespace := createExternalTestNamespace(ctx, t, kubectl, "certhub-secret-sync")

	manifest := fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: gateway
  namespace: %s
spec:
  domains:
    - gateway.example.com
  secretName: gateway-tls
  keyType: ecdsa-p256
  issuer: letsencrypt_staging
  secretDeletionPolicy: Retain
`, APIVersion, Kind, namespace)
	runKubectl(ctx, t, kubectl, []byte(manifest), "apply", "-f", "-")

	proxyURL, stopProxy := startKubectlProxy(ctx, t, kubectl)
	defer stopProxy()
	kube := &RESTKubeClient{
		baseURL:          proxyURL,
		defaultNamespace: namespace,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
	}

	certs, err := kube.ListCertificates(ctx, namespace)
	if err != nil {
		t.Fatalf("list CerthubCertificate through Kubernetes API: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("listed %d CerthubCertificate resources, want 1", len(certs))
	}
	cert := certs[0]
	if cert.Metadata.UID == "" || cert.Metadata.ResourceVersion == "" {
		t.Fatalf("Kubernetes API did not populate UID/resourceVersion: %#v", cert.Metadata)
	}

	backend := &fakeBackend{materials: []materialResponse{{
		value: testMaterial("etag-real-k8s"),
		meta:  certhubclient.ResponseMeta{StatusCode: http.StatusOK},
	}}}
	reconciler := NewReconciler(kube, backend)
	result, err := reconciler.Reconcile(ctx, cert)
	if err != nil {
		t.Fatalf("reconcile against real Kubernetes API: %v", err)
	}
	if result.Result != "synced" {
		t.Fatalf("reconcile result = %#v, want synced", result)
	}

	secret, err := kube.GetSecret(ctx, namespace, "gateway-tls")
	if err != nil {
		t.Fatalf("get synced TLS Secret through Kubernetes API: %v", err)
	}
	if secret.Type != SecretTypeTLS {
		t.Fatalf("Secret type = %q", secret.Type)
	}
	if string(secret.Data["tls.crt"]) != "FULLCHAIN" || string(secret.Data["tls.key"]) != "PRIVATEKEY" {
		t.Fatalf("synced Secret data mismatch")
	}
	if secret.Metadata.Annotations[AnnotationMaterialETag] != "etag-real-k8s" {
		t.Fatalf("Secret material ETag annotation = %q", secret.Metadata.Annotations[AnnotationMaterialETag])
	}
	if secret.Metadata.Annotations[AnnotationOwnerUID] != cert.Metadata.UID {
		t.Fatalf("Secret owner UID annotation = %q, want %q", secret.Metadata.Annotations[AnnotationOwnerUID], cert.Metadata.UID)
	}
	if len(secret.Metadata.OwnerReferences) != 0 {
		t.Fatalf("Retain Secret owner reference = %#v, want none", secret.Metadata.OwnerReferences)
	}

	updated, err := kube.ListCertificates(ctx, namespace)
	if err != nil {
		t.Fatalf("re-list CerthubCertificate through Kubernetes API: %v", err)
	}
	if len(updated) != 1 || updated[0].Status.Phase != PhaseReady || updated[0].Status.CertificateID != "cert-1" {
		t.Fatalf("updated status = %#v", updated)
	}
	if !hasCondition(updated[0].Status, ConditionSecretSynced, ConditionTrue) {
		t.Fatalf("updated status is missing true SecretSynced condition: %#v", updated[0].Status.Conditions)
	}
	if updated[0].Status.ObservedGeneration != updated[0].Metadata.Generation {
		t.Fatalf("status observedGeneration=%d, metadata.generation=%d", updated[0].Status.ObservedGeneration, updated[0].Metadata.Generation)
	}

	runKubectl(ctx, t, kubectl, nil, "delete", "certhubcertificate", "gateway", "--namespace", namespace, "--wait=false")
	deleting, err := kube.ListCertificates(ctx, namespace)
	if err != nil || len(deleting) != 1 || deleting[0].Metadata.DeletionTimestamp == nil {
		t.Fatalf("get terminating CerthubCertificate: items=%#v err=%v", deleting, err)
	}
	if _, err := reconciler.Reconcile(ctx, deleting[0]); err != nil {
		t.Fatalf("reconcile Retain deletion: %v", err)
	}
	runKubectl(ctx, t, kubectl, nil, "wait", "--for=delete", "certhubcertificate/gateway", "--namespace", namespace, "--timeout=30s")
	retained, err := kube.GetSecret(ctx, namespace, "gateway-tls")
	if err != nil {
		t.Fatalf("Retain Secret disappeared after CerthubCertificate deletion: %v", err)
	}
	if retained.Metadata.Annotations[AnnotationOwnerUID] != cert.Metadata.UID {
		t.Fatalf("retained Secret ownership metadata changed: %#v", retained.Metadata.Annotations)
	}
	if len(retained.Metadata.OwnerReferences) != 0 {
		t.Fatalf("retained Secret still has owner reference: %#v", retained.Metadata.OwnerReferences)
	}
}

// TestExternalKubernetesRetainSecretSurvivesForegroundDeletion reproduces an
// Argo CD style prune (propagationPolicy=Foreground). The garbage collector
// deletes every dependent of an owner in foreground deletion while the owner
// still exists, so a Retain Secret must never carry an owner reference that
// the operator would only remove after it observes the deletion.
func TestExternalKubernetesRetainSecretSurvivesForegroundDeletion(t *testing.T) {
	if os.Getenv("CERTHUB_EXTERNAL_K8S_SECRET_SYNC") != "1" {
		t.Skip("set CERTHUB_EXTERNAL_K8S_SECRET_SYNC=1 to run real Kubernetes Secret sync validation")
	}
	kubectl := strings.TrimSpace(os.Getenv("KUBECTL_BIN"))
	if kubectl == "" {
		kubectl = "kubectl"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ensureExternalKubernetesCRD(ctx, t, kubectl)
	namespace := createExternalTestNamespace(ctx, t, kubectl, "certhub-retain-foreground")

	manifest := fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: gateway
  namespace: %s
spec:
  domains:
    - gateway.example.com
  secretName: gateway-tls
  keyType: ecdsa-p256
  issuer: letsencrypt_staging
  secretDeletionPolicy: Retain
`, APIVersion, Kind, namespace)
	runKubectl(ctx, t, kubectl, []byte(manifest), "apply", "-f", "-")

	proxyURL, stopProxy := startKubectlProxy(ctx, t, kubectl)
	defer stopProxy()
	kube := &RESTKubeClient{
		baseURL:          proxyURL,
		defaultNamespace: namespace,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
	}

	certs, err := kube.ListCertificates(ctx, namespace)
	if err != nil || len(certs) != 1 {
		t.Fatalf("list CerthubCertificate through Kubernetes API: items=%#v err=%v", certs, err)
	}
	cert := certs[0]
	backend := &fakeBackend{materials: []materialResponse{{
		value: testMaterial("etag-foreground"),
		meta:  certhubclient.ResponseMeta{StatusCode: http.StatusOK},
	}}}
	reconciler := NewReconciler(kube, backend)
	if result, err := reconciler.Reconcile(ctx, cert); err != nil || result.Result != "synced" {
		t.Fatalf("reconcile against real Kubernetes API: result=%#v err=%v", result, err)
	}
	synced, err := kube.GetSecret(ctx, namespace, "gateway-tls")
	if err != nil {
		t.Fatalf("get synced TLS Secret through Kubernetes API: %v", err)
	}

	// Delete like an Argo CD prune. The operator has not observed the
	// deletion yet; give the garbage collector time to act first.
	runKubectl(ctx, t, kubectl, nil, "delete", "certhubcertificate", "gateway", "--namespace", namespace, "--cascade=foreground", "--wait=false")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := kube.GetSecret(ctx, namespace, "gateway-tls"); stderrors.Is(err, ErrNotFound) {
			t.Fatalf("garbage collector deleted the Retain Secret during foreground deletion before the operator reconciled; Secret owner references at sync: %#v", synced.Metadata.OwnerReferences)
		} else if err != nil {
			t.Fatalf("get Secret during foreground deletion: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	deleting, err := kube.ListCertificates(ctx, namespace)
	if err != nil || len(deleting) != 1 || deleting[0].Metadata.DeletionTimestamp == nil {
		t.Fatalf("get terminating CerthubCertificate: items=%#v err=%v", deleting, err)
	}
	if result, err := reconciler.Reconcile(ctx, deleting[0]); err != nil || result.Result != "deleted" {
		t.Fatalf("reconcile Retain foreground deletion: result=%#v err=%v", result, err)
	}
	runKubectl(ctx, t, kubectl, nil, "wait", "--for=delete", "certhubcertificate/gateway", "--namespace", namespace, "--timeout=30s")
	retained, err := kube.GetSecret(ctx, namespace, "gateway-tls")
	if err != nil {
		t.Fatalf("Retain Secret disappeared after foreground CerthubCertificate deletion: %v", err)
	}
	if retained.Metadata.UID != synced.Metadata.UID || string(retained.Data["tls.crt"]) != "FULLCHAIN" {
		t.Fatalf("retained Secret identity or data changed: uid=%q want %q", retained.Metadata.UID, synced.Metadata.UID)
	}
	if len(retained.Metadata.OwnerReferences) != 0 {
		t.Fatalf("retained Secret still has owner reference: %#v", retained.Metadata.OwnerReferences)
	}
}

// createExternalTestNamespace creates a disposable namespace and deletes it at
// cleanup. CERTHUB_EXTERNAL_K8S_NAMESPACE_PREFIX optionally prefixes the name
// so shared clusters can scope test namespaces.
func createExternalTestNamespace(ctx context.Context, t *testing.T, kubectl, base string) string {
	t.Helper()
	namespace := fmt.Sprintf("%s%s-%d", strings.TrimSpace(os.Getenv("CERTHUB_EXTERNAL_K8S_NAMESPACE_PREFIX")), base, time.Now().UTC().Unix())
	runKubectl(ctx, t, kubectl, nil, "create", "namespace", namespace)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, kubectl, "delete", "namespace", namespace, "--ignore-not-found=true", "--wait=false").Run()
	})
	return namespace
}

func ensureExternalKubernetesCRD(ctx context.Context, t *testing.T, kubectl string) {
	t.Helper()
	if err := exec.CommandContext(ctx, kubectl, "get", "crd", "certhubcertificates.certs.torob.dev", "--request-timeout=10s").Run(); err == nil {
		return
	}
	if os.Getenv("CERTHUB_EXTERNAL_K8S_MANAGE_CRD") != "1" {
		t.Fatal("CerthubCertificate CRD is not installed; set CERTHUB_EXTERNAL_K8S_MANAGE_CRD=1 only on a disposable cluster")
	}
	crdPath := filepath.Join(operatorTestRepoRoot(t), "deploy/helm/certhub-operator/crds/certs.torob.dev_certhubcertificates.yaml")
	runKubectl(ctx, t, kubectl, nil, "apply", "-f", crdPath)
	runKubectl(ctx, t, kubectl, nil, "wait", "--for=condition=Established", "crd/certhubcertificates.certs.torob.dev", "--timeout=60s")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, kubectl, "delete", "crd", "certhubcertificates.certs.torob.dev", "--ignore-not-found=true").Run()
	})
}

func startKubectlProxy(ctx context.Context, t *testing.T, kubectl string) (string, func()) {
	t.Helper()
	port := freeTCPPort(t)
	cmd := exec.CommandContext(ctx, kubectl, "proxy", "--port", port, "--address", "127.0.0.1", "--accept-hosts=^127\\.0\\.0\\.1$")
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kubectl proxy: %v", err)
	}
	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	baseURL := "http://127.0.0.1:" + port
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/version", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return baseURL, stop
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatalf("kubectl proxy did not become ready: %s", stderr.String())
	return "", func() {}
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local TCP port: %v", err)
	}
	defer listener.Close()
	return fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
}

func runKubectl(ctx context.Context, t *testing.T, kubectl string, stdin []byte, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, kubectl, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func operatorTestRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("could not find repository root")
		}
		dir = next
	}
}

// TestExternalKubernetesWatchOutlivesRequestTimeout checks against a real API
// server that a CerthubCertificate watch stays open past the whole-request
// timeout of the normal Kubernetes client and still delivers events promptly.
func TestExternalKubernetesWatchOutlivesRequestTimeout(t *testing.T) {
	if os.Getenv("CERTHUB_EXTERNAL_K8S_SECRET_SYNC") != "1" {
		t.Skip("set CERTHUB_EXTERNAL_K8S_SECRET_SYNC=1 to run real Kubernetes watch validation")
	}
	kubectl := strings.TrimSpace(os.Getenv("KUBECTL_BIN"))
	if kubectl == "" {
		kubectl = "kubectl"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ensureExternalKubernetesCRD(ctx, t, kubectl)
	namespace := createExternalTestNamespace(ctx, t, kubectl, "certhub-watch")
	proxyURL, stopProxy := startKubectlProxy(ctx, t, kubectl)
	defer stopProxy()

	const requestTimeout = 2 * time.Second
	kube := &RESTKubeClient{
		baseURL:          proxyURL,
		defaultNamespace: namespace,
		httpClient:       &http.Client{Timeout: requestTimeout},
	}
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watch, err := kube.WatchCertificateChanges(watchCtx, namespace)
	if err != nil {
		t.Fatalf("watch CerthubCertificate: %v", err)
	}
	time.Sleep(requestTimeout + 1500*time.Millisecond)

	manifest := fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: late
  namespace: %s
spec:
  domains:
    - late.example.com
  secretName: late-tls
  keyType: ecdsa-p256
`, APIVersion, Kind, namespace)
	runKubectl(ctx, t, kubectl, []byte(manifest), "apply", "-f", "-")
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event, ok := <-watch:
			if !ok {
				t.Fatal("watch channel closed")
			}
			if event.Certificate != nil && event.Certificate.Metadata.Name == "late" {
				if event.Type != "ADDED" {
					t.Fatalf("event type = %q; want ADDED on the open stream", event.Type)
				}
				return
			}
		case <-deadline:
			t.Fatalf("no watch event within 2s of creation; the stream did not outlive the %s request timeout", requestTimeout)
		}
	}
}
