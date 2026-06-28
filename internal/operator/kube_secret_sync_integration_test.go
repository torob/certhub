package operator

import (
	"bytes"
	"context"
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
	namespace := fmt.Sprintf("certhub-secret-sync-%d", time.Now().UTC().Unix())
	runKubectl(ctx, t, kubectl, nil, "create", "namespace", namespace)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, kubectl, "delete", "namespace", namespace, "--ignore-not-found=true", "--wait=false").Run()
	})

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
	reconciler.AllowedSecretNames = []string{"gateway-tls"}
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
