package operator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/netretry"
)

func TestRESTKubeClientRetriesReadsButNotMutations(t *testing.T) {
	t.Run("GET eventually succeeds", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			requireKubeAuth(t, r)
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s; want GET", r.Method)
			}
			if calls < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writeKubeJSON(t, w, &Secret{Metadata: Metadata{Name: "token", Namespace: "ns"}, Data: map[string][]byte{"token": []byte("value")}})
		}))
		defer server.Close()
		client := testRESTKubeClient(server.URL)
		client.retry = netretry.Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
		if _, err := client.GetSecret(context.Background(), "ns", "token"); err != nil {
			t.Fatal(err)
		}
		if calls != 3 {
			t.Fatalf("GET calls = %d; want 3", calls)
		}
	})

	t.Run("POST is not replayed", func(t *testing.T) {
		getCalls := 0
		postCalls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requireKubeAuth(t, r)
			switch r.Method {
			case http.MethodGet:
				getCalls++
				http.NotFound(w, r)
			case http.MethodPost:
				postCalls++
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				t.Fatalf("unexpected method %s", r.Method)
			}
		}))
		defer server.Close()
		client := testRESTKubeClient(server.URL)
		client.retry = netretry.Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
		err := client.CreateOrUpdateSecret(context.Background(), ownedSecret(testCertificate(), "etag"))
		if err == nil {
			t.Fatal("503 mutation unexpectedly succeeded")
		}
		if getCalls != 1 || postCalls != 1 {
			t.Fatalf("GET calls=%d POST calls=%d; want 1 each", getCalls, postCalls)
		}
	})
}

func TestRESTKubeClientSecretCreateUpdateDeleteUsesKubernetesRESTSemantics(t *testing.T) {
	ctx := context.Background()
	var stored *Secret
	var sawPost, sawOwnerReferencePatch, sawPut, sawDelete bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireKubeAuth(t, r)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/ns/secrets/gateway-tls":
			if stored == nil {
				http.NotFound(w, r)
				return
			}
			writeKubeJSON(t, w, stored)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/ns/secrets":
			requireKubeContentType(t, r, "application/json")
			var created Secret
			decodeKubeJSON(t, r, &created)
			if created.APIVersion != "v1" || created.Kind != "Secret" {
				t.Fatalf("create did not set apiVersion/kind: apiVersion=%q kind=%q", created.APIVersion, created.Kind)
			}
			if created.Metadata.Name != "gateway-tls" || created.Metadata.Namespace != "ns" || created.Type != SecretTypeTLS {
				t.Fatalf("unexpected created Secret metadata/type: name=%q namespace=%q type=%q", created.Metadata.Name, created.Metadata.Namespace, created.Type)
			}
			if got := string(created.Data["tls.key"]); got != "KEY1" {
				t.Fatalf("unexpected created Secret tls.key length=%d", len(got))
			}
			created.Metadata.UID = "secret-uid"
			created.Metadata.ResourceVersion = "rv-1"
			stored = &created
			sawPost = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/namespaces/ns/secrets/gateway-tls":
			if r.Header.Get("Content-Type") != "application/merge-patch+json" {
				t.Fatalf("owner-reference patch content type = %q", r.Header.Get("Content-Type"))
			}
			var patch struct {
				Metadata Metadata `json:"metadata"`
			}
			decodeKubeJSON(t, r, &patch)
			if patch.Metadata.ResourceVersion != "rv-1" || patch.Metadata.OwnerReferences == nil || len(patch.Metadata.OwnerReferences) != 0 {
				t.Fatalf("unexpected owner-reference patch: %#v", patch.Metadata)
			}
			stored.Metadata.OwnerReferences = nil
			stored.Metadata.ResourceVersion = "rv-cleaned"
			sawOwnerReferencePatch = true
			writeKubeJSON(t, w, stored)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/ns/secrets/gateway-tls":
			requireKubeContentType(t, r, "application/json")
			var updated Secret
			decodeKubeJSON(t, r, &updated)
			if updated.Metadata.ResourceVersion != "rv-cleaned" {
				t.Fatalf("update did not carry resourceVersion: %#v", updated.Metadata)
			}
			if got := string(updated.Data["tls.key"]); got != "KEY2" {
				t.Fatalf("unexpected updated Secret tls.key length=%d", len(got))
			}
			updated.Metadata.UID = "secret-uid"
			updated.Metadata.ResourceVersion = "rv-2"
			stored = &updated
			sawPut = true
			writeKubeJSON(t, w, updated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/namespaces/ns/secrets/gateway-tls":
			requireKubeContentType(t, r, "application/json")
			var opts struct {
				APIVersion    string `json:"apiVersion"`
				Kind          string `json:"kind"`
				Preconditions struct {
					UID             string `json:"uid"`
					ResourceVersion string `json:"resourceVersion"`
				} `json:"preconditions"`
			}
			decodeKubeJSON(t, r, &opts)
			if opts.APIVersion != "v1" || opts.Kind != "DeleteOptions" || opts.Preconditions.UID != "secret-uid" || opts.Preconditions.ResourceVersion != "rv-2" {
				t.Fatalf("unexpected delete options: %#v", opts)
			}
			stored = nil
			sawDelete = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected Kubernetes request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testRESTKubeClient(server.URL)
	cert := testCertificate()
	secret := ownedSecret(cert, "etag-1")
	secret.Data["tls.key"] = []byte("KEY1")
	if err := client.CreateOrUpdateSecret(ctx, secret); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if !sawPost {
		t.Fatalf("create did not POST")
	}
	stored.Metadata.OwnerReferences = []OwnerReference{certhubOwnerReference(cert)}
	if err := client.ClearSecretOwnerReferences(ctx, stored); err != nil {
		t.Fatalf("owner-reference cleanup failed: %v", err)
	}
	if !sawOwnerReferencePatch {
		t.Fatalf("owner-reference cleanup did not PATCH")
	}

	updated := ownedSecret(cert, "etag-2")
	updated.Data["tls.key"] = []byte("KEY2")
	if err := client.CreateOrUpdateSecret(ctx, updated); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if !sawPut {
		t.Fatalf("update did not PUT")
	}

	if err := client.DeleteSecret(ctx, "ns", "gateway-tls", stored); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if !sawDelete {
		t.Fatalf("delete did not use Kubernetes delete preconditions")
	}
}

func TestRESTKubeClientOwnerReferenceCleanupRequiresVersionedSecret(t *testing.T) {
	client := &RESTKubeClient{}
	if err := client.ClearSecretOwnerReferences(context.Background(), nil); err == nil {
		t.Fatal("nil Secret accepted for owner-reference cleanup")
	}
	if err := client.ClearSecretOwnerReferences(context.Background(), &Secret{Metadata: Metadata{Name: "gateway-tls", Namespace: "ns"}}); err == nil {
		t.Fatal("unversioned Secret accepted for owner-reference cleanup")
	}
}

func TestRESTKubeClientRefusesUnownedExistingSecretBeforeUpdate(t *testing.T) {
	ctx := context.Background()
	putCalled := false
	cert := testCertificate()
	existing := ownedSecret(cert, "old")
	existing.Metadata.Annotations[AnnotationOwnerUID] = "other-owner"
	existing.Metadata.ResourceVersion = "rv-conflict"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireKubeAuth(t, r)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/ns/secrets/gateway-tls":
			writeKubeJSON(t, w, existing)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/ns/secrets/gateway-tls":
			putCalled = true
			t.Fatalf("unowned Secret must not be updated")
		default:
			t.Fatalf("unexpected Kubernetes request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testRESTKubeClient(server.URL)
	err := client.CreateOrUpdateSecret(ctx, ownedSecret(cert, "new"))
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("unexpected ownership error: %v", err)
	}
	if putCalled {
		t.Fatalf("PUT was called for unowned Secret")
	}
}

func TestRESTKubeClientStatusFinalizersListAndWatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sawStatus, sawFinalizers bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireKubeAuth(t, r)
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/apis/certs.torob.dev/v1alpha1/namespaces/ns/certhubcertificates/gateway/status":
			requireKubeContentType(t, r, "application/json")
			var body CerthubCertificate
			decodeKubeJSON(t, r, &body)
			if body.APIVersion != APIVersion || body.Kind != Kind || body.Metadata.ResourceVersion != "rv-cert" || body.Status.Phase != PhaseReady {
				t.Fatalf("unexpected status body: %#v", body)
			}
			sawStatus = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch && r.URL.Path == "/apis/certs.torob.dev/v1alpha1/namespaces/ns/certhubcertificates/gateway":
			if ct := r.Header.Get("Content-Type"); ct != "application/merge-patch+json" {
				t.Fatalf("patch content-type = %q", ct)
			}
			var body struct {
				Metadata Metadata `json:"metadata"`
			}
			decodeKubeJSON(t, r, &body)
			if body.Metadata.ResourceVersion != "rv-cert" || len(body.Metadata.Finalizers) != 1 || body.Metadata.Finalizers[0] != Finalizer {
				t.Fatalf("unexpected finalizer patch: %#v", body)
			}
			sawFinalizers = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/certs.torob.dev/v1alpha1/namespaces/ns/certhubcertificates" && r.URL.RawQuery == "":
			writeKubeJSON(t, w, map[string]any{"items": []CerthubCertificate{*testCertificate()}})
		case r.Method == http.MethodGet && r.URL.Path == "/apis/certs.torob.dev/v1alpha1/namespaces/ns/certhubcertificates" && r.URL.Query().Get("watch") == "true":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"ADDED","object":{"metadata":{"name":"gateway"}}}` + "\n"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		default:
			t.Fatalf("unexpected Kubernetes request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testRESTKubeClient(server.URL)
	cert := testCertificate()
	cert.Metadata.ResourceVersion = "rv-cert"
	cert.Status.Phase = PhaseReady
	if err := client.UpdateStatus(ctx, cert); err != nil {
		t.Fatalf("status update failed: %v", err)
	}
	if err := client.UpdateFinalizers(ctx, cert, []string{Finalizer}); err != nil {
		t.Fatalf("finalizer update failed: %v", err)
	}
	items, err := client.ListCertificates(ctx, "ns")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(items) != 1 || items[0].Metadata.Name != "gateway" {
		t.Fatalf("unexpected list result: %#v", items)
	}
	watch, err := client.WatchCertificateChanges(ctx, "ns")
	if err != nil {
		t.Fatalf("watch failed: %v", err)
	}
	select {
	case <-watch:
	case <-time.After(time.Second):
		t.Fatalf("watch did not publish change")
	}
	cancel()
	select {
	case _, ok := <-watch:
		if ok {
			t.Fatalf("watch channel remained open after context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatalf("watch channel did not close after context cancellation")
	}
	if !sawStatus || !sawFinalizers {
		t.Fatalf("status/finalizer calls missing: status=%v finalizers=%v", sawStatus, sawFinalizers)
	}
}

func testRESTKubeClient(baseURL string) *RESTKubeClient {
	return &RESTKubeClient{
		baseURL:          baseURL,
		token:            "test-token",
		defaultNamespace: "ns",
		httpClient:       http.DefaultClient,
	}
}

func requireKubeAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("authorization header = %q", got)
	}
	if accept := r.Header.Get("Accept"); !strings.Contains(accept, "application/json") {
		t.Fatalf("accept header = %q", accept)
	}
}

func requireKubeContentType(t *testing.T, r *http.Request, want string) {
	t.Helper()
	if ct := r.Header.Get("Content-Type"); ct != want {
		t.Fatalf("content-type = %q, want %q", ct, want)
	}
}

func decodeKubeJSON(t *testing.T, r *http.Request, out any) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
}

func writeKubeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
