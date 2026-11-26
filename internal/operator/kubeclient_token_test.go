package operator

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// rotatingTokenAPI accepts only the current service account token, like an
// API server after the previous projected token expired. Rejected requests
// get 401 Unauthorized.
type rotatingTokenAPI struct {
	t        *testing.T
	mu       sync.Mutex
	accepted string
	sent     []string
	streams  int
}

func (a *rotatingTokenAPI) rotate(dir, token string) {
	a.t.Helper()
	writeServiceAccountToken(a.t, dir, token)
	a.mu.Lock()
	a.accepted = token
	a.sent = nil
	a.mu.Unlock()
}

// sentTokens returns the bearer tokens of the requests since the last rotation.
func (a *rotatingTokenAPI) sentTokens() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.sent...)
}

func (a *rotatingTokenAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	a.mu.Lock()
	a.sent = append(a.sent, token)
	accepted := token == a.accepted
	stream := 0
	if accepted && r.URL.Query().Get("watch") == "true" {
		a.streams++
		stream = a.streams
	}
	a.mu.Unlock()
	if !accepted {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`))
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == fakeAPISecretPath:
		writeKubeJSON(a.t, w, ownedSecret(testCertificate(), "etag"))
	case r.Method == http.MethodPost && r.URL.Path == fakeAPIEventsPath:
		var event Event
		decodeKubeJSON(a.t, r, &event)
		if event.Reason != "TokenRotated" {
			a.t.Errorf("event body was not sent again intact: %#v", event)
		}
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && r.URL.Path == "/apis/certs.torob.dev/v1alpha1/namespaces/ns/certhubcertificates" && stream > 0:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"type":"ADDED","object":{"metadata":{"name":"stream-` + strconv.Itoa(stream) + `"}}}` + "\n"))
		w.(http.Flusher).Flush()
		// End the stream cleanly, as the API server does at timeoutSeconds.
		select {
		case <-time.After(watchMinHealthyDuration + 200*time.Millisecond):
		case <-r.Context().Done():
		}
	default:
		a.t.Errorf("unexpected Kubernetes request: %s %s", r.Method, r.URL.String())
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}
}

// writeServiceAccountToken replaces the token file atomically, as the kubelet
// does for a projected service account token.
func writeServiceAccountToken(t *testing.T, dir, token string) {
	t.Helper()
	tmp := filepath.Join(dir, ".token.tmp")
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
}

// newTestInClusterClient starts a TLS API server and builds the in-cluster
// client from a service account directory that trusts it.
func newTestInClusterClient(t *testing.T, handler http.Handler, token string) (*RESTKubeClient, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "namespace"), []byte("ns\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeServiceAccountToken(t, dir, token)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)
	client, err := newInClusterRESTKubeClient(dir)
	if err != nil {
		t.Fatalf("newInClusterRESTKubeClient: %v", err)
	}
	return client, dir
}

// The kubelet rotates the projected service account token file. After the
// API server stops accepting the old token, every request kind (reads,
// mutations, and watch reconnects) must use the new token instead of failing
// with 401 Unauthorized until the operator restarts.
func TestInClusterRESTKubeClientFollowsServiceAccountTokenRotation(t *testing.T) {
	api := &rotatingTokenAPI{t: t, accepted: "token-1"}
	client, dir := newTestInClusterClient(t, api, "token-1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := client.GetSecret(ctx, "ns", "gateway-tls"); err != nil {
		t.Fatalf("GET with the startup token: %v", err)
	}

	t.Run("read after rotation", func(t *testing.T) {
		api.rotate(dir, "token-2")
		if _, err := client.GetSecret(ctx, "ns", "gateway-tls"); err != nil {
			t.Fatalf("GET after token rotation: %v (sent tokens %q)", err, api.sentTokens())
		}
		if sent := api.sentTokens(); len(sent) > 2 || sent[len(sent)-1] != "token-2" {
			t.Fatalf("sent tokens = %q; want at most one rejected request, then token-2", sent)
		}
	})

	t.Run("mutation after rotation", func(t *testing.T) {
		api.rotate(dir, "token-3")
		err := client.EmitEvent(ctx, Event{Namespace: "ns", Name: "gateway", Type: "Normal", Reason: "TokenRotated", Message: "token rotated"})
		if err != nil {
			t.Fatalf("POST after token rotation: %v (sent tokens %q)", err, api.sentTokens())
		}
		if sent := api.sentTokens(); len(sent) > 2 || sent[len(sent)-1] != "token-3" {
			t.Fatalf("sent tokens = %q; want at most one rejected request, then token-3", sent)
		}
	})

	t.Run("watch reconnect after rotation", func(t *testing.T) {
		api.rotate(dir, "token-4")
		watchCtx, cancelWatch := context.WithCancel(ctx)
		defer cancelWatch()
		watch, err := client.WatchCertificateChanges(watchCtx, "ns")
		if err != nil {
			t.Fatalf("watch: %v", err)
		}
		receive := func(want string) {
			t.Helper()
			select {
			case event := <-watch:
				if event.Certificate == nil || event.Certificate.Metadata.Name != want {
					t.Fatalf("watch event = %#v; want %s", event, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("watch event %s not received (sent tokens %q)", want, api.sentTokens())
			}
		}
		receive("stream-1")
		// Rotate while the first stream is open. The API server ends it,
		// and the reconnect must authenticate with the new token.
		api.rotate(dir, "token-5")
		receive("stream-2")
		if sent := api.sentTokens(); sent[len(sent)-1] != "token-5" {
			t.Fatalf("watch reconnect tokens = %q; want token-5 last", sent)
		}
	})
}

// tokenRecorder accepts every request and records its bearer token.
type tokenRecorder struct {
	t      *testing.T
	mu     sync.Mutex
	tokens []string
	status int
}

func (r *tokenRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.tokens = append(r.tokens, strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
	status := r.status
	r.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	writeKubeJSON(r.t, w, ownedSecret(testCertificate(), "etag"))
}

func (r *tokenRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	tokens := r.tokens
	r.tokens = nil
	return tokens
}

// The kubelet writes a new token while the old one is still valid. The client
// changes to it after the cache period, without a 401 first.
func TestInClusterRESTKubeClientReloadsServiceAccountTokenPeriodically(t *testing.T) {
	recorder := &tokenRecorder{t: t}
	client, dir := newTestInClusterClient(t, recorder, "token-1")
	now := time.Now()
	client.tokenFile.now = func() time.Time { return now }
	ctx := context.Background()
	get := func() {
		t.Helper()
		if _, err := client.GetSecret(ctx, "ns", "gateway-tls"); err != nil {
			t.Fatalf("GET: %v", err)
		}
	}

	writeServiceAccountToken(t, dir, "token-2")
	get()
	now = now.Add(serviceAccountTokenReloadPeriod - time.Second)
	get()
	if got := recorder.take(); !slices.Equal(got, []string{"token-1", "token-1"}) {
		t.Fatalf("tokens inside the cache period = %q; want the cached token-1", got)
	}
	now = now.Add(2 * time.Second)
	get()
	get()
	if got := recorder.take(); !slices.Equal(got, []string{"token-2", "token-2"}) {
		t.Fatalf("tokens after the cache period = %q; want token-2", got)
	}

	// A missing or empty token file keeps the last token.
	if err := os.Remove(filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * serviceAccountTokenReloadPeriod)
	get()
	writeServiceAccountToken(t, dir, "")
	now = now.Add(2 * serviceAccountTokenReloadPeriod)
	get()
	if got := recorder.take(); !slices.Equal(got, []string{"token-2", "token-2"}) {
		t.Fatalf("tokens with a missing or empty token file = %q; want the last token-2", got)
	}
}

// A 401 when the token file still holds the rejected token is returned at
// once: there is no new token to send.
func TestInClusterRESTKubeClientDoesNotRepeatUnauthorizedWithSameToken(t *testing.T) {
	recorder := &tokenRecorder{t: t, status: http.StatusUnauthorized}
	client, _ := newTestInClusterClient(t, recorder, "token-1")
	_, err := client.GetSecret(context.Background(), "ns", "gateway-tls")
	if err == nil || !strings.Contains(err.Error(), "status=401") {
		t.Fatalf("GET error = %v; want 401", err)
	}
	if got := recorder.take(); !slices.Equal(got, []string{"token-1"}) {
		t.Fatalf("sent tokens = %q; want one request", got)
	}
}

// A client with a fixed token keeps its behavior: a 401 is returned at once
// and nothing is read from a token file.
func TestRESTKubeClientFixedTokenUnauthorizedIsReturned(t *testing.T) {
	recorder := &tokenRecorder{t: t, status: http.StatusUnauthorized}
	server := httptest.NewServer(recorder)
	defer server.Close()
	client := testRESTKubeClient(server.URL)
	_, err := client.GetSecret(context.Background(), "ns", "gateway-tls")
	if err == nil || !strings.Contains(err.Error(), "status=401") {
		t.Fatalf("GET error = %v; want 401", err)
	}
	if got := recorder.take(); !slices.Equal(got, []string{"test-token"}) {
		t.Fatalf("sent tokens = %q; want one request with the fixed token", got)
	}
}
