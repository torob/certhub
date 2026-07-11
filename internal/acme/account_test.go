package acme

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/netretry"
)

func TestAccountClientRegistersThroughInjectedHTTPClient(t *testing.T) {
	var directoryCalled bool
	var directoryCalls int
	var accountPosts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/directory":
			directoryCalled = true
			directoryCalls++
			if directoryCalls < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   "http://" + r.Host + "/new-nonce",
				"newAccount": "http://" + r.Host + "/new-account",
				"newOrder":   "http://" + r.Host + "/new-order",
			})
		case r.Method == http.MethodHead && r.URL.Path == "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/new-account":
			accountPosts++
			if r.Header.Get("Content-Type") != "application/jose+json" {
				t.Fatalf("content type = %s", r.Header.Get("Content-Type"))
			}
			w.Header().Set("Location", "http://"+r.Host+"/acct/123")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"valid","contact":["mailto:platform@example.com"]}`))
		default:
			t.Fatalf("unexpected ACME request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewAccountClient(server.Client(), netretry.Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond})
	registration, err := client.RegisterOrReuseAccount(context.Background(), AccountRegistrationParams{
		DirectoryURL: server.URL + "/directory",
		Email:        "platform@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !directoryCalled {
		t.Fatalf("directory endpoint was not called")
	}
	if directoryCalls != 3 {
		t.Fatalf("directory calls = %d; want 3", directoryCalls)
	}
	if accountPosts != 1 {
		t.Fatalf("account posts = %d", accountPosts)
	}
	if registration.AccountURL != server.URL+"/acct/123" {
		t.Fatalf("account URL = %q", registration.AccountURL)
	}
	if block, _ := pem.Decode(registration.PrivateKeyPEM); block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("private key PEM was not generated")
	}
}
