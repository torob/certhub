package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/netretry"
	xacme "golang.org/x/crypto/acme"
)

func TestOrderClientRunsOrderFlowThroughInjectedHTTPClient(t *testing.T) {
	_, keyPEM, err := newECDSAPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	certDER := []byte("leaf-cert-der")
	var calls []string
	directoryCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/directory" {
			directoryCalls++
			if directoryCalls < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   "http://" + r.Host + "/new-nonce",
				"newAccount": "http://" + r.Host + "/new-account",
				"newOrder":   "http://" + r.Host + "/new-order",
				"revokeCert": "http://" + r.Host + "/revoke-cert",
				"keyChange":  "http://" + r.Host + "/key-change",
			})
			return
		}
		w.Header().Set("Replay-Nonce", "nonce")
		if r.Method == http.MethodHead && r.URL.Path == "/new-nonce" {
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected ACME method: %s %s", r.Method, r.URL.Path)
		}
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/new-order":
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         xacme.StatusPending,
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{"http://" + r.Host + "/authz/1"},
				"finalize":       "http://" + r.Host + "/finalize/1",
			})
		case "/order/1":
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         xacme.StatusReady,
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{"http://" + r.Host + "/authz/1"},
				"finalize":       "http://" + r.Host + "/finalize/1",
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     xacme.StatusPending,
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]string{{
					"type":   "dns-01",
					"url":    "http://" + r.Host + "/challenge/1",
					"token":  "challenge-token",
					"status": xacme.StatusPending,
				}},
			})
		case "/challenge/1":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"type":   "dns-01",
				"url":    "http://" + r.Host + "/challenge/1",
				"token":  "challenge-token",
				"status": xacme.StatusProcessing,
			})
		case "/finalize/1":
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":      xacme.StatusValid,
				"certificate": "http://" + r.Host + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(certDER) + "\n-----END CERTIFICATE-----\n"))
		case "/revoke-cert":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected ACME request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewOrderClient(server.Client(), netretry.Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond})
	common := OrderClientParams{
		DirectoryURL:         server.URL + "/directory",
		AccountURL:           server.URL + "/acct/1",
		AccountPrivateKeyPEM: keyPEM,
	}
	order, err := client.CreateOrder(context.Background(), CreateOrderParams{
		OrderClientParams: common,
		Identifiers:       []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if order.URL != server.URL+"/order/1" || order.FinalizeURL != server.URL+"/finalize/1" {
		t.Fatalf("order = %#v", order)
	}
	if directoryCalls != 3 {
		t.Fatalf("directory calls = %d; want 3", directoryCalls)
	}
	fetched, err := client.FetchOrder(context.Background(), FetchOrderParams{
		OrderClientParams: common,
		OrderURL:          order.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Status != xacme.StatusReady {
		t.Fatalf("fetched status = %q", fetched.Status)
	}
	authz, err := client.FetchAuthorization(context.Background(), FetchAuthorizationParams{
		OrderClientParams: common,
		AuthorizationURL:  server.URL + "/authz/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if authz.DNSChallenge == nil || authz.DNSChallenge.Token != "challenge-token" || authz.DNSChallenge.TXTValue == "" {
		t.Fatalf("authorization = %#v", authz)
	}
	if err := client.AcceptChallenge(context.Background(), AcceptChallengeParams{
		OrderClientParams: common,
		ChallengeURL:      authz.DNSChallenge.URL,
		Token:             authz.DNSChallenge.Token,
	}); err != nil {
		t.Fatal(err)
	}
	bundle, err := client.FinalizeOrder(context.Background(), FinalizeOrderParams{
		OrderClientParams: common,
		FinalizeURL:       order.FinalizeURL,
		CSRDER:            []byte("csr-der"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.CertificateURL != server.URL+"/cert/1" || string(bundle.DERChain[0]) != string(certDER) {
		t.Fatalf("bundle = %#v", bundle)
	}
	chain, err := client.FetchCertificate(context.Background(), FetchCertificateParams{
		OrderClientParams: common,
		CertificateURL:    bundle.CertificateURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(chain[0]) != string(certDER) {
		t.Fatalf("chain = %q", chain[0])
	}
	if err := client.RevokeCertificate(context.Background(), RevokeCertificateParams{
		OrderClientParams: common,
		CertificateDER:    certDER,
		Reason:            xacme.CRLReasonCessationOfOperation,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/new-order", "/order/1", "/authz/1", "/challenge/1", "/finalize/1", "/cert/1", "/revoke-cert"} {
		if !containsString(calls, want) {
			t.Fatalf("calls %v did not include %s", calls, want)
		}
	}
}

func TestOrderClientDoesNotLeakUpstreamErrorDetails(t *testing.T) {
	_, keyPEM, err := newECDSAPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	const canary = "ACCOUNT-SECRET-CANARY"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/directory" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   "http://" + r.Host + "/new-nonce",
				"newAccount": "http://" + r.Host + "/new-account",
				"newOrder":   "http://" + r.Host + "/new-order",
			})
			return
		}
		w.Header().Set("Replay-Nonce", "nonce")
		if r.Method == http.MethodHead && r.URL.Path == "/new-nonce" {
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"` + canary + `"}`))
	}))
	defer server.Close()

	client := NewOrderClient(server.Client())
	_, err = client.CreateOrder(context.Background(), CreateOrderParams{
		OrderClientParams: OrderClientParams{
			DirectoryURL:         server.URL + "/directory",
			AccountURL:           server.URL + "/acct/1",
			AccountPrivateKeyPEM: keyPEM,
		},
		Identifiers: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), string(keyPEM)) {
		t.Fatalf("error leaked secret material: %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
