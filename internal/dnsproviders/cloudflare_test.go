package dnsproviders

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

func TestCloudflarePresentAndCleanUpExactTXTValue(t *testing.T) {
	const (
		token    = "CF-TOKEN-CANARY"
		txtValue = "CF-TXT-VALUE-CANARY"
	)
	var created bool
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") != "example.com" {
				t.Fatalf("zone query = %q", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "zone-id", "name": "example.com"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			if r.URL.Query().Get("name") != "_acme-challenge.example.com" {
				t.Fatalf("record query = %q", r.URL.RawQuery)
			}
			result := []map[string]string{{
				"id":      "keep-id",
				"type":    "TXT",
				"name":    "_acme-challenge.example.com",
				"content": "unrelated-value",
			}}
			if created {
				result = append(result, map[string]string{
					"id":      "delete-id",
					"type":    "TXT",
					"name":    "_acme-challenge.example.com",
					"content": txtValue,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["type"] != "TXT" || body["name"] != "_acme-challenge.example.com" || body["content"] != txtValue {
				t.Fatalf("create body = %#v", body)
			}
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone-id/dns_records/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/zones/zone-id/dns_records/"))
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := NewCloudflareClient(server.Client())
	client.BaseURL = server.URL
	op := DNS01ChallengeOperation{
		ZoneName:   "Example.COM.",
		RecordName: "_ACME-Challenge.Example.COM.",
		TXTValue:   txtValue,
	}
	if err := client.Present(context.Background(), CloudflareCredentials{APIToken: token}, op); err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("TXT record was not created")
	}
	if err := client.CleanUp(context.Background(), CloudflareCredentials{APIToken: token}, op); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "delete-id" {
		t.Fatalf("deleted = %v", deleted)
	}
}

func TestCloudflarePresentVerifiesAmbiguousCreateBeforeRetry(t *testing.T) {
	created := false
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone-id", "name": "example.com"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			result := []map[string]string{}
			if created {
				result = append(result, map[string]string{"id": "record-id", "type": "TXT", "name": "_acme-challenge.example.com", "content": "value"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		case r.Method == http.MethodPost:
			posts++
			created = true
			w.WriteHeader(http.StatusServiceUnavailable) // Simulate a committed mutation with a lost success response.
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	policy := netretry.Policy{MaxAttempts: 5, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
	client := NewCloudflareClient(server.Client(), policy)
	client.BaseURL = server.URL
	err := client.Present(context.Background(), CloudflareCredentials{APIToken: "token"}, DNS01ChallengeOperation{ZoneName: "example.com", RecordName: "_acme-challenge.example.com", TXTValue: "value", TTL: 120})
	if err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("create requests = %d; want 1", posts)
	}
}

func TestCloudflareCleanUpVerifiesAmbiguousDeleteBeforeRetry(t *testing.T) {
	created := true
	deletes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone-id", "name": "example.com"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			result := []map[string]string{}
			if created {
				result = append(result, map[string]string{"id": "record-id", "type": "TXT", "name": "_acme-challenge.example.com", "content": "value"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-id/dns_records/record-id":
			deletes++
			created = false
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client := NewCloudflareClient(server.Client(), netretry.Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond})
	client.BaseURL = server.URL
	err := client.CleanUp(context.Background(), CloudflareCredentials{APIToken: "token"}, DNS01ChallengeOperation{ZoneName: "example.com", RecordName: "_acme-challenge.example.com", TXTValue: "value", TTL: 120})
	if err != nil {
		t.Fatal(err)
	}
	if deletes != 1 {
		t.Fatalf("delete requests = %d; want 1", deletes)
	}
}

func TestCloudflareChallengeErrorsAreSanitized(t *testing.T) {
	const (
		token    = "CF-TOKEN-CANARY"
		txtValue = "CF-TXT-VALUE-CANARY"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(token + " " + txtValue))
	}))
	defer server.Close()

	client := NewCloudflareClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	err := client.Present(context.Background(), CloudflareCredentials{APIToken: token}, DNS01ChallengeOperation{
		ZoneName:   "example.com",
		RecordName: "_acme-challenge.example.com",
		TXTValue:   txtValue,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoDNSCanaryLeak(t, err, token, txtValue)
}
