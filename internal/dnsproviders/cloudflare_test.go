package dnsproviders

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	client := NewCloudflareClient(server.Client())
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
