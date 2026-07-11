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

func TestArvanCloudPresentVerifiesAmbiguousCreateBeforeRetry(t *testing.T) {
	created := false
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/domains/example.com/dns-records":
			data := []map[string]any{}
			if created {
				data = append(data, map[string]any{"id": "record-id", "type": "txt", "name": "_acme-challenge", "value": map[string]string{"text": "value"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case r.Method == http.MethodPost && r.URL.Path == "/domains/example.com/dns-records":
			posts++
			created = true
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client := NewArvanCloudClient(server.Client(), netretry.Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond})
	client.BaseURL = server.URL
	err := client.Present(context.Background(), ArvanCloudCredentials{APIKey: "Apikey token"}, DNS01ChallengeOperation{ZoneName: "example.com", RecordName: "_acme-challenge.example.com", TXTValue: "value", TTL: 120})
	if err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("create requests = %d; want 1", posts)
	}
}

func TestArvanCloudPresentAndCleanUpExactTXTValue(t *testing.T) {
	const (
		apiKey   = "Apikey ARVAN-KEY-CANARY"
		txtValue = "ARVAN-TXT-VALUE-CANARY"
	)
	var created bool
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != apiKey {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/domains/example.com/dns-records":
			result := []map[string]any{{
				"id":    "keep-id",
				"type":  "txt",
				"name":  "_acme-challenge",
				"value": map[string]string{"text": "unrelated-value"},
			}}
			if created {
				result = append(result, map[string]any{
					"id":    "delete-id",
					"type":  "txt",
					"name":  "_acme-challenge",
					"value": map[string]string{"text": txtValue},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": result})
		case r.Method == http.MethodPost && r.URL.Path == "/domains/example.com/dns-records":
			var body struct {
				Type  string            `json:"type"`
				Name  string            `json:"name"`
				Value map[string]string `json:"value"`
				TTL   int               `json:"ttl"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Type != "txt" || body.Name != "_acme-challenge" || body.Value["text"] != txtValue {
				t.Fatalf("create body = %#v", body)
			}
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": "new-id"}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/domains/example.com/dns-records/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/domains/example.com/dns-records/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected ArvanCloud request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := NewArvanCloudClient(server.Client())
	client.BaseURL = server.URL
	op := DNS01ChallengeOperation{
		ZoneName:   "Example.COM.",
		RecordName: "_ACME-Challenge.Example.COM.",
		TXTValue:   txtValue,
	}
	if err := client.Present(context.Background(), ArvanCloudCredentials{APIKey: apiKey}, op); err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("TXT record was not created")
	}
	if err := client.CleanUp(context.Background(), ArvanCloudCredentials{APIKey: apiKey}, op); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "delete-id" {
		t.Fatalf("deleted = %v", deleted)
	}
}

func TestArvanCloudChallengeErrorsAreSanitized(t *testing.T) {
	const (
		apiKey   = "Apikey ARVAN-KEY-CANARY"
		txtValue = "ARVAN-TXT-VALUE-CANARY"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(apiKey + " " + txtValue))
	}))
	defer server.Close()

	client := NewArvanCloudClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	err := client.Present(context.Background(), ArvanCloudCredentials{APIKey: apiKey}, DNS01ChallengeOperation{
		ZoneName:   "example.com",
		RecordName: "_acme-challenge.example.com",
		TXTValue:   txtValue,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoDNSCanaryLeak(t, err, apiKey, txtValue)
}

func TestArvanCloudTXTRecordsAcceptArrayValueShape(t *testing.T) {
	const apiKey = "Apikey ARVAN-KEY-CANARY"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != apiKey {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Method != http.MethodGet || r.URL.Path != "/domains/example.com/dns-records" {
			t.Fatalf("unexpected ArvanCloud request: %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
			"id":    "record-id",
			"type":  "txt",
			"name":  "_acme-challenge",
			"value": []map[string]string{{"text": "array-shaped-value"}},
		}}})
	}))
	defer server.Close()

	client := NewArvanCloudClient(server.Client())
	client.BaseURL = server.URL
	records, err := client.arvanCloudTXTRecords(context.Background(), ArvanCloudCredentials{APIKey: apiKey}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Text != "array-shaped-value" {
		t.Fatalf("records = %#v", records)
	}
}
