package dnsproviders

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
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

func arvanCloudPage(page, lastPage int, data any) map[string]any {
	return map[string]any{
		"data": data,
		"meta": map[string]int{"current_page": page, "last_page": lastPage, "per_page": 1, "total": lastPage},
	}
}

func TestArvanCloudListZonesReadsAllPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/domains" {
			t.Fatalf("unexpected ArvanCloud request: %s %s", r.Method, r.URL.String())
		}
		switch page := r.URL.Query().Get("page"); page {
		case "", "1":
			_ = json.NewEncoder(w).Encode(arvanCloudPage(1, 2, []map[string]string{{"domain": "example.com"}}))
		case "2":
			_ = json.NewEncoder(w).Encode(arvanCloudPage(2, 2, []map[string]string{{"domain": "last-page.example.org"}}))
		default:
			t.Fatalf("unexpected page %q", page)
		}
	}))
	defer server.Close()

	client := NewArvanCloudClient(server.Client())
	client.BaseURL = server.URL
	zones, err := client.ListZones(context.Background(), json.RawMessage(`{"api_key":"Apikey token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(zones, []string{"example.com", "last-page.example.org"}) {
		t.Fatalf("zones = %v; want both pages", zones)
	}
}

func TestArvanCloudListZonesFailsWhenAnyPageFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if page := r.URL.Query().Get("page"); page == "" || page == "1" {
			_ = json.NewEncoder(w).Encode(arvanCloudPage(1, 2, []map[string]string{{"domain": "example.com"}}))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewArvanCloudClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	zones, err := client.ListZones(context.Background(), json.RawMessage(`{"api_key":"Apikey token"}`))
	if !errors.Is(err, ErrZoneDiscoveryFailed) {
		t.Fatalf("ListZones() = %v, %v; want ErrZoneDiscoveryFailed and no partial list", zones, err)
	}
}

func TestArvanCloudPresentAndCleanUpFindTXTRecordOnLaterPage(t *testing.T) {
	var posts int
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/domains/example.com/dns-records":
			switch page := r.URL.Query().Get("page"); page {
			case "", "1":
				_ = json.NewEncoder(w).Encode(arvanCloudPage(1, 2, []map[string]any{{"id": "a-record", "type": "a", "name": "www", "value": []map[string]string{{"ip": "192.0.2.1"}}}}))
			case "2":
				_ = json.NewEncoder(w).Encode(arvanCloudPage(2, 2, []map[string]any{{"id": "txt-record", "type": "txt", "name": "_acme-challenge", "value": map[string]string{"text": "value"}}}))
			default:
				t.Fatalf("unexpected page %q", page)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/domains/example.com/dns-records":
			posts++
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": "duplicate"}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/domains/example.com/dns-records/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/domains/example.com/dns-records/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected ArvanCloud request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := NewArvanCloudClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	op := DNS01ChallengeOperation{ZoneName: "example.com", RecordName: "_acme-challenge.example.com", TXTValue: "value"}
	if err := client.Present(context.Background(), ArvanCloudCredentials{APIKey: "Apikey token"}, op); err != nil {
		t.Fatal(err)
	}
	if posts != 0 {
		t.Fatalf("create requests = %d; want 0 because the record exists on page 2", posts)
	}
	if err := client.CleanUp(context.Background(), ArvanCloudCredentials{APIKey: "Apikey token"}, op); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "txt-record" {
		t.Fatalf("deleted = %v; want [txt-record]", deleted)
	}
}
