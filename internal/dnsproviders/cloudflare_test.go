package dnsproviders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
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

func cloudflareZonePage(page, totalPages int, names ...string) map[string]any {
	result := make([]map[string]string, 0, len(names))
	for _, name := range names {
		result = append(result, map[string]string{"id": name + "-id", "name": name})
	}
	return map[string]any{
		"success":     true,
		"result":      result,
		"result_info": map[string]int{"page": page, "per_page": 50, "count": len(names), "total_pages": totalPages},
	}
}

func TestCloudflareListZonesReadsAllPages(t *testing.T) {
	firstPage := make([]string, 0, 50)
	for i := range 50 {
		firstPage = append(firstPage, fmt.Sprintf("zone%02d.example.com", i))
	}
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/zones" {
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.String())
		}
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		switch page {
		case "1":
			_ = json.NewEncoder(w).Encode(cloudflareZonePage(1, 2, firstPage...))
		case "2":
			_ = json.NewEncoder(w).Encode(cloudflareZonePage(2, 2, "last-page.example.org"))
		default:
			t.Fatalf("unexpected page %q", page)
		}
	}))
	defer server.Close()

	client := NewCloudflareClient(server.Client())
	client.BaseURL = server.URL
	zones, err := client.ListZones(context.Background(), json.RawMessage(`{"api_token":"token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 51 || !slices.Contains(zones, "last-page.example.org") {
		t.Fatalf("zones = %d %v; want 51 including last-page.example.org (pages requested %v)", len(zones), zones, pages)
	}
}

func TestCloudflareListZonesFailsWhenAnyPageFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			_ = json.NewEncoder(w).Encode(cloudflareZonePage(1, 2, "example.com"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewCloudflareClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	zones, err := client.ListZones(context.Background(), json.RawMessage(`{"api_token":"token"}`))
	if !errors.Is(err, ErrZoneDiscoveryFailed) {
		t.Fatalf("ListZones() = %v, %v; want ErrZoneDiscoveryFailed and no partial list", zones, err)
	}
}

func TestCloudflareListZonesFailsWhenPageCapExceeded(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		_ = json.NewEncoder(w).Encode(cloudflareZonePage(page, maxProviderListPages+1, fmt.Sprintf("zone%d.example.com", page)))
	}))
	defer server.Close()

	client := NewCloudflareClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	zones, err := client.ListZones(context.Background(), json.RawMessage(`{"api_token":"token"}`))
	if !errors.Is(err, ErrZoneDiscoveryFailed) {
		t.Fatalf("ListZones() = %d zones, %v; want ErrZoneDiscoveryFailed", len(zones), err)
	}
	if requests > maxProviderListPages {
		t.Fatalf("requests = %d; want at most %d", requests, maxProviderListPages)
	}
}

func TestCloudflareCleanUpFindsTXTRecordOnLaterPage(t *testing.T) {
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone-id", "name": "example.com"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			page := r.URL.Query().Get("page")
			if page == "" {
				page = "1"
			}
			content := "other-value"
			if page == "2" {
				content = "value"
			} else if page != "1" {
				t.Fatalf("unexpected page %q", page)
			}
			pageNumber, _ := strconv.Atoi(page)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":     true,
				"result":      []map[string]string{{"id": "record-" + page, "type": "TXT", "name": "_acme-challenge.example.com", "content": content}},
				"result_info": map[string]int{"page": pageNumber, "per_page": 1, "count": 1, "total_pages": 2},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone-id/dns_records/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/zones/zone-id/dns_records/"))
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := NewCloudflareClient(server.Client(), netretry.Policy{})
	client.BaseURL = server.URL
	err := client.CleanUp(context.Background(), CloudflareCredentials{APIToken: "token"}, DNS01ChallengeOperation{ZoneName: "example.com", RecordName: "_acme-challenge.example.com", TXTValue: "value"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "record-2" {
		t.Fatalf("deleted = %v; want [record-2]", deleted)
	}
}
