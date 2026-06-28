package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	dnsproviders "github.com/torob/certhub/internal/dnsproviders"
)

func TestExternalDNSProviderChallengeLifecycle(t *testing.T) {
	if os.Getenv("CERTHUB_EXTERNAL_DNS") != "1" {
		t.Skip("set CERTHUB_EXTERNAL_DNS=1 to run real DNS provider validation")
	}
	creds, err := loadExternalDNSCredentials()
	if err != nil {
		t.Fatal(err)
	}
	selected := selectedExternalDNSProviders()
	if len(selected) == 0 {
		t.Fatal("no external DNS providers selected")
	}
	ran := false
	for _, provider := range selected {
		switch provider {
		case "cloudflare":
			if creds.CloudflareAPIToken == "" {
				t.Fatalf("cloudflare selected but no credential was found")
			}
			ran = true
			t.Run("cloudflare", func(t *testing.T) {
				zone := requiredExternalEnv(t, "CERTHUB_EXTERNAL_DNS_CLOUDFLARE_ZONE")
				raw := json.RawMessage(fmt.Sprintf(`{"api_token":%q}`, creds.CloudflareAPIToken))
				client := dnsproviders.NewCloudflareClient(httpClient())
				assertZoneListed(t, client, raw, zone)
				runCloudflareTXTCRUD(t, client, dnsproviders.CloudflareCredentials{APIToken: creds.CloudflareAPIToken}, zone)
			})
		case "arvancloud":
			if creds.ArvanCloudAPIKey == "" {
				t.Fatalf("arvancloud selected but no credential was found")
			}
			ran = true
			t.Run("arvancloud", func(t *testing.T) {
				zone := requiredExternalEnv(t, "CERTHUB_EXTERNAL_DNS_ARVANCLOUD_ZONE")
				raw := json.RawMessage(fmt.Sprintf(`{"api_key":%q}`, creds.ArvanCloudAPIKey))
				client := dnsproviders.NewArvanCloudClient(httpClient())
				assertZoneListed(t, client, raw, zone)
				runArvanCloudTXTCRUD(t, client, dnsproviders.ArvanCloudCredentials{APIKey: creds.ArvanCloudAPIKey}, zone)
			})
		default:
			t.Fatalf("unsupported external DNS provider %q", provider)
		}
	}
	if !ran {
		t.Fatal("no external DNS provider checks ran")
	}
}

type externalDNSCredentials struct {
	CloudflareAPIToken string
	ArvanCloudAPIKey   string
}

func loadExternalDNSCredentials() (externalDNSCredentials, error) {
	creds := externalDNSCredentials{
		CloudflareAPIToken: strings.TrimSpace(os.Getenv("CERTHUB_EXTERNAL_DNS_CLOUDFLARE_API_TOKEN")),
		ArvanCloudAPIKey:   strings.TrimSpace(os.Getenv("CERTHUB_EXTERNAL_DNS_ARVANCLOUD_API_KEY")),
	}
	path := strings.TrimSpace(os.Getenv("CERTHUB_EXTERNAL_DNS_CREDENTIALS_FILE"))
	if path == "" {
		if creds.CloudflareAPIToken != "" || creds.ArvanCloudAPIKey != "" {
			return creds, nil
		}
		return externalDNSCredentials{}, errors.New("external DNS credentials require CERTHUB_EXTERNAL_DNS_CLOUDFLARE_API_TOKEN, CERTHUB_EXTERNAL_DNS_ARVANCLOUD_API_KEY, or CERTHUB_EXTERNAL_DNS_CREDENTIALS_FILE")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if creds.CloudflareAPIToken != "" || creds.ArvanCloudAPIKey != "" {
			return creds, nil
		}
		return externalDNSCredentials{}, fmt.Errorf("read external DNS credentials file: %w", err)
	}
	fromFile := parseExternalDNSCredentialBytes(data)
	if creds.CloudflareAPIToken == "" {
		creds.CloudflareAPIToken = fromFile.CloudflareAPIToken
	}
	if creds.ArvanCloudAPIKey == "" {
		creds.ArvanCloudAPIKey = fromFile.ArvanCloudAPIKey
	}
	if creds.CloudflareAPIToken == "" && creds.ArvanCloudAPIKey == "" {
		return externalDNSCredentials{}, errors.New("external DNS credentials file did not contain supported Cloudflare or ArvanCloud credentials")
	}
	return creds, nil
}

func parseExternalDNSCredentialBytes(data []byte) externalDNSCredentials {
	var creds externalDNSCredentials
	var obj any
	if json.Unmarshal(data, &obj) == nil {
		for key, value := range flattenJSONStrings("", obj) {
			assignExternalDNSCredential(&creds, key, value)
		}
	}
	var currentProvider string
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		text := strings.TrimSpace(string(line))
		key, value, ok := splitCredentialLine(string(line))
		if ok {
			if assignExternalDNSCredential(&creds, key, value) {
				if provider := providerFromCredentialLabel(key); provider != "" {
					currentProvider = provider
				}
				continue
			}
			if provider := providerFromCredentialLabel(key); provider != "" {
				currentProvider = provider
			}
			if currentProvider != "" && keyLooksCredential(key) {
				assignExternalDNSCredentialByProvider(&creds, currentProvider, value)
			}
			continue
		}
		if currentProvider != "" {
			if value, ok := extractPotentialSecretValueForProvider(currentProvider, text); ok {
				assignExternalDNSCredentialByProvider(&creds, currentProvider, value)
				continue
			}
		}
		if provider := providerFromCredentialLabel(text); provider != "" && !looksLikeSecretValue(text) {
			currentProvider = provider
			continue
		}
	}
	return creds
}

func TestExternalDNSCredentialParserSupportsCommonFormats(t *testing.T) {
	parsed := parseExternalDNSCredentialBytes([]byte(`
CLOUDFLARE_API_TOKEN=cf-token-value-with-enough-length
ARVANCLOUD_API_KEY: Apikey arvan-key-value-with-enough-length
`))
	if parsed.CloudflareAPIToken == "" {
		t.Fatal("cloudflare key/value credential was not parsed")
	}
	if parsed.ArvanCloudAPIKey == "" {
		t.Fatal("arvancloud key/value credential was not parsed")
	}

	parsed = parseExternalDNSCredentialBytes([]byte(`
ArvanCloud
Apikey arvan-section-token-with-enough-length

Cloudflare
zone_id: ignored-zone-identifier-value
api_token: cf-section-token-with-enough-length
`))
	if parsed.CloudflareAPIToken == "" {
		t.Fatal("cloudflare section credential was not parsed")
	}
	if parsed.ArvanCloudAPIKey == "" {
		t.Fatal("arvancloud section credential was not parsed")
	}
	if parsed.ArvanCloudAPIKey != "Apikey arvan-section-token-with-enough-length" {
		t.Fatalf("arvancloud section credential = %q", parsed.ArvanCloudAPIKey)
	}
	if parsed.CloudflareAPIToken == "ignored-zone-identifier-value" {
		t.Fatal("cloudflare parser selected non-credential zone id")
	}
}

func flattenJSONStrings(prefix string, value any) map[string]string {
	out := map[string]string{}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			next := key
			if prefix != "" {
				next = prefix + "." + key
			}
			for childKey, childValue := range flattenJSONStrings(next, child) {
				out[childKey] = childValue
			}
		}
	case string:
		out[prefix] = typed
	}
	return out
}

func splitCredentialLine(line string) (string, string, bool) {
	for _, sep := range []string{"=", ":"} {
		left, right, ok := strings.Cut(line, sep)
		if !ok {
			continue
		}
		key := strings.TrimSpace(left)
		value := strings.Trim(strings.TrimSpace(right), `"'`)
		if key == "" || value == "" {
			return "", "", false
		}
		return key, value, true
	}
	return "", "", false
}

var nonAlphaNum = regexp.MustCompile(`[^a-z0-9]+`)

func assignExternalDNSCredential(creds *externalDNSCredentials, key, value string) bool {
	normalized := nonAlphaNum.ReplaceAllString(strings.ToLower(key), "")
	switch {
	case creds.CloudflareAPIToken == "" && strings.Contains(normalized, "cloudflare") && strings.Contains(normalized, "token"):
		creds.CloudflareAPIToken = strings.TrimSpace(value)
		return true
	case creds.CloudflareAPIToken == "" && strings.HasPrefix(normalized, "cf") && strings.Contains(normalized, "token"):
		creds.CloudflareAPIToken = strings.TrimSpace(value)
		return true
	case creds.ArvanCloudAPIKey == "" && strings.Contains(normalized, "arvan") && (strings.Contains(normalized, "key") || strings.Contains(normalized, "token")):
		creds.ArvanCloudAPIKey = strings.TrimSpace(value)
		return true
	}
	return false
}

func providerFromCredentialLabel(label string) string {
	normalized := nonAlphaNum.ReplaceAllString(strings.ToLower(label), "")
	switch {
	case strings.Contains(normalized, "cloudflare"):
		return "cloudflare"
	case strings.Contains(normalized, "arvan"):
		return "arvancloud"
	default:
		return ""
	}
}

func keyLooksCredential(key string) bool {
	normalized := nonAlphaNum.ReplaceAllString(strings.ToLower(key), "")
	return strings.Contains(normalized, "token") || strings.Contains(normalized, "apikey") || normalized == "key"
}

func looksLikeSecretValue(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 20 {
		return false
	}
	return !strings.ContainsAny(value, " \t")
}

func extractPotentialSecretValue(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if looksLikeSecretValue(line) {
		return line, true
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	candidate := fields[len(fields)-1]
	if looksLikeSecretValue(candidate) {
		return candidate, true
	}
	return "", false
}

func extractPotentialSecretValueForProvider(provider, line string) (string, bool) {
	line = strings.TrimSpace(line)
	if provider == "arvancloud" && strings.HasPrefix(strings.ToLower(line), "apikey ") && len(line) > len("Apikey ") {
		return line, true
	}
	return extractPotentialSecretValue(line)
}

func assignExternalDNSCredentialByProvider(creds *externalDNSCredentials, provider, value string) {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" {
		return
	}
	switch provider {
	case "cloudflare":
		if creds.CloudflareAPIToken == "" {
			creds.CloudflareAPIToken = value
		}
	case "arvancloud":
		if creds.ArvanCloudAPIKey == "" {
			creds.ArvanCloudAPIKey = value
		}
	}
}

func selectedExternalDNSProviders() []string {
	raw := strings.TrimSpace(os.Getenv("CERTHUB_EXTERNAL_DNS_PROVIDERS"))
	if raw == "" {
		return []string{"cloudflare", "arvancloud"}
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func assertZoneListed(t *testing.T, lister dnsproviders.ZoneLister, raw json.RawMessage, zone string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	zones, err := lister.ListZones(ctx, raw)
	if err != nil {
		t.Fatalf("zone discovery failed for %s", zone)
	}
	for _, candidate := range zones {
		if candidate == zone {
			return
		}
	}
	t.Fatalf("expected zone %s was not listed by provider", zone)
}

func runCloudflareTXTCRUD(t *testing.T, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zone string) {
	t.Helper()
	recordName, initialValue, updatedValue := externalDNSRecordAndValues(t, zone)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	zoneID := cloudflareZoneID(t, ctx, client, creds, zone)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if err := cloudflareDeleteTXTByValues(cleanupCtx, client, creds, zoneID, recordName, initialValue, updatedValue); err != nil {
			t.Errorf("cloudflare cleanup failed for %s", recordName)
		}
	}()
	recordID := cloudflareCreateTXT(t, ctx, client, creds, zoneID, recordName, initialValue)
	if !cloudflareTXTRecordVisible(t, ctx, client, creds, zoneID, recordName, initialValue) {
		t.Fatalf("cloudflare TXT record %s was not visible through provider readback after create", recordName)
	}
	cloudflareUpdateTXT(t, ctx, client, creds, zoneID, recordID, recordName, updatedValue)
	if cloudflareTXTRecordVisible(t, ctx, client, creds, zoneID, recordName, initialValue) {
		t.Fatalf("cloudflare TXT record %s still exposed initial value after update", recordName)
	}
	if !cloudflareTXTRecordVisible(t, ctx, client, creds, zoneID, recordName, updatedValue) {
		t.Fatalf("cloudflare TXT record %s was not visible through provider readback after update", recordName)
	}
	if err := cloudflareDeleteTXTByID(ctx, client, creds, zoneID, recordID); err != nil {
		t.Fatalf("cloudflare cleanup failed for %s", recordName)
	}
	if cloudflareTXTRecordVisible(t, ctx, client, creds, zoneID, recordName, updatedValue) {
		t.Fatalf("cloudflare TXT record %s remained visible after cleanup", recordName)
	}
}

func runArvanCloudTXTCRUD(t *testing.T, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone string) {
	t.Helper()
	recordName, initialValue, updatedValue := externalDNSRecordAndValues(t, zone)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var recordID string
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if recordID != "" {
			if err := arvanCloudDeleteTXTByID(cleanupCtx, client, creds, zone, recordID); err == nil {
				return
			}
		}
		if err := arvanCloudDeleteTXTByValues(cleanupCtx, client, creds, zone, recordName, initialValue, updatedValue); err != nil {
			t.Errorf("arvancloud cleanup failed for %s", recordName)
		}
	}()
	recordID = arvanCloudCreateTXT(t, ctx, client, creds, zone, recordName, initialValue)
	if !arvanCloudTXTRecordVisible(t, ctx, client, creds, zone, recordName, initialValue) {
		t.Fatalf("arvancloud TXT record %s was not visible through provider readback after create", recordName)
	}
	arvanCloudUpdateTXT(t, ctx, client, creds, zone, recordID, recordName, updatedValue)
	if arvanCloudTXTRecordVisible(t, ctx, client, creds, zone, recordName, initialValue) {
		t.Fatalf("arvancloud TXT record %s still exposed initial value after update", recordName)
	}
	if !arvanCloudTXTRecordVisible(t, ctx, client, creds, zone, recordName, updatedValue) {
		t.Fatalf("arvancloud TXT record %s was not visible through provider readback after update", recordName)
	}
	if err := arvanCloudDeleteTXTByID(ctx, client, creds, zone, recordID); err != nil {
		t.Fatalf("arvancloud cleanup failed for %s", recordName)
	}
	if arvanCloudTXTRecordVisible(t, ctx, client, creds, zone, recordName, updatedValue) {
		t.Fatalf("arvancloud TXT record %s remained visible after cleanup", recordName)
	}
}

func externalDNSRecordAndValues(t *testing.T, zone string) (string, string, string) {
	t.Helper()
	suffix := randomHex(t, 8)
	recordName := "_certhub-test-" + time.Now().UTC().Format("20060102") + "-" + suffix + "." + zone
	return recordName, "certhub-external-dns-create-" + suffix, "certhub-external-dns-update-" + suffix
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func cloudflareCreateTXT(t *testing.T, ctx context.Context, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zoneID, recordName, txtValue string) string {
	t.Helper()
	body := map[string]any{"type": "TXT", "name": recordName, "content": txtValue, "ttl": 120}
	var response struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodPost, strings.TrimRight(client.BaseURL, "/")+"/zones/"+url.PathEscape(zoneID)+"/dns_records", "Bearer "+creds.APIToken, body, &response); err != nil {
		t.Fatalf("cloudflare TXT create failed for %s: %v", recordName, err)
	}
	if !response.Success || response.Result.ID == "" {
		t.Fatalf("cloudflare TXT create returned no record id for %s", recordName)
	}
	return response.Result.ID
}

func cloudflareUpdateTXT(t *testing.T, ctx context.Context, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zoneID, recordID, recordName, txtValue string) {
	t.Helper()
	body := map[string]any{"type": "TXT", "name": recordName, "content": txtValue, "ttl": 120}
	var response struct {
		Success bool `json:"success"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodPatch, strings.TrimRight(client.BaseURL, "/")+"/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), "Bearer "+creds.APIToken, body, &response); err != nil {
		t.Fatalf("cloudflare TXT update failed for %s: %v", recordName, err)
	}
	if !response.Success {
		t.Fatalf("cloudflare TXT update returned unsuccessful response for %s", recordName)
	}
}

func cloudflareTXTRecordVisible(t *testing.T, ctx context.Context, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zoneID, recordName, txtValue string) bool {
	t.Helper()
	query := url.Values{}
	query.Set("type", "TXT")
	query.Set("name", recordName)
	query.Set("per_page", "100")
	var body struct {
		Success bool `json:"success"`
		Result  []struct {
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodGet, strings.TrimRight(client.BaseURL, "/")+"/zones/"+url.PathEscape(zoneID)+"/dns_records?"+query.Encode(), "Bearer "+creds.APIToken, nil, &body); err != nil {
		t.Fatalf("cloudflare TXT readback failed for %s", recordName)
	}
	if !body.Success {
		t.Fatalf("cloudflare TXT readback returned unsuccessful response for %s", recordName)
	}
	for _, record := range body.Result {
		if record.Content == txtValue {
			return true
		}
	}
	return false
}

func cloudflareDeleteTXTByID(ctx context.Context, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zoneID, recordID string) error {
	return providerJSONRequest(ctx, client.HTTPClient, http.MethodDelete, strings.TrimRight(client.BaseURL, "/")+"/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), "Bearer "+creds.APIToken, nil, nil)
}

func cloudflareDeleteTXTByValues(ctx context.Context, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zoneID, recordName string, values ...string) error {
	query := url.Values{}
	query.Set("type", "TXT")
	query.Set("name", recordName)
	query.Set("per_page", "100")
	var body struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodGet, strings.TrimRight(client.BaseURL, "/")+"/zones/"+url.PathEscape(zoneID)+"/dns_records?"+query.Encode(), "Bearer "+creds.APIToken, nil, &body); err != nil {
		return err
	}
	if !body.Success {
		return errors.New("cloudflare cleanup lookup returned unsuccessful response")
	}
	wanted := stringSet(values...)
	for _, record := range body.Result {
		if record.ID == "" || !wanted[record.Content] {
			continue
		}
		if err := cloudflareDeleteTXTByID(ctx, client, creds, zoneID, record.ID); err != nil {
			return err
		}
	}
	return nil
}

func cloudflareZoneID(t *testing.T, ctx context.Context, client *dnsproviders.CloudflareClient, creds dnsproviders.CloudflareCredentials, zone string) string {
	t.Helper()
	query := url.Values{}
	query.Set("name", zone)
	query.Set("per_page", "50")
	query.Set("page", "1")
	var body struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodGet, strings.TrimRight(client.BaseURL, "/")+"/zones?"+query.Encode(), "Bearer "+creds.APIToken, nil, &body); err != nil {
		t.Fatalf("cloudflare zone lookup failed for %s", zone)
	}
	if !body.Success {
		t.Fatalf("cloudflare zone lookup returned unsuccessful response for %s", zone)
	}
	for _, candidate := range body.Result {
		if strings.EqualFold(strings.TrimSuffix(candidate.Name, "."), zone) && candidate.ID != "" {
			return candidate.ID
		}
	}
	t.Fatalf("cloudflare zone %s was not found", zone)
	return ""
}

func arvanCloudCreateTXT(t *testing.T, ctx context.Context, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone, recordName, txtValue string) string {
	t.Helper()
	body := arvanCloudTXTBody(recordName, zone, txtValue)
	var response struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodPost, strings.TrimRight(client.BaseURL, "/")+"/domains/"+url.PathEscape(zone)+"/dns-records", creds.APIKey, body, &response); err != nil {
		t.Fatalf("arvancloud TXT create failed for %s: %v", recordName, err)
	}
	if response.Data.ID != "" {
		return response.Data.ID
	}
	records := arvanCloudTXTRecords(t, ctx, client, creds, zone, recordName)
	for _, record := range records {
		if record.Text == txtValue && record.ID != "" {
			return record.ID
		}
	}
	t.Fatalf("arvancloud TXT create returned no record id for %s", recordName)
	return ""
}

func arvanCloudUpdateTXT(t *testing.T, ctx context.Context, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone, recordID, recordName, txtValue string) {
	t.Helper()
	body := arvanCloudTXTBody(recordName, zone, txtValue)
	path := strings.TrimRight(client.BaseURL, "/") + "/domains/" + url.PathEscape(zone) + "/dns-records/" + url.PathEscape(recordID)
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodPatch, path, creds.APIKey, body, nil); err == nil {
		return
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodPut, path, creds.APIKey, body, nil); err != nil {
		t.Fatalf("arvancloud TXT update failed for %s: %v", recordName, err)
	}
}

func arvanCloudTXTBody(recordName, zone, txtValue string) map[string]any {
	return map[string]any{
		"type": "txt",
		"name": relativeExternalDNSRecordName(recordName, zone),
		"value": map[string]string{
			"text": txtValue,
		},
		"ttl": 120,
	}
}

type externalTXTRecord struct {
	ID   string
	Text string
}

func arvanCloudTXTRecordVisible(t *testing.T, ctx context.Context, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone, recordName, txtValue string) bool {
	t.Helper()
	for _, record := range arvanCloudTXTRecords(t, ctx, client, creds, zone, recordName) {
		if record.Text == txtValue {
			return true
		}
	}
	return false
}

func arvanCloudTXTRecords(t *testing.T, ctx context.Context, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone, recordName string) []externalTXTRecord {
	t.Helper()
	var body struct {
		Data []struct {
			ID     string          `json:"id"`
			Type   string          `json:"type"`
			Name   string          `json:"name"`
			Value  json.RawMessage `json:"value"`
			Values []struct {
				Text string `json:"text"`
			} `json:"values"`
		} `json:"data"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodGet, strings.TrimRight(client.BaseURL, "/")+"/domains/"+url.PathEscape(zone)+"/dns-records", creds.APIKey, nil, &body); err != nil {
		t.Fatalf("arvancloud TXT readback failed for %s: %v", recordName, err)
	}
	relative := relativeExternalDNSRecordName(recordName, zone)
	var out []externalTXTRecord
	for _, record := range body.Data {
		if !strings.EqualFold(record.Type, "txt") {
			continue
		}
		text := arvanCloudTXTText(record.Value)
		if text == "" && len(record.Values) > 0 {
			text = record.Values[0].Text
		}
		if normalizeExternalArvanName(record.Name) == relative {
			out = append(out, externalTXTRecord{ID: record.ID, Text: text})
		}
	}
	return out
}

func arvanCloudDeleteTXTByID(ctx context.Context, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone, recordID string) error {
	return providerJSONRequest(ctx, client.HTTPClient, http.MethodDelete, strings.TrimRight(client.BaseURL, "/")+"/domains/"+url.PathEscape(zone)+"/dns-records/"+url.PathEscape(recordID), creds.APIKey, nil, nil)
}

func arvanCloudDeleteTXTByValues(ctx context.Context, client *dnsproviders.ArvanCloudClient, creds dnsproviders.ArvanCloudCredentials, zone, recordName string, values ...string) error {
	var body struct {
		Data []struct {
			ID     string          `json:"id"`
			Type   string          `json:"type"`
			Name   string          `json:"name"`
			Value  json.RawMessage `json:"value"`
			Values []struct {
				Text string `json:"text"`
			} `json:"values"`
		} `json:"data"`
	}
	if err := providerJSONRequest(ctx, client.HTTPClient, http.MethodGet, strings.TrimRight(client.BaseURL, "/")+"/domains/"+url.PathEscape(zone)+"/dns-records", creds.APIKey, nil, &body); err != nil {
		return err
	}
	relative := relativeExternalDNSRecordName(recordName, zone)
	wanted := stringSet(values...)
	for _, record := range body.Data {
		text := arvanCloudTXTText(record.Value)
		if text == "" && len(record.Values) > 0 {
			text = record.Values[0].Text
		}
		if record.ID == "" || !strings.EqualFold(record.Type, "txt") || normalizeExternalArvanName(record.Name) != relative || !wanted[text] {
			continue
		}
		if err := arvanCloudDeleteTXTByID(ctx, client, creds, zone, record.ID); err != nil {
			return err
		}
	}
	return nil
}

func arvanCloudTXTText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var object struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &object) == nil && object.Text != "" {
		return object.Text
	}
	var array []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &array) == nil {
		for _, item := range array {
			if item.Text != "" {
				return item.Text
			}
		}
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return ""
}

func providerJSONRequest(ctx context.Context, client *http.Client, method, rawURL, authorization string, requestBody any, responseBody any) error {
	var reader io.Reader
	if requestBody != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(requestBody); err != nil {
			return err
		}
		reader = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("provider request failed with status %d", resp.StatusCode)
	}
	if responseBody == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(responseBody)
}

func relativeExternalDNSRecordName(recordName, zone string) string {
	return strings.TrimSuffix(strings.TrimSuffix(recordName, "."), "."+strings.TrimSuffix(zone, "."))
}

func normalizeExternalArvanName(name string) string {
	name = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(name, ".")))
	if name == "" {
		return "@"
	}
	return name
}

func stringSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func requiredExternalEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required for this external integration test", name)
	}
	return value
}
