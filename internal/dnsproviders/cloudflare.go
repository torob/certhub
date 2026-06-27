package dnsproviders

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"certhub/internal/storage"
)

type CloudflareCredentials struct {
	APIToken string `json:"api_token"`
}

type CloudflareChallengeOperator interface {
	Present(context.Context, CloudflareCredentials, DNS01ChallengeOperation) error
	CleanUp(context.Context, CloudflareCredentials, DNS01ChallengeOperation) error
}

var (
	_ ChallengeOperator[CloudflareCredentials] = (*CloudflareClient)(nil)
	_ CloudflareChallengeOperator              = (*CloudflareClient)(nil)
)

type CloudflareClient struct {
	HTTPClient *http.Client
	BaseURL    string
}

func NewCloudflareClient(client *http.Client) *CloudflareClient {
	if client == nil {
		client = &http.Client{}
	}
	return &CloudflareClient{HTTPClient: client, BaseURL: "https://api.cloudflare.com/client/v4"}
}

func (c *CloudflareClient) ListZones(ctx context.Context, raw json.RawMessage) ([]string, error) {
	var creds CloudflareCredentials
	if err := json.Unmarshal(raw, &creds); err != nil || !validSecretString(creds.APIToken) {
		return nil, ErrZoneDiscoveryFailed
	}
	if c == nil || c.HTTPClient == nil {
		return nil, ErrZoneDiscoveryFailed
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/zones?per_page=50&page=1", nil)
	if err != nil {
		return nil, ErrZoneDiscoveryFailed
	}
	req.Header.Set("Authorization", "Bearer "+creds.APIToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, ErrZoneDiscoveryFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrZoneDiscoveryFailed
	}
	var body struct {
		Success bool `json:"success"`
		Result  []struct {
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil || !body.Success {
		return nil, ErrZoneDiscoveryFailed
	}
	out := make([]string, 0, len(body.Result))
	for _, zone := range body.Result {
		normalized, err := storage.NormalizeDNSName(zone.Name)
		if err != nil {
			return nil, ErrZoneDiscoveryFailed
		}
		out = append(out, normalized)
	}
	return uniqueSortedZones(out)
}

func (c *CloudflareClient) Present(ctx context.Context, creds CloudflareCredentials, op DNS01ChallengeOperation) error {
	normalized, err := normalizeDNS01ChallengeOperation(op)
	if err != nil || !validSecretString(creds.APIToken) {
		return ErrDNSChallengeOperation
	}
	if c == nil || c.HTTPClient == nil {
		return ErrDNSProviderUnavailable
	}
	zoneID, err := c.cloudflareZoneID(ctx, creds, normalized.ZoneName)
	if err != nil {
		return ErrDNSChallengeOperation
	}
	records, err := c.cloudflareTXTRecords(ctx, creds, zoneID, normalized.RecordName)
	if err != nil {
		return ErrDNSChallengeOperation
	}
	for _, record := range records {
		if record.Content == normalized.TXTValue {
			return nil
		}
	}
	body := map[string]any{
		"type":    "TXT",
		"name":    normalized.RecordName,
		"content": normalized.TXTValue,
		"ttl":     normalized.TTL,
	}
	if err := c.cloudflareRequest(ctx, creds, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, body); err != nil {
		return ErrDNSChallengeOperation
	}
	return nil
}

func (c *CloudflareClient) CleanUp(ctx context.Context, creds CloudflareCredentials, op DNS01ChallengeOperation) error {
	normalized, err := normalizeDNS01ChallengeOperation(op)
	if err != nil || !validSecretString(creds.APIToken) {
		return ErrDNSChallengeOperation
	}
	if c == nil || c.HTTPClient == nil {
		return ErrDNSProviderUnavailable
	}
	zoneID, err := c.cloudflareZoneID(ctx, creds, normalized.ZoneName)
	if err != nil {
		return ErrDNSChallengeOperation
	}
	records, err := c.cloudflareTXTRecords(ctx, creds, zoneID, normalized.RecordName)
	if err != nil {
		return ErrDNSChallengeOperation
	}
	for _, record := range records {
		if record.Content != normalized.TXTValue {
			continue
		}
		if err := c.cloudflareRequest(ctx, creds, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(record.ID), nil, nil); err != nil {
			return ErrDNSChallengeOperation
		}
	}
	return nil
}

type cloudflareDNSRecord struct {
	ID      string
	Type    string
	Name    string
	Content string
}

func (c *CloudflareClient) cloudflareZoneID(ctx context.Context, creds CloudflareCredentials, zoneName string) (string, error) {
	query := url.Values{}
	query.Set("name", zoneName)
	query.Set("per_page", "50")
	query.Set("page", "1")
	var body struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := c.cloudflareRequest(ctx, creds, http.MethodGet, "/zones", query, nil, &body); err != nil {
		return "", err
	}
	if !body.Success {
		return "", errors.New("cloudflare zone lookup failed")
	}
	for _, zone := range body.Result {
		normalized, err := storage.NormalizeDNSName(zone.Name)
		if err == nil && normalized == zoneName && zone.ID != "" {
			return zone.ID, nil
		}
	}
	return "", errors.New("cloudflare zone not found")
}

func (c *CloudflareClient) cloudflareTXTRecords(ctx context.Context, creds CloudflareCredentials, zoneID, recordName string) ([]cloudflareDNSRecord, error) {
	query := url.Values{}
	query.Set("type", "TXT")
	query.Set("name", recordName)
	query.Set("per_page", "100")
	var body struct {
		Success bool                  `json:"success"`
		Result  []cloudflareDNSRecord `json:"result"`
	}
	if err := c.cloudflareRequest(ctx, creds, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", query, nil, &body); err != nil {
		return nil, err
	}
	if !body.Success {
		return nil, errors.New("cloudflare record lookup failed")
	}
	return body.Result, nil
}

func (c *CloudflareClient) cloudflareRequest(ctx context.Context, creds CloudflareCredentials, method, path string, query url.Values, requestBody any, responseBody ...any) error {
	req, err := newJSONRequest(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, query, requestBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+creds.APIToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("cloudflare request failed")
	}
	if len(responseBody) == 0 || responseBody[0] == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDNSProviderResponseSize))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDNSProviderResponseSize)).Decode(responseBody[0]); err != nil {
		return err
	}
	return nil
}
