package dnsproviders

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/pkg/netretry"
)

type ArvanCloudCredentials struct {
	APIKey string `json:"api_key"`
}

type ArvanCloudChallengeOperator interface {
	Present(context.Context, ArvanCloudCredentials, DNS01ChallengeOperation) error
	CleanUp(context.Context, ArvanCloudCredentials, DNS01ChallengeOperation) error
}

var (
	_ ChallengeOperator[ArvanCloudCredentials] = (*ArvanCloudClient)(nil)
	_ ArvanCloudChallengeOperator              = (*ArvanCloudClient)(nil)
)

type ArvanCloudClient struct {
	HTTPClient *http.Client
	BaseURL    string
	Retry      netretry.Policy
	client     netretry.Doer
}

func NewArvanCloudClient(client *http.Client, policies ...netretry.Policy) *ArvanCloudClient {
	if client == nil {
		client = &http.Client{}
	}
	policy := netretry.DefaultPolicy()
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &ArvanCloudClient{HTTPClient: client, BaseURL: "https://napi.arvancloud.ir/cdn/4.0", Retry: policy, client: netretry.NewClient(client, policy)}
}

func (c *ArvanCloudClient) ListZones(ctx context.Context, raw json.RawMessage) ([]string, error) {
	var creds ArvanCloudCredentials
	if err := json.Unmarshal(raw, &creds); err != nil || !validSecretString(creds.APIKey) {
		return nil, ErrZoneDiscoveryFailed
	}
	if c == nil || c.HTTPClient == nil {
		return nil, ErrZoneDiscoveryFailed
	}
	zones, err := arvanCloudListAll[struct {
		Domain string `json:"domain"`
		Name   string `json:"name"`
	}](ctx, c, creds, "/domains")
	if err != nil {
		return nil, ErrZoneDiscoveryFailed
	}
	out := make([]string, 0, len(zones))
	for _, zone := range zones {
		name := zone.Domain
		if name == "" {
			name = zone.Name
		}
		normalized, err := storage.NormalizeDNSName(name)
		if err != nil {
			return nil, ErrZoneDiscoveryFailed
		}
		out = append(out, normalized)
	}
	return uniqueSortedZones(out)
}

func (c *ArvanCloudClient) Present(ctx context.Context, creds ArvanCloudCredentials, op DNS01ChallengeOperation) error {
	normalized, err := normalizeDNS01ChallengeOperation(op)
	if err != nil || !validSecretString(creds.APIKey) {
		return ErrDNSChallengeOperation
	}
	if c == nil || c.HTTPClient == nil {
		return ErrDNSProviderUnavailable
	}
	relativeName := relativeTXTRecordName(normalized.RecordName, normalized.ZoneName)
	body := map[string]any{
		"type": "txt",
		"name": relativeName,
		"value": map[string]string{
			"text": normalized.TXTValue,
		},
		"ttl": normalized.TTL,
	}
	err = netretry.DoWithRetryAfter(ctx, c.Retry, func() (bool, time.Duration, error) {
		records, err := c.arvanCloudTXTRecords(ctx, creds, normalized.ZoneName)
		if err != nil {
			return providerRetry(ctx, err)
		}
		for _, record := range records {
			if normalizeArvanRecordName(record.Name) == relativeName && record.Text == normalized.TXTValue {
				return false, 0, nil
			}
		}
		err = c.arvanCloudRequest(ctx, creds, http.MethodPost, "/domains/"+url.PathEscape(normalized.ZoneName)+"/dns-records", nil, body, nil)
		return providerRetry(ctx, err)
	})
	if err != nil {
		return ErrDNSChallengeOperation
	}
	return nil
}

func (c *ArvanCloudClient) CleanUp(ctx context.Context, creds ArvanCloudCredentials, op DNS01ChallengeOperation) error {
	normalized, err := normalizeDNS01ChallengeOperation(op)
	if err != nil || !validSecretString(creds.APIKey) {
		return ErrDNSChallengeOperation
	}
	if c == nil || c.HTTPClient == nil {
		return ErrDNSProviderUnavailable
	}
	relativeName := relativeTXTRecordName(normalized.RecordName, normalized.ZoneName)
	err = netretry.DoWithRetryAfter(ctx, c.Retry, func() (bool, time.Duration, error) {
		records, err := c.arvanCloudTXTRecords(ctx, creds, normalized.ZoneName)
		if err != nil {
			return providerRetry(ctx, err)
		}
		for _, record := range records {
			if normalizeArvanRecordName(record.Name) != relativeName || record.Text != normalized.TXTValue {
				continue
			}
			if err := c.arvanCloudRequest(ctx, creds, http.MethodDelete, "/domains/"+url.PathEscape(normalized.ZoneName)+"/dns-records/"+url.PathEscape(record.ID), nil, nil, nil); err != nil {
				return providerRetry(ctx, err)
			}
		}
		return false, 0, nil
	})
	if err != nil {
		return ErrDNSChallengeOperation
	}
	return nil
}

type arvanCloudDNSRecord struct {
	ID   string
	Type string
	Name string
	Text string
}

func (c *ArvanCloudClient) arvanCloudTXTRecords(ctx context.Context, creds ArvanCloudCredentials, zoneName string) ([]arvanCloudDNSRecord, error) {
	records, err := arvanCloudListAll[struct {
		ID     string          `json:"id"`
		Type   string          `json:"type"`
		Name   string          `json:"name"`
		Value  json.RawMessage `json:"value"`
		Values []struct {
			Text string `json:"text"`
		} `json:"values"`
	}](ctx, c, creds, "/domains/"+url.PathEscape(zoneName)+"/dns-records")
	if err != nil {
		return nil, err
	}
	out := make([]arvanCloudDNSRecord, 0, len(records))
	for _, record := range records {
		if !strings.EqualFold(record.Type, "txt") {
			continue
		}
		text := arvanCloudTXTText(record.Value)
		if text == "" && len(record.Values) > 0 {
			text = record.Values[0].Text
		}
		out = append(out, arvanCloudDNSRecord{ID: record.ID, Type: record.Type, Name: record.Name, Text: text})
	}
	return out, nil
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

func normalizeArvanRecordName(name string) string {
	name = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(name, ".")))
	if name == "" {
		return "@"
	}
	return name
}

// arvanCloudListAll reads every page of an ArvanCloud CDN v4 list endpoint.
// It uses the Laravel-style meta.current_page and meta.last_page fields. A
// response without meta is one page. Any failed page fails the whole call, so
// callers never get a partial list.
func arvanCloudListAll[T any](ctx context.Context, c *ArvanCloudClient, creds ArvanCloudCredentials, path string) ([]T, error) {
	var out []T
	for page := 1; page <= maxProviderListPages; page++ {
		query := url.Values{}
		query.Set("page", strconv.Itoa(page))
		var body struct {
			Data []T `json:"data"`
			Meta *struct {
				CurrentPage int `json:"current_page"`
				LastPage    int `json:"last_page"`
			} `json:"meta"`
		}
		if err := c.arvanCloudRequest(ctx, creds, http.MethodGet, path, query, nil, &body); err != nil {
			return nil, err
		}
		out = append(out, body.Data...)
		meta := body.Meta
		if meta == nil || meta.LastPage <= page {
			return out, nil
		}
		if meta.CurrentPage != page {
			return nil, errProviderListPageOrder
		}
		if meta.LastPage > maxProviderListPages {
			return nil, errProviderListPageLimit
		}
	}
	return nil, errProviderListPageLimit
}

func (c *ArvanCloudClient) arvanCloudRequest(ctx context.Context, creds ArvanCloudCredentials, method, path string, query url.Values, requestBody any, responseBody any) error {
	req, err := newJSONRequest(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, query, requestBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", creds.APIKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return providerRequestError{status: resp.StatusCode, retryAfter: netretry.ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now().UTC())}
	}
	if responseBody == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDNSProviderResponseSize))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDNSProviderResponseSize)).Decode(responseBody); err != nil {
		return err
	}
	return nil
}
