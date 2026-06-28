package dnsproviders

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/torob/certhub/internal/storage"
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
}

func NewArvanCloudClient(client *http.Client) *ArvanCloudClient {
	if client == nil {
		client = &http.Client{}
	}
	return &ArvanCloudClient{HTTPClient: client, BaseURL: "https://napi.arvancloud.ir/cdn/4.0"}
}

func (c *ArvanCloudClient) ListZones(ctx context.Context, raw json.RawMessage) ([]string, error) {
	var creds ArvanCloudCredentials
	if err := json.Unmarshal(raw, &creds); err != nil || !validSecretString(creds.APIKey) {
		return nil, ErrZoneDiscoveryFailed
	}
	if c == nil || c.HTTPClient == nil {
		return nil, ErrZoneDiscoveryFailed
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/domains", nil)
	if err != nil {
		return nil, ErrZoneDiscoveryFailed
	}
	req.Header.Set("Authorization", creds.APIKey)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, ErrZoneDiscoveryFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrZoneDiscoveryFailed
	}
	var body struct {
		Data []struct {
			Domain string `json:"domain"`
			Name   string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, ErrZoneDiscoveryFailed
	}
	out := make([]string, 0, len(body.Data))
	for _, zone := range body.Data {
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
	records, err := c.arvanCloudTXTRecords(ctx, creds, normalized.ZoneName)
	if err != nil {
		return ErrDNSChallengeOperation
	}
	relativeName := relativeTXTRecordName(normalized.RecordName, normalized.ZoneName)
	for _, record := range records {
		if normalizeArvanRecordName(record.Name) == relativeName && record.Text == normalized.TXTValue {
			return nil
		}
	}
	body := map[string]any{
		"type": "txt",
		"name": relativeName,
		"value": map[string]string{
			"text": normalized.TXTValue,
		},
		"ttl": normalized.TTL,
	}
	if err := c.arvanCloudRequest(ctx, creds, http.MethodPost, "/domains/"+url.PathEscape(normalized.ZoneName)+"/dns-records", body, nil); err != nil {
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
	records, err := c.arvanCloudTXTRecords(ctx, creds, normalized.ZoneName)
	if err != nil {
		return ErrDNSChallengeOperation
	}
	relativeName := relativeTXTRecordName(normalized.RecordName, normalized.ZoneName)
	for _, record := range records {
		if normalizeArvanRecordName(record.Name) != relativeName || record.Text != normalized.TXTValue {
			continue
		}
		if err := c.arvanCloudRequest(ctx, creds, http.MethodDelete, "/domains/"+url.PathEscape(normalized.ZoneName)+"/dns-records/"+url.PathEscape(record.ID), nil, nil); err != nil {
			return ErrDNSChallengeOperation
		}
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
	if err := c.arvanCloudRequest(ctx, creds, http.MethodGet, "/domains/"+url.PathEscape(zoneName)+"/dns-records", nil, &body); err != nil {
		return nil, err
	}
	out := make([]arvanCloudDNSRecord, 0, len(body.Data))
	for _, record := range body.Data {
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

func (c *ArvanCloudClient) arvanCloudRequest(ctx context.Context, creds ArvanCloudCredentials, method, path string, requestBody any, responseBody any) error {
	req, err := newJSONRequest(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, nil, requestBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", creds.APIKey)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("arvancloud request failed")
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
