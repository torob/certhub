package dnsproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/torob/certhub/internal/storage"
)

var (
	ErrZoneDiscoveryFailed     = errors.New("dns zone discovery failed")
	ErrDNSChallengeOperation   = errors.New("dns challenge operation failed")
	ErrDNSProviderUnavailable  = errors.New("dns provider client unavailable")
	defaultDNSChallengeTTL     = 120
	maxDNSProviderResponseSize = int64(1 << 20)
)

type ZoneLister interface {
	ListZones(context.Context, json.RawMessage) ([]string, error)
}

type DNS01ChallengeOperation struct {
	ZoneName   string
	RecordName string
	TXTValue   string
	TTL        int
}

type ChallengeOperator[C any] interface {
	Present(context.Context, C, DNS01ChallengeOperation) error
	CleanUp(context.Context, C, DNS01ChallengeOperation) error
}

type ZoneListerRegistry map[ProviderType]ZoneLister

type normalizedDNS01ChallengeOperation struct {
	ZoneName   string
	RecordName string
	TXTValue   string
	TTL        int
}

func normalizeDNS01ChallengeOperation(op DNS01ChallengeOperation) (normalizedDNS01ChallengeOperation, error) {
	zoneName, err := storage.NormalizeDNSName(op.ZoneName)
	if err != nil {
		return normalizedDNS01ChallengeOperation{}, err
	}
	recordName, err := normalizeDNSTXTRecordName(op.RecordName)
	if err != nil {
		return normalizedDNS01ChallengeOperation{}, err
	}
	if recordName != "_acme-challenge."+zoneName && !strings.HasSuffix(recordName, "."+zoneName) {
		return normalizedDNS01ChallengeOperation{}, errors.New("record_name is outside zone")
	}
	if !validSecretString(op.TXTValue) {
		return normalizedDNS01ChallengeOperation{}, errors.New("txt value is invalid")
	}
	ttl := op.TTL
	if ttl <= 0 {
		ttl = defaultDNSChallengeTTL
	}
	return normalizedDNS01ChallengeOperation{
		ZoneName:   zoneName,
		RecordName: recordName,
		TXTValue:   op.TXTValue,
		TTL:        ttl,
	}, nil
}

func normalizeDNSTXTRecordName(value string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(value), "_acme-challenge.") {
		return "", errors.New("record_name must be an _acme-challenge TXT owner name")
	}
	name, err := storage.NormalizeDNSName(value[len("_acme-challenge."):])
	if err != nil {
		return "", err
	}
	return "_acme-challenge." + name, nil
}

func relativeTXTRecordName(recordName, zoneName string) string {
	suffix := "." + zoneName
	relative := strings.TrimSuffix(recordName, suffix)
	if relative == "" {
		return "@"
	}
	return relative
}

func newJSONRequest(ctx context.Context, method, rawURL string, query url.Values, body any) (*http.Request, error) {
	if query != nil {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		parsed.RawQuery = query.Encode()
		rawURL = parsed.String()
	}
	var reader io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
		reader = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}
