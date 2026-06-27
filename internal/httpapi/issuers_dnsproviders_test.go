package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"certhub/internal/auth"
	dnsdomain "certhub/internal/dnsproviders"
	issuerdomain "certhub/internal/issuers"
	"certhub/internal/storage"
)

func TestIssuerUpstreamDependencyErrorIsRetryable(t *testing.T) {
	rec := httptest.NewRecorder()
	writeIssuerError(rec, issuerdomain.ErrUpstreamDependency)

	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("status=%d retry-after=%q body=%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["code"] != "issuer_unavailable" || body["error"]["retryable"] != true {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestDNSProviderDiscoveryErrorIsRetryable(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDNSProviderError(rec, dnsdomain.ErrProviderDiscovery)

	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("status=%d retry-after=%q body=%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["code"] != "dns_zone_discovery_failed" || body["error"]["retryable"] != true {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestRefreshDNSProviderZonesRejectsUnknownLifecycleFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/dns-providers/123/zones/refresh", strings.NewReader(`{"extra":"nope"}`))
	if err := decodeOptionalLifecycleNote(req); err == nil {
		t.Fatalf("unknown lifecycle note field was accepted")
	}
}

func TestCreateDNSProviderResponseIsWriteOnlyForCredentials(t *testing.T) {
	keys := testKeySet(t)
	user := fakeUser()
	userToken := auth.UserAccessTokenPrefix + strings.Repeat("D", 43)
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository: &identityFakeAuthRepo{session: auth.Session{
			ID:              "52345678-1234-4234-9234-123456789abc",
			UserID:          user.ID,
			AuthMethod:      auth.AuthMethodPassword,
			AccessTokenHash: keys.HashToken(userToken),
			Status:          auth.SessionStatusActive,
			AccessExpiresAt: time.Now().Add(time.Minute),
		}},
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
		Config:          testConfig(t, "").Auth,
	})
	store := &httpDNSProviderStore{now: time.Now().UTC()}
	dnsSvc := dnsdomain.NewService(dnsdomain.ServiceConfig{
		Repository:      store,
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
	})
	handler := New(testConfig(t, ""), WithIdentityServices(authSvc, nil), WithDNSProviderService(dnsSvc)).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/dns-providers", strings.NewReader(`{
		"name":"cloudflare_main",
		"type":"cloudflare",
		"zone_mode":"manual",
		"credentials":{"api_token":"DNS-CREDENTIAL-CANARY"}
	}`))
	req.Header.Set("Authorization", "Bearer "+userToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "DNS-CREDENTIAL-CANARY") || strings.Contains(rec.Body.String(), "credentials") {
		t.Fatalf("response leaked credentials: %s", rec.Body.String())
	}
	if store.created.CredentialsEncrypted == "" || strings.Contains(store.created.CredentialsEncrypted, "DNS-CREDENTIAL-CANARY") {
		t.Fatalf("stored credentials were not encrypted: %s", store.created.CredentialsEncrypted)
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["dns_provider"]["type"] != "cloudflare" {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

type httpDNSProviderStore struct {
	now      time.Time
	provider dnsdomain.Provider
	created  dnsdomain.CreateProviderParams
}

func (s *httpDNSProviderStore) Create(_ context.Context, params dnsdomain.CreateProviderParams) (dnsdomain.Provider, error) {
	s.created = params
	s.provider = dnsdomain.Provider{
		ID:                params.ID,
		Name:              params.Name,
		Type:              params.Type,
		ZoneMode:          params.ZoneMode,
		ZoneRefreshStatus: dnsdomain.RefreshStatusIdle,
		Status:            dnsdomain.StatusActive,
		CreatedAt:         s.now,
		UpdatedAt:         s.now,
	}
	return s.provider, nil
}

func (s *httpDNSProviderStore) Get(context.Context, string) (dnsdomain.Provider, error) {
	return s.provider, nil
}
func (s *httpDNSProviderStore) List(context.Context, dnsdomain.ListProvidersParams) ([]dnsdomain.Provider, error) {
	return []dnsdomain.Provider{s.provider}, nil
}
func (s *httpDNSProviderStore) Count(context.Context, dnsdomain.ListProvidersParams) (int64, error) {
	return 1, nil
}
func (s *httpDNSProviderStore) Update(context.Context, string, dnsdomain.UpdateProviderParams) (dnsdomain.Provider, error) {
	return s.provider, nil
}
func (s *httpDNSProviderStore) ReplaceCredentials(context.Context, string, string) (dnsdomain.Provider, error) {
	return s.provider, nil
}
func (s *httpDNSProviderStore) GetCredentialsEncrypted(context.Context, string) (string, error) {
	return s.created.CredentialsEncrypted, nil
}
func (s *httpDNSProviderStore) AddZone(context.Context, dnsdomain.AddZoneParams) (dnsdomain.Zone, error) {
	return dnsdomain.Zone{}, nil
}
func (s *httpDNSProviderStore) DeleteZone(context.Context, string, string) (bool, error) {
	return false, nil
}
func (s *httpDNSProviderStore) ListZones(context.Context, string, storage.ListOptions) ([]dnsdomain.Zone, error) {
	return nil, nil
}
func (s *httpDNSProviderStore) CountZones(context.Context, string) (int64, error) { return 0, nil }
func (s *httpDNSProviderStore) FindZoneForDNSName(context.Context, string) (dnsdomain.ZoneMatch, error) {
	return dnsdomain.ZoneMatch{}, storage.ErrNoRows
}
func (s *httpDNSProviderStore) EnsureRefreshJob(context.Context, dnsdomain.EnsureRefreshJobParams) (dnsdomain.RefreshJob, error) {
	return dnsdomain.RefreshJob{}, nil
}
func (s *httpDNSProviderStore) ClaimNextRefreshJob(context.Context, dnsdomain.ClaimRefreshJobParams) (dnsdomain.RefreshJob, error) {
	return dnsdomain.RefreshJob{}, storage.ErrNoRows
}
func (s *httpDNSProviderStore) CompleteRefreshJobSuccess(context.Context, dnsdomain.CompleteRefreshJobParams) (dnsdomain.RefreshJob, error) {
	return dnsdomain.RefreshJob{}, nil
}
func (s *httpDNSProviderStore) FailRefreshJob(context.Context, dnsdomain.FailRefreshJobParams) (dnsdomain.RefreshJob, error) {
	return dnsdomain.RefreshJob{}, nil
}
