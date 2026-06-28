package dnsproviders

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestCreateProviderEncryptsTypedCredentialsAndAuditsNoSecret(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &dnsServiceStore{now: time.Now().UTC()}
	auditRepo := &dnsAuditStore{}
	service := NewService(ServiceConfig{Repository: store, AuditRepository: auditRepo, KeySet: keys})
	provider, err := service.CreateProvider(context.Background(), Actor{
		ID:         "12345678-1234-4234-9234-123456789abc",
		GlobalRole: users.GlobalRoleAdmin,
	}, CreateProviderServiceParams{
		Name:        "cloudflare_main",
		Type:        ProviderTypeCloudflare,
		ZoneMode:    ZoneModeManual,
		Status:      StatusActive,
		Credentials: json.RawMessage(`{"api_token":"DNS-CREDENTIAL-CANARY"}`),
	}, AuditContext{CorrelationID: "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	if provider.ID == "" || provider.Type != ProviderTypeCloudflare {
		t.Fatalf("provider = %#v", provider)
	}
	if store.created.CredentialsEncrypted == "" || strings.Contains(store.created.CredentialsEncrypted, "DNS-CREDENTIAL-CANARY") {
		t.Fatalf("credentials were not encrypted: %s", store.created.CredentialsEncrypted)
	}
	auditJSON, _ := json.Marshal(auditRepo.events)
	if strings.Contains(string(auditJSON), "DNS-CREDENTIAL-CANARY") || strings.Contains(string(auditJSON), store.created.CredentialsEncrypted) {
		t.Fatalf("audit leaked credential material: %s", auditJSON)
	}
}

func TestCreateProviderRejectsUnexpectedCredentialFields(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(ServiceConfig{Repository: &dnsServiceStore{now: time.Now().UTC()}, KeySet: keys})
	_, err = service.CreateProvider(context.Background(), Actor{
		ID:         "12345678-1234-4234-9234-123456789abc",
		GlobalRole: users.GlobalRoleAdmin,
	}, CreateProviderServiceParams{
		Name:        "cloudflare_main",
		Type:        ProviderTypeCloudflare,
		ZoneMode:    ZoneModeManual,
		Status:      StatusActive,
		Credentials: json.RawMessage(`{"api_token":"token-value","extra":"not allowed"}`),
	}, AuditContext{})
	if err != ErrInvalidRequest {
		t.Fatalf("err = %v", err)
	}
}

func TestSystemActorAuditsDNSMutationsAsSystemIdentity(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &dnsServiceStore{now: time.Now().UTC()}
	auditRepo := &dnsAuditStore{}
	service := NewService(ServiceConfig{Repository: store, AuditRepository: auditRepo, KeySet: keys})
	actor := Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: users.GlobalRoleAdmin, System: true}
	provider, err := service.CreateProvider(context.Background(), actor, CreateProviderServiceParams{
		Name:        "cloudflare_main",
		Type:        ProviderTypeCloudflare,
		ZoneMode:    ZoneModeManual,
		Status:      StatusActive,
		Credentials: json.RawMessage(`{"api_token":"DNS-CREDENTIAL-CANARY"}`),
	}, AuditContext{CorrelationID: "bootstrap-create-dns-provider", Command: "certhub-server bootstrap create-dns-provider"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddZone(context.Background(), actor, provider.ID, "example.com", AuditContext{CorrelationID: "bootstrap-add-dns-provider-zone", Command: "certhub-server bootstrap add-dns-provider-zone"}); err != nil {
		t.Fatal(err)
	}
	store.provider.ZoneMode = ZoneModeAuto
	if _, err := service.RefreshZones(context.Background(), actor, provider.ID, AuditContext{CorrelationID: "bootstrap-refresh-dns-provider-zones", Command: "certhub-server bootstrap refresh-dns-provider-zones"}); err != nil {
		t.Fatal(err)
	}
	if len(auditRepo.events) < 3 {
		t.Fatalf("events = %#v", auditRepo.events)
	}
	wantCommands := map[string]string{
		"dns_provider_created":                "certhub-server bootstrap create-dns-provider",
		"dns_provider_zone_created":           "certhub-server bootstrap add-dns-provider-zone",
		"dns_provider_zone_refresh_requested": "certhub-server bootstrap refresh-dns-provider-zones",
	}
	for _, event := range auditRepo.events {
		if event.IdentityType != audit.IdentityTypeSystem || event.IdentityID != nil {
			t.Fatalf("audit identity for %s = %s %#v", event.Action, event.IdentityType, event.IdentityID)
		}
		var metadata map[string]any
		if err := json.Unmarshal(event.Metadata, &metadata); err != nil {
			t.Fatal(err)
		}
		if metadata["command"] != wantCommands[event.Action] {
			t.Fatalf("metadata for %s = %#v", event.Action, metadata)
		}
	}
}

type dnsServiceStore struct {
	now      time.Time
	provider Provider
	created  CreateProviderParams
}

func (s *dnsServiceStore) Create(_ context.Context, params CreateProviderParams) (Provider, error) {
	s.created = params
	s.provider = Provider{
		ID:                params.ID,
		Name:              params.Name,
		Type:              params.Type,
		ZoneMode:          params.ZoneMode,
		ZoneRefreshStatus: RefreshStatusIdle,
		Status:            params.Status,
		CreatedAt:         s.now,
		UpdatedAt:         s.now,
	}
	return s.provider, nil
}

func (s *dnsServiceStore) Get(context.Context, string) (Provider, error) { return s.provider, nil }
func (s *dnsServiceStore) List(context.Context, ListProvidersParams) ([]Provider, error) {
	return []Provider{s.provider}, nil
}
func (s *dnsServiceStore) Count(context.Context, ListProvidersParams) (int64, error) { return 1, nil }
func (s *dnsServiceStore) Update(context.Context, string, UpdateProviderParams) (Provider, error) {
	return s.provider, nil
}
func (s *dnsServiceStore) ReplaceCredentials(context.Context, string, string) (Provider, error) {
	return s.provider, nil
}
func (s *dnsServiceStore) GetCredentialsEncrypted(context.Context, string) (string, error) {
	return s.created.CredentialsEncrypted, nil
}
func (s *dnsServiceStore) AddZone(_ context.Context, params AddZoneParams) (Zone, error) {
	return Zone{ID: "32345678-1234-4234-9234-123456789abc", DNSProviderID: params.DNSProviderID, ZoneName: params.ZoneName}, nil
}
func (s *dnsServiceStore) DeleteZone(context.Context, string, string) (bool, error) {
	return false, nil
}
func (s *dnsServiceStore) ListZones(context.Context, string, storage.ListOptions) ([]Zone, error) {
	return nil, nil
}
func (s *dnsServiceStore) CountZones(context.Context, string) (int64, error) { return 0, nil }
func (s *dnsServiceStore) FindZoneForDNSName(context.Context, string) (ZoneMatch, error) {
	return ZoneMatch{}, storage.ErrNoRows
}
func (s *dnsServiceStore) EnsureRefreshJob(context.Context, EnsureRefreshJobParams) (RefreshJob, error) {
	return RefreshJob{ID: "42345678-1234-4234-9234-123456789abc", DNSProviderID: s.provider.ID, Status: RefreshJobStatusPending}, nil
}
func (s *dnsServiceStore) ClaimNextRefreshJob(context.Context, ClaimRefreshJobParams) (RefreshJob, error) {
	return RefreshJob{}, storage.ErrNoRows
}
func (s *dnsServiceStore) CompleteRefreshJobSuccess(context.Context, CompleteRefreshJobParams) (RefreshJob, error) {
	return RefreshJob{}, nil
}
func (s *dnsServiceStore) FailRefreshJob(context.Context, FailRefreshJobParams) (RefreshJob, error) {
	return RefreshJob{}, nil
}

type dnsAuditStore struct {
	events []audit.AppendEventParams
}

func (s *dnsAuditStore) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	s.events = append(s.events, params)
	return audit.Event{}, nil
}
