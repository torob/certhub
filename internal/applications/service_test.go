package applications

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestValidateApplicationTokenUsesHashAndSourceCIDRs(t *testing.T) {
	keys := serviceTestKeySet(t)
	raw := ApplicationTokenPrefix + strings.Repeat("A", 43)
	now := time.Now().UTC()
	store := &serviceFakeStore{
		tokenIdentity: TokenIdentity{
			Token: ApplicationToken{
				ID:            "32345678-1234-4234-9234-123456789abc",
				ApplicationID: "22345678-1234-4234-9234-123456789abc",
				Name:          "primary",
				TokenHash:     keys.HashToken(raw),
				Status:        TokenStatusActive,
				CreatedAt:     now,
			},
			Application: Application{
				ID:                 "22345678-1234-4234-9234-123456789abc",
				Name:               "api_app",
				DisplayName:        "API App",
				Status:             StatusActive,
				TrustedSourceCIDRs: []string{"203.0.113.0/24"},
				CreatedAt:          now,
				UpdatedAt:          now,
			},
		},
	}
	service := NewService(ServiceConfig{Repository: store, AuditRepository: &serviceFakeAudit{}, KeySet: keys, Config: serviceTokenConfig()})

	current, err := service.ValidateApplicationToken(context.Background(), raw, netip.MustParseAddr("203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Application.ID != store.tokenIdentity.Application.ID {
		t.Fatalf("current = %#v", current)
	}
	if store.lookupHash != keys.HashToken(raw) || store.lookupHash == raw {
		t.Fatalf("lookup hash = %q", store.lookupHash)
	}
	if store.markedTokenID != store.tokenIdentity.Token.ID {
		t.Fatalf("marked token = %q", store.markedTokenID)
	}
}

func TestValidateApplicationTokenRejectsUserTokenClassAndDeniedSourceIP(t *testing.T) {
	keys := serviceTestKeySet(t)
	service := NewService(ServiceConfig{Repository: &serviceFakeStore{}, AuditRepository: &serviceFakeAudit{}, KeySet: keys, Config: serviceTokenConfig()})
	_, err := service.ValidateApplicationToken(context.Background(), "cth_uat_v1_"+strings.Repeat("A", 43), netip.MustParseAddr("203.0.113.10"))
	if !errors.Is(err, ErrApplicationTokenRequired) {
		t.Fatalf("err = %v", err)
	}

	raw := ApplicationTokenPrefix + strings.Repeat("B", 43)
	now := time.Now().UTC()
	store := &serviceFakeStore{tokenIdentity: TokenIdentity{
		Token: ApplicationToken{
			ID:            "32345678-1234-4234-9234-123456789abc",
			ApplicationID: "22345678-1234-4234-9234-123456789abc",
			Name:          "primary",
			TokenHash:     keys.HashToken(raw),
			Status:        TokenStatusActive,
			CreatedAt:     now,
		},
		Application: Application{
			ID:                 "22345678-1234-4234-9234-123456789abc",
			Name:               "api_app",
			DisplayName:        "API App",
			Status:             StatusActive,
			TrustedSourceCIDRs: []string{"203.0.113.0/24"},
			CreatedAt:          now,
			UpdatedAt:          now,
		},
	}}
	service = NewService(ServiceConfig{Repository: store, AuditRepository: &serviceFakeAudit{}, KeySet: keys, Config: serviceTokenConfig()})
	_, err = service.ValidateApplicationToken(context.Background(), raw, netip.MustParseAddr("198.51.100.10"))
	if !errors.Is(err, ErrSourceIPDenied) {
		t.Fatalf("err = %v", err)
	}
	if store.markedTokenID != "" {
		t.Fatalf("denied token was marked used")
	}
}

func TestCreateTokenReturnsRawOnceAndStoresHashOnly(t *testing.T) {
	keys := serviceTestKeySet(t)
	now := time.Now().UTC()
	app := Application{
		ID:          "22345678-1234-4234-9234-123456789abc",
		Name:        "api_app",
		DisplayName: "API App",
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	auditRepo := &serviceFakeAudit{}
	store := &serviceFakeStore{application: app}
	service := NewService(ServiceConfig{Repository: store, AuditRepository: auditRepo, KeySet: keys, Config: serviceTokenConfig()})

	result, err := service.CreateToken(context.Background(), Actor{
		ID:         "12345678-1234-4234-9234-123456789abc",
		GlobalRole: users.GlobalRoleAdmin,
	}, app.ID, CreateTokenServiceParams{Name: "deploy"}, AuditContext{CorrelationID: "req-test", SourceIP: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.TokenValue, ApplicationTokenPrefix) {
		t.Fatalf("token value = %q", result.TokenValue)
	}
	if store.createdToken.TokenHash != keys.HashToken(result.TokenValue) || store.createdToken.TokenHash == result.TokenValue {
		t.Fatalf("stored token hash = %q", store.createdToken.TokenHash)
	}
	body, _ := json.Marshal(auditRepo.events)
	if strings.Contains(string(body), result.TokenValue) || strings.Contains(string(body), store.createdToken.TokenHash) {
		t.Fatalf("audit leaked token secret/hash: %s", body)
	}
}

func TestRotateTokenUpdatesSameRowAndDoesNotLeakSecret(t *testing.T) {
	keys := serviceTestKeySet(t)
	now := time.Now().UTC()
	app := Application{
		ID:          "22345678-1234-4234-9234-123456789abc",
		Name:        "api_app",
		DisplayName: "API App",
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	auditRepo := &serviceFakeAudit{}
	store := &serviceFakeStore{application: app}
	service := NewService(ServiceConfig{Repository: store, AuditRepository: auditRepo, KeySet: keys, Config: serviceTokenConfig()})
	expiresAt := now.Add(2 * time.Hour)

	result, err := service.RotateToken(context.Background(), Actor{
		ID:         "12345678-1234-4234-9234-123456789abc",
		GlobalRole: users.GlobalRoleAdmin,
	}, app.ID, "42345678-1234-4234-9234-123456789abc", CreateTokenServiceParams{ExpiresAtSet: true, ExpiresAt: &expiresAt}, AuditContext{CorrelationID: "req-test", SourceIP: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Token.ID != "42345678-1234-4234-9234-123456789abc" {
		t.Fatalf("rotated token id = %q", result.Token.ID)
	}
	if !strings.HasPrefix(result.TokenValue, ApplicationTokenPrefix) {
		t.Fatalf("token value = %q", result.TokenValue)
	}
	if store.rotatedToken.TokenHash != keys.HashToken(result.TokenValue) || store.rotatedToken.TokenHash == result.TokenValue {
		t.Fatalf("stored rotated token hash = %q", store.rotatedToken.TokenHash)
	}
	if store.rotatedToken.ExpiresAt == nil || !store.rotatedToken.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("rotated expires_at = %#v; want %s", store.rotatedToken.ExpiresAt, expiresAt)
	}
	body, _ := json.Marshal(auditRepo.events)
	if strings.Contains(string(body), result.TokenValue) || strings.Contains(string(body), store.rotatedToken.TokenHash) {
		t.Fatalf("audit leaked token secret/hash: %s", body)
	}
}

func TestDomainScopeCoverageHelpers(t *testing.T) {
	scopes := []DomainScope{{Value: "*.example.com"}, {Value: "api.internal.example.com"}}
	result, err := ScopesCoverIdentifiers(scopes, []string{"API.Example.com.", "*.example.com", "api.internal.example.com", "deep.api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.NormalizedIdentifiers, ",") != "api.example.com,*.example.com,api.internal.example.com,deep.api.example.com" {
		t.Fatalf("normalized = %#v", result.NormalizedIdentifiers)
	}
	if len(result.UncoveredIdentifiers) != 1 || result.UncoveredIdentifiers[0] != "deep.api.example.com" {
		t.Fatalf("uncovered = %#v", result.UncoveredIdentifiers)
	}
}

func TestDomainScopeCoverageAllowsExactAndWildcardWhenIndependentlyCovered(t *testing.T) {
	scopes := []DomainScope{{Value: "example.com"}, {Value: "*.example.com"}}
	result, err := ScopesCoverIdentifiers(scopes, []string{"example.com", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.UncoveredIdentifiers) != 0 {
		t.Fatalf("uncovered = %#v", result.UncoveredIdentifiers)
	}
}

func TestDomainScopeCoverageRequiresExactAndWildcardScopesIndependently(t *testing.T) {
	for name, tc := range map[string]struct {
		scopes []DomainScope
		want   string
	}{
		"missing exact":    {scopes: []DomainScope{{Value: "*.example.com"}}, want: "example.com"},
		"missing wildcard": {scopes: []DomainScope{{Value: "example.com"}}, want: "*.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := ScopesCoverIdentifiers(tc.scopes, []string{"example.com", "*.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.UncoveredIdentifiers) != 1 || result.UncoveredIdentifiers[0] != tc.want {
				t.Fatalf("uncovered = %#v want %q", result.UncoveredIdentifiers, tc.want)
			}
		})
	}
}

type serviceFakeStore struct {
	application     Application
	tokenIdentity   TokenIdentity
	lookupHash      string
	markedTokenID   string
	createdToken    CreateTokenParams
	rotatedToken    RotateTokenParams
	accessibleAppID []string
}

func (f *serviceFakeStore) Create(context.Context, CreateApplicationParams) (Application, error) {
	return f.application, nil
}

func (f *serviceFakeStore) Get(context.Context, string) (Application, error) {
	if f.application.ID == "" {
		return Application{}, storage.ErrNoRows
	}
	return f.application, nil
}

func (f *serviceFakeStore) List(context.Context, ListApplicationsParams) ([]Application, error) {
	return []Application{f.application}, nil
}

func (f *serviceFakeStore) Count(context.Context, ListApplicationsParams) (int64, error) {
	return 1, nil
}

func (f *serviceFakeStore) ListVisible(context.Context, string, ListApplicationsParams) ([]Application, error) {
	return []Application{f.application}, nil
}

func (f *serviceFakeStore) CountVisible(context.Context, string, ListApplicationsParams) (int64, error) {
	return 1, nil
}

func (f *serviceFakeStore) ListAccessibleApplicationIDs(context.Context, string) ([]string, error) {
	return append([]string(nil), f.accessibleAppID...), nil
}

func (f *serviceFakeStore) Update(context.Context, string, UpdateApplicationParams) (Application, error) {
	return f.application, nil
}

func (f *serviceFakeStore) CreateToken(_ context.Context, params CreateTokenParams) (ApplicationToken, error) {
	f.createdToken = params
	return ApplicationToken{
		ID:            "42345678-1234-4234-9234-123456789abc",
		ApplicationID: params.ApplicationID,
		Name:          params.Name,
		TokenHash:     params.TokenHash,
		Status:        TokenStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     params.ExpiresAt,
	}, nil
}

func (f *serviceFakeStore) LookupTokenByHash(_ context.Context, hash string) (TokenIdentity, error) {
	f.lookupHash = hash
	if f.tokenIdentity.Token.ID == "" {
		return TokenIdentity{}, storage.ErrNoRows
	}
	return f.tokenIdentity, nil
}

func (f *serviceFakeStore) MarkTokenUsed(_ context.Context, tokenID string) error {
	f.markedTokenID = tokenID
	return nil
}

func (f *serviceFakeStore) RotateToken(_ context.Context, params RotateTokenParams) (ApplicationToken, error) {
	f.rotatedToken = params
	return ApplicationToken{
		ID:            params.TokenID,
		ApplicationID: params.ApplicationID,
		Name:          "deploy",
		TokenHash:     params.TokenHash,
		Status:        TokenStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     params.ExpiresAt,
	}, nil
}

func (f *serviceFakeStore) ListTokens(context.Context, string, ListTokensParams) ([]ApplicationToken, error) {
	return nil, errors.New("not implemented")
}

func (f *serviceFakeStore) CountTokens(context.Context, string, ListTokensParams) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *serviceFakeStore) RevokeToken(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (f *serviceFakeStore) AddDomainScope(context.Context, AddDomainScopeParams) (DomainScope, error) {
	return DomainScope{}, errors.New("not implemented")
}

func (f *serviceFakeStore) ListDomainScopes(context.Context, string, storage.ListOptions) ([]DomainScope, error) {
	return nil, errors.New("not implemented")
}

func (f *serviceFakeStore) CountDomainScopes(context.Context, string, storage.ListOptions) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *serviceFakeStore) DeleteDomainScope(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (f *serviceFakeStore) UpsertGrant(context.Context, UpsertGrantParams) (UserGrant, error) {
	return UserGrant{}, errors.New("not implemented")
}

func (f *serviceFakeStore) ListGrants(context.Context, string, storage.ListOptions) ([]UserGrant, error) {
	return nil, errors.New("not implemented")
}

func (f *serviceFakeStore) CountGrants(context.Context, string, storage.ListOptions) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *serviceFakeStore) GetGrant(context.Context, string, string) (UserGrant, error) {
	return UserGrant{}, storage.ErrNoRows
}

func (f *serviceFakeStore) DeleteGrant(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

type serviceFakeAudit struct {
	events []audit.AppendEventParams
}

func (f *serviceFakeAudit) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	f.events = append(f.events, params)
	return audit.Event{}, nil
}

func serviceTestKeySet(t *testing.T) *security.KeySet {
	t.Helper()
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func serviceTokenConfig() config.ApplicationTokenConfig {
	return config.ApplicationTokenConfig{DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400}
}
