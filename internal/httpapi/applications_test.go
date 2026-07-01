package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	auditdomain "github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/config"
	"github.com/torob/certhub/internal/storage"
)

func TestAuthMeWithApplicationToken(t *testing.T) {
	keys := testKeySet(t)
	raw := appdomain.ApplicationTokenPrefix + strings.Repeat("A", 43)
	now := time.Now().UTC()
	store := &httpAppFakeStore{tokenIdentity: appdomain.TokenIdentity{
		Token: appdomain.ApplicationToken{
			ID:            "32345678-1234-4234-9234-123456789abc",
			ApplicationID: "22345678-1234-4234-9234-123456789abc",
			Name:          "primary",
			TokenHash:     keys.HashToken(raw),
			Status:        appdomain.TokenStatusActive,
			CreatedAt:     now,
		},
		Application: httpFakeApplication(now, nil),
	}}
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      store,
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
		Config:          testConfig(t, "").ApplicationToken,
	})
	handler := New(testConfig(t, ""), WithApplicationAccessServices(appSvc, nil)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if store.markedTokenID != store.tokenIdentity.Token.ID {
		t.Fatalf("token was not marked used: %q", store.markedTokenID)
	}
	if strings.Contains(rec.Body.String(), raw) || strings.Contains(rec.Body.String(), store.tokenIdentity.Token.TokenHash) {
		t.Fatalf("auth/me leaked token material: %s", rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["identity_type"] != "application" {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestAuthMeApplicationTokenSourceIPDenied(t *testing.T) {
	keys := testKeySet(t)
	raw := appdomain.ApplicationTokenPrefix + strings.Repeat("B", 43)
	now := time.Now().UTC()
	store := &httpAppFakeStore{tokenIdentity: appdomain.TokenIdentity{
		Token: appdomain.ApplicationToken{
			ID:            "32345678-1234-4234-9234-123456789abc",
			ApplicationID: "22345678-1234-4234-9234-123456789abc",
			Name:          "primary",
			TokenHash:     keys.HashToken(raw),
			Status:        appdomain.TokenStatusActive,
			CreatedAt:     now,
		},
		Application: httpFakeApplication(now, []string{"203.0.113.0/24"}),
	}}
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      store,
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
		Config:          testConfig(t, "").ApplicationToken,
	})
	handler := New(testConfig(t, ""), WithApplicationAccessServices(appSvc, nil)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, "application_source_ip_denied")
	if store.markedTokenID != "" {
		t.Fatalf("denied token was marked used")
	}
}

func TestApplicationManagementEndpointRejectsApplicationTokenClass(t *testing.T) {
	keys := testKeySet(t)
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      &httpAppFakeStore{},
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
		Config:          testConfig(t, "").ApplicationToken,
	})
	handler := New(testConfig(t, ""), WithIdentityServices(testAuthService(t, fakeUser()), nil), WithApplicationAccessServices(appSvc, nil)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/applications", nil)
	req.Header.Set("Authorization", "Bearer "+appdomain.ApplicationTokenPrefix+strings.Repeat("A", 43))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, "user_token_required")

	req = httptest.NewRequest(http.MethodGet, "/v1/applications", nil)
	req.Header.Set("Authorization", "Bearer "+auth.UserRefreshTokenPrefix+strings.Repeat("B", 43))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, "refresh_token_not_allowed")
}

func TestApplicationConflictErrorCarriesRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	writeApplicationError(rec, appdomain.ErrConflict)
	if rec.Code != http.StatusConflict || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("status=%d retry-after=%q body=%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["retry_after_seconds"] != float64(1) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSerializeApplicationIncludesCertificateCount(t *testing.T) {
	now := time.Now().UTC()
	app := httpFakeApplication(now, nil)
	app.CertificateCount = 4
	out := serializeApplication(appdomain.ApplicationWithRole{Application: app, CurrentRole: "admin"})
	if out.CertificateCount != 4 {
		t.Fatalf("certificate_count = %d", out.CertificateCount)
	}
}

func TestCreateApplicationTokenResponseShowsRawOnceAndNoHash(t *testing.T) {
	keys := testKeySet(t)
	user := fakeUser()
	userToken := auth.UserAccessTokenPrefix + strings.Repeat("C", 43)
	authRepo := &identityFakeAuthRepo{session: auth.Session{
		ID:              "52345678-1234-4234-9234-123456789abc",
		UserID:          user.ID,
		AuthMethod:      auth.AuthMethodPassword,
		AccessTokenHash: keys.HashToken(userToken),
		Status:          auth.SessionStatusActive,
		AccessExpiresAt: time.Now().Add(time.Minute),
	}}
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository:  authRepo,
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
		Config:          testConfig(t, "").Auth,
	})
	now := time.Now().UTC()
	app := httpFakeApplication(now, nil)
	appAudit := &httpAppFakeAudit{}
	store := &httpAppFakeStore{application: app}
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      store,
		AuditRepository: appAudit,
		KeySet:          keys,
		Config:          config.ApplicationTokenConfig{DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400},
	})
	handler := New(testConfig(t, ""), WithIdentityServices(authSvc, nil), WithApplicationAccessServices(appSvc, nil)).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/applications/"+app.ID+"/tokens", strings.NewReader(`{"name":"deploy"}`))
	req.Header.Set("Authorization", "Bearer "+userToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store header")
	}
	var body struct {
		TokenValue string `json:"token_value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.TokenValue, appdomain.ApplicationTokenPrefix) {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "token_hash") || strings.Contains(rec.Body.String(), store.createdToken.TokenHash) {
		t.Fatalf("response leaked token hash: %s", rec.Body.String())
	}
	auditJSON, _ := json.Marshal(appAudit.events)
	if strings.Contains(string(auditJSON), body.TokenValue) || strings.Contains(string(auditJSON), store.createdToken.TokenHash) {
		t.Fatalf("audit leaked token material: %s", auditJSON)
	}
}

func httpFakeApplication(now time.Time, cidrs []string) appdomain.Application {
	if cidrs == nil {
		cidrs = []string{}
	}
	return appdomain.Application{
		ID:                     "22345678-1234-4234-9234-123456789abc",
		Name:                   "api_app",
		DisplayName:            "API App",
		Status:                 appdomain.StatusActive,
		TrustedSourceCIDRs:     cidrs,
		CreatedAt:              now,
		UpdatedAt:              now,
		TrustedSourceCIDRCount: int64(len(cidrs)),
	}
}

type httpAppFakeStore struct {
	application   appdomain.Application
	tokenIdentity appdomain.TokenIdentity
	createdToken  appdomain.CreateTokenParams
	markedTokenID string
}

func (f *httpAppFakeStore) Create(context.Context, appdomain.CreateApplicationParams) (appdomain.Application, error) {
	return f.application, nil
}

func (f *httpAppFakeStore) Get(context.Context, string) (appdomain.Application, error) {
	if f.application.ID != "" {
		return f.application, nil
	}
	if f.tokenIdentity.Application.ID != "" {
		return f.tokenIdentity.Application, nil
	}
	return appdomain.Application{}, storage.ErrNoRows
}

func (f *httpAppFakeStore) List(context.Context, appdomain.ListApplicationsParams) ([]appdomain.Application, error) {
	return []appdomain.Application{f.application}, nil
}

func (f *httpAppFakeStore) Count(context.Context, appdomain.ListApplicationsParams) (int64, error) {
	return 1, nil
}

func (f *httpAppFakeStore) ListVisible(context.Context, string, appdomain.ListApplicationsParams) ([]appdomain.Application, error) {
	return []appdomain.Application{f.application}, nil
}

func (f *httpAppFakeStore) CountVisible(context.Context, string, appdomain.ListApplicationsParams) (int64, error) {
	return 1, nil
}

func (f *httpAppFakeStore) ListAccessibleApplicationIDs(context.Context, string) ([]string, error) {
	return nil, nil
}

func (f *httpAppFakeStore) Update(context.Context, string, appdomain.UpdateApplicationParams) (appdomain.Application, error) {
	return f.application, nil
}

func (f *httpAppFakeStore) CreateToken(_ context.Context, params appdomain.CreateTokenParams) (appdomain.ApplicationToken, error) {
	f.createdToken = params
	return appdomain.ApplicationToken{
		ID:            "42345678-1234-4234-9234-123456789abc",
		ApplicationID: params.ApplicationID,
		Name:          params.Name,
		TokenHash:     params.TokenHash,
		Status:        appdomain.TokenStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     params.ExpiresAt,
	}, nil
}

func (f *httpAppFakeStore) LookupTokenByHash(context.Context, string) (appdomain.TokenIdentity, error) {
	if f.tokenIdentity.Token.ID == "" {
		return appdomain.TokenIdentity{}, storage.ErrNoRows
	}
	return f.tokenIdentity, nil
}

func (f *httpAppFakeStore) MarkTokenUsed(_ context.Context, tokenID string) error {
	f.markedTokenID = tokenID
	return nil
}

func (f *httpAppFakeStore) ListTokens(context.Context, string, appdomain.ListTokensParams) ([]appdomain.ApplicationToken, error) {
	return nil, errors.New("not implemented")
}

func (f *httpAppFakeStore) CountTokens(context.Context, string, appdomain.ListTokensParams) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *httpAppFakeStore) RevokeToken(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (f *httpAppFakeStore) AddDomainScope(context.Context, appdomain.AddDomainScopeParams) (appdomain.DomainScope, error) {
	return appdomain.DomainScope{}, errors.New("not implemented")
}

func (f *httpAppFakeStore) ListDomainScopes(context.Context, string, storage.ListOptions) ([]appdomain.DomainScope, error) {
	return nil, errors.New("not implemented")
}

func (f *httpAppFakeStore) CountDomainScopes(context.Context, string, storage.ListOptions) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *httpAppFakeStore) DeleteDomainScope(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (f *httpAppFakeStore) UpsertGrant(context.Context, appdomain.UpsertGrantParams) (appdomain.UserGrant, error) {
	return appdomain.UserGrant{}, errors.New("not implemented")
}

func (f *httpAppFakeStore) ListGrants(context.Context, string, storage.ListOptions) ([]appdomain.UserGrant, error) {
	return nil, errors.New("not implemented")
}

func (f *httpAppFakeStore) CountGrants(context.Context, string, storage.ListOptions) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *httpAppFakeStore) GetGrant(context.Context, string, string) (appdomain.UserGrant, error) {
	return appdomain.UserGrant{}, storage.ErrNoRows
}

func (f *httpAppFakeStore) DeleteGrant(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

type httpAppFakeAudit struct {
	events []auditdomain.AppendEventParams
}

func (f *httpAppFakeAudit) Append(_ context.Context, params auditdomain.AppendEventParams) (auditdomain.Event, error) {
	f.events = append(f.events, params)
	return auditdomain.Event{}, nil
}
