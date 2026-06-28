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

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

func TestIdentityTokenClassRouting(t *testing.T) {
	handler := New(testConfig(t, ""), WithIdentityServices(testAuthService(t, fakeUser()), nil)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+auth.UserRefreshTokenPrefix+strings.Repeat("A", 43))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, "refresh_token_not_allowed")

	req = httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+auth.UserRefreshTokenPrefix+strings.Repeat("B", 43)+`"}`))
	req.Header.Set("Authorization", "Bearer "+auth.UserRefreshTokenPrefix+strings.Repeat("C", 43))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, "refresh_token_not_allowed")
}

func TestUserEndpointRejectsApplicationTokenByPrefix(t *testing.T) {
	authSvc := testAuthService(t, fakeUser())
	userSvc := userdomain.NewService(userdomain.ServiceConfig{
		Repository:      &identityFakeUserRepo{user: fakeUser()},
		AuditRepository: identityFakeAudit{},
		KeySet:          testKeySet(t),
		Config:          testConfig(t, "").Auth,
	})
	handler := New(testConfig(t, ""), WithIdentityServices(authSvc, userSvc)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("Authorization", "Bearer cth_app_v1_"+strings.Repeat("A", 43))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, "user_token_required")
}

func TestAuthMeWithUserAccessToken(t *testing.T) {
	user := fakeUser()
	token := auth.UserAccessTokenPrefix + strings.Repeat("A", 43)
	repo := &identityFakeAuthRepo{session: auth.Session{
		ID:              "22345678-1234-4234-9234-123456789abc",
		UserID:          user.ID,
		AuthMethod:      auth.AuthMethodPassword,
		AccessTokenHash: testKeySet(t).HashToken(token),
		Status:          auth.SessionStatusActive,
		AccessExpiresAt: time.Now().Add(time.Minute),
	}}
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          testKeySet(t),
		Config:          testConfig(t, "").Auth,
	})
	handler := New(testConfig(t, ""), WithIdentityServices(authSvc, nil)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if repo.markedSessionID != repo.session.ID {
		t.Fatalf("session last-used was not marked: %q", repo.markedSessionID)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["identity_type"] != "user" || strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), token) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestIdentityConflictErrorCarriesRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	writeIdentityError(rec, auth.ErrConflict)
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

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["code"] != code {
		t.Fatalf("error code = %#v body = %s", body["error"]["code"], rec.Body.String())
	}
}

func testAuthService(t *testing.T, user userdomain.User) *auth.Service {
	t.Helper()
	return auth.NewService(auth.ServiceConfig{
		AuthRepository:  &identityFakeAuthRepo{},
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          testKeySet(t),
		Config:          testConfig(t, "").Auth,
	})
}

func testKeySet(t *testing.T) *security.KeySet {
	t.Helper()
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func fakeUser() userdomain.User {
	now := time.Now()
	return userdomain.User{
		ID:                    "12345678-1234-4234-9234-123456789abc",
		Email:                 "user@example.com",
		DisplayName:           "User Name",
		GlobalRole:            userdomain.GlobalRoleAdmin,
		Status:                userdomain.StatusActive,
		CreatedAt:             now,
		UpdatedAt:             now,
		ApplicationGrantCount: 0,
	}
}

type identityFakeAuthRepo struct {
	session         auth.Session
	markedSessionID string
}

func (f *identityFakeAuthRepo) CreateSession(context.Context, auth.CreateSessionParams) (auth.Session, error) {
	return auth.Session{}, errors.New("not implemented")
}

func (f *identityFakeAuthRepo) GetSessionByAccessTokenHash(context.Context, string) (auth.Session, error) {
	if f.session.ID == "" {
		return auth.Session{}, storage.ErrNoRows
	}
	return f.session, nil
}

func (f *identityFakeAuthRepo) MarkSessionUsed(_ context.Context, id string) error {
	f.markedSessionID = id
	return nil
}

func (f *identityFakeAuthRepo) RevokeSession(context.Context, string, auth.SessionRevokedReason) (bool, error) {
	return false, errors.New("not implemented")
}

func (f *identityFakeAuthRepo) RotateRefreshToken(context.Context, auth.RotateRefreshTokenParams) (auth.Session, error) {
	return auth.Session{}, errors.New("not implemented")
}

func (f *identityFakeAuthRepo) CreateOIDCState(context.Context, auth.CreateOIDCStateParams) (auth.OIDCLoginState, error) {
	return auth.OIDCLoginState{}, errors.New("not implemented")
}

func (f *identityFakeAuthRepo) ConsumeOIDCState(context.Context, string) (auth.OIDCLoginState, error) {
	return auth.OIDCLoginState{}, errors.New("not implemented")
}

func (f *identityFakeAuthRepo) CreateOIDCHandoff(context.Context, auth.CreateOIDCHandoffParams) (auth.OIDCLoginHandoff, error) {
	return auth.OIDCLoginHandoff{}, errors.New("not implemented")
}

func (f *identityFakeAuthRepo) ConsumeOIDCHandoff(context.Context, string) (auth.OIDCLoginHandoff, error) {
	return auth.OIDCLoginHandoff{}, errors.New("not implemented")
}

type identityFakeUserRepo struct {
	user userdomain.User
}

func (f *identityFakeUserRepo) Get(context.Context, string) (userdomain.User, error) {
	return f.user, nil
}

func (f *identityFakeUserRepo) LookupByNormalizedEmail(context.Context, string) (userdomain.User, error) {
	return f.user, nil
}

func (f *identityFakeUserRepo) LookupActiveByNormalizedEmail(context.Context, string) (userdomain.User, error) {
	return f.user, nil
}

func (f *identityFakeUserRepo) LookupByOIDC(context.Context, string, string) (userdomain.User, error) {
	return f.user, nil
}

func (f *identityFakeUserRepo) Create(context.Context, userdomain.CreateUserParams) (userdomain.User, error) {
	return f.user, nil
}

func (f *identityFakeUserRepo) List(context.Context, userdomain.ListUsersParams) ([]userdomain.User, error) {
	return []userdomain.User{f.user}, nil
}

func (f *identityFakeUserRepo) Count(context.Context, userdomain.ListUsersParams) (int64, error) {
	return 1, nil
}

func (f *identityFakeUserRepo) Update(context.Context, string, userdomain.UpdateUserParams) (userdomain.User, error) {
	return f.user, nil
}

type identityFakeAudit struct{}

func (identityFakeAudit) Append(context.Context, audit.AppendEventParams) (audit.Event, error) {
	return audit.Event{}, nil
}
