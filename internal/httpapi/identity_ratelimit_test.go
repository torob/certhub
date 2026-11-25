package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/torob/certhub/internal/auth"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

// Default per-process limit for one normalized email plus source IP.
const testLoginEmailIPFailureLimit = 5

func TestPasswordLoginRateLimitedForKnownAndUnknownEmail(t *testing.T) {
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	known := fakeUser()
	known.PasswordHash = &hash
	cases := []struct {
		name     string
		email    string
		userRepo auth.UserRepository
	}{
		{name: "known email", email: known.Email, userRepo: &identityFakeUserRepo{user: known}},
		{name: "unknown email", email: "nobody@example.com", userRepo: identityMissingUserRepo{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authSvc := auth.NewService(auth.ServiceConfig{
				AuthRepository:  &identityFakeAuthRepo{},
				UserRepository:  tc.userRepo,
				AuditRepository: identityFakeAudit{},
				KeySet:          testKeySet(t),
				Config:          testConfig(t, "").Auth,
			})
			handler := New(testConfig(t, ""), WithIdentityServices(authSvc, nil)).Handler()
			login := func(remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"`+tc.email+`","password":"wrong horse battery staple"}`))
				req.RemoteAddr = remoteAddr
				for name, value := range headers {
					req.Header.Set(name, value)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			for i := 0; i < testLoginEmailIPFailureLimit; i++ {
				assertErrorCode(t, login("203.0.113.7:1234", nil), http.StatusUnauthorized, "invalid_credentials")
			}
			rec := login("203.0.113.7:1234", nil)
			assertErrorCode(t, rec, http.StatusTooManyRequests, "rate_limited")
			assertRateLimitRetryAfter(t, rec)

			// Forwarded headers from an untrusted peer must not change the rate-limit key.
			spoofed := login("203.0.113.7:1234", map[string]string{"X-Forwarded-For": "198.51.100.99", "Forwarded": "for=198.51.100.98"})
			assertErrorCode(t, spoofed, http.StatusTooManyRequests, "rate_limited")

			// The email plus source IP key does not block the same email from another source IP.
			assertErrorCode(t, login("203.0.113.8:1234", nil), http.StatusUnauthorized, "invalid_credentials")
		})
	}
}

func assertRateLimitRetryAfter(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	header, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || header <= 0 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["retryable"] != true || body["error"]["retry_after_seconds"] != float64(header) {
		t.Fatalf("rate limit body = %s", rec.Body.String())
	}
}

type identityMissingUserRepo struct{}

func (identityMissingUserRepo) Get(context.Context, string) (userdomain.User, error) {
	return userdomain.User{}, storage.ErrNoRows
}

func (identityMissingUserRepo) GetForUpdate(context.Context, string) (userdomain.User, error) {
	return userdomain.User{}, storage.ErrNoRows
}

func (identityMissingUserRepo) LookupByNormalizedEmail(context.Context, string) (userdomain.User, error) {
	return userdomain.User{}, storage.ErrNoRows
}

func (identityMissingUserRepo) LookupByOIDC(context.Context, string, string) (userdomain.User, error) {
	return userdomain.User{}, storage.ErrNoRows
}

func (identityMissingUserRepo) Update(context.Context, string, userdomain.UpdateUserParams) (userdomain.User, error) {
	return userdomain.User{}, storage.ErrNoRows
}
