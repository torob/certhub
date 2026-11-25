package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/torob/certhub/internal/auth"
	security "github.com/torob/certhub/internal/crypto"
)

// canceledSessionAuthRepo returns the context error from CreateSession, as
// PostgreSQL does when the request context is canceled.
type canceledSessionAuthRepo struct {
	identityFakeAuthRepo
}

func (f *canceledSessionAuthRepo) CreateSession(ctx context.Context, params auth.CreateSessionParams) (auth.Session, error) {
	if err := ctx.Err(); err != nil {
		return auth.Session{}, err
	}
	return f.identityFakeAuthRepo.CreateSession(ctx, params)
}

// testClientClosedStatus is the nginx "client closed request" status.
const testClientClosedStatus = 499

func TestCanceledPasswordLoginIsClientClosedRequest(t *testing.T) {
	const password = "correct horse battery staple"
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user := fakeUser()
	user.PasswordHash = &hash
	cfg := testConfig(t, `
auth:
  password:
    2fa_required: false
`)
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository:  &canceledSessionAuthRepo{},
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          testKeySet(t),
		Config:          cfg.Auth,
	})
	var logs bytes.Buffer
	handler := New(cfg, WithIdentityServices(authSvc, nil), WithLogWriter(&logs)).Handler()
	login := func(ctx context.Context, password string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"`+user.Email+`","password":"`+password+`"}`)).WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// The client closes the request. The login then fails with
	// context.Canceled, either in the Argon2id slot wait or in the session
	// write.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	rec := login(canceled, password)
	if rec.Code != testClientClosedStatus || rec.Body.Len() != 0 {
		t.Errorf("status = %d body = %q", rec.Code, rec.Body.String())
	}
	events := decodeLogEvents(t, logs.String())
	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0]["status"] != float64(testClientClosedStatus) || events[0]["level"] != "warn" || events[0]["error_code"] != "" {
		t.Errorf("event = %#v", events[0])
	}

	// A canceled login is not a failed login. More canceled logins than the
	// failure limit must not rate limit the next login.
	for i := 0; i < testLoginEmailIPFailureLimit; i++ {
		if rec := login(canceled, password); rec.Code != testClientClosedStatus {
			t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
		}
	}
	assertErrorCode(t, login(context.Background(), "wrong horse battery staple"), http.StatusUnauthorized, "invalid_credentials")

	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `certhub_http_requests_total{method="POST",path="/v1/*",status="499",error_code=""} 6`) {
		t.Fatalf("metrics = %s", metrics.Body.String())
	}
	if strings.Contains(metrics.Body.String(), `status="500"`) {
		t.Fatalf("canceled login counted as server error: %s", metrics.Body.String())
	}
}

func TestErrorMappersTreatOnlyClientCancelAsClientClosed(t *testing.T) {
	mappers := map[string]func(http.ResponseWriter, error) (int, string){
		"identity":     writeIdentityError,
		"application":  writeApplicationError,
		"audit":        writeAuditError,
		"certificate":  writeCertificateError,
		"issuer":       writeIssuerError,
		"dns provider": writeDNSProviderError,
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name       string
		requestCtx context.Context
		err        error
		status     int
	}{
		{name: "client closed", requestCtx: canceled, err: fmt.Errorf("lookup user: %w", context.Canceled), status: testClientClosedStatus},
		{name: "server-side cancel", requestCtx: context.Background(), err: context.Canceled, status: http.StatusInternalServerError},
		{name: "deadline after client closed", requestCtx: canceled, err: context.DeadlineExceeded, status: http.StatusInternalServerError},
		{name: "server error after client closed", requestCtx: canceled, err: errors.New("postgresql error"), status: http.StatusInternalServerError},
	}
	for name, write := range mappers {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				status, code := write(&requestResponseWriter{ResponseWriter: rec, ctx: tc.requestCtx}, tc.err)
				if status != tc.status || rec.Code != tc.status {
					t.Fatalf("status = %d recorded = %d body = %q", status, rec.Code, rec.Body.String())
				}
				if tc.status != testClientClosedStatus {
					if code != "internal_error" {
						t.Fatalf("code = %q", code)
					}
					assertErrorCode(t, rec, tc.status, "internal_error")
					return
				}
				if code != "" || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
					t.Fatalf("code = %q content type = %q body = %q", code, rec.Header().Get("Content-Type"), rec.Body.String())
				}
			})
		}
	}
}
