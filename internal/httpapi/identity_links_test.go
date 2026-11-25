package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/config"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

// linkFakeAuthRepo lets the admin password-reset-link endpoint succeed.
type linkFakeAuthRepo struct {
	*identityFakeAuthRepo
}

func (linkFakeAuthRepo) CreatePasswordReset(_ context.Context, params auth.CreatePasswordResetParams) (auth.PasswordResetToken, error) {
	return auth.PasswordResetToken{
		ID:              params.ID,
		UserID:          params.UserID,
		TokenHash:       params.TokenHash,
		CreatedByUserID: params.CreatedByUserID,
		ExpiresAt:       params.ExpiresAt,
	}, nil
}

// linkFakeUserRepo lets the invite endpoint succeed for a new email.
type linkFakeUserRepo struct {
	*identityFakeUserRepo
}

func (linkFakeUserRepo) LookupActiveByNormalizedEmail(context.Context, string) (userdomain.User, error) {
	return userdomain.User{}, storage.ErrNoRows
}

const linkTestAccessToken = auth.UserAccessTokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func linkTestConfig(t *testing.T) *config.Config {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.test"
http:
  require_https: false
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
}

func linkTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := linkTestConfig(t)
	admin := fakeUser()
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository: linkFakeAuthRepo{&identityFakeAuthRepo{session: auth.Session{
			ID:               "22345678-1234-4234-9234-123456789abc",
			UserID:           admin.ID,
			AuthMethod:       auth.AuthMethodPassword,
			AccessTokenHash:  testKeySet(t).HashToken(linkTestAccessToken),
			Status:           auth.SessionStatusActive,
			AccessExpiresAt:  time.Now().Add(time.Minute),
			SessionExpiresAt: time.Now().Add(time.Hour),
		}}},
		UserRepository:  &identityFakeUserRepo{user: admin},
		AuditRepository: identityFakeAudit{},
		KeySet:          testKeySet(t),
		Config:          cfg.Auth,
	})
	usersSvc := userdomain.NewService(userdomain.ServiceConfig{
		Repository:      linkFakeUserRepo{&identityFakeUserRepo{user: admin}},
		AuditRepository: identityFakeAudit{},
		KeySet:          testKeySet(t),
		Config:          cfg.Auth,
	})
	return New(cfg, WithIdentityServices(authSvc, usersSvc))
}

type linkRequest struct {
	host       string
	tls        bool
	remoteAddr string
	headers    map[string]string
}

func (lr linkRequest) build(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = lr.host
	if lr.tls {
		req.TLS = &tls.ConnectionState{}
	} else {
		req.TLS = nil
	}
	if lr.remoteAddr != "" {
		req.RemoteAddr = lr.remoteAddr
	}
	for name, value := range lr.headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("Authorization", "Bearer "+linkTestAccessToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func createInviteURL(t *testing.T, handler http.Handler, lr linkRequest) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, lr.build(http.MethodPost, "/v1/users", `{"email":"new.user@example.com","global_role":"user"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create invite status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Invite struct {
			InviteURL string `json:"invite_url"`
		} `json:"invite"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Invite.InviteURL
}

func createResetURL(t *testing.T, handler http.Handler, lr linkRequest) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, lr.build(http.MethodPost, "/v1/users/"+fakeUser().ID+"/password-reset-link", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("create reset link status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		PasswordReset struct {
			ResetURL string `json:"reset_url"`
		} `json:"password_reset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.PasswordReset.ResetURL
}

func assertLinkBase(t *testing.T, kind, got, wantPrefix, tokenPrefix string) {
	t.Helper()
	if !strings.HasPrefix(got, wantPrefix+tokenPrefix) {
		t.Errorf("%s = %q, want prefix %q", kind, got, wantPrefix+tokenPrefix)
		return
	}
	token := strings.TrimPrefix(got, wantPrefix)
	if strings.ContainsAny(token, "/:?#&") {
		t.Errorf("%s = %q has unexpected text after the base URL", kind, got)
	}
}

func TestGeneratedLinksUseEffectiveHostPort(t *testing.T) {
	const trustedPeer = "10.0.0.20:443"
	cases := []struct {
		name     string
		req      linkRequest
		wantBase string
	}{
		{
			name:     "direct TLS with non-default port keeps port",
			req:      linkRequest{host: "certhub.example.test:8443", tls: true},
			wantBase: "https://certhub.example.test:8443",
		},
		{
			name:     "direct plain HTTP with non-default port keeps port",
			req:      linkRequest{host: "certhub.example.test:8080"},
			wantBase: "http://certhub.example.test:8080",
		},
		{
			name: "trusted X-Forwarded-Host with non-default port keeps port",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "certhub.example.test:8443",
			}},
			wantBase: "https://certhub.example.test:8443",
		},
		{
			name: "trusted Forwarded host with non-default port keeps port",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"Forwarded": `for=203.0.113.9;proto=https;host="certhub.example.test:8443"`,
			}},
			wantBase: "https://certhub.example.test:8443",
		},
		{
			name: "trusted proxy scheme only keeps Host port",
			req: linkRequest{host: "certhub.example.test:8443", remoteAddr: trustedPeer, headers: map[string]string{
				"X-Forwarded-Proto": "https",
			}},
			wantBase: "https://certhub.example.test:8443",
		},
		{
			name: "Forwarded host port wins over X-Forwarded-Host port",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"Forwarded":        `proto=https;host="certhub.example.test:8443"`,
				"X-Forwarded-Host": "certhub.example.test:9443",
			}},
			wantBase: "https://certhub.example.test:8443",
		},
		{
			name: "untrusted X-Forwarded-Host port is ignored",
			req: linkRequest{host: "certhub.example.test:8443", tls: true, remoteAddr: "198.51.100.10:1234", headers: map[string]string{
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "certhub.example.test:9443",
			}},
			wantBase: "https://certhub.example.test:8443",
		},
		{
			name:     "https on port 80 keeps port",
			req:      linkRequest{host: "certhub.example.test:80", tls: true},
			wantBase: "https://certhub.example.test:80",
		},
		{
			name:     "leading zeros in port are normalized",
			req:      linkRequest{host: "certhub.example.test:08443", tls: true},
			wantBase: "https://certhub.example.test:8443",
		},
		// Default ports and hosts without a port must keep today's output.
		{
			name:     "direct TLS default port 443 is omitted",
			req:      linkRequest{host: "certhub.example.test:443", tls: true},
			wantBase: "https://certhub.example.test",
		},
		{
			name:     "direct plain HTTP default port 80 is omitted",
			req:      linkRequest{host: "certhub.example.test:80"},
			wantBase: "http://certhub.example.test",
		},
		{
			name:     "TLS host without port is unchanged",
			req:      linkRequest{host: "certhub.example.test", tls: true},
			wantBase: "https://certhub.example.test",
		},
		{
			name:     "plain HTTP host without port is unchanged",
			req:      linkRequest{host: "certhub.example.test"},
			wantBase: "http://certhub.example.test",
		},
		{
			name: "trusted X-Forwarded-Host default port 443 is omitted",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "certhub.example.test:443",
			}},
			wantBase: "https://certhub.example.test",
		},
		{
			name: "trusted Forwarded host default port 443 is omitted",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"Forwarded": `for=203.0.113.9;proto=https;host="certhub.example.test:443"`,
			}},
			wantBase: "https://certhub.example.test",
		},
		{
			name: "trusted forwarded host without port does not take internal Host port",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "certhub.example.test",
			}},
			wantBase: "https://certhub.example.test",
		},
		{
			name: "trusted Forwarded host without port does not take internal Host port",
			req: linkRequest{host: "internal.invalid:8080", remoteAddr: trustedPeer, headers: map[string]string{
				"Forwarded": `for=203.0.113.9;proto=https;host=certhub.example.test`,
			}},
			wantBase: "https://certhub.example.test",
		},
		{
			name:     "non-numeric port is dropped and host check is unchanged",
			req:      linkRequest{host: "certhub.example.test:abc", tls: true},
			wantBase: "https://certhub.example.test",
		},
		{
			name:     "out of range port is dropped",
			req:      linkRequest{host: "certhub.example.test:65536", tls: true},
			wantBase: "https://certhub.example.test",
		},
		{
			name:     "port zero is dropped",
			req:      linkRequest{host: "certhub.example.test:0", tls: true},
			wantBase: "https://certhub.example.test",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := linkTestServer(t).Handler()
			assertLinkBase(t, "invite_url", createInviteURL(t, handler, tc.req), tc.wantBase+"/signup?invite=", "cth_inv_v1_")
			assertLinkBase(t, "reset_url", createResetURL(t, handler, tc.req), tc.wantBase+"/reset-password?token=", "cth_pwd_reset_v1_")
		})
	}
}

func TestGeneratedLinksPublicHostnameFallbackIsPortless(t *testing.T) {
	server := linkTestServer(t)
	reqctx := RequestContext{EffectiveScheme: "https"}
	if got, want := server.userInviteURL(reqctx, "cth_inv_v1_token"), "https://certhub.example.test/signup?invite=cth_inv_v1_token"; got != want {
		t.Fatalf("invite_url = %q, want %q", got, want)
	}
	if got, want := server.passwordResetURL(reqctx, "cth_pwd_reset_v1_token"), "https://certhub.example.test/reset-password?token=cth_pwd_reset_v1_token"; got != want {
		t.Fatalf("reset_url = %q, want %q", got, want)
	}

	// An IP-literal Host is rejected as an effective host, so its port must
	// not be attached to the public_hostname fallback.
	req := httptest.NewRequest(http.MethodPost, "/v1/users", nil)
	req.Host = "192.0.2.10:8443"
	reqctx = server.deriveRequestContext(req, "req-1")
	if reqctx.EffectiveHost != "" {
		t.Fatalf("IP-literal host was accepted: %#v", reqctx)
	}
	if got, want := server.userInviteURL(reqctx, "cth_inv_v1_token"), "http://certhub.example.test/signup?invite=cth_inv_v1_token"; got != want {
		t.Fatalf("invite_url = %q, want %q", got, want)
	}
}

func TestRequestContextKeepsHostPortSeparate(t *testing.T) {
	server := linkTestServer(t)
	cases := []struct {
		name       string
		host       string
		remoteAddr string
		headers    map[string]string
		wantHost   string
		wantPort   string
	}{
		{name: "Host with port", host: "Certhub.Example.Test.:8443", wantHost: "certhub.example.test", wantPort: "8443"},
		{name: "Host without port", host: "certhub.example.test", wantHost: "certhub.example.test"},
		{name: "trusted X-Forwarded-Host replaces Host port", host: "internal.invalid:8080", remoteAddr: "10.0.0.20:443",
			headers:  map[string]string{"X-Forwarded-Host": "evil.example.test:1, certhub.example.test:9443"},
			wantHost: "certhub.example.test", wantPort: "9443"},
		{name: "trusted Forwarded uses rightmost element port", host: "internal.invalid:8080", remoteAddr: "10.0.0.20:443",
			headers:  map[string]string{"Forwarded": `host="evil.example.test:1", host=certhub.example.test`},
			wantHost: "certhub.example.test"},
		{name: "untrusted X-Forwarded-Host is ignored", host: "certhub.example.test:8443", remoteAddr: "198.51.100.10:1234",
			headers:  map[string]string{"X-Forwarded-Host": "certhub.example.test:9443"},
			wantHost: "certhub.example.test", wantPort: "8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tc.host
			if tc.remoteAddr != "" {
				req.RemoteAddr = tc.remoteAddr
			}
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			ctx := server.deriveRequestContext(req, "req-1")
			if ctx.EffectiveHost != tc.wantHost || ctx.EffectivePort != tc.wantPort || ctx.ForwardedMalformed {
				t.Fatalf("context = %#v, want host %q port %q", ctx, tc.wantHost, tc.wantPort)
			}
			if !server.acceptHost(ctx) {
				t.Fatalf("host check rejected %#v", ctx)
			}
		})
	}
}
