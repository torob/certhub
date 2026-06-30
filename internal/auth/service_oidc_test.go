package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestStartOIDCLoginBuildsAuthorizationCodePKCERedirect(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := &oidcFakeRepo{}
	discoveryRequests := 0
	provider := oidcDiscoveryServer(t, func(base string) map[string]string {
		discoveryRequests++
		return map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/custom/authorize",
			"token_endpoint":         base + "/oauth/v2/token",
			"jwks_uri":               base + "/oauth/v2/keys",
		}
	})
	service := NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled:           true,
				IssuerURL:         provider.URL,
				ClientID:          "certhub-web",
				RedirectURL:       "https://certhub.example.com/v1/auth/oidc/callback",
				AllowedReturnURLs: []string{"https://certhub.example.com/auth/callback"},
			},
		},
		HTTPClient: provider.Client(),
	})
	result, err := service.StartOIDCLogin(context.Background(), "https://certhub.example.com/auth/callback", AuditContext{SourceIP: "203.0.113.10", UserAgent: "test-agent"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if discoveryRequests != 1 {
		t.Fatalf("discovery requests = %d", discoveryRequests)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != provider.URL+"/custom/authorize" {
		t.Fatalf("authorization endpoint = %q", got)
	}
	query := parsed.Query()
	expectedKeys := map[string]bool{
		"response_type":         true,
		"client_id":             true,
		"redirect_uri":          true,
		"scope":                 true,
		"state":                 true,
		"nonce":                 true,
		"code_challenge":        true,
		"code_challenge_method": true,
	}
	for key, values := range query {
		if !expectedKeys[key] {
			t.Fatalf("unexpected authorization query parameter %q", key)
		}
		if len(values) != 1 {
			t.Fatalf("authorization query parameter %q has %d values", key, len(values))
		}
	}
	for key := range expectedKeys {
		if _, ok := query[key]; !ok {
			t.Fatalf("authorization query parameter %q is missing", key)
		}
	}
	for _, forbidden := range []string{"code_verifier", "client_secret", "access_token", "refresh_token", "id_token"} {
		if query.Get(forbidden) != "" {
			t.Fatalf("authorization URL leaked forbidden parameter %q", forbidden)
		}
	}
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "certhub-web",
		"redirect_uri":          "https://certhub.example.com/v1/auth/oidc/callback",
		"scope":                 "openid email profile",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("%s = %q", key, got)
		}
	}
	state := query.Get("state")
	nonce := query.Get("nonce")
	challenge := query.Get("code_challenge")
	if state == "" || nonce == "" || challenge == "" {
		t.Fatalf("missing state, nonce, or code challenge")
	}
	if !strings.HasPrefix(state, oidcStatePrefix) || len(strings.TrimPrefix(state, oidcStatePrefix)) != 43 {
		t.Fatalf("unexpected state shape")
	}
	if len(nonce) != 43 || len(challenge) != 43 {
		t.Fatalf("unexpected nonce/challenge lengths")
	}
	if repo.createdState.StateHash != keys.HashOIDCState(state) {
		t.Fatalf("state hash was not stored")
	}
	if repo.createdState.Nonce != nonce {
		t.Fatalf("nonce was not stored")
	}
	if repo.createdState.ProviderCallbackURL != "https://certhub.example.com/v1/auth/oidc/callback" {
		t.Fatalf("provider callback URL mismatch")
	}
	if repo.createdState.FrontendReturnURL == nil || *repo.createdState.FrontendReturnURL != "https://certhub.example.com/auth/callback" {
		t.Fatalf("frontend return URL mismatch")
	}
	verifier, err := keys.OpenDatabaseValue(repo.createdState.CodeVerifierEncrypted, oidcVerifierAAD(repo.createdState.ID))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(verifier)
	if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("code challenge was not derived from stored verifier")
	}
}

func TestStartOIDCLoginAllowsDefaultSameOriginReturnURLBeforeDiscovery(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := &oidcFakeRepo{}
	discoveryRequests := 0
	provider := oidcDiscoveryServer(t, func(base string) map[string]string {
		discoveryRequests++
		return map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/custom/authorize",
			"token_endpoint":         base + "/oauth/v2/token",
			"jwks_uri":               base + "/oauth/v2/keys",
		}
	})
	service := NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled:     true,
				IssuerURL:   provider.URL,
				ClientID:    "certhub-web",
				RedirectURL: "https://certhub.example.com/v1/auth/oidc/callback",
			},
		},
		HTTPClient: provider.Client(),
	})
	if _, err := service.StartOIDCLogin(context.Background(), "https://certhub.example.com/auth/callback?next=%2F", AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if discoveryRequests != 1 {
		t.Fatalf("discovery requests = %d", discoveryRequests)
	}
	if repo.createdState.FrontendReturnURL == nil || *repo.createdState.FrontendReturnURL != "https://certhub.example.com/auth/callback?next=%2F" {
		t.Fatalf("frontend return URL mismatch")
	}

	_, err = service.StartOIDCLogin(context.Background(), "https://evil.example.com/auth/callback", AuditContext{})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-origin return URL err = %v", err)
	}
	if discoveryRequests != 1 {
		t.Fatalf("invalid return URL triggered discovery")
	}
}

func TestStartOIDCLoginRejectsInvalidDiscoveryMetadata(t *testing.T) {
	tests := []struct {
		name      string
		discovery func(string) map[string]string
	}{
		{
			name: "missing issuer",
			discovery: func(base string) map[string]string {
				return map[string]string{
					"authorization_endpoint": base + "/custom/authorize",
					"token_endpoint":         base + "/oauth/v2/token",
					"jwks_uri":               base + "/oauth/v2/keys",
				}
			},
		},
		{
			name: "authorization endpoint query",
			discovery: func(base string) map[string]string {
				return map[string]string{
					"issuer":                 base,
					"authorization_endpoint": base + "/custom/authorize?client_secret=leak",
					"token_endpoint":         base + "/oauth/v2/token",
					"jwks_uri":               base + "/oauth/v2/keys",
				}
			},
		},
		{
			name: "token endpoint userinfo",
			discovery: func(base string) map[string]string {
				return map[string]string{
					"issuer":                 base,
					"authorization_endpoint": base + "/custom/authorize",
					"token_endpoint":         strings.Replace(base, "https://", "https://user:pass@", 1) + "/oauth/v2/token",
					"jwks_uri":               base + "/oauth/v2/keys",
				}
			},
		},
		{
			name: "jwks fragment",
			discovery: func(base string) map[string]string {
				return map[string]string{
					"issuer":                 base,
					"authorization_endpoint": base + "/custom/authorize",
					"token_endpoint":         base + "/oauth/v2/token",
					"jwks_uri":               base + "/oauth/v2/keys#fragment",
				}
			},
		},
		{
			name: "plain http endpoint",
			discovery: func(base string) map[string]string {
				return map[string]string{
					"issuer":                 base,
					"authorization_endpoint": strings.Replace(base, "https://", "http://", 1) + "/custom/authorize",
					"token_endpoint":         base + "/oauth/v2/token",
					"jwks_uri":               base + "/oauth/v2/keys",
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := security.NewKeySet(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			repo := &oidcFakeRepo{}
			provider := oidcDiscoveryServer(t, tt.discovery)
			service := NewService(ServiceConfig{
				AuthRepository:  repo,
				UserRepository:  repo,
				AuditRepository: repo,
				KeySet:          keys,
				Config: config.AuthConfig{
					UserAccessTokenTTLSeconds:  300,
					UserRefreshTokenTTLSeconds: 3600,
					OIDC: config.OIDCConfig{
						Enabled:           true,
						IssuerURL:         provider.URL,
						ClientID:          "certhub-web",
						RedirectURL:       "https://certhub.example.com/v1/auth/oidc/callback",
						AllowedReturnURLs: []string{"https://certhub.example.com/auth/callback"},
					},
				},
				HTTPClient: provider.Client(),
			})
			_, err = service.StartOIDCLogin(context.Background(), "https://certhub.example.com/auth/callback", AuditContext{})
			if !errors.Is(err, ErrOIDCValidationFailed) {
				t.Fatalf("err = %v", err)
			}
			if repo.createdState.ID != "" {
				t.Fatalf("invalid discovery created OIDC state")
			}
		})
	}
}

func TestValidateIDTokenVerifiesRS256ClaimsAndNonce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key"
	const issuer = "https://issuer.example.com"
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	token := signedOIDCTestToken(t, key, kid, map[string]any{
		"iss":   issuer,
		"sub":   "subject-1",
		"aud":   []string{"certhub-web"},
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nonce": "nonce-1",
		"email": "user@example.com",
	})
	service := NewService(ServiceConfig{
		Config:     config.AuthConfig{OIDC: config.OIDCConfig{ClientID: "certhub-web"}},
		HTTPClient: server.Client(),
	})
	claims, err := service.validateIDToken(context.Background(), token, oidcDiscovery{Issuer: issuer, JWKSURI: server.URL + "/jwks"}, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "subject-1" || claims.Email != "user@example.com" {
		t.Fatalf("claims = %#v", claims)
	}
	if _, err := service.validateIDToken(context.Background(), token, oidcDiscovery{Issuer: issuer, JWKSURI: server.URL + "/jwks"}, "wrong-nonce"); !errors.Is(err, ErrOIDCValidationFailed) {
		t.Fatalf("wrong nonce err = %v", err)
	}
}

func TestCompleteOIDCCallbackExchangesCodeWithPKCEAndCreatesHandoff(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const (
		kid          = "provider-key"
		rawState     = "cth_oidc_state_1234567890123456789012345678901234567890123"
		stateID      = "12345678-1234-4234-9234-123456789abc"
		codeVerifier = "stored-pkce-verifier"
		authCode     = "provider-auth-code"
		nonce        = "nonce-from-state"
		userID       = "12345678-1234-4234-9234-000000000001"
	)
	encryptedVerifier, err := keys.SealDatabaseValue([]byte(codeVerifier), oidcVerifierAAD(stateID))
	if err != nil {
		t.Fatal(err)
	}
	repo := &oidcFakeRepo{
		wantStateHash: keys.HashOIDCState(rawState),
		state: OIDCLoginState{
			ID:                    stateID,
			StateHash:             keys.HashOIDCState(rawState),
			Nonce:                 nonce,
			CodeVerifierEncrypted: encryptedVerifier,
			ProviderCallbackURL:   "https://certhub.example.com/v1/auth/oidc/callback",
			FrontendReturnURL:     ptrString("https://certhub.example.com/auth/callback?next=%2Fcertificates"),
			ExpiresAt:             time.Now().Add(time.Minute),
		},
		user: users.User{
			ID:          userID,
			Email:       "user@example.com",
			DisplayName: "OIDC User",
			OIDCIssuer:  ptrString(""),
			OIDCSubject: ptrString("subject-1"),
			GlobalRole:  users.GlobalRoleUser,
			Status:      users.StatusActive,
		},
	}
	tokenRequests := 0
	var issuedIDToken string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/oauth/v2/authorize",
				"token_endpoint":         server.URL + "/oauth/v2/token",
				"jwks_uri":               server.URL + "/oauth/v2/keys",
			})
		case "/oauth/v2/token":
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("token request method = %s", r.Method)
			}
			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Fatalf("token request Accept = %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Fatalf("token request Content-Type = %q", got)
			}
			if auth := r.Header.Get("Authorization"); auth != "" {
				t.Fatalf("token request used Authorization header")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			expectedForm := map[string]string{
				"grant_type":    "authorization_code",
				"code":          authCode,
				"redirect_uri":  "https://certhub.example.com/v1/auth/oidc/callback",
				"client_id":     "certhub-web",
				"code_verifier": codeVerifier,
			}
			if len(r.PostForm) != len(expectedForm) {
				t.Fatalf("token request parameter count = %d", len(r.PostForm))
			}
			for key, values := range r.PostForm {
				if _, ok := expectedForm[key]; !ok {
					t.Fatalf("token request included unexpected parameter %q", key)
				}
				if len(values) != 1 {
					t.Fatalf("token request parameter %q has %d values", key, len(values))
				}
			}
			for key, want := range expectedForm {
				if got := r.PostForm.Get(key); got != want {
					t.Fatalf("token request parameter %q mismatch", key)
				}
			}
			issuedIDToken = signedOIDCTestToken(t, signingKey, kid, map[string]any{
				"iss":            server.URL,
				"sub":            "subject-1",
				"aud":            "certhub-web",
				"exp":            time.Now().Add(time.Hour).Unix(),
				"iat":            time.Now().Add(-time.Minute).Unix(),
				"nonce":          nonce,
				"email":          "user@example.com",
				"email_verified": true,
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id_token":      issuedIDToken,
				"access_token":  "provider-access-token-canary",
				"refresh_token": "provider-refresh-token-canary",
			})
		case "/oauth/v2/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	repo.user.OIDCIssuer = &server.URL

	service := NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled:     true,
				IssuerURL:   server.URL,
				ClientID:    "certhub-web",
				RedirectURL: "https://certhub.example.com/v1/auth/oidc/callback",
			},
		},
		HTTPClient: server.Client(),
	})
	result, err := service.CompleteOIDCCallback(context.Background(), authCode, rawState, AuditContext{
		CorrelationID: "req-1",
		SourceIP:      "203.0.113.10",
		UserAgent:     "test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d", tokenRequests)
	}
	if repo.consumedStateHash != keys.HashOIDCState(rawState) {
		t.Fatalf("state was not consumed by HMAC hash")
	}
	redirect, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != "https://certhub.example.com/auth/callback" {
		t.Fatalf("redirect target = %q", got)
	}
	redirectQuery := redirect.Query()
	handoffID := redirect.Query().Get("handoff_id")
	if !strings.HasPrefix(handoffID, OIDCHandoffPrefix) {
		t.Fatalf("handoff ID shape mismatch")
	}
	expectedRedirectQuery := map[string]string{
		"next":       "/certificates",
		"handoff_id": handoffID,
	}
	if len(redirectQuery) != len(expectedRedirectQuery) {
		t.Fatalf("redirect query parameter count = %d", len(redirectQuery))
	}
	for key, values := range redirectQuery {
		want, ok := expectedRedirectQuery[key]
		if !ok {
			t.Fatalf("redirect included unexpected parameter %q", key)
		}
		if len(values) != 1 {
			t.Fatalf("redirect parameter %q has %d values", key, len(values))
		}
		if values[0] != want {
			t.Fatalf("redirect parameter %q mismatch", key)
		}
	}
	if !repo.createdHandoff {
		t.Fatalf("OIDC callback did not create handoff")
	}
	if repo.createdHandoffParams.HandoffHash != keys.HashToken(handoffID) || repo.createdHandoffParams.HandoffHash == handoffID {
		t.Fatalf("handoff was not stored as a hash")
	}
	if repo.createdHandoffParams.UserID != userID || repo.createdHandoffParams.OIDCLoginStateID == nil || *repo.createdHandoffParams.OIDCLoginStateID != stateID {
		t.Fatalf("unexpected handoff user/state: %#v", repo.createdHandoffParams)
	}
	if repo.createdHandoffParams.FrontendReturnURL == nil || *repo.createdHandoffParams.FrontendReturnURL != "https://certhub.example.com/auth/callback?next=%2Fcertificates" {
		t.Fatalf("handoff return URL mismatch")
	}
	if repo.lookupOIDCIssuer != server.URL || repo.lookupOIDCSubject != "subject-1" {
		t.Fatalf("OIDC lookup = issuer %q subject %q", repo.lookupOIDCIssuer, repo.lookupOIDCSubject)
	}
	auditPayload, err := json.Marshal(repo.auditEvents)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{authCode, rawState, codeVerifier, handoffID, issuedIDToken, "provider-access-token-canary", "provider-refresh-token-canary"} {
		if strings.Contains(string(auditPayload), forbidden) {
			t.Fatalf("audit events leaked sensitive OIDC value")
		}
	}
}

func TestCompleteOIDCCallbackLinksProvisionedUserByVerifiedEmail(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const (
		kid          = "provider-key"
		rawState     = "cth_oidc_state_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		stateID      = "12345678-1234-4234-9234-123456789abc"
		codeVerifier = "stored-pkce-verifier"
		authCode     = "provider-auth-code"
		nonce        = "nonce-from-state"
		userID       = "12345678-1234-4234-9234-000000000001"
	)
	encryptedVerifier, err := keys.SealDatabaseValue([]byte(codeVerifier), oidcVerifierAAD(stateID))
	if err != nil {
		t.Fatal(err)
	}
	repo := &oidcFakeRepo{
		wantStateHash: keys.HashOIDCState(rawState),
		state: OIDCLoginState{
			ID:                    stateID,
			StateHash:             keys.HashOIDCState(rawState),
			Nonce:                 nonce,
			CodeVerifierEncrypted: encryptedVerifier,
			ProviderCallbackURL:   "https://certhub.example.com/v1/auth/oidc/callback",
			ExpiresAt:             time.Now().Add(time.Minute),
		},
		user: users.User{
			ID:          userID,
			Email:       "user@example.com",
			DisplayName: "OIDC User",
			GlobalRole:  users.GlobalRoleUser,
			Status:      users.StatusActive,
		},
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/oauth/v2/authorize",
				"token_endpoint":         server.URL + "/oauth/v2/token",
				"jwks_uri":               server.URL + "/oauth/v2/keys",
			})
		case "/oauth/v2/token":
			idToken := signedOIDCTestToken(t, signingKey, kid, map[string]any{
				"iss":            server.URL,
				"sub":            "subject-verified-email",
				"aud":            "certhub-web",
				"exp":            time.Now().Add(time.Hour).Unix(),
				"iat":            time.Now().Add(-time.Minute).Unix(),
				"nonce":          nonce,
				"email":          "user@example.com",
				"email_verified": true,
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
		case "/oauth/v2/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	service := NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled:     true,
				IssuerURL:   server.URL,
				ClientID:    "certhub-web",
				RedirectURL: "https://certhub.example.com/v1/auth/oidc/callback",
			},
		},
		HTTPClient: server.Client(),
	})
	if _, err := service.CompleteOIDCCallback(context.Background(), authCode, rawState, AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if repo.lookupOIDCIssuer != server.URL || repo.lookupOIDCSubject != "subject-verified-email" {
		t.Fatalf("OIDC lookup = issuer %q subject %q", repo.lookupOIDCIssuer, repo.lookupOIDCSubject)
	}
	if repo.lookupEmail != "user@example.com" {
		t.Fatalf("email lookup = %q", repo.lookupEmail)
	}
	if repo.updatedUserID != userID || !repo.updatedUserParams.OIDCIssuer.Set || repo.updatedUserParams.OIDCIssuer.Value == nil || *repo.updatedUserParams.OIDCIssuer.Value != server.URL {
		t.Fatalf("issuer update = user %q params %#v", repo.updatedUserID, repo.updatedUserParams)
	}
	if !repo.updatedUserParams.OIDCSubject.Set || repo.updatedUserParams.OIDCSubject.Value == nil || *repo.updatedUserParams.OIDCSubject.Value != "subject-verified-email" {
		t.Fatalf("subject update = %#v", repo.updatedUserParams)
	}
	if !repo.createdHandoff || repo.createdHandoffParams.UserID != userID {
		t.Fatalf("handoff was not created for linked user: %#v", repo.createdHandoffParams)
	}
}

func TestCompleteOIDCCallbackRejectsInvalidProviderIdentitySignals(t *testing.T) {
	tests := []struct {
		name               string
		mutateClaims       func(map[string]any, string)
		signWithUnknownKey bool
		tokenKeyID         string
		userStatus         users.Status
		noExistingLink     bool
		wantErr            error
	}{
		{
			name: "bad issuer",
			mutateClaims: func(claims map[string]any, issuer string) {
				claims["iss"] = issuer + "/other"
			},
			wantErr: ErrOIDCValidationFailed,
		},
		{
			name: "bad audience",
			mutateClaims: func(claims map[string]any, _ string) {
				claims["aud"] = "other-client"
			},
			wantErr: ErrOIDCValidationFailed,
		},
		{
			name:               "bad signature",
			signWithUnknownKey: true,
			wantErr:            ErrOIDCValidationFailed,
		},
		{
			name:       "missing jwks key",
			tokenKeyID: "missing-key",
			wantErr:    ErrOIDCValidationFailed,
		},
		{
			name: "expired token",
			mutateClaims: func(claims map[string]any, _ string) {
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			},
			wantErr: ErrOIDCValidationFailed,
		},
		{
			name: "bad nonce",
			mutateClaims: func(claims map[string]any, _ string) {
				claims["nonce"] = "wrong-nonce"
			},
			wantErr: ErrOIDCValidationFailed,
		},
		{
			name:       "disabled linked user",
			userStatus: users.StatusDisabled,
			wantErr:    ErrOIDCUserNotProvisioned,
		},
		{
			name: "unverified email cannot create link",
			mutateClaims: func(claims map[string]any, _ string) {
				claims["email_verified"] = false
			},
			noExistingLink: true,
			wantErr:        ErrOIDCUserNotProvisioned,
		},
		{
			name: "missing verified email cannot create link",
			mutateClaims: func(claims map[string]any, _ string) {
				delete(claims, "email_verified")
			},
			noExistingLink: true,
			wantErr:        ErrOIDCUserNotProvisioned,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := security.NewKeySet(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			unknownKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			const (
				kid          = "provider-key"
				rawState     = "cth_oidc_state_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				stateID      = "12345678-1234-4234-9234-123456789abc"
				codeVerifier = "stored-pkce-verifier"
				authCode     = "provider-auth-code"
				nonce        = "nonce-from-state"
				userID       = "12345678-1234-4234-9234-000000000001"
			)
			encryptedVerifier, err := keys.SealDatabaseValue([]byte(codeVerifier), oidcVerifierAAD(stateID))
			if err != nil {
				t.Fatal(err)
			}
			status := tt.userStatus
			if status == "" {
				status = users.StatusActive
			}
			repo := &oidcFakeRepo{
				wantStateHash: keys.HashOIDCState(rawState),
				state: OIDCLoginState{
					ID:                    stateID,
					StateHash:             keys.HashOIDCState(rawState),
					Nonce:                 nonce,
					CodeVerifierEncrypted: encryptedVerifier,
					ProviderCallbackURL:   "https://certhub.example.com/v1/auth/oidc/callback",
					ExpiresAt:             time.Now().Add(time.Minute),
				},
				user: users.User{
					ID:          userID,
					Email:       "user@example.com",
					DisplayName: "OIDC User",
					OIDCIssuer:  ptrString(""),
					OIDCSubject: ptrString("subject-1"),
					GlobalRole:  users.GlobalRoleUser,
					Status:      status,
				},
			}
			tokenRequests := 0
			var issuedIDToken string
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{
						"issuer":                 server.URL,
						"authorization_endpoint": server.URL + "/oauth/v2/authorize",
						"token_endpoint":         server.URL + "/oauth/v2/token",
						"jwks_uri":               server.URL + "/oauth/v2/keys",
					})
				case "/oauth/v2/token":
					tokenRequests++
					if r.Method != http.MethodPost {
						t.Fatalf("token request method = %s", r.Method)
					}
					signing := signingKey
					if tt.signWithUnknownKey {
						signing = unknownKey
					}
					claims := map[string]any{
						"iss":            server.URL,
						"sub":            "subject-1",
						"aud":            "certhub-web",
						"exp":            time.Now().Add(time.Hour).Unix(),
						"iat":            time.Now().Add(-time.Minute).Unix(),
						"nonce":          nonce,
						"email":          "user@example.com",
						"email_verified": true,
					}
					if tt.mutateClaims != nil {
						tt.mutateClaims(claims, server.URL)
					}
					tokenKeyID := kid
					if tt.tokenKeyID != "" {
						tokenKeyID = tt.tokenKeyID
					}
					issuedIDToken = signedOIDCTestToken(t, signing, tokenKeyID, claims)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{
						"id_token":      issuedIDToken,
						"access_token":  "provider-access-token-canary",
						"refresh_token": "provider-refresh-token-canary",
					})
				case "/oauth/v2/keys":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
						"kty": "RSA",
						"kid": kid,
						"use": "sig",
						"alg": "RS256",
						"n":   base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes()),
					}}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			if !tt.noExistingLink {
				repo.user.OIDCIssuer = &server.URL
			}
			service := NewService(ServiceConfig{
				AuthRepository:  repo,
				UserRepository:  repo,
				AuditRepository: repo,
				KeySet:          keys,
				Config: config.AuthConfig{
					UserAccessTokenTTLSeconds:  300,
					UserRefreshTokenTTLSeconds: 3600,
					OIDC: config.OIDCConfig{
						Enabled:     true,
						IssuerURL:   server.URL,
						ClientID:    "certhub-web",
						RedirectURL: "https://certhub.example.com/v1/auth/oidc/callback",
					},
				},
				HTTPClient: server.Client(),
			})
			_, err = service.CompleteOIDCCallback(context.Background(), authCode, rawState, AuditContext{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("callback err = %v", err)
			}
			if tokenRequests != 1 {
				t.Fatalf("token requests = %d", tokenRequests)
			}
			if repo.createdHandoff {
				t.Fatalf("rejected OIDC callback created a handoff")
			}
			auditPayload, err := json.Marshal(repo.auditEvents)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{authCode, rawState, codeVerifier, issuedIDToken, "provider-access-token-canary", "provider-refresh-token-canary"} {
				if strings.Contains(string(auditPayload), forbidden) {
					t.Fatalf("audit events leaked sensitive OIDC value")
				}
			}
		})
	}
}

func TestExchangeOIDCHandoffConsumesSingleUseHashAndCreatesOIDCSession(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	const (
		userID    = "12345678-1234-4234-9234-000000000001"
		handoffID = "cth_oidc_handoff_replayproof"
	)
	repo := &oidcFakeRepo{
		user: users.User{
			ID:          userID,
			Email:       "user@example.com",
			DisplayName: "OIDC User",
			GlobalRole:  users.GlobalRoleUser,
			Status:      users.StatusActive,
		},
		handoff: OIDCLoginHandoff{
			ID:          "12345678-1234-4234-9234-000000000002",
			HandoffHash: keys.HashToken(handoffID),
			UserID:      userID,
			Status:      HandoffStatusActive,
			ExpiresAt:   time.Now().Add(time.Minute),
		},
	}
	service := NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled: true,
			},
		},
	})
	result, err := service.ExchangeOIDCHandoff(context.Background(), handoffID, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.ID != userID || !strings.HasPrefix(result.Tokens.AccessToken, UserAccessTokenPrefix) || !strings.HasPrefix(result.Tokens.RefreshToken, UserRefreshTokenPrefix) {
		t.Fatalf("unexpected OIDC handoff login result")
	}
	if repo.consumedHandoffHash != keys.HashToken(handoffID) || repo.consumedHandoffHash == handoffID {
		t.Fatalf("handoff was not consumed by hash")
	}
	if len(repo.createdSessions) != 1 || repo.createdSessions[0].AuthMethod != AuthMethodOIDC || repo.createdSessions[0].UserID != userID {
		t.Fatalf("OIDC handoff did not create one OIDC session")
	}
	if _, err := service.ExchangeOIDCHandoff(context.Background(), handoffID, AuditContext{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed handoff err = %v", err)
	}
	if len(repo.createdSessions) != 1 {
		t.Fatalf("replayed handoff created another session")
	}
	auditPayload, err := json.Marshal(repo.auditEvents)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{handoffID, result.Tokens.AccessToken, result.Tokens.RefreshToken} {
		if strings.Contains(string(auditPayload), forbidden) {
			t.Fatalf("audit events leaked sensitive OIDC handoff value")
		}
	}
}

func TestOIDCLoginFlowWithPostgresServiceTransactions(t *testing.T) {
	dbURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping OIDC service PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrationDB, err := migrations.OpenDB(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close()
	if _, err := migrations.NewRunner(migrations.DefaultDir).Up(ctx, migrationDB); err != nil {
		t.Fatal(err)
	}
	pool, err := storage.Open(ctx, storage.Config{URL: dbURL})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const (
		kid            = "postgres-provider-key"
		clientID       = "certhub-web"
		redirectURL    = "https://certhub.example.com/v1/auth/oidc/callback"
		frontendReturn = "https://certhub.example.com/auth/callback?next=%2Fcertificates"
		authCode       = "postgres-provider-auth-code"
		subject        = "postgres-subject"
	)
	correlationPrefix := "pg-oidc-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	var (
		expectedChallenge string
		expectedNonce     string
		tokenRequests     int
		tokenVerifier     string
		providerIDToken   string
	)
	userEmail := "oidc-postgres-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "") + "@example.com"
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 provider.URL,
				"authorization_endpoint": provider.URL + "/oauth/v2/authorize",
				"token_endpoint":         provider.URL + "/oauth/v2/token",
				"jwks_uri":               provider.URL + "/oauth/v2/keys",
			})
		case "/oauth/v2/token":
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("token request method = %s", r.Method)
			}
			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Fatalf("token request Accept = %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Fatalf("token request Content-Type = %q", got)
			}
			if r.Header.Get("Authorization") != "" {
				t.Fatalf("token request used Authorization header")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			expectedForm := map[string]string{
				"grant_type":    "authorization_code",
				"code":          authCode,
				"redirect_uri":  redirectURL,
				"client_id":     clientID,
				"code_verifier": "",
			}
			if len(r.PostForm) != len(expectedForm) {
				t.Fatalf("token request parameter count = %d", len(r.PostForm))
			}
			for key, values := range r.PostForm {
				if _, ok := expectedForm[key]; !ok {
					t.Fatalf("token request included unexpected parameter %q", key)
				}
				if len(values) != 1 {
					t.Fatalf("token request parameter %q has %d values", key, len(values))
				}
			}
			for key, want := range expectedForm {
				got := r.PostForm.Get(key)
				if key == "code_verifier" {
					if got == "" {
						t.Fatalf("token request code_verifier missing")
					}
					tokenVerifier = got
					sum := sha256.Sum256([]byte(got))
					if base64.RawURLEncoding.EncodeToString(sum[:]) != expectedChallenge {
						t.Fatalf("token request code_verifier did not match stored challenge")
					}
					continue
				}
				if got != want {
					t.Fatalf("token request parameter %q mismatch", key)
				}
			}
			providerIDToken = signedOIDCTestToken(t, signingKey, kid, map[string]any{
				"iss":            provider.URL,
				"sub":            subject,
				"aud":            clientID,
				"exp":            time.Now().Add(time.Hour).Unix(),
				"iat":            time.Now().Add(-time.Minute).Unix(),
				"nonce":          expectedNonce,
				"email":          userEmail,
				"email_verified": true,
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id_token":      providerIDToken,
				"access_token":  "postgres-provider-access-canary",
				"refresh_token": "postgres-provider-refresh-canary",
			})
		case "/oauth/v2/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	userRepo := users.NewRepository(pool)
	user, err := userRepo.Create(ctx, users.CreateUserParams{
		Email:       userEmail,
		DisplayName: "OIDC PostgreSQL User",
		OIDCIssuer:  &provider.URL,
		OIDCSubject: ptrString(subject),
		GlobalRole:  users.GlobalRoleUser,
		Status:      users.StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(ServiceConfig{
		AuthRepository:  NewRepository(pool),
		UserRepository:  userRepo,
		AuditRepository: audit.NewRepository(pool),
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled:     true,
				IssuerURL:   provider.URL,
				ClientID:    clientID,
				RedirectURL: redirectURL,
			},
		},
		Storage:    pool,
		HTTPClient: provider.Client(),
	})
	start, err := service.StartOIDCLogin(ctx, frontendReturn, AuditContext{CorrelationID: correlationPrefix + "-start", SourceIP: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	authQuery := authorizationURL.Query()
	rawState := authQuery.Get("state")
	expectedNonce = authQuery.Get("nonce")
	expectedChallenge = authQuery.Get("code_challenge")
	if rawState == "" || expectedNonce == "" || expectedChallenge == "" {
		t.Fatalf("OIDC authorization URL missing state, nonce, or challenge")
	}
	var storedStateHash, storedNonce, storedVerifier, storedReturnURL string
	if err := pool.QueryRow(ctx, `
select state_hash, nonce, code_verifier_encrypted, frontend_return_url
from oidc_login_states
where state_hash = $1`, keys.HashOIDCState(rawState)).Scan(&storedStateHash, &storedNonce, &storedVerifier, &storedReturnURL); err != nil {
		t.Fatal(err)
	}
	if storedStateHash != keys.HashOIDCState(rawState) || storedStateHash == rawState {
		t.Fatalf("OIDC state was not stored as expected hash")
	}
	if storedNonce != expectedNonce || storedReturnURL != frontendReturn || !strings.HasPrefix(storedVerifier, "{") {
		t.Fatalf("OIDC state stored unexpected non-secret fields")
	}
	callback, err := service.CompleteOIDCCallback(ctx, authCode, rawState, AuditContext{CorrelationID: correlationPrefix + "-callback", SourceIP: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d", tokenRequests)
	}
	if _, err := service.CompleteOIDCCallback(ctx, authCode, rawState, AuditContext{CorrelationID: correlationPrefix + "-callback-replay"}); !errors.Is(err, ErrOIDCValidationFailed) {
		t.Fatalf("replayed OIDC callback err = %v", err)
	}
	if tokenRequests != 1 {
		t.Fatalf("replayed callback reached token endpoint")
	}
	callbackURL, err := url.Parse(callback.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := callbackURL.Scheme + "://" + callbackURL.Host + callbackURL.Path; got != "https://certhub.example.com/auth/callback" {
		t.Fatalf("callback redirect target = %q", got)
	}
	redirectQuery := callbackURL.Query()
	handoffID := redirectQuery.Get("handoff_id")
	if !strings.HasPrefix(handoffID, OIDCHandoffPrefix) {
		t.Fatalf("handoff ID shape mismatch")
	}
	if len(redirectQuery) != 2 || redirectQuery.Get("next") != "/certificates" {
		t.Fatalf("callback redirect query shape mismatch")
	}
	var storedHandoffHash, storedHandoffReturnURL string
	if err := pool.QueryRow(ctx, `
select handoff_hash, frontend_return_url
from oidc_login_handoffs
where handoff_hash = $1`, keys.HashToken(handoffID)).Scan(&storedHandoffHash, &storedHandoffReturnURL); err != nil {
		t.Fatal(err)
	}
	if storedHandoffHash != keys.HashToken(handoffID) || storedHandoffHash == handoffID {
		t.Fatalf("OIDC handoff was not stored as expected hash")
	}
	if storedHandoffReturnURL != frontendReturn {
		t.Fatalf("OIDC handoff stored unexpected return URL")
	}
	login, err := service.ExchangeOIDCHandoff(ctx, handoffID, AuditContext{CorrelationID: correlationPrefix + "-handoff"})
	if err != nil {
		t.Fatal(err)
	}
	if login.User.ID != user.ID || !strings.HasPrefix(login.Tokens.AccessToken, UserAccessTokenPrefix) || !strings.HasPrefix(login.Tokens.RefreshToken, UserRefreshTokenPrefix) {
		t.Fatalf("unexpected OIDC login result")
	}
	if _, err := service.ExchangeOIDCHandoff(ctx, handoffID, AuditContext{CorrelationID: correlationPrefix + "-handoff-replay"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed OIDC handoff err = %v", err)
	}
	if _, err := service.ValidateUserAccessToken(ctx, login.Tokens.AccessToken); err != nil {
		t.Fatalf("OIDC access token was not persisted: %v", err)
	}
	updated, err := userRepo.Get(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastLoginAt == nil {
		t.Fatalf("OIDC handoff did not update last_login_at")
	}
	var sessionCount int
	if err := pool.QueryRow(ctx, `select count(*) from user_sessions where user_id = $1 and auth_method = 'oidc'`, user.ID).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 {
		t.Fatalf("OIDC session count = %d", sessionCount)
	}
	rows, err := pool.Query(ctx, `
select correlation_id, action, result, metadata::text
from audit_events
where correlation_id like $1
order by created_at, id`, correlationPrefix+"-%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var auditPayload strings.Builder
	type observedAudit struct {
		Action   string
		Result   string
		Metadata map[string]string
	}
	requireOIDCAudit := func(records []observedAudit, action, result, metadataKey, metadataValue string) {
		t.Helper()
		for _, record := range records {
			if record.Action != action || record.Result != result {
				continue
			}
			if metadataKey == "" || record.Metadata[metadataKey] == metadataValue {
				return
			}
		}
		t.Fatalf("missing expected OIDC audit event action=%q result=%q metadata_key=%q", action, result, metadataKey)
	}
	auditByCorrelation := map[string][]observedAudit{}
	for rows.Next() {
		var correlationID, action, result, metadataRaw string
		if err := rows.Scan(&correlationID, &action, &result, &metadataRaw); err != nil {
			t.Fatal(err)
		}
		var metadata map[string]string
		if err := json.Unmarshal([]byte(metadataRaw), &metadata); err != nil {
			t.Fatal(err)
		}
		auditByCorrelation[correlationID] = append(auditByCorrelation[correlationID], observedAudit{
			Action:   action,
			Result:   result,
			Metadata: metadata,
		})
		auditPayload.WriteString(metadataRaw)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	requireOIDCAudit(auditByCorrelation[correlationPrefix+"-callback"], "user_login_succeeded", "success", "phase", "callback")
	requireOIDCAudit(auditByCorrelation[correlationPrefix+"-callback-replay"], "user_login_failed", "failure", "reason", "invalid_oidc_state")
	requireOIDCAudit(auditByCorrelation[correlationPrefix+"-handoff"], "user_session_created", "success", "", "")
	requireOIDCAudit(auditByCorrelation[correlationPrefix+"-handoff"], "user_login_succeeded", "success", "phase", "handoff")
	requireOIDCAudit(auditByCorrelation[correlationPrefix+"-handoff-replay"], "user_login_failed", "failure", "reason", "invalid_handoff")
	for _, forbidden := range []string{
		authCode,
		rawState,
		tokenVerifier,
		handoffID,
		login.Tokens.AccessToken,
		login.Tokens.RefreshToken,
		providerIDToken,
		"postgres-provider-access-canary",
		"postgres-provider-refresh-canary",
	} {
		if forbidden != "" && strings.Contains(auditPayload.String(), forbidden) {
			t.Fatalf("audit events leaked sensitive OIDC value")
		}
	}
}

func TestCompleteOIDCCallbackRejectsFakeCodeWithoutLocalBypass(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier"
	encrypted, err := keys.SealDatabaseValue([]byte(verifier), oidcVerifierAAD("12345678-1234-4234-9234-123456789abc"))
	if err != nil {
		t.Fatal(err)
	}
	repo := &oidcFakeRepo{state: OIDCLoginState{
		ID:                    "12345678-1234-4234-9234-123456789abc",
		StateHash:             stringsForOIDCTest(43, "A"),
		Nonce:                 "nonce-1",
		CodeVerifierEncrypted: encrypted,
		ProviderCallbackURL:   "https://certhub.example.com/v1/auth/oidc/callback",
		ExpiresAt:             time.Now().Add(time.Minute),
	}}
	service := NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			OIDC: config.OIDCConfig{
				Enabled:     true,
				IssuerURL:   "https://127.0.0.1:1",
				ClientID:    "certhub-web",
				RedirectURL: "https://certhub.example.com/v1/auth/oidc/callback",
			},
		},
		HTTPClient: &http.Client{Timeout: 100 * time.Millisecond},
	})
	_, err = service.CompleteOIDCCallback(context.Background(), "fake:victim-subject:user@example.com", "state", AuditContext{})
	if !errors.Is(err, ErrOIDCValidationFailed) {
		t.Fatalf("err = %v", err)
	}
	if repo.createdHandoff {
		t.Fatalf("fake OIDC code created a handoff")
	}
}

func signedOIDCTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func oidcDiscoveryServer(t *testing.T, discovery func(base string) map[string]string) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discovery(server.URL))
	}))
	t.Cleanup(server.Close)
	return server
}

func stringsForOIDCTest(n int, s string) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

type oidcFakeRepo struct {
	state                OIDCLoginState
	wantStateHash        string
	consumedStateHash    string
	createdState         OIDCLoginState
	createdHandoff       bool
	createdHandoffParams CreateOIDCHandoffParams
	handoff              OIDCLoginHandoff
	handoffConsumed      bool
	consumedHandoffHash  string
	createdSessions      []CreateSessionParams
	user                 users.User
	lookupOIDCIssuer     string
	lookupOIDCSubject    string
	lookupEmail          string
	updatedUserID        string
	updatedUserParams    users.UpdateUserParams
	auditEvents          []audit.AppendEventParams
}

func (f *oidcFakeRepo) CreateSession(_ context.Context, params CreateSessionParams) (Session, error) {
	f.createdSessions = append(f.createdSessions, params)
	return Session{
		ID:               "12345678-1234-4234-9234-000000000003",
		UserID:           params.UserID,
		AuthMethod:       params.AuthMethod,
		AccessTokenHash:  params.AccessTokenHash,
		RefreshTokenHash: params.RefreshTokenHash,
		Status:           SessionStatusActive,
		AccessExpiresAt:  params.AccessExpiresAt,
		RefreshExpiresAt: params.RefreshExpiresAt,
	}, nil
}

func (f *oidcFakeRepo) GetSessionByAccessTokenHash(context.Context, string) (Session, error) {
	return Session{}, errors.New("not implemented")
}

func (f *oidcFakeRepo) MarkSessionUsed(context.Context, string) error {
	return errors.New("not implemented")
}

func (f *oidcFakeRepo) RevokeSession(context.Context, string, SessionRevokedReason) (bool, error) {
	return false, errors.New("not implemented")
}

func (f *oidcFakeRepo) RotateRefreshToken(context.Context, RotateRefreshTokenParams) (Session, error) {
	return Session{}, errors.New("not implemented")
}

func (f *oidcFakeRepo) CreateOIDCState(_ context.Context, params CreateOIDCStateParams) (OIDCLoginState, error) {
	f.createdState = OIDCLoginState{
		ID:                    params.ID,
		StateHash:             params.StateHash,
		Nonce:                 params.Nonce,
		CodeVerifierEncrypted: params.CodeVerifierEncrypted,
		ProviderCallbackURL:   params.ProviderCallbackURL,
		FrontendReturnURL:     params.FrontendReturnURL,
		ExpiresAt:             params.ExpiresAt,
		SourceIP:              params.SourceIP,
		UserAgent:             params.UserAgent,
	}
	return f.createdState, nil
}

func (f *oidcFakeRepo) ConsumeOIDCState(_ context.Context, stateHash string) (OIDCLoginState, error) {
	f.consumedStateHash = stateHash
	if f.wantStateHash != "" && stateHash != f.wantStateHash {
		return OIDCLoginState{}, storage.ErrNoRows
	}
	return f.state, nil
}

func (f *oidcFakeRepo) CreateOIDCHandoff(_ context.Context, params CreateOIDCHandoffParams) (OIDCLoginHandoff, error) {
	f.createdHandoff = true
	f.createdHandoffParams = params
	f.handoff = OIDCLoginHandoff{
		HandoffHash:       params.HandoffHash,
		UserID:            params.UserID,
		OIDCLoginStateID:  params.OIDCLoginStateID,
		FrontendReturnURL: params.FrontendReturnURL,
		Status:            HandoffStatusActive,
		ExpiresAt:         params.ExpiresAt,
		SourceIP:          params.SourceIP,
		UserAgent:         params.UserAgent,
	}
	return f.handoff, nil
}

func (f *oidcFakeRepo) ConsumeOIDCHandoff(_ context.Context, handoffHash string) (OIDCLoginHandoff, error) {
	f.consumedHandoffHash = handoffHash
	if f.handoffConsumed || f.handoff.HandoffHash == "" || handoffHash != f.handoff.HandoffHash {
		return OIDCLoginHandoff{}, storage.ErrNoRows
	}
	f.handoffConsumed = true
	return f.handoff, nil
}

func (f *oidcFakeRepo) Get(_ context.Context, userID string) (users.User, error) {
	if f.user.ID == userID {
		return f.user, nil
	}
	return users.User{}, storage.ErrNoRows
}

func (f *oidcFakeRepo) LookupByNormalizedEmail(_ context.Context, email string) (users.User, error) {
	f.lookupEmail = email
	if f.user.ID != "" && strings.EqualFold(f.user.Email, email) {
		return f.user, nil
	}
	return users.User{}, storage.ErrNoRows
}

func (f *oidcFakeRepo) LookupByOIDC(_ context.Context, issuer, subject string) (users.User, error) {
	f.lookupOIDCIssuer = issuer
	f.lookupOIDCSubject = subject
	if f.user.ID != "" && f.user.OIDCIssuer != nil && *f.user.OIDCIssuer == issuer && f.user.OIDCSubject != nil && *f.user.OIDCSubject == subject {
		return f.user, nil
	}
	return users.User{}, storage.ErrNoRows
}

func (f *oidcFakeRepo) Update(_ context.Context, userID string, params users.UpdateUserParams) (users.User, error) {
	if f.user.ID != userID {
		return users.User{}, storage.ErrNoRows
	}
	f.updatedUserID = userID
	f.updatedUserParams = params
	if params.OIDCIssuer.Set {
		f.user.OIDCIssuer = params.OIDCIssuer.Value
	}
	if params.OIDCSubject.Set {
		f.user.OIDCSubject = params.OIDCSubject.Value
	}
	if params.LastLoginAt.Set {
		f.user.LastLoginAt = params.LastLoginAt.Value
	}
	return f.user, nil
}

func (f *oidcFakeRepo) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	f.auditEvents = append(f.auditEvents, params)
	return audit.Event{Action: params.Action, Metadata: params.Metadata}, nil
}

func ptrString(value string) *string {
	return &value
}
