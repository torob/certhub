package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExternalZITADELOIDCDiscoveryCompatibility(t *testing.T) {
	if os.Getenv("CERTHUB_EXTERNAL_OIDC") != "1" {
		t.Skip("set CERTHUB_EXTERNAL_OIDC=1 to run real ZITADEL OIDC provider validation")
	}
	cfg, err := loadExternalOIDCConfig()
	if err != nil {
		t.Fatal(err)
	}
	issuer := requireExternalOIDCURL(t, "issuer URL", cfg.IssuerURL)
	redirect := requireExternalOIDCURL(t, "redirect URL", cfg.RedirectURL)
	if strings.TrimSpace(cfg.ClientID) == "" {
		t.Fatal("OIDC client ID is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := httpClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := validateExternalOIDCURL("redirect URL", req.URL); err != nil {
			return errors.New("OIDC provider redirect target is not an allowed external HTTPS DNS URL")
		}
		return nil
	}
	discoveryURL := strings.TrimRight(issuer.String(), "/") + "/.well-known/openid-configuration"
	var discovery externalOIDCDiscovery
	fetchExternalOIDCJSON(t, ctx, client, "discovery document", discoveryURL, &discovery)

	if discovery.Issuer != strings.TrimRight(issuer.String(), "/") {
		t.Fatalf("OIDC discovery issuer mismatch")
	}
	for name, raw := range map[string]string{
		"authorization endpoint": discovery.AuthorizationEndpoint,
		"token endpoint":         discovery.TokenEndpoint,
		"JWKS URI":               discovery.JWKSURI,
	} {
		requireExternalOIDCURL(t, name, raw)
	}
	expectedAuthorizationEndpoint := strings.TrimRight(issuer.String(), "/") + "/oauth/v2/authorize"
	if discovery.AuthorizationEndpoint != expectedAuthorizationEndpoint {
		t.Fatalf("OIDC authorization endpoint does not match Certhub's configured ZITADEL endpoint shape")
	}
	requireExternalOIDCListContains(t, "response_types_supported", discovery.ResponseTypesSupported, "code")
	if len(discovery.GrantTypesSupported) > 0 {
		requireExternalOIDCListContains(t, "grant_types_supported", discovery.GrantTypesSupported, "authorization_code")
	}
	requireExternalOIDCListContains(t, "code_challenge_methods_supported", discovery.CodeChallengeMethodsSupported, "S256")
	if len(discovery.ScopesSupported) > 0 {
		requireExternalOIDCListContains(t, "scopes_supported", discovery.ScopesSupported, "openid")
	}
	if len(discovery.IDTokenSigningAlgsSupported) > 0 {
		requireExternalOIDCListContains(t, "id_token_signing_alg_values_supported", discovery.IDTokenSigningAlgsSupported, "RS256")
	}

	var jwks externalOIDCJWKS
	fetchExternalOIDCJSON(t, ctx, client, "JWKS document", discovery.JWKSURI, &jwks)
	if !externalOIDCHasUsableRS256Key(jwks) {
		t.Fatal("OIDC JWKS did not expose a usable RSA signing key for RS256 ID-token validation")
	}

	representativeAuthorizationURL := externalOIDCAuthorizationURL(discovery.AuthorizationEndpoint, cfg.ClientID, redirect.String())
	params := representativeAuthorizationURL.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             cfg.ClientID,
		"redirect_uri":          redirect.String(),
		"code_challenge_method": "S256",
	} {
		if got := params.Get(key); got != want {
			t.Fatalf("authorization URL parameter %s mismatch", key)
		}
	}
	if params.Get("state") == "" || params.Get("nonce") == "" || params.Get("code_challenge") == "" {
		t.Fatal("authorization URL is missing state, nonce, or code_challenge")
	}
}

func TestExternalOIDCConfigParserSupportsCommonFormats(t *testing.T) {
	parsed := parseExternalOIDCConfigBytes([]byte(`
{
  "zitadel": {
    "issuer_url": "https://issuer.example.com",
    "client_id": "json-client",
    "redirect_url": "https://certhub.example.com/v1/auth/oidc/callback"
  }
}
ZITADEL_ISSUER_URL=https://issuer-file.example.com
ZITADEL_CLIENT_ID=file-client
ZITADEL_REDIRECT_URL=https://login.example.com/v1/auth/oidc/callback
`))
	if parsed.IssuerURL != "https://issuer-file.example.com" {
		t.Fatalf("issuer URL not parsed: %#v", parsed)
	}
	if parsed.ClientID != "file-client" {
		t.Fatalf("client ID not parsed: %#v", parsed)
	}
	if parsed.RedirectURL != "https://login.example.com/v1/auth/oidc/callback" {
		t.Fatalf("redirect URL not parsed: %#v", parsed)
	}
}

type externalOIDCConfig struct {
	IssuerURL   string
	ClientID    string
	RedirectURL string
}

type externalOIDCDiscovery struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
	IDTokenSigningAlgsSupported   []string `json:"id_token_signing_alg_values_supported"`
}

type externalOIDCJWKS struct {
	Keys []externalOIDCJWK `json:"keys"`
}

type externalOIDCJWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func loadExternalOIDCConfig() (externalOIDCConfig, error) {
	cfg := externalOIDCConfig{
		IssuerURL:   firstNonEmptyEnv("CERTHUB_EXTERNAL_OIDC_ISSUER_URL", "ZITADEL_ISSUER_URL", "ZITADEL_ISSUER"),
		ClientID:    firstNonEmptyEnv("CERTHUB_EXTERNAL_OIDC_CLIENT_ID", "ZITADEL_CLIENT_ID"),
		RedirectURL: firstNonEmptyEnv("CERTHUB_EXTERNAL_OIDC_REDIRECT_URL", "ZITADEL_REDIRECT_URL"),
	}
	path := strings.TrimSpace(os.Getenv("CERTHUB_EXTERNAL_OIDC_CREDENTIALS_FILE"))
	if path == "" {
		if cfg.IssuerURL != "" || cfg.ClientID != "" || cfg.RedirectURL != "" {
			return cfg, nil
		}
		return externalOIDCConfig{}, errors.New("external OIDC configuration requires CERTHUB_EXTERNAL_OIDC_ISSUER_URL, CERTHUB_EXTERNAL_OIDC_CLIENT_ID, CERTHUB_EXTERNAL_OIDC_REDIRECT_URL, or CERTHUB_EXTERNAL_OIDC_CREDENTIALS_FILE")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if cfg.IssuerURL != "" || cfg.ClientID != "" || cfg.RedirectURL != "" {
			return cfg, nil
		}
		return externalOIDCConfig{}, fmt.Errorf("read external OIDC credentials file: %w", err)
	}
	fromFile := parseExternalOIDCConfigBytes(data)
	if cfg.IssuerURL == "" {
		cfg.IssuerURL = fromFile.IssuerURL
	}
	if cfg.ClientID == "" {
		cfg.ClientID = fromFile.ClientID
	}
	if cfg.RedirectURL == "" {
		cfg.RedirectURL = fromFile.RedirectURL
	}
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return externalOIDCConfig{}, errors.New("external OIDC configuration requires issuer URL, client ID, and redirect URL")
	}
	return cfg, nil
}

func parseExternalOIDCConfigBytes(data []byte) externalOIDCConfig {
	var cfg externalOIDCConfig
	var obj any
	if json.Unmarshal(data, &obj) == nil {
		for key, value := range flattenJSONStrings("", obj) {
			assignExternalOIDCConfig(&cfg, key, value)
		}
	}
	for _, rawLine := range strings.Split(string(data), "\n") {
		key, value, ok := splitCredentialLine(rawLine)
		if !ok {
			continue
		}
		assignExternalOIDCConfig(&cfg, key, value)
	}
	return cfg
}

func assignExternalOIDCConfig(cfg *externalOIDCConfig, key, value string) {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(strings.TrimSpace(key)))
	value = strings.TrimSpace(value)
	switch {
	case value == "":
	case strings.Contains(normalized, "issuer") && (strings.Contains(normalized, "oidc") || strings.Contains(normalized, "zitadel")):
		cfg.IssuerURL = value
	case (strings.Contains(normalized, "client_id") || strings.HasSuffix(normalized, "_client")) && (strings.Contains(normalized, "oidc") || strings.Contains(normalized, "zitadel")):
		cfg.ClientID = value
	case strings.Contains(normalized, "redirect") && (strings.Contains(normalized, "oidc") || strings.Contains(normalized, "zitadel")):
		cfg.RedirectURL = value
	case normalized == "issuer_url" || normalized == "issuer":
		cfg.IssuerURL = value
	case normalized == "client_id":
		cfg.ClientID = value
	case normalized == "redirect_url":
		cfg.RedirectURL = value
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func fetchExternalOIDCJSON(t *testing.T, ctx context.Context, client *http.Client, label, rawURL string, out any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build OIDC %s request failed", label)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("OIDC provider %s request failed", label)
	}
	defer resp.Body.Close()
	if err := validateExternalOIDCURL("final "+label+" URL", resp.Request.URL); err != nil {
		t.Fatalf("OIDC provider %s response URL is not an allowed external HTTPS DNS URL", label)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		t.Fatalf("OIDC provider %s request returned status %d", label, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		t.Fatalf("decode OIDC %s JSON failed", label)
	}
}

func requireExternalOIDCURL(t *testing.T, name, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || validateExternalOIDCURL(name, parsed) != nil {
		t.Fatalf("%s must be an absolute https URL with a real DNS name and without userinfo or fragment", name)
	}
	return parsed
}

func validateExternalOIDCURL(_ string, parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("invalid URL")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("localhost is not allowed")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return errors.New("IP literal is not allowed")
	}
	if strings.Contains(host, "_") || net.ParseIP(host) != nil {
		return errors.New("host is not DNS-shaped")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("host is not DNS-shaped")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errors.New("host is not DNS-shaped")
			}
		}
	}
	return nil
}

func requireExternalOIDCListContains(t *testing.T, field string, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("OIDC discovery field %s does not contain required value", field)
}

func externalOIDCHasUsableRS256Key(jwks externalOIDCJWKS) bool {
	for _, key := range jwks.Keys {
		if key.KeyType != "RSA" || key.KeyID == "" || (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != "RS256") {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
		if err != nil || len(modulus) == 0 {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 8 {
			continue
		}
		var exponent int
		for _, b := range exponentBytes {
			exponent = exponent<<8 + int(b)
		}
		if exponent < 3 || new(big.Int).SetBytes(modulus).Sign() <= 0 {
			continue
		}
		return true
	}
	return false
}

func externalOIDCAuthorizationURL(endpoint, clientID, redirectURL string) *url.URL {
	u, err := url.Parse(endpoint)
	if err != nil {
		return &url.URL{}
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURL)
	q.Set("scope", "openid email profile")
	q.Set("state", "cth_oidc_state_external_validation")
	q.Set("nonce", "external-validation-nonce")
	q.Set("code_challenge", "external-validation-code-challenge")
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u
}
