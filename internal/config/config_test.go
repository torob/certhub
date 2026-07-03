package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func validYAML() string {
	return `
database:
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
http:
  require_https: false
`
}

func env(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLoadAppliesDefaultsAndEnvSecrets(t *testing.T) {
	cfg, err := Load([]byte(validYAML()), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTP.BindAddr != ":8080" {
		t.Fatalf("BindAddr = %q", cfg.HTTP.BindAddr)
	}
	if cfg.HTTP.RequireHTTPS {
		t.Fatalf("RequireHTTPS default override was not applied")
	}
	if cfg.Auth.Password.Enabled != true || cfg.Auth.Password.TwoFARequired != true {
		t.Fatalf("password auth defaults not applied: %+v", cfg.Auth.Password)
	}
	if cfg.SelfCertificate.KeyType != "ecdsa-p256" {
		t.Fatalf("self certificate key type default = %q", cfg.SelfCertificate.KeyType)
	}
}

func TestLoadRejectsUnknownAndDuplicateKeys(t *testing.T) {
	tests := map[string]string{
		"unknown": validYAML() + "unexpected: true\n",
		"duplicate": `
database:
  url_env: "CERTHUB_DATABASE_URL"
database:
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
				"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
				"CERTHUB_ENCRYPTION_KEY": validKey(),
			})})
			if err == nil {
				t.Fatalf("Load() succeeded")
			}
		})
	}
}

func TestLoadRejectsImplicitStringCoercion(t *testing.T) {
	input := `
database:
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
http:
  bind_addr: 1234
`
	_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err == nil || !strings.Contains(err.Error(), "http.bind_addr") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsSecretEnvReferenceErrors(t *testing.T) {
	tests := map[string]string{
		"both": `
database:
  url: "postgres://certhub:secret@db.example/certhub"
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
`,
		"neither": `
database: {}
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
`,
		"bad_env_name": `
database:
  url_env: "certhub_database_url"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
				"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
				"CERTHUB_ENCRYPTION_KEY": validKey(),
			})})
			if err == nil {
				t.Fatalf("Load() succeeded")
			}
		})
	}
}

func TestLoadRedactsSecretValuesInErrors(t *testing.T) {
	const canary = "SECRET-CANARY-VALUE"
	input := `
database:
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key: "SECRET-CANARY-VALUE"
`
	_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL": "postgres://certhub:secret@db.example/certhub",
	})})
	if err == nil {
		t.Fatalf("Load() succeeded")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error leaked secret: %v", err)
	}
}

func TestLoadRedactsConfiguredSecretCanariesInErrors(t *testing.T) {
	const dbCanary = "DB-CANARY-PASSWORD"
	const proxyCanary = "PROXY-CANARY-PASSWORD"
	const tokenCanary = "cth_app_v1_SECRET_CANARY_TOKEN"
	input := `
database:
  url: "postgres://certhub:DB-CANARY-PASSWORD@db.example/certhub"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
outbound_http:
  proxies:
    corp_proxy:
      url: "http://user:PROXY-CANARY-PASSWORD@proxy.example:8080"
    bad-name:
      url: "http://` + tokenCanary + `@proxy.example:8080"
`
	_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err == nil {
		t.Fatalf("Load() succeeded")
	}
	for _, canary := range []string{dbCanary, proxyCanary, tokenCanary} {
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("error leaked %s: %v", canary, err)
		}
	}
}

func TestLoadRejectsMachineNameHyphen(t *testing.T) {
	input := validYAML() + `
self_certificate:
  sync_enabled: true
  output_dir: "/var/lib/certhub/self"
  issuer: "lets-encrypt"
server:
  public_hostname: "certhub.example.com"
`
	_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err == nil || !strings.Contains(err.Error(), "self_certificate.issuer") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadValidatesRelativeValues(t *testing.T) {
	input := validYAML() + `
dns:
  propagation_timeout_seconds: 5
  propagation_poll_seconds: 5
`
	_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err == nil || !strings.Contains(err.Error(), "dns.propagation_poll_seconds") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadDNSPropagationResolverDefaults(t *testing.T) {
	cfg, err := Load([]byte(validYAML()), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	for _, providerType := range []string{"cloudflare", "arvancloud"} {
		if cfg.DNS.PropagationResolvers[providerType].Type != "system" {
			t.Fatalf("%s resolver = %+v", providerType, cfg.DNS.PropagationResolvers[providerType])
		}
	}
}

func TestLoadDNSPropagationResolverExamples(t *testing.T) {
	input := validYAML() + `
outbound_http:
  proxies:
    corp_proxy:
      url: "http://proxy.example.com:8080"
dns:
  propagation_resolvers:
    cloudflare:
      type: doh
      endpoint: "https://cloudflare-dns.com/dns-query"
      proxy: "corp_proxy"
    arvancloud:
      type: dot
      endpoint: "1.1.1.1:853"
      tls_server_name: "cloudflare-dns.com"
      proxy: "corp_proxy"
`
	cfg, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.DNS.PropagationResolvers["cloudflare"]; got.Type != "doh" || got.Endpoint != "https://cloudflare-dns.com/dns-query" || got.Proxy != "corp_proxy" {
		t.Fatalf("cloudflare resolver = %+v", got)
	}
	if got := cfg.DNS.PropagationResolvers["arvancloud"]; got.Type != "dot" || got.Endpoint != "1.1.1.1:853" || got.TLSServerName != "cloudflare-dns.com" || got.Proxy != "corp_proxy" {
		t.Fatalf("arvancloud resolver = %+v", got)
	}

	regularDNS := validYAML() + `
dns:
  propagation_resolvers:
    cloudflare:
      type: dns
      endpoint: "1.1.1.1:53"
`
	cfg, err = Load([]byte(regularDNS), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err != nil {
		t.Fatalf("Load(regular dns) error = %v", err)
	}
	if got := cfg.DNS.PropagationResolvers["cloudflare"]; got.Type != "dns" || got.Endpoint != "1.1.1.1:53" {
		t.Fatalf("regular dns resolver = %+v", got)
	}
}

func TestLoadRejectsInvalidDNSPropagationResolvers(t *testing.T) {
	tests := map[string]string{
		"unknown_type": `
dns:
  propagation_resolvers:
    cloudflare:
      type: bogus
`,
		"unknown_provider": `
dns:
  propagation_resolvers:
    route53:
      type: system
`,
		"missing_endpoint": `
dns:
  propagation_resolvers:
    cloudflare:
      type: doh
`,
		"dns_proxy": `
dns:
  propagation_resolvers:
    cloudflare:
      type: dns
      endpoint: "1.1.1.1:53"
      proxy: "corp_proxy"
`,
		"unknown_proxy": `
dns:
  propagation_resolvers:
    cloudflare:
      type: doh
      endpoint: "https://cloudflare-dns.com/dns-query"
      proxy: "corp_proxy"
`,
		"doh_query": `
dns:
  propagation_resolvers:
    cloudflare:
      type: doh
      endpoint: "https://cloudflare-dns.com/dns-query?name=example.com"
`,
		"bad_port": `
dns:
  propagation_resolvers:
    cloudflare:
      type: dot
      endpoint: "1.1.1.1:0"
`,
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(validYAML()+extra), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
				"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
				"CERTHUB_ENCRYPTION_KEY": validKey(),
			})})
			if err == nil || !strings.Contains(err.Error(), "dns.propagation_resolvers") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadValidatesHTTPSURLs(t *testing.T) {
	tests := map[string]string{
		"credentials": `
auth:
  oidc:
    enabled: true
    issuer_url: "https://user:password@issuer.example.com"
    client_id: "certhub"
    redirect_url: "https://certhub.example.com/v1/auth/oidc/callback"
`,
		"fragment": `
auth:
  oidc:
    enabled: true
    issuer_url: "https://issuer.example.com/realms/main#fragment"
    client_id: "certhub"
    redirect_url: "https://certhub.example.com/v1/auth/oidc/callback"
`,
		"invalid_host": `
auth:
  oidc:
    enabled: true
    issuer_url: "https://bad_host.example.com"
    client_id: "certhub"
    redirect_url: "https://certhub.example.com/v1/auth/oidc/callback"
`,
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(validYAML()+extra), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
				"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
				"CERTHUB_ENCRYPTION_KEY": validKey(),
			})})
			if err == nil || !strings.Contains(err.Error(), "auth.oidc.issuer_url") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadValidatesOutboundProxyURLs(t *testing.T) {
	valid := validYAML() + `
outbound_http:
  proxies:
    corp_proxy:
      url: "https://user:password@proxy.example.com:8443/"
  acme:
    proxy: "corp_proxy"
`
	cfg, err := Load([]byte(valid), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})})
	if err != nil {
		t.Fatalf("Load(valid proxy credentials) error = %v", err)
	}
	if _, ok := cfg.OutboundHTTP.Proxies["corp_proxy"]; !ok {
		t.Fatalf("proxy was not loaded")
	}

	tests := map[string]string{
		"path":       "http://proxy.example.com:8080/path",
		"query":      "http://proxy.example.com:8080?debug=true",
		"fragment":   "http://proxy.example.com:8080/#frag",
		"empty_port": "http://proxy.example.com:",
	}
	for name, proxyURL := range tests {
		t.Run(name, func(t *testing.T) {
			input := validYAML() + `
outbound_http:
  proxies:
    corp_proxy:
      url: "` + proxyURL + `"
`
			_, err := Load([]byte(input), "/safe/server.yaml", LoadOptions{Env: env(map[string]string{
				"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
				"CERTHUB_ENCRYPTION_KEY": validKey(),
			})})
			if err == nil || !strings.Contains(err.Error(), "outbound_http.proxies.corp_proxy.url") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadFileSafety(t *testing.T) {
	dir := t.TempDir()
	// The system temp parent is commonly world-writable, so place a private
	// directory under the repository working directory for this safety check.
	privateRoot, err := os.MkdirTemp(".", "config-safety-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(privateRoot)
	if err := os.Chmod(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	validPath := filepath.Join(privateRoot, "server.yaml")
	if err := os.WriteFile(validPath, []byte(validYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(validPath, LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})}); err != nil {
		t.Fatalf("LoadFile(valid) error = %v", err)
	}

	worldReadable := filepath.Join(privateRoot, "world.yaml")
	if err := os.WriteFile(worldReadable, []byte(validYAML()), 0o604); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(worldReadable, LoadOptions{}); err == nil {
		t.Fatalf("LoadFile(world-readable) succeeded")
	}

	groupReadableEnvOnly := filepath.Join(privateRoot, "group-env.yaml")
	if err := os.WriteFile(groupReadableEnvOnly, []byte(validYAML()), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupReadableEnvOnly, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(groupReadableEnvOnly, LoadOptions{Env: env(map[string]string{
		"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
		"CERTHUB_ENCRYPTION_KEY": validKey(),
	})}); err != nil {
		t.Fatalf("LoadFile(group-readable env-only) error = %v", err)
	}

	inlineSecretCases := map[string]string{
		"database_url": `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
http:
  require_https: false
`,
		"encryption_key": `
database:
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key: "` + validKey() + `"
http:
  require_https: false
`,
		"proxy_url": validYAML() + `
outbound_http:
  proxies:
    corp_proxy:
      url: "http://user:password@proxy.example.com:8080"
`,
	}
	for name, input := range inlineSecretCases {
		t.Run("group_readable_inline_"+name, func(t *testing.T) {
			path := filepath.Join(privateRoot, name+".yaml")
			if err := os.WriteFile(path, []byte(input), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFile(path, LoadOptions{Env: env(map[string]string{
				"CERTHUB_DATABASE_URL":   "postgres://certhub:secret@db.example/certhub",
				"CERTHUB_ENCRYPTION_KEY": validKey(),
			})})
			if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
				t.Fatalf("LoadFile(group-readable inline secret) error = %v", err)
			}
		})
	}

	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte(validYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(privateRoot, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadFile(link, LoadOptions{}); err == nil {
		t.Fatalf("LoadFile(symlink) succeeded")
	}
}
