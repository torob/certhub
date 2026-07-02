package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	security "github.com/torob/certhub/internal/crypto"
	"go.yaml.in/yaml/v4"
)

const DefaultPath = "/etc/certhub/server.yaml"

var (
	envNameRE     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	machineNameRE = regexp.MustCompile(`^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$`)
	dnsLabelRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type SecretString string

func (s SecretString) String() string { return "[redacted]" }

type Config struct {
	Path             string
	Database         DatabaseConfig
	Encryption       EncryptionConfig
	HTTP             HTTPConfig
	Server           ServerConfig
	TLS              TLSConfig
	SelfCertificate  SelfCertificateConfig
	Log              LogConfig
	Workers          WorkersConfig
	API              APIConfig
	ACME             ACMEConfig
	DNS              DNSConfig
	OutboundHTTP     OutboundHTTPConfig
	Auth             AuthConfig
	ApplicationToken ApplicationTokenConfig
}

type DatabaseConfig struct {
	URL SecretString
}

type EncryptionConfig struct {
	Key SecretString
}

type HTTPConfig struct {
	BindAddr          string
	RequireHTTPS      bool
	TrustedProxyCIDRs []netip.Prefix
}

type ServerConfig struct {
	PublicHostname string
}

type TLSConfig struct {
	CertFile string
	KeyFile  string
}

type SelfCertificateConfig struct {
	SyncEnabled         bool
	OutputDir           string
	Issuer              string
	KeyType             string
	SyncIntervalSeconds int
}

type LogConfig struct {
	Level string
}

type WorkersConfig struct {
	Concurrency int
}

type APIConfig struct {
	DefaultRetryAfterSeconds int
}

type ACMEConfig struct {
	OrderTimeoutSeconds int
}

type DNSConfig struct {
	PropagationTimeoutSeconds int
	PropagationPollSeconds    int
}

type OutboundHTTPConfig struct {
	Proxies    map[string]ProxyConfig
	ACMEProxy  string
	Cloudflare string
	ArvanCloud string
	OIDCProxy  string
}

type ProxyConfig struct {
	URL SecretString
}

type AuthConfig struct {
	Password                   PasswordConfig
	OIDC                       OIDCConfig
	UserAccessTokenTTLSeconds  int
	UserRefreshTokenTTLSeconds int
	UserInviteTTLSeconds       int
}

type PasswordConfig struct {
	Enabled       bool
	TwoFARequired bool
}

type OIDCConfig struct {
	Enabled           bool
	IssuerURL         string
	ClientID          string
	RedirectURL       string
	AllowedReturnURLs []string
}

type ApplicationTokenConfig struct {
	DefaultTTLSeconds int
	MaxTTLSeconds     int
}

type LoadOptions struct {
	Env func(string) (string, bool)
}

type rawConfig struct {
	Database         rawDatabase         `yaml:"database"`
	Encryption       rawEncryption       `yaml:"encryption"`
	HTTP             rawHTTP             `yaml:"http"`
	Server           rawServer           `yaml:"server"`
	TLS              rawTLS              `yaml:"tls"`
	SelfCertificate  rawSelfCertificate  `yaml:"self_certificate"`
	Log              rawLog              `yaml:"log"`
	Workers          rawWorkers          `yaml:"workers"`
	API              rawAPI              `yaml:"api"`
	ACME             rawACME             `yaml:"acme"`
	DNS              rawDNS              `yaml:"dns"`
	OutboundHTTP     rawOutboundHTTP     `yaml:"outbound_http"`
	Auth             rawAuth             `yaml:"auth"`
	ApplicationToken rawApplicationToken `yaml:"application_tokens"`
}

type rawDatabase struct {
	URL    string `yaml:"url"`
	URLEnv string `yaml:"url_env"`
}

type rawEncryption struct {
	Key    string `yaml:"key"`
	KeyEnv string `yaml:"key_env"`
}

type rawHTTP struct {
	BindAddr          string   `yaml:"bind_addr"`
	RequireHTTPS      *bool    `yaml:"require_https"`
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`
}

type rawServer struct {
	PublicHostname string `yaml:"public_hostname"`
}

type rawTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type rawSelfCertificate struct {
	SyncEnabled         *bool  `yaml:"sync_enabled"`
	OutputDir           string `yaml:"output_dir"`
	Issuer              string `yaml:"issuer"`
	KeyType             string `yaml:"key_type"`
	SyncIntervalSeconds *int   `yaml:"sync_interval_seconds"`
}

type rawLog struct {
	Level string `yaml:"level"`
}

type rawWorkers struct {
	Concurrency *int `yaml:"concurrency"`
}

type rawAPI struct {
	DefaultRetryAfterSeconds *int `yaml:"default_retry_after_seconds"`
}

type rawACME struct {
	OrderTimeoutSeconds *int `yaml:"order_timeout_seconds"`
}

type rawDNS struct {
	PropagationTimeoutSeconds *int `yaml:"propagation_timeout_seconds"`
	PropagationPollSeconds    *int `yaml:"propagation_poll_seconds"`
}

type rawOutboundHTTP struct {
	Proxies      map[string]rawProxy `yaml:"proxies"`
	ACME         rawProxyRef         `yaml:"acme"`
	DNSProviders rawDNSProviders     `yaml:"dns_providers"`
	OIDC         rawProxyRef         `yaml:"oidc"`
}

type rawProxy struct {
	URL    string `yaml:"url"`
	URLEnv string `yaml:"url_env"`
}

type rawProxyRef struct {
	Proxy string `yaml:"proxy"`
}

type rawDNSProviders struct {
	Cloudflare rawProxyRef `yaml:"cloudflare"`
	ArvanCloud rawProxyRef `yaml:"arvancloud"`
}

type rawAuth struct {
	Password                   rawPassword `yaml:"password"`
	OIDC                       rawOIDC     `yaml:"oidc"`
	UserAccessTokenTTLSeconds  *int        `yaml:"user_access_token_ttl_seconds"`
	UserRefreshTokenTTLSeconds *int        `yaml:"user_refresh_token_ttl_seconds"`
	UserInviteTTLSeconds       *int        `yaml:"user_invite_ttl_seconds"`
}

type rawPassword struct {
	Enabled       *bool `yaml:"enabled"`
	TwoFARequired *bool `yaml:"2fa_required"`
}

type rawOIDC struct {
	Enabled           *bool    `yaml:"enabled"`
	IssuerURL         string   `yaml:"issuer_url"`
	ClientID          string   `yaml:"client_id"`
	RedirectURL       string   `yaml:"redirect_url"`
	AllowedReturnURLs []string `yaml:"allowed_return_urls"`
}

type rawApplicationToken struct {
	DefaultTTLSeconds *int `yaml:"default_ttl_seconds"`
	MaxTTLSeconds     *int `yaml:"max_ttl_seconds"`
}

func LoadFile(path string, opts LoadOptions) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config path: %w", err)
	}
	safety, err := checkConfigFileSafety(abs)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config file: read failed")
	}
	if safety.groupReadable() {
		inlineSecrets, err := configContainsInlineSecrets(data)
		if err == nil && inlineSecrets {
			return nil, fmt.Errorf("config file: unsafe permissions")
		}
	}
	cfg, err := Load(data, abs, opts)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func Load(data []byte, path string, opts LoadOptions) (*Config, error) {
	if opts.Env == nil {
		opts.Env = os.LookupEnv
	}
	if err := rejectUnsafeYAML(data); err != nil {
		return nil, err
	}

	var raw rawConfig
	if err := yaml.Load(data, &raw, yaml.WithKnownFields(), yaml.WithUniqueKeys(), yaml.WithSingleDocument()); err != nil {
		return nil, fmt.Errorf("config yaml: %s", sanitizeYAMLError(err))
	}
	return normalize(raw, path, opts.Env)
}

func ValidateEncryptionKey(value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("must be standard base64 encoding of exactly 32 bytes")
	}
	return nil
}

func normalize(raw rawConfig, path string, env func(string) (string, bool)) (*Config, error) {
	cfg := &Config{
		Path: path,
		HTTP: HTTPConfig{BindAddr: ":8080", RequireHTTPS: true},
		SelfCertificate: SelfCertificateConfig{
			KeyType:             "ecdsa-p256",
			SyncIntervalSeconds: 300,
		},
		Log:     LogConfig{Level: "info"},
		Workers: WorkersConfig{Concurrency: 4},
		API:     APIConfig{DefaultRetryAfterSeconds: 10},
		ACME:    ACMEConfig{OrderTimeoutSeconds: 600},
		DNS: DNSConfig{
			PropagationTimeoutSeconds: 120,
			PropagationPollSeconds:    5,
		},
		OutboundHTTP: OutboundHTTPConfig{Proxies: map[string]ProxyConfig{}},
		Auth: AuthConfig{
			Password:                   PasswordConfig{Enabled: true, TwoFARequired: true},
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 28800,
			UserInviteTTLSeconds:       86400,
		},
		ApplicationToken: ApplicationTokenConfig{
			DefaultTTLSeconds: 7776000,
			MaxTTLSeconds:     31536000,
		},
	}

	dbURL, err := resolveSecret("database.url", raw.Database.URL, raw.Database.URLEnv, env, validateDatabaseURL)
	if err != nil {
		return nil, err
	}
	cfg.Database.URL = SecretString(dbURL)

	key, err := resolveSecret("encryption.key", raw.Encryption.Key, raw.Encryption.KeyEnv, env, ValidateEncryptionKey)
	if err != nil {
		return nil, err
	}
	cfg.Encryption.Key = SecretString(key)

	if raw.HTTP.BindAddr != "" {
		cfg.HTTP.BindAddr = raw.HTTP.BindAddr
	}
	if raw.HTTP.RequireHTTPS != nil {
		cfg.HTTP.RequireHTTPS = *raw.HTTP.RequireHTTPS
	}
	for _, item := range raw.HTTP.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fieldError("http.trusted_proxy_cidrs", "must contain valid CIDRs")
		}
		cfg.HTTP.TrustedProxyCIDRs = append(cfg.HTTP.TrustedProxyCIDRs, prefix.Masked())
	}

	host, err := normalizeHostname(raw.Server.PublicHostname)
	if err != nil {
		return nil, fieldError("server.public_hostname", err.Error())
	}
	cfg.Server.PublicHostname = host

	cfg.TLS.CertFile = raw.TLS.CertFile
	cfg.TLS.KeyFile = raw.TLS.KeyFile
	if (cfg.TLS.CertFile == "") != (cfg.TLS.KeyFile == "") {
		return nil, fieldError("tls.cert_file", "must be configured together with tls.key_file")
	}

	if raw.SelfCertificate.SyncEnabled != nil {
		cfg.SelfCertificate.SyncEnabled = *raw.SelfCertificate.SyncEnabled
	}
	if raw.SelfCertificate.OutputDir != "" {
		cfg.SelfCertificate.OutputDir = raw.SelfCertificate.OutputDir
	}
	if raw.SelfCertificate.Issuer != "" {
		if !machineNameRE.MatchString(raw.SelfCertificate.Issuer) {
			return nil, fieldError("self_certificate.issuer", "must be a machine_name")
		}
		cfg.SelfCertificate.Issuer = raw.SelfCertificate.Issuer
	}
	if raw.SelfCertificate.KeyType != "" {
		if !validKeyType(raw.SelfCertificate.KeyType) {
			return nil, fieldError("self_certificate.key_type", "must be a supported key type")
		}
		cfg.SelfCertificate.KeyType = raw.SelfCertificate.KeyType
	}
	if raw.SelfCertificate.SyncIntervalSeconds != nil {
		if *raw.SelfCertificate.SyncIntervalSeconds <= 0 {
			return nil, fieldError("self_certificate.sync_interval_seconds", "must be positive")
		}
		cfg.SelfCertificate.SyncIntervalSeconds = *raw.SelfCertificate.SyncIntervalSeconds
	}
	if cfg.SelfCertificate.SyncEnabled {
		if cfg.Server.PublicHostname == "" {
			return nil, fieldError("server.public_hostname", "is required when self-certificate sync is enabled")
		}
		if cfg.SelfCertificate.OutputDir == "" {
			return nil, fieldError("self_certificate.output_dir", "is required when self-certificate sync is enabled")
		}
		if cfg.SelfCertificate.Issuer == "" {
			return nil, fieldError("self_certificate.issuer", "is required when self-certificate sync is enabled")
		}
	}

	if raw.Log.Level != "" {
		switch raw.Log.Level {
		case "debug", "info", "warn", "error":
			cfg.Log.Level = raw.Log.Level
		default:
			return nil, fieldError("log.level", "must be one of debug, info, warn, error")
		}
	}

	if err := positiveInt("workers.concurrency", raw.Workers.Concurrency, &cfg.Workers.Concurrency); err != nil {
		return nil, err
	}
	if err := positiveInt("api.default_retry_after_seconds", raw.API.DefaultRetryAfterSeconds, &cfg.API.DefaultRetryAfterSeconds); err != nil {
		return nil, err
	}
	if err := positiveInt("acme.order_timeout_seconds", raw.ACME.OrderTimeoutSeconds, &cfg.ACME.OrderTimeoutSeconds); err != nil {
		return nil, err
	}
	if err := positiveInt("dns.propagation_timeout_seconds", raw.DNS.PropagationTimeoutSeconds, &cfg.DNS.PropagationTimeoutSeconds); err != nil {
		return nil, err
	}
	if err := positiveInt("dns.propagation_poll_seconds", raw.DNS.PropagationPollSeconds, &cfg.DNS.PropagationPollSeconds); err != nil {
		return nil, err
	}
	if cfg.DNS.PropagationPollSeconds >= cfg.DNS.PropagationTimeoutSeconds {
		return nil, fieldError("dns.propagation_poll_seconds", "must be lower than dns.propagation_timeout_seconds")
	}

	if raw.OutboundHTTP.Proxies != nil {
		for name, proxy := range raw.OutboundHTTP.Proxies {
			if !machineNameRE.MatchString(name) {
				return nil, fieldError("outbound_http.proxies", "proxy names must be machine_name values")
			}
			proxyURL, err := resolveSecret("outbound_http.proxies."+name+".url", proxy.URL, proxy.URLEnv, env, validateProxyURL)
			if err != nil {
				return nil, err
			}
			cfg.OutboundHTTP.Proxies[name] = ProxyConfig{URL: SecretString(proxyURL)}
		}
	}
	cfg.OutboundHTTP.ACMEProxy = raw.OutboundHTTP.ACME.Proxy
	cfg.OutboundHTTP.Cloudflare = raw.OutboundHTTP.DNSProviders.Cloudflare.Proxy
	cfg.OutboundHTTP.ArvanCloud = raw.OutboundHTTP.DNSProviders.ArvanCloud.Proxy
	cfg.OutboundHTTP.OIDCProxy = raw.OutboundHTTP.OIDC.Proxy
	for field, ref := range map[string]string{
		"outbound_http.acme.proxy":                     cfg.OutboundHTTP.ACMEProxy,
		"outbound_http.dns_providers.cloudflare.proxy": cfg.OutboundHTTP.Cloudflare,
		"outbound_http.dns_providers.arvancloud.proxy": cfg.OutboundHTTP.ArvanCloud,
		"outbound_http.oidc.proxy":                     cfg.OutboundHTTP.OIDCProxy,
	} {
		if ref != "" {
			if _, ok := cfg.OutboundHTTP.Proxies[ref]; !ok {
				return nil, fieldError(field, "references an unknown proxy")
			}
		}
	}

	if raw.Auth.Password.Enabled != nil {
		cfg.Auth.Password.Enabled = *raw.Auth.Password.Enabled
	}
	if raw.Auth.Password.TwoFARequired != nil {
		cfg.Auth.Password.TwoFARequired = *raw.Auth.Password.TwoFARequired
	}
	if raw.Auth.OIDC.Enabled != nil {
		cfg.Auth.OIDC.Enabled = *raw.Auth.OIDC.Enabled
	}
	cfg.Auth.OIDC.IssuerURL = raw.Auth.OIDC.IssuerURL
	cfg.Auth.OIDC.ClientID = raw.Auth.OIDC.ClientID
	cfg.Auth.OIDC.RedirectURL = raw.Auth.OIDC.RedirectURL
	cfg.Auth.OIDC.AllowedReturnURLs = raw.Auth.OIDC.AllowedReturnURLs
	if cfg.Auth.OIDC.Enabled {
		if err := validateHTTPSURLField("auth.oidc.issuer_url", cfg.Auth.OIDC.IssuerURL); err != nil {
			return nil, err
		}
		if cfg.Auth.OIDC.ClientID == "" {
			return nil, fieldError("auth.oidc.client_id", "is required when OIDC is enabled")
		}
		if err := validateHTTPSURLField("auth.oidc.redirect_url", cfg.Auth.OIDC.RedirectURL); err != nil {
			return nil, err
		}
	}
	if err := positiveInt("auth.user_access_token_ttl_seconds", raw.Auth.UserAccessTokenTTLSeconds, &cfg.Auth.UserAccessTokenTTLSeconds); err != nil {
		return nil, err
	}
	if err := positiveInt("auth.user_refresh_token_ttl_seconds", raw.Auth.UserRefreshTokenTTLSeconds, &cfg.Auth.UserRefreshTokenTTLSeconds); err != nil {
		return nil, err
	}
	if err := positiveInt("auth.user_invite_ttl_seconds", raw.Auth.UserInviteTTLSeconds, &cfg.Auth.UserInviteTTLSeconds); err != nil {
		return nil, err
	}
	if cfg.Auth.UserRefreshTokenTTLSeconds <= cfg.Auth.UserAccessTokenTTLSeconds {
		return nil, fieldError("auth.user_refresh_token_ttl_seconds", "must be greater than auth.user_access_token_ttl_seconds")
	}

	if err := positiveInt("application_tokens.default_ttl_seconds", raw.ApplicationToken.DefaultTTLSeconds, &cfg.ApplicationToken.DefaultTTLSeconds); err != nil {
		return nil, err
	}
	if err := positiveInt("application_tokens.max_ttl_seconds", raw.ApplicationToken.MaxTTLSeconds, &cfg.ApplicationToken.MaxTTLSeconds); err != nil {
		return nil, err
	}
	if cfg.ApplicationToken.MaxTTLSeconds < cfg.ApplicationToken.DefaultTTLSeconds {
		return nil, fieldError("application_tokens.max_ttl_seconds", "must be greater than or equal to application_tokens.default_ttl_seconds")
	}

	return cfg, nil
}

func resolveSecret(field, inline, envName string, env func(string) (string, bool), validate func(string) error) (string, error) {
	if (inline == "") == (envName == "") {
		return "", fieldError(field, "set exactly one inline value or matching *_env key")
	}
	value := inline
	if envName != "" {
		if !envNameRE.MatchString(envName) {
			return "", fieldError(field+"_env", "must be an environment variable name")
		}
		var ok bool
		value, ok = env(envName)
		if !ok || value == "" {
			return "", fieldError(field+"_env", "environment variable is missing or empty")
		}
	}
	if err := validate(value); err != nil {
		return "", fieldError(field, err.Error())
	}
	return value, nil
}

func positiveInt(field string, raw *int, target *int) error {
	if raw == nil {
		return nil
	}
	if *raw <= 0 {
		return fieldError(field, "must be positive")
	}
	*target = *raw
	return nil
}

func validateDatabaseURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("must be a PostgreSQL URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return errors.New("must use postgres or postgresql scheme")
	}
	return nil
}

func validateProxyURL(value string) error {
	if err := validateProcessURL(value); err != nil {
		return err
	}
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return errors.New("must be an http or https URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("must use http or https scheme")
	}
	if err := validateURLHost(u); err != nil {
		return err
	}
	if u.Path != "" && (u.Path != "/" || (u.RawPath != "" && u.RawPath != "/")) {
		return errors.New("must not include a path other than /")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("must not include a query")
	}
	if u.Fragment != "" || strings.Contains(value, "#") {
		return errors.New("must not include a fragment")
	}
	return nil
}

func validateHTTPSURLField(field, value string) error {
	if err := validateProcessURL(value); err != nil {
		return fieldError(field, err.Error())
	}
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Scheme != "https" || u.Host == "" {
		return fieldError(field, "must be an HTTPS URL")
	}
	if u.User != nil {
		return fieldError(field, "must not include username or password")
	}
	if err := validateURLHost(u); err != nil {
		return fieldError(field, err.Error())
	}
	if u.Fragment != "" || strings.Contains(value, "#") {
		return fieldError(field, "must not include a fragment")
	}
	return nil
}

func validateProcessURL(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	if len(value) > 2048 {
		return errors.New("must be at most 2048 characters")
	}
	return nil
}

func validateURLHost(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return errors.New("must include a valid host")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("must include a valid port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("must include a valid port")
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4In6() {
			return errors.New("must include a valid host")
		}
		return nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "*.") {
		return errors.New("must include a valid host")
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelRE.MatchString(label) {
			return errors.New("must include a valid host")
		}
	}
	return nil
}

func normalizeHostname(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/?#") {
		return "", errors.New("must be a DNS hostname without scheme, path, query, or fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(value), ".")
	if strings.Contains(host, ":") {
		return "", errors.New("must not include a port")
	}
	if strings.HasPrefix(host, "*.") || net.ParseIP(host) != nil {
		return "", errors.New("must be an exact DNS hostname")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", errors.New("must not be public-suffix-only or single-label")
	}
	for _, label := range labels {
		if !dnsLabelRE.MatchString(label) {
			return "", errors.New("must be a valid DNS hostname")
		}
	}
	return host, nil
}

func validKeyType(value string) bool {
	switch value {
	case "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384":
		return true
	default:
		return false
	}
}

type configFileSafety struct {
	mode os.FileMode
}

func (s configFileSafety) groupReadable() bool {
	return s.mode.Perm()&0040 != 0
}

func checkConfigFileSafety(path string) (configFileSafety, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return configFileSafety{}, fmt.Errorf("config file: stat failed")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return configFileSafety{}, fmt.Errorf("config file: must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0004 != 0 || info.Mode().Perm()&0022 != 0 {
		return configFileSafety{}, fmt.Errorf("config file: unsafe permissions")
	}
	if err := checkOwner(info); err != nil {
		return configFileSafety{}, err
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		dinfo, err := os.Lstat(dir)
		if err != nil {
			return configFileSafety{}, fmt.Errorf("config file: parent directory stat failed")
		}
		if dinfo.Mode()&os.ModeSymlink != 0 {
			return configFileSafety{}, fmt.Errorf("config file: parent directories must not be symlinks")
		}
		if dinfo.Mode().Perm()&0002 != 0 {
			return configFileSafety{}, fmt.Errorf("config file: parent directory is world-writable")
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
	}
	return configFileSafety{mode: info.Mode()}, nil
}

func configContainsInlineSecrets(data []byte) (bool, error) {
	var node yaml.Node
	if err := yaml.Load(data, &node, yaml.WithUniqueKeys(), yaml.WithSingleDocument()); err != nil {
		return false, err
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) != 1 {
		return false, nil
	}
	root := node.Content[0]
	if mappingValuePresent(mappingChild(root, "database"), "url") {
		return true, nil
	}
	if mappingValuePresent(mappingChild(root, "encryption"), "key") {
		return true, nil
	}
	proxies := mappingChild(mappingChild(root, "outbound_http"), "proxies")
	if proxies != nil && proxies.Kind == yaml.MappingNode {
		for i := 1; i < len(proxies.Content); i += 2 {
			if mappingValuePresent(proxies.Content[i], "url") {
				return true, nil
			}
		}
	}
	return false, nil
}

func mappingChild(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func mappingValuePresent(node *yaml.Node, key string) bool {
	value := mappingChild(node, key)
	return value != nil && strings.TrimSpace(value.Value) != ""
}

func checkOwner(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("config file: owner check unavailable")
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != uid {
		return fmt.Errorf("config file: unexpected owner")
	}
	return nil
}

func rejectUnsafeYAML(data []byte) error {
	var node yaml.Node
	if err := yaml.Load(data, &node, yaml.WithUniqueKeys(), yaml.WithSingleDocument()); err != nil {
		return fmt.Errorf("config yaml: %s", sanitizeYAMLError(err))
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return inspectNode(node.Content[0], "")
	}
	return nil
}

func inspectNode(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode {
		return fieldError(path, "YAML aliases are not supported")
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		child := key.Value
		if path != "" {
			child = path + "." + child
		}
		if val.Kind == yaml.AliasNode {
			return fieldError(child, "YAML aliases are not supported")
		}
		if stringField(child) && val.Kind == yaml.ScalarNode && val.ShortTag() != "!!str" {
			return fieldError(child, "must be a YAML string")
		}
		if err := inspectNode(val, child); err != nil {
			return err
		}
	}
	return nil
}

func stringField(path string) bool {
	if strings.HasPrefix(path, "outbound_http.proxies.") && (strings.HasSuffix(path, ".url") || strings.HasSuffix(path, ".url_env")) {
		return true
	}
	switch path {
	case "database.url", "database.url_env", "encryption.key", "encryption.key_env",
		"http.bind_addr", "server.public_hostname", "tls.cert_file", "tls.key_file",
		"self_certificate.output_dir", "self_certificate.issuer", "self_certificate.key_type",
		"log.level", "outbound_http.acme.proxy",
		"outbound_http.dns_providers.cloudflare.proxy", "outbound_http.dns_providers.arvancloud.proxy",
		"outbound_http.oidc.proxy", "auth.oidc.issuer_url", "auth.oidc.client_id", "auth.oidc.redirect_url":
		return true
	default:
		return false
	}
}

func fieldError(field, message string) error {
	if field == "" {
		field = "config"
	}
	return fmt.Errorf("%s: %s", field, message)
}

func sanitizeYAMLError(err error) string {
	msg := security.RedactString(err.Error())
	for _, marker := range []string{"postgres://", "postgresql://", "cth_app_v1_", "cth_uat_v1_", "cth_urt_v1_", "-----BEGIN"} {
		if strings.Contains(msg, marker) {
			return "invalid YAML"
		}
	}
	return msg
}
