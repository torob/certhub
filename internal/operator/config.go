package operator

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
	"github.com/torob/certhub/pkg/netretry"
)

var namespaceNameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Config struct {
	CerthubURL       string
	Token            string
	WatchNamespaces  []string
	MetricsBindAddr  string
	ResyncInterval   time.Duration
	ReconcileBackoff time.Duration
	HTTPTimeout      time.Duration
	RetryPolicy      netretry.Policy
}

func LoadConfigFromEnv() (Config, error) {
	return LoadConfig(func(key string) string { return os.Getenv(key) })
}

func LoadConfig(getenv func(string) string) (Config, error) {
	if strings.TrimSpace(getenv("WATCH_NAMESPACE")) != "" {
		return Config{}, errors.New("WATCH_NAMESPACE is no longer supported; use WATCH_NAMESPACES")
	}
	if strings.TrimSpace(getenv("CERTHUB_ALLOWED_SECRET_NAMES")) != "" {
		return Config{}, errors.New("CERTHUB_ALLOWED_SECRET_NAMES is no longer supported")
	}
	for _, legacy := range []string{
		"CERTHUB_TOKEN_SECRET_NAME",
		"CERTHUB_TOKEN_SECRET_KEY",
		"CERTHUB_TOKEN_SECRET_NAMESPACE",
	} {
		if strings.TrimSpace(getenv(legacy)) != "" {
			return Config{}, fmt.Errorf("%s is no longer supported; use CERTHUB_TOKEN", legacy)
		}
	}
	watchNamespaces, err := parseWatchNamespaces(getenv("WATCH_NAMESPACES"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		CerthubURL:       strings.TrimSpace(getenv("CERTHUB_URL")),
		Token:            strings.TrimSpace(getenv("CERTHUB_TOKEN")),
		WatchNamespaces:  watchNamespaces,
		MetricsBindAddr:  strings.TrimSpace(getenv("CERTHUB_METRICS_BIND_ADDR")),
		ResyncInterval:   6 * time.Hour,
		ReconcileBackoff: time.Minute,
		HTTPTimeout:      30 * time.Second,
		RetryPolicy:      netretry.DefaultPolicy(),
	}
	if cfg.MetricsBindAddr == "" {
		cfg.MetricsBindAddr = ":8080"
	}
	if cfg.CerthubURL == "" {
		return Config{}, errors.New("CERTHUB_URL is required")
	}
	parsed, err := url.Parse(cfg.CerthubURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return Config{}, errors.New("CERTHUB_URL must be an absolute https URL")
	}
	if err := certhubclient.ValidateApplicationToken(cfg.Token); err != nil {
		return Config{}, err
	}
	if value := strings.TrimSpace(getenv("CERTHUB_RESYNC_INTERVAL")); value != "" {
		interval, err := time.ParseDuration(value)
		if err != nil || interval < 30*time.Second {
			return Config{}, errors.New("CERTHUB_RESYNC_INTERVAL must be a duration of at least 30s")
		}
		cfg.ResyncInterval = interval
	}
	if value := strings.TrimSpace(getenv("CERTHUB_RECONCILE_BACKOFF")); value != "" {
		backoff, err := time.ParseDuration(value)
		if err != nil || backoff < time.Second {
			return Config{}, errors.New("CERTHUB_RECONCILE_BACKOFF must be a duration of at least 1s")
		}
		cfg.ReconcileBackoff = backoff
	}
	if value := strings.TrimSpace(getenv("CERTHUB_HTTP_TIMEOUT")); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout < time.Second {
			return Config{}, errors.New("CERTHUB_HTTP_TIMEOUT must be a duration of at least 1s")
		}
		cfg.HTTPTimeout = timeout
	}
	if value := strings.TrimSpace(getenv("CERTHUB_HTTP_RETRY_MAX_ATTEMPTS")); value != "" {
		attempts, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, errors.New("CERTHUB_HTTP_RETRY_MAX_ATTEMPTS must be an integer")
		}
		cfg.RetryPolicy.MaxAttempts = attempts
	}
	if value := strings.TrimSpace(getenv("CERTHUB_HTTP_RETRY_INITIAL_BACKOFF")); value != "" {
		delay, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, errors.New("CERTHUB_HTTP_RETRY_INITIAL_BACKOFF must be a duration")
		}
		cfg.RetryPolicy.InitialBackoff = delay
	}
	if value := strings.TrimSpace(getenv("CERTHUB_HTTP_RETRY_MAX_BACKOFF")); value != "" {
		delay, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, errors.New("CERTHUB_HTTP_RETRY_MAX_BACKOFF must be a duration")
		}
		cfg.RetryPolicy.MaxBackoff = delay
	}
	if err := cfg.RetryPolicy.Validate(); err != nil {
		return Config{}, fmt.Errorf("operator HTTP retry configuration: %w", err)
	}
	return cfg, nil
}

func BackendHTTPClient(cfg Config) *http.Client {
	return &http.Client{Timeout: cfg.HTTPTimeout}
}

func parseWatchNamespaces(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		namespace := strings.TrimSpace(part)
		if namespace == "" || !namespaceNameRE.MatchString(namespace) {
			return nil, errors.New("WATCH_NAMESPACES must contain comma-separated Kubernetes namespace names")
		}
		if _, ok := seen[namespace]; ok {
			return nil, fmt.Errorf("WATCH_NAMESPACES contains duplicate namespace %q", namespace)
		}
		seen[namespace] = struct{}{}
		out = append(out, namespace)
	}
	return out, nil
}
