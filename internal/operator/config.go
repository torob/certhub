package operator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
)

type Config struct {
	CerthubURL         string
	TokenNamespace     string
	TokenSecretName    string
	TokenSecretKey     string
	WatchNamespace     string
	AllowedSecretNames []string
	MetricsBindAddr    string
	ResyncInterval     time.Duration
	ReconcileBackoff   time.Duration
	HTTPTimeout        time.Duration
}

func LoadConfigFromEnv() (Config, error) {
	return LoadConfig(func(key string) string { return os.Getenv(key) })
}

func LoadConfig(getenv func(string) string) (Config, error) {
	cfg := Config{
		CerthubURL:         strings.TrimSpace(getenv("CERTHUB_URL")),
		TokenNamespace:     strings.TrimSpace(getenv("CERTHUB_TOKEN_SECRET_NAMESPACE")),
		TokenSecretName:    strings.TrimSpace(getenv("CERTHUB_TOKEN_SECRET_NAME")),
		TokenSecretKey:     strings.TrimSpace(getenv("CERTHUB_TOKEN_SECRET_KEY")),
		WatchNamespace:     strings.TrimSpace(getenv("WATCH_NAMESPACE")),
		AllowedSecretNames: splitCSV(getenv("CERTHUB_ALLOWED_SECRET_NAMES")),
		MetricsBindAddr:    strings.TrimSpace(getenv("CERTHUB_METRICS_BIND_ADDR")),
		ResyncInterval:     6 * time.Hour,
		ReconcileBackoff:   time.Minute,
		HTTPTimeout:        30 * time.Second,
	}
	if cfg.TokenSecretKey == "" {
		cfg.TokenSecretKey = "token"
	}
	if cfg.TokenNamespace == "" {
		cfg.TokenNamespace = cfg.WatchNamespace
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
	if cfg.TokenSecretName == "" {
		return Config{}, errors.New("CERTHUB_TOKEN_SECRET_NAME is required")
	}
	if cfg.TokenSecretKey == "" {
		return Config{}, errors.New("CERTHUB_TOKEN_SECRET_KEY is required")
	}
	if value := strings.TrimSpace(getenv("CERTHUB_RESYNC_INTERVAL")); value != "" {
		interval, err := time.ParseDuration(value)
		if err != nil || interval < time.Minute {
			return Config{}, errors.New("CERTHUB_RESYNC_INTERVAL must be a duration of at least 1m")
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
	return cfg, nil
}

func LoadApplicationToken(ctx context.Context, kube KubernetesClient, namespace, name, key string) (string, error) {
	secret, err := kube.GetSecret(ctx, namespace, name)
	if err != nil {
		return "", fmt.Errorf("read Certhub token Secret: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", errors.New("Certhub token Secret has no data")
	}
	token := strings.TrimSpace(string(secret.Data[key]))
	if err := certhubclient.ValidateApplicationToken(token); err != nil {
		return "", err
	}
	return token, nil
}

func BackendHTTPClient(cfg Config) *http.Client {
	return &http.Client{Timeout: cfg.HTTPTimeout}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
