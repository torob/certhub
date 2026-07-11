package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAppToken = "cth_app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestLoadConfigRejectsDuplicateKeysAndUserTokens(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
url: https://certhub.example.com
token: cth_uat_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
sync:
  wait: false
domains:
  - api.example.com
out_dir: /tmp/out
out_dir: /tmp/other
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate YAML key") {
		t.Fatalf("LoadConfig error = %v; want duplicate key", err)
	}

	if err := os.WriteFile(path, []byte(`
url: https://certhub.example.com
domains:
  - api.example.com
out_dir: /tmp/out
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTHUB_TOKEN", "cth_uat_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_, err = LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "application_token_required") {
		t.Fatalf("LoadConfig error = %v; want local user-token rejection", err)
	}
}

func TestLoadConfigRequiresSafeModeForStoredTokenAndAllowsEnvToken(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	config := []byte(`
url: https://certhub.example.com
token: cth_app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
domains:
  - api.example.com
out_dir: /tmp/out
`)
	if err := os.WriteFile(path, config, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("LoadConfig accepted token in broad-mode file")
	}

	if err := os.WriteFile(path, []byte(`
url: https://certhub.example.com
domains:
  - api.example.com
out_dir: /tmp/out
`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTHUB_TOKEN", testAppToken)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig env token: %v", err)
	}
	if cfg.Token != testAppToken {
		t.Fatalf("token = %q; want env override", cfg.Token)
	}
	if cfg.Sync.RequestTimeout != 30*time.Second {
		t.Fatalf("default request timeout = %s; want 30s", cfg.Sync.RequestTimeout)
	}
}

func TestLoadConfigRejectsTokenBearingSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.yaml")
	config := []byte(`
url: https://certhub.example.com
token: cth_app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
domains:
  - api.example.com
out_dir: /tmp/out
`)
	if err := os.WriteFile(target, config, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatalf("LoadConfig accepted token-bearing symlink")
	}
}

func TestBuildPlanRejectsMixedShapesAndNormalizes(t *testing.T) {
	cfg := Config{
		URL:   "https://certhub.example.com",
		Token: testAppToken,
		Sync:  SyncConfig{Wait: true},
		Certificates: []CertificateConfig{{
			Domains: []string{"WWW.Example.COM.", "*.Example.COM"},
			OutDir:  "/tmp/out",
		}},
	}
	defaultSync(&cfg)
	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got := plan[0].Criteria.Domains; len(got) != 2 || got[0] != "*.example.com" || got[1] != "www.example.com" {
		t.Fatalf("domains = %#v", got)
	}
	if plan[0].Criteria.KeyType != "ecdsa-p256" || !plan[0].Wait {
		t.Fatalf("plan = %#v", plan[0])
	}

	cfg.Domains = []string{"api.example.com"}
	if _, err := BuildPlan(cfg); err == nil {
		t.Fatalf("BuildPlan accepted mixed shorthand and certificates")
	}
}

func TestLoadConfigAcceptsCustomRequestTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
url: https://certhub.example.com
sync:
  request_timeout: 2s
  retry_max_attempts: 3
  retry_initial_backoff: 2s
  retry_max_backoff: 6s
domains:
  - api.example.com
out_dir: /tmp/out
`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTHUB_TOKEN", testAppToken)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Sync.RequestTimeout != 2*time.Second {
		t.Fatalf("request timeout = %s; want 2s", cfg.Sync.RequestTimeout)
	}
	if policy := cfg.Sync.RetryPolicy(); policy.MaxAttempts != 3 || policy.InitialBackoff != 2*time.Second || policy.MaxBackoff != 6*time.Second {
		t.Fatalf("retry policy = %#v", policy)
	}
}

func TestValidateURLRejectsUserinfo(t *testing.T) {
	if err := validateURL("https://user:secret@certhub.example.com", false); err == nil {
		t.Fatalf("validateURL accepted userinfo")
	}
}
