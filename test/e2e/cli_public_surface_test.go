package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const appToken = "cth_app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestCLISyncAgainstPublicHTTPBackendWritesMaterialAndRedactsOutput(t *testing.T) {
	repoRoot := findRepoRoot(t)
	cliPath := filepath.Join(repoRoot, "dist", "bin", "certhub-cli")
	if info, err := os.Stat(cliPath); err != nil || info.IsDir() {
		t.Skipf("built CLI binary is required for public-surface E2E: %s", cliPath)
	}

	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var paths []string
	var sawEnsure bool
	var sawSecondIfNoneMatch bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if got := r.Header.Get("Authorization"); got != "Bearer "+appToken {
			t.Fatalf("unexpected Authorization header %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req-m10-e2e")
		switch r.URL.Path {
		case "/v1/sync/certificates/tls-material":
			switch len(paths) {
			case 1:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"code":"certificate_not_found","message":"missing","retryable":false,"details":{}}}`))
			case 3:
				_, _ = w.Write([]byte(materialResponseJSON()))
			case 4:
				if got := r.Header.Get("If-None-Match"); got != `"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"` {
					t.Fatalf("If-None-Match = %q", got)
				}
				sawSecondIfNoneMatch = true
				w.Header().Set("ETag", `"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`)
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected material request %d", len(paths))
			}
		case "/v1/sync/certificates":
			if len(paths) != 2 {
				t.Fatalf("ensure request occurred at position %d", len(paths))
			}
			sawEnsure = true
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(certificateResponseJSON()))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "cli.yaml")
	config := "url: " + server.URL + "\n" +
		"allow_plain_http_for_local_development: true\n" +
		"sync:\n" +
		"  wait: true\n" +
		"  timeout: 2s\n" +
		"  poll_interval: 10ms\n" +
		"certificates:\n" +
		"  - domains:\n" +
		"      - api.example.com\n" +
		"    out_dir: " + outDir + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(cliPath, "run", "--config", configPath, "--once", "--json")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CERTHUB_TOKEN="+appToken)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("certhub-cli failed: %v\n%s", err, output)
	}
	if !sawEnsure || len(paths) != 3 {
		t.Fatalf("paths after first run = %#v, sawEnsure=%v", paths, sawEnsure)
	}
	for _, canary := range []string{appToken, "M10_PRIVATE_KEY_CANARY", "-----BEGIN PRIVATE KEY-----"} {
		if strings.Contains(string(output), canary) {
			t.Fatalf("CLI output leaked canary %q: %s", canary, output)
		}
	}
	var summary struct {
		Configured int `json:"configured"`
		Succeeded  int `json:"succeeded"`
		Failed     int `json:"failed"`
	}
	if err := json.Unmarshal(output, &summary); err != nil {
		t.Fatalf("decode CLI JSON summary: %v\n%s", err, output)
	}
	if summary.Configured != 1 || summary.Succeeded != 1 || summary.Failed != 0 {
		t.Fatalf("summary = %+v", summary)
	}

	keyPath := filepath.Join(outDir, "current", "privkey.pem")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(key), "M10_PRIVATE_KEY_CANARY") {
		t.Fatalf("private key material was not written through CLI public surface")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o, want 0600", info.Mode().Perm())
	}

	cmd = exec.Command(cliPath, "run", "--config", configPath, "--once", "--json")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CERTHUB_TOKEN="+appToken)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second certhub-cli run failed: %v\n%s", err, output)
	}
	if !sawSecondIfNoneMatch || len(paths) != 4 {
		t.Fatalf("paths after second run = %#v, sawSecondIfNoneMatch=%v", paths, sawSecondIfNoneMatch)
	}
	var secondSummary struct {
		Changed bool `json:"changed"`
		Failed  int  `json:"failed"`
	}
	if err := json.Unmarshal(output, &secondSummary); err != nil {
		t.Fatalf("decode second CLI JSON summary: %v\n%s", err, output)
	}
	if secondSummary.Changed || secondSummary.Failed != 0 {
		t.Fatalf("second summary = %+v", secondSummary)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("could not find repo root")
		}
		dir = next
	}
}

func materialResponseJSON() string {
	return `{
		"certificate_id":"72345678-1234-4234-9234-123456789abc",
		"application_id":"22345678-1234-4234-9234-123456789abc",
		"domains":["api.example.com"],
		"key_type":"ecdsa-p256",
		"issuer_id":"32345678-1234-4234-9234-123456789abc",
		"issuer_name":"letsencrypt-staging",
		"version":1,
		"cert_pem":"-----BEGIN CERTIFICATE-----\nM10_CERT_CANARY\n-----END CERTIFICATE-----",
		"chain_pem":"-----BEGIN CERTIFICATE-----\nM10_CHAIN_CANARY\n-----END CERTIFICATE-----",
		"fullchain_pem":"-----BEGIN CERTIFICATE-----\nM10_CERT_CANARY\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nM10_CHAIN_CANARY\n-----END CERTIFICATE-----",
		"private_key_pem":"-----BEGIN PRIVATE KEY-----\nM10_PRIVATE_KEY_CANARY\n-----END PRIVATE KEY-----",
		"not_before":"2026-06-24T00:00:00Z",
		"not_after":"2026-09-22T00:00:00Z",
		"serial_number":"m10",
		"fingerprint_sha256":"m10-cert-fingerprint",
		"key_fingerprint_sha256":"m10-key-fingerprint",
		"material_etag":"\"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
	}`
}

func certificateResponseJSON() string {
	return `{
		"certificate":{
			"id":"72345678-1234-4234-9234-123456789abc",
			"application_id":"22345678-1234-4234-9234-123456789abc",
			"normalized_sans":["api.example.com"],
			"key_type":"ecdsa-p256",
			"issuer_id":"32345678-1234-4234-9234-123456789abc",
			"issuer_name":"letsencrypt-staging",
			"status":"pending",
			"created_at":"2026-06-24T00:00:00Z",
			"updated_at":"2026-06-24T00:00:00Z"
		}
	}`
}
