package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
	"github.com/torob/certhub/pkg/material"
)

func TestRunOnceCreatesThenPollsAndWritesMaterial(t *testing.T) {
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var paths []string
	var sawApplicationID bool
	var sleeps []time.Duration
	originalSleep := sleepContext
	sleepContext = func(_ context.Context, d time.Duration) bool {
		sleeps = append(sleeps, d)
		return true
	}
	t.Cleanup(func() { sleepContext = originalSleep })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, ok := body["application_id"]; ok {
			sawApplicationID = true
		}
		w.Header().Set("X-Request-ID", "req-test")
		switch r.URL.Path {
		case "/v1/sync/certificates/tls-material":
			if len(paths) == 1 {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"code":"certificate_not_found","message":"missing","retryable":false,"details":{}}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(materialJSON()))
		case "/v1/sync/certificates":
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"certificate":{"id":"cert-1","application_id":"app-1","normalized_sans":["api.example.com"],"key_type":"ecdsa-p256","issuer_id":"issuer-1","status":"pending","created_at":"2026-06-24T00:00:00Z","updated_at":"2026-06-24T00:00:00Z"}}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := Config{URL: server.URL, Token: testAppToken, AllowPlainHTTPForLocalDev: true, Sync: SyncConfig{PerCertificateTimeout: 5 * time.Second, PollInterval: time.Millisecond}}
	plan := []PlanItem{{Criteria: testCriteria(), OutDir: outDir, Wait: true, Timeout: 5 * time.Second, PollInterval: time.Millisecond}}
	runner, err := NewSyncRunner(cfg, plan)
	if err != nil {
		t.Fatal(err)
	}
	summary := runner.RunOnce(t.Context())
	if summary.ExitCode() != 0 || summary.Failed != 0 || !summary.Changed {
		t.Fatalf("summary = %#v", summary)
	}
	if sawApplicationID {
		t.Fatalf("request body included application_id")
	}
	if len(paths) != 3 || paths[0] != "/v1/sync/certificates/tls-material" || paths[1] != "/v1/sync/certificates" || paths[2] != "/v1/sync/certificates/tls-material" {
		t.Fatalf("paths = %#v", paths)
	}
	if len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("sleeps = %#v; want 2s Retry-After", sleeps)
	}
	keyInfo, err := os.Stat(filepath.Join(outDir, "current", "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("privkey mode = %o; want 0600", keyInfo.Mode().Perm())
	}
	metadata, err := ReadMetadata(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.MaterialETag == "" || metadata.CertificateID != "cert-1" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestRunOnceNoContentLeavesCurrentUnchanged(t *testing.T) {
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PublishMaterial(outDir, testMaterial("OLD"), time.Unix(1, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	before, err := os.Readlink(filepath.Join(outDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got == "" {
			t.Fatalf("missing If-None-Match")
		}
		w.Header().Set("X-Request-ID", "req-204")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := Config{URL: server.URL, Token: testAppToken, AllowPlainHTTPForLocalDev: true, Sync: SyncConfig{PerCertificateTimeout: time.Second, PollInterval: time.Millisecond}}
	runner, err := NewSyncRunner(cfg, []PlanItem{{Criteria: testCriteria(), OutDir: outDir, Timeout: time.Second, PollInterval: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	summary := runner.RunOnce(t.Context())
	if summary.ExitCode() != 0 || summary.Changed {
		t.Fatalf("summary = %#v", summary)
	}
	after, err := os.Readlink(filepath.Join(outDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("current changed on 204: before=%q after=%q", before, after)
	}
}

func TestPublishMaterialRejectsUnsafeSymlink(t *testing.T) {
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(outDir, "releases")); err != nil {
		t.Fatal(err)
	}
	if err := PublishMaterial(outDir, testMaterial("BAD"), time.Now()); err == nil {
		t.Fatalf("PublishMaterial accepted symlink releases dir")
	}
}

func TestPublishMaterialRejectsSymlinkLock(t *testing.T) {
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "lock"), filepath.Join(outDir, ".certhub.lock")); err != nil {
		t.Fatal(err)
	}
	if err := PublishMaterial(outDir, testMaterial("BAD"), time.Now()); err == nil {
		t.Fatalf("PublishMaterial accepted symlink lock file")
	}
}

func TestPublishMaterialRejectsEscapingCurrentSymlink(t *testing.T) {
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(outDir, "current")); err != nil {
		t.Fatal(err)
	}
	if err := PublishMaterial(outDir, testMaterial("BAD"), time.Now()); err == nil {
		t.Fatalf("PublishMaterial accepted escaping current symlink")
	}
}

func testCriteria() certhubclient.CertificateCriteria {
	return certhubclient.CertificateCriteria{Domains: []string{"api.example.com"}, KeyType: "ecdsa-p256"}
}

func testMaterial(cert string) material.TLSMaterial {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	return material.TLSMaterial{
		CertificateID:        "cert-1",
		ApplicationID:        "app-1",
		Domains:              []string{"api.example.com"},
		KeyType:              "ecdsa-p256",
		IssuerID:             "issuer-1",
		IssuerName:           "letsencrypt",
		Version:              3,
		CertPEM:              cert,
		ChainPEM:             "CHAIN",
		FullchainPEM:         "FULLCHAIN",
		PrivateKeyPEM:        "PRIVATE",
		NotBefore:            now,
		NotAfter:             now.Add(90 * 24 * time.Hour),
		SerialNumber:         "03aabb",
		FingerprintSHA256:    "abc123",
		KeyFingerprintSHA256: "def456",
		MaterialETag:         `"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
	}
}

func materialJSON() string {
	return `{
		"certificate_id":"cert-1",
		"application_id":"app-1",
		"domains":["api.example.com"],
		"key_type":"ecdsa-p256",
		"issuer_id":"issuer-1",
		"issuer_name":"letsencrypt",
		"version":3,
		"cert_pem":"CERT",
		"chain_pem":"CHAIN",
		"fullchain_pem":"FULLCHAIN",
		"private_key_pem":"PRIVATE",
		"not_before":"2026-06-24T00:00:00Z",
		"not_after":"2026-09-22T00:00:00Z",
		"serial_number":"03aabb",
		"fingerprint_sha256":"abc123",
		"key_fingerprint_sha256":"def456",
		"material_etag":"\"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
	}`
}
