package commands

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/config"
	"github.com/torob/certhub/internal/httpapi"
	"github.com/torob/certhub/internal/migrations"
)

func TestBareServerPrintsHelpAndDoesNotRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), nil)
	if code == 0 {
		t.Fatalf("bare command returned success")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("bare command ran a scaffolded subcommand: %q", stderr.String())
	}
}

func TestGenerateEncryptionKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"generate-encryption-key"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	output := stdout.String()
	if !strings.HasSuffix(output, "\n") || strings.Count(output, "\n") != 1 {
		t.Fatalf("output is not exactly one line: %q", output)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(output))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d", len(decoded))
	}
	if err := config.ValidateEncryptionKey(strings.TrimSpace(output)); err != nil {
		t.Fatalf("generated key failed shared validation: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestWriteTOTPProvisioningIncludesQRCodeAndURI(t *testing.T) {
	var stdout bytes.Buffer
	uri := "otpauth://totp/Certhub:admin@example.com?secret=ABCDEFGHIJKLMNOP&issuer=Certhub"
	(ServerRunner{Stdout: &stdout}).writeTOTPProvisioning(uri)
	output := stdout.String()
	if !strings.Contains(output, "totp_qr_code:\n") {
		t.Fatalf("output missing qr label: %q", output)
	}
	if !strings.Contains(output, "totp_provisioning_uri: "+uri) {
		t.Fatalf("output missing uri: %q", output)
	}
	if strings.Count(output, "\n") < 10 {
		t.Fatalf("output does not look like a terminal QR code: %q", output)
	}
}

func TestMigrateLoadsConfigAndFailsClosedWithoutDatabase(t *testing.T) {
	configPath := writeCommandConfig(t)
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"migrate", "--config", configPath})
	if code == 0 {
		t.Fatalf("migrate unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "migration failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "secret") || strings.Contains(stdout.String(), "secret") {
		t.Fatalf("command output leaked config secret: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestMigrateJSONFailureDoesNotLeakDetails(t *testing.T) {
	configPath := writeCommandConfig(t)
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"migrate", "--config", configPath, "--json"})
	if code == 0 {
		t.Fatalf("migrate unexpectedly succeeded")
	}
	var body map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "failed" || body["error"] == "" {
		t.Fatalf("body = %#v", body)
	}
	if strings.Contains(stdout.String(), "postgres://") || strings.Contains(stdout.String(), "secret") || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestMigrateJSONConfigLoadFailureIsMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"migrate", "--config", missingPath, "--json"})
	if code == 0 {
		t.Fatalf("migrate unexpectedly succeeded")
	}
	var body map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "failed" || body["error"] != "config_invalid" {
		t.Fatalf("body = %#v", body)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMigrateJSONIncompatibleStatusReportsFailed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := migrations.Status{CurrentVersion: 99, LatestVersion: 1, Pending: 0, Compatible: false}
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).reportMigrationFailure(true, "migration failed", "migration_failed", migrations.IncompatibleError{Status: status})
	if code == 0 {
		t.Fatalf("incompatible migration failure returned success")
	}
	var body map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "failed" || body["error"] != "migration_incompatible" || body["compatible"] != false {
		t.Fatalf("body = %#v", body)
	}
	if body["current_version"].(float64) != 99 || body["latest_version"].(float64) != 1 {
		t.Fatalf("body = %#v", body)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunHelpIncludesMigrateFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"run", "--help"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "run [--migrate] --config <path>") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMigrateDoesNotValidateTLSBeforeStorage(t *testing.T) {
	dir := newCommandTempDir(t)
	configPath := writeCommandConfigInDir(t, dir, "postgres://certhub:secret@127.0.0.1:1/certhub?sslmode=disable", `
tls:
  cert_file: "`+filepath.Join(dir, "future-fullchain.pem")+`"
  key_file: "`+filepath.Join(dir, "future-privkey.pem")+`"
`)
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"migrate", "--config", configPath})
	if code == 0 {
		t.Fatalf("migrate unexpectedly succeeded")
	}
	if strings.Contains(stderr.String(), "tls validation failed") {
		t.Fatalf("migrate validated TLS before direct DB work: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "migration failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestBootstrapCreateAdminIsNotScaffolded(t *testing.T) {
	var stdout, stderr bytes.Buffer
	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	code := (ServerRunner{Stdin: strings.NewReader("correct horse battery staple\n"), Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{
		"bootstrap", "create-admin",
		"--config", missingPath,
		"--email", "admin@example.com",
		"--display-name", "Admin User",
		"--password-stdin",
	})
	if code == 0 {
		t.Fatalf("bootstrap unexpectedly succeeded")
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, "scaffolding") || strings.Contains(output, "pending") {
		t.Fatalf("bootstrap still appears scaffolded: %q", output)
	}
	if !strings.Contains(stderr.String(), "bootstrap failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestBootstrapCreateAdminRejectsOIDCLinkFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{
		"bootstrap", "create-admin",
		"--config", filepath.Join(t.TempDir(), "missing.yaml"),
		"--email", "admin@example.com",
		"--display-name", "Admin User",
		"--oidc-issuer", "https://issuer.example.com",
		"--oidc-subject", "subject",
	})
	if code != 2 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestBootstrapCredentialFileRequiresPrivateRegularFile(t *testing.T) {
	dir := newCommandTempDir(t)
	secretPath := filepath.Join(dir, "credentials.json")
	const canary = "DNS-CREDENTIAL-CANARY"
	if err := os.WriteFile(secretPath, []byte(`{"api_token":"`+canary+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := (ServerRunner{}).readBootstrapCredentials(false, "", secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), canary) {
		t.Fatalf("credential data was not read")
	}
	if err := os.Chmod(secretPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = (ServerRunner{}).readBootstrapCredentials(false, "", secretPath)
	if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("broad credential file error = %v", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("credential error leaked secret: %v", err)
	}
	linkPath := filepath.Join(dir, "credentials-link.json")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err = (ServerRunner{}).readBootstrapCredentials(false, "", linkPath)
	if err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink credential file error = %v", err)
	}
}

func TestBootstrapInteractiveFailsClosedInNonTTY(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"bootstrap", "--interactive"})
	if code == 0 {
		t.Fatalf("interactive bootstrap unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "requires a TTY") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "scaffolding") {
		t.Fatalf("unexpected scaffold output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestBootstrapInteractiveRequiresStderrTTY(t *testing.T) {
	dir := newCommandTempDir(t)
	in, err := os.Create(filepath.Join(dir, "stdin"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	errOut, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer errOut.Close()
	runner := ServerRunner{Stdin: in, Stdout: out, Stderr: errOut}
	err = runner.requireInteractiveTerminalWith(func(file *os.File) bool {
		return file != errOut
	})
	if err == nil {
		t.Fatalf("interactive terminal check accepted non-TTY stderr")
	}
}

func TestRunValidatesDirectTLSBeforeStorage(t *testing.T) {
	dir := newCommandTempDir(t)
	configPath := writeCommandConfigInDir(t, dir, "postgres://certhub:secret@127.0.0.1:1/certhub?sslmode=disable", `
tls:
  cert_file: "`+filepath.Join(dir, "missing-fullchain.pem")+`"
  key_file: "`+filepath.Join(dir, "missing-privkey.pem")+`"
`)

	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"run", "--config", configPath})
	if code == 0 {
		t.Fatalf("run unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "tls validation failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "server readiness failed") || strings.Contains(stderr.String(), "migration failed") {
		t.Fatalf("TLS validation did not fail before storage side effects: %q", stderr.String())
	}
}

func TestRunAllowsPendingSelfCertificateBeforeStorage(t *testing.T) {
	dir := newCommandTempDir(t)
	outputDir := filepath.Join(dir, "self-certificate")
	configPath := writeCommandConfigInDir(t, dir, "postgres://certhub:secret@127.0.0.1:1/certhub?sslmode=disable", `
server:
  public_hostname: "certhub.example.com"
self_certificate:
  sync_enabled: true
  output_dir: "`+outputDir+`"
  issuer: "lets_encrypt"
tls:
  cert_file: "`+filepath.Join(outputDir, "current", "fullchain.pem")+`"
  key_file: "`+filepath.Join(outputDir, "current", "privkey.pem")+`"
`)

	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"run", "--config", configPath})
	if code == 0 {
		t.Fatalf("run unexpectedly succeeded")
	}
	if strings.Contains(stderr.String(), "tls validation failed") {
		t.Fatalf("pending self-certificate was rejected: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "server readiness failed") {
		t.Fatalf("run did not proceed to storage readiness: %q", stderr.String())
	}
}

func TestRunRejectsMalformedAndMismatchedTLSBeforeStorage(t *testing.T) {
	tests := map[string]func(t *testing.T, dir string) (string, string){
		"malformed": func(t *testing.T, dir string) (string, string) {
			certFile := filepath.Join(dir, "bad-fullchain.pem")
			keyFile := filepath.Join(dir, "bad-privkey.pem")
			if err := os.WriteFile(certFile, []byte("not a certificate\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyFile, []byte("not a private key\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return certFile, keyFile
		},
		"mismatched": func(t *testing.T, dir string) (string, string) {
			certKey := newRSAKey(t)
			fileKey := newRSAKey(t)
			certFile := filepath.Join(dir, "fullchain.pem")
			keyFile := filepath.Join(dir, "privkey.pem")
			writeCertificatePEM(t, certFile, certKey)
			writePrivateKeyPEM(t, keyFile, fileKey)
			return certFile, keyFile
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			dir := newCommandTempDir(t)
			certFile, keyFile := setup(t, dir)
			configPath := writeCommandConfigInDir(t, dir, "postgres://certhub:secret@127.0.0.1:1/certhub?sslmode=disable", `
tls:
  cert_file: "`+certFile+`"
  key_file: "`+keyFile+`"
`)

			var stdout, stderr bytes.Buffer
			code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"run", "--config", configPath})
			if code == 0 {
				t.Fatalf("run unexpectedly succeeded")
			}
			if !strings.Contains(stderr.String(), "tls validation failed") {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if strings.Contains(stderr.String(), "server readiness failed") || strings.Contains(stderr.String(), "migration failed") {
				t.Fatalf("TLS validation did not fail before storage side effects: %q", stderr.String())
			}
		})
	}
}

func TestRuntimeReadinessIncludesTLSReloadFailure(t *testing.T) {
	dir := newCommandTempDir(t)
	certKey := newRSAKey(t)
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	writeCertificatePEM(t, certFile, certKey)
	writePrivateKeyPEM(t, keyFile, certKey)
	configPath := writeCommandConfigInDir(t, dir, "postgres://certhub:secret@127.0.0.1:1/certhub?sslmode=disable", `
server:
  public_hostname: "certhub.example.com"
tls:
  cert_file: "`+certFile+`"
  key_file: "`+keyFile+`"
`)
	cfg, err := config.LoadFile(configPath, config.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tlsLoader, err := config.NewTLSCertificateLoader(cfg)
	if err != nil {
		t.Fatal(err)
	}

	writeCertificatePEMForHost(t, certFile, certKey, "other.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	resources := &runtimeResources{cfg: cfg, TLSLoader: tlsLoader}
	if status := readinessStatus(resources.CheckReadiness(), "tls_certificate"); status != "failed" {
		t.Fatalf("tls_certificate readiness = %q", status)
	}

	handler := httpapi.New(cfg, httpapi.WithReadinessChecker(resources)).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "tls_certificate") {
		t.Fatalf("readyz status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "certhub_platform_ready 0\n") {
		t.Fatalf("metrics status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRunFailsClosedWhenStorageUnavailable(t *testing.T) {
	configPath := writeCommandConfig(t)
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"run", "--config", configPath})
	if code == 0 {
		t.Fatalf("run unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "server readiness failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "secret") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
}

func readinessStatus(checks []httpapi.ReadinessCheck, name string) string {
	for _, check := range checks {
		if check.Name == name {
			return check.Status
		}
	}
	return ""
}

func TestMigrateWithPostgresIntegration(t *testing.T) {
	dbURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping certhub-server migrate PostgreSQL smoke")
	}
	configPath := writeCommandConfigWithDatabaseURL(t, dbURL)
	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"migrate", "--config", configPath, "--json"})
	if code != 0 {
		t.Fatalf("migrate code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"ok"`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunMigrationModeWithPostgresIntegration(t *testing.T) {
	dbURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping certhub-server run migration mode PostgreSQL smoke")
	}
	pendingDBURL := commandTestDatabaseURL(t, dbURL)
	pendingConfigPath := writeCommandConfigWithDatabaseURL(t, pendingDBURL)

	var stdout, stderr bytes.Buffer
	code := (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"run", "--config", pendingConfigPath})
	if code == 0 {
		t.Fatalf("run unexpectedly succeeded without --migrate")
	}
	if !strings.Contains(stderr.String(), "database migrations are pending") || !strings.Contains(stderr.String(), "run --migrate") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}

	migratingDBURL := commandTestDatabaseURL(t, dbURL)
	migratingConfigPath := writeCommandConfigWithDatabaseURL(t, migratingDBURL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdout.Reset()
	stderr.Reset()
	code = (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(ctx, []string{"run", "--migrate", "--config", migratingConfigPath})
	if code != 0 {
		t.Fatalf("run --migrate code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	db, err := migrations.OpenDB(migratingDBURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	status, err := migrations.NewRunner(migrations.DefaultDir).Status(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Compatible || status.Pending != 0 {
		t.Fatalf("status = %#v", status)
	}

	currentConfigPath := writeCommandConfigWithDatabaseURL(t, migratingDBURL)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdout.Reset()
	stderr.Reset()
	code = (ServerRunner{Stdout: &stdout, Stderr: &stderr}).Execute(ctx, []string{"run", "--config", currentConfigPath})
	if code != 0 {
		t.Fatalf("run on current schema code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func writeCommandConfig(t *testing.T) string {
	return writeCommandConfigWithDatabaseURL(t, "postgres://certhub:secret@127.0.0.1:1/certhub?sslmode=disable")
}

func writeCommandConfigWithDatabaseURL(t *testing.T, dbURL string) string {
	dir := newCommandTempDir(t)
	return writeCommandConfigInDir(t, dir, dbURL, "")
}

func newCommandTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "command-config-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func commandTestDatabaseURL(t *testing.T, dbURL string) string {
	t.Helper()
	database := "command_test_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	db, err := migrations.OpenDB(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), "create database "+database); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "drop database if exists "+database+" with (force)")
		_ = db.Close()
	})

	parsed, err := neturl.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	return parsed.String()
}

func writeCommandConfigInDir(t *testing.T, dir, dbURL, extra string) string {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	path := filepath.Join(dir, "server.yaml")
	body := `
database:
  url: "` + dbURL + `"
encryption:
  key: "` + key + `"
http:
  bind_addr: "127.0.0.1:0"
  require_https: false
` + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeCertificatePEM(t *testing.T, path string, key *rsa.PrivateKey) {
	t.Helper()
	writeCertificatePEMForHost(t, path, key, "certhub.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func writeCertificatePEMForHost(t *testing.T, path string, key *rsa.PrivateKey, host string, notBefore, notAfter time.Time) {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func writePrivateKeyPEM(t *testing.T, path string, key *rsa.PrivateKey) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
}
