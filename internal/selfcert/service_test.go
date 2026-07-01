package selfcert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/config"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
	tlsmaterial "github.com/torob/certhub/pkg/material"
)

const (
	testAppID     = "12345678-1234-4234-9234-123456789abc"
	testCertID    = "22345678-1234-4234-9234-123456789abc"
	testIssuerID  = "32345678-1234-4234-9234-123456789abc"
	testVersionID = "42345678-1234-4234-9234-123456789abc"
)

func TestPublishAtomicPreservesCurrentOnReleaseCollision(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	oldMaterial := testMaterial("old.example.com", "OLD-FULLCHAIN", "OLD-KEY")
	newMaterial := oldMaterial
	newMaterial.FullchainPEM = "NEW-FULLCHAIN"
	newMaterial.PrivateKeyPEM = "NEW-KEY"

	first, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: oldMaterial, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed {
		t.Fatalf("first publish Changed = false")
	}
	if _, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: newMaterial, Now: func() time.Time { return now }}); err == nil {
		t.Fatalf("second publish unexpectedly succeeded despite immutable release collision")
	}
	currentFullchain, err := os.ReadFile(filepath.Join(dir, "current", "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(currentFullchain) != "OLD-FULLCHAIN" {
		t.Fatalf("current fullchain was overwritten: %q", string(currentFullchain))
	}
	keyInfo, err := os.Stat(filepath.Join(first.ReleaseDir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("privkey mode = %o", keyInfo.Mode().Perm())
	}
}

func TestPublishIdenticalMaterialIsNoop(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	material := testMaterial("certhub.example.com", "FULLCHAIN", "KEY")

	first, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: material, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed {
		t.Fatalf("first publish Changed = false")
	}
	second, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: material, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Fatalf("identical publish Changed = true")
	}
	if second.ReleaseDir != first.ReleaseDir {
		t.Fatalf("release dir = %q want %q", second.ReleaseDir, first.ReleaseDir)
	}
	if got := releaseCount(t, dir); got != 1 {
		t.Fatalf("release count = %d want 1", got)
	}
}

func TestPublishRepublishesWhenCurrentPEMChanges(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	material := testMaterial("certhub.example.com", "FULLCHAIN", "KEY")

	if _, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: material, Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "current", "fullchain.pem"), []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}
	published, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: material, Now: func() time.Time { return now.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	if !published.Changed {
		t.Fatalf("tampered publish Changed = false")
	}
	currentFullchain, err := os.ReadFile(filepath.Join(dir, "current", "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(currentFullchain) != "FULLCHAIN" {
		t.Fatalf("current fullchain = %q want FULLCHAIN", string(currentFullchain))
	}
	if got := releaseCount(t, dir); got != 2 {
		t.Fatalf("release count = %d want 2", got)
	}
}

func TestReconcileDesiredStateUsesInternalStoresAndEnqueuesInitialIssuance(t *testing.T) {
	apps := &fakeApplications{}
	certs := &fakeCertificates{
		certs: []certificates.Certificate{{
			ID:             "52345678-1234-4234-9234-123456789abc",
			ApplicationID:  testAppID,
			IssuerID:       testIssuerID,
			NormalizedSANs: []string{"old.example.com"},
			KeyType:        certificates.KeyTypeECDSAP256,
			Status:         certificates.StatusReady,
		}},
	}
	reconciler := Reconciler{
		Runtime: RuntimeConfig{Enabled: true, Hostname: "Certhub.Example.COM.", Issuer: "lets_encrypt", KeyType: "ecdsa-p256"},
		Apps:    apps,
		Certs:   certs,
		Issuers: fakeIssuers{issuer: issuers.Issuer{ID: testIssuerID, Name: "lets_encrypt", Status: issuers.StatusActive}},
	}
	desired, err := reconciler.ReconcileDesired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if desired.Application.ID != testAppID || apps.scope != "certhub.example.com" {
		t.Fatalf("application/scope = %#v scope=%q", desired.Application, apps.scope)
	}
	if len(certs.deleted) != 1 || certs.deleted[0] != "52345678-1234-4234-9234-123456789abc" {
		t.Fatalf("deleted = %#v", certs.deleted)
	}
	if !certs.created || certs.createdParams.NormalizedSANs[0] != "certhub.example.com" || certs.createdParams.IssuerID != testIssuerID {
		t.Fatalf("created params = %#v", certs.createdParams)
	}
	if !certs.versionCreated || !certs.jobCreated {
		t.Fatalf("initial issuance was not enqueued")
	}
}

func TestSyncedAuditMetadataIsSanitized(t *testing.T) {
	appender := &fakeAudit{}
	now := time.Now()
	material := testMaterial("certhub.example.com", "-----BEGIN CERTIFICATE-----\nCERT-CANARY\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nKEY-CANARY\n-----END PRIVATE KEY-----\n")
	err := appendSyncedAudit(context.Background(), appender, DesiredState{
		Application: applications.Application{ID: testAppID},
		Certificate: certificates.Certificate{ID: testCertID},
	}, certificates.CertificateVersion{ID: testVersionID, Version: 7, CreatedAt: now}, material, PublishResult{ReleaseDir: filepath.Join("releases", "abc")})
	if err != nil {
		t.Fatal(err)
	}
	if appender.params.IdentityType != audit.IdentityTypeSystem || appender.params.IdentityID != nil {
		t.Fatalf("identity = %s %#v", appender.params.IdentityType, appender.params.IdentityID)
	}
	if appender.params.Action != "server_self_certificate_synced" || *appender.params.ScopeApplicationID != testAppID || *appender.params.ScopeCertificateID != testCertID {
		t.Fatalf("audit params = %#v", appender.params)
	}
	raw := string(appender.params.Metadata)
	for _, secret := range []string{"CERT-CANARY", "KEY-CANARY", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if contains(raw, secret) {
			t.Fatalf("audit metadata leaked %q: %s", secret, raw)
		}
	}
	var metadata map[string]any
	if err := json.Unmarshal(appender.params.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["material_etag"] != material.MaterialETag {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestPublishThenReloadPendingTLSLoader(t *testing.T) {
	dir := t.TempDir()
	loader, err := config.NewTLSCertificateLoader(&config.Config{
		Server:          config.ServerConfig{PublicHostname: "certhub.example.com"},
		TLS:             config.TLSConfig{CertFile: filepath.Join(dir, "current", "fullchain.pem"), KeyFile: filepath.Join(dir, "current", "privkey.pem")},
		SelfCertificate: config.SelfCertificateConfig{SyncEnabled: true, OutputDir: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !loader.Pending() {
		t.Fatalf("loader should start pending")
	}
	certPEM, keyPEM := generateTLSPEM(t, "certhub.example.com")
	material := testMaterial("certhub.example.com", certPEM, keyPEM)
	material.CertPEM = certPEM
	material.ChainPEM = ""
	material.FullchainPEM = certPEM
	material.PrivateKeyPEM = keyPEM
	if _, err := Publish(context.Background(), PublishOptions{OutputDir: dir, Material: material}); err != nil {
		t.Fatal(err)
	}
	if err := loader.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Leaf == nil || loaded.Leaf.DNSNames[0] != "certhub.example.com" {
		t.Fatalf("loaded certificate = %#v", loaded)
	}
}

func testMaterial(domain, fullchain, key string) tlsmaterial.TLSMaterial {
	now := time.Now().UTC()
	return tlsmaterial.TLSMaterial{
		CertificateID:        testCertID,
		ApplicationID:        testAppID,
		Domains:              []string{domain},
		KeyType:              "ecdsa-p256",
		IssuerID:             testIssuerID,
		IssuerName:           "lets_encrypt",
		Version:              1,
		CertPEM:              fullchain,
		ChainPEM:             "",
		FullchainPEM:         fullchain,
		PrivateKeyPEM:        key,
		NotBefore:            now.Add(-time.Hour),
		NotAfter:             now.Add(time.Hour),
		SerialNumber:         "01",
		FingerprintSHA256:    "1111111111111111111111111111111111111111111111111111111111111111",
		KeyFingerprintSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		MaterialETag:         `"cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E"`,
	}
}

func generateTLSPEM(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && (s == substr || contains(s[1:], substr) || s[:len(substr)] == substr))
}

func releaseCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "releases"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

type fakeApplications struct {
	scope string
}

func (f *fakeApplications) EnsureSystemApplication(context.Context, applications.CreateApplicationParams) (applications.Application, error) {
	kind := applications.SystemKindCerthubServer
	return applications.Application{ID: testAppID, Name: "certhub_server", Status: applications.StatusActive, SystemKind: &kind}, nil
}

func (f *fakeApplications) ReplaceSystemDomainScopes(_ context.Context, _ string, value string) ([]applications.DomainScope, error) {
	f.scope = value
	return []applications.DomainScope{{ApplicationID: testAppID, Value: value}}, nil
}

type fakeCertificates struct {
	certs          []certificates.Certificate
	deleted        []string
	created        bool
	createdParams  certificates.CreateOrReuseCertificateParams
	versionCreated bool
	jobCreated     bool
}

func (f *fakeCertificates) CreateOrReuse(_ context.Context, params certificates.CreateOrReuseCertificateParams) (certificates.Certificate, error) {
	f.created = true
	f.createdParams = params
	return certificates.Certificate{ID: testCertID, ApplicationID: params.ApplicationID, IssuerID: params.IssuerID, NormalizedSANs: params.NormalizedSANs, KeyType: params.KeyType, Status: certificates.StatusPending}, nil
}

func (f *fakeCertificates) List(context.Context, certificates.ListCertificatesParams) ([]certificates.Certificate, error) {
	return append([]certificates.Certificate(nil), f.certs...), nil
}

func (f *fakeCertificates) GetLatestValidMaterial(context.Context, string) (certificates.CertificateVersion, error) {
	return certificates.CertificateVersion{}, errors.New("not implemented")
}

func (f *fakeCertificates) CreateIssuingVersion(_ context.Context, params certificates.CreateIssuingVersionParams) (certificates.CertificateVersion, error) {
	f.versionCreated = true
	return certificates.CertificateVersion{ID: testVersionID, CertificateID: params.CertificateID, Version: 1, Status: certificates.VersionStatusIssuing}, nil
}

func (f *fakeCertificates) EnsureIssuanceJob(context.Context, certificates.EnsureIssuanceJobParams) (certificates.IssuanceJob, error) {
	f.jobCreated = true
	return certificates.IssuanceJob{}, nil
}

func (f *fakeCertificates) DeleteCertificate(_ context.Context, params certificates.DeleteCertificateParams) (certificates.Certificate, error) {
	f.deleted = append(f.deleted, params.ID)
	return certificates.Certificate{ID: params.ID, Status: certificates.StatusDeleted}, nil
}

type fakeIssuers struct {
	issuer issuers.Issuer
}

func (f fakeIssuers) GetByName(context.Context, string) (issuers.Issuer, error) {
	return f.issuer, nil
}

type fakeAudit struct {
	params audit.AppendEventParams
}

func (f *fakeAudit) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	f.params = params
	return audit.Event{}, nil
}

var _ ApplicationStore = (*fakeApplications)(nil)
var _ CertificateStore = (*fakeCertificates)(nil)
var _ IssuerStore = fakeIssuers{}
var _ AuditAppender = (*fakeAudit)(nil)
var _ = storage.MaxListLimit
