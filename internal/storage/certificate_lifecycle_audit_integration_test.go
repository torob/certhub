package storage_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

// TestCertificateLifecycleAuditWithPostgres proves that certificate lifecycle
// mutations commit their audit event in the same transaction as the mutation.
func TestCertificateLifecycleAuditWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping certificate lifecycle audit integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrationDB, err := migrations.OpenDB(url)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close()
	if _, err := migrations.NewRunner(migrations.DefaultDir).Up(ctx, migrationDB); err != nil {
		t.Fatal(err)
	}

	pool, err := storage.Open(ctx, storage.Config{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	user, err := users.NewRepository(tx).Create(ctx, users.CreateUserParams{
		Email:       "lifecycle.audit@example.com",
		DisplayName: "Lifecycle Audit User",
		GlobalRole:  users.GlobalRoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	appRepo := applications.NewRepository(tx)
	app, err := appRepo.Create(ctx, applications.CreateApplicationParams{
		Name:        "lifecycle_audit_app",
		DisplayName: "Lifecycle Audit App",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appRepo.AddDomainScope(ctx, applications.AddDomainScopeParams{ApplicationID: app.ID, Value: "*.lifecycle-audit.example.com"}); err != nil {
		t.Fatal(err)
	}
	issuerRepo := issuers.NewRepository(tx)
	issuer, err := issuerRepo.Create(ctx, issuers.CreateIssuerParams{
		Name:         "lifecycle_audit_issuer",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ContactEmail: "lifecycle.audit@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.CreateACMEAccount(ctx, issuers.CreateACMEAccountParams{
		IssuerID:               issuer.ID,
		Email:                  "lifecycle.audit@example.com",
		AccountURL:             "https://acme-staging-v02.api.letsencrypt.org/acct/lifecycle-audit",
		PrivateKeyPEMEncrypted: `{"version":"1"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.Update(ctx, issuer.ID, issuers.UpdateIssuerParams{Status: storage.SetString(string(issuers.StatusActive))}); err != nil {
		t.Fatal(err)
	}

	certRepo := certificates.NewRepository(tx)
	// The service opens its own write transaction; savepoints nest it in the
	// test transaction so a failed mutation really rolls back.
	service := certificates.NewService(certificates.ServiceConfig{
		Repository:        certRepo,
		ApplicationReader: appRepo,
		IssuerReader:      issuerRepo,
		AuditRepository:   audit.NewRepository(tx),
		Storage:           savepointBeginner{tx: tx},
	})
	actor := certificates.Actor{ID: user.ID, GlobalRole: users.GlobalRoleAdmin}
	auditCtx := certificates.AuditContext{CorrelationID: "req_lifecycle_audit_pg", SourceIP: "203.0.113.9"}

	etagSeq := 0
	storeValidMaterial := func(t *testing.T, versionID string) {
		t.Helper()
		etagSeq++
		if _, err := certRepo.StoreMaterial(ctx, certificates.StoreMaterialParams{
			CertificateVersionID:   versionID,
			CertPEM:                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
			ChainPEM:               "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
			FullchainPEM:           "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
			PrivateKeyPEMEncrypted: `{"version":"1","kind":"private-key"}`,
			NotBefore:              time.Now().Add(-time.Hour),
			NotAfter:               time.Now().Add(90 * 24 * time.Hour),
			SerialNumber:           fmt.Sprintf("%02x", etagSeq),
			FingerprintSHA256:      strings.Repeat("1", 64),
			KeyFingerprintSHA256:   strings.Repeat("2", 64),
			MaterialETag:           `"cth-mat-v1.` + fmt.Sprintf("%043d", etagSeq) + `"`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	type auditRow struct {
		identityType, identityID, targetType, targetID, scopeApplicationID, scopeCertificateID, correlationID, sourceIP, versionID string
	}
	auditRows := func(t *testing.T, action, certificateID string) []auditRow {
		t.Helper()
		rows, err := tx.Query(ctx, `
select identity_type, coalesce(identity_id::text, ''), target_type, coalesce(target_id::text, ''),
       coalesce(scope_application_id::text, ''), coalesce(scope_certificate_id::text, ''),
       coalesce(correlation_id, ''), coalesce(source_ip, ''), coalesce(metadata->>'certificate_version_id', '')
from audit_events
where action = $1 and scope_certificate_id = $2
order by created_at, id`, action, certificateID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []auditRow
		for rows.Next() {
			var row auditRow
			if err := rows.Scan(&row.identityType, &row.identityID, &row.targetType, &row.targetID, &row.scopeApplicationID, &row.scopeCertificateID, &row.correlationID, &row.sourceIP, &row.versionID); err != nil {
				t.Fatal(err)
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	requireAudit := func(t *testing.T, action, certificateID string, want auditRow) {
		t.Helper()
		got := auditRows(t, action, certificateID)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s audit rows = %#v, want [%#v]", action, got, want)
		}
	}

	criteria := certificates.Criteria{Domains: []string{"api.lifecycle-audit.example.com"}, KeyType: "ecdsa-p256", Issuer: issuer.Name}
	ensured, err := service.EnsureForApplicationToken(ctx, certificates.ApplicationActor{ApplicationID: app.ID}, criteria, auditCtx)
	if err != nil {
		t.Fatal(err)
	}
	cert := ensured.Certificate
	versions, err := certRepo.ListVersions(ctx, certificates.ListVersionsParams{CertificateID: cert.ID})
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions after ensure = %#v, %v", versions, err)
	}
	initial := versions[0]
	requireAudit(t, "certificate_created", cert.ID, auditRow{"application", app.ID, "certificate", cert.ID, app.ID, cert.ID, auditCtx.CorrelationID, auditCtx.SourceIP, initial.ID})

	// A repeated ensure reuses the Certificate and its issuing version.
	if _, err := service.EnsureForApplicationToken(ctx, certificates.ApplicationActor{ApplicationID: app.ID}, criteria, auditCtx); err != nil {
		t.Fatal(err)
	}
	if got := auditRows(t, "certificate_created", cert.ID); len(got) != 1 {
		t.Fatalf("certificate_created rows after repeated ensure = %d", len(got))
	}
	if got := auditRows(t, "certificate_issuance_started", cert.ID); len(got) != 0 {
		t.Fatalf("certificate_issuance_started rows after repeated ensure = %d", len(got))
	}
	storeValidMaterial(t, initial.ID)

	rotation, err := service.StartLifecycle(ctx, actor, cert.ID, certificates.IssuanceReasonKeyRotation, auditCtx)
	if err != nil {
		t.Fatal(err)
	}
	requireAudit(t, "certificate_key_rotation_started", cert.ID, auditRow{"user", user.ID, "certificate_version", rotation.ID, app.ID, cert.ID, auditCtx.CorrelationID, auditCtx.SourceIP, rotation.ID})
	if _, err := service.StartLifecycle(ctx, actor, cert.ID, certificates.IssuanceReasonKeyRotation, auditCtx); err != nil {
		t.Fatal(err)
	}
	if got := auditRows(t, "certificate_key_rotation_started", cert.ID); len(got) != 1 {
		t.Fatalf("key rotation audit rows after in-progress repeat = %d", len(got))
	}
	storeValidMaterial(t, rotation.ID)

	if _, err := service.RevokeCertificateVersion(ctx, actor, cert.ID, initial.ID, certificates.RevocationReasonSuperseded, auditCtx); err != nil {
		t.Fatal(err)
	}
	requireAudit(t, "certificate_revoked", cert.ID, auditRow{"user", user.ID, "certificate_version", initial.ID, app.ID, cert.ID, auditCtx.CorrelationID, auditCtx.SourceIP, initial.ID})
	// ACME revocation is still pending, so a repeated request is a retry.
	if _, err := service.RevokeCertificateVersion(ctx, actor, cert.ID, initial.ID, certificates.RevocationReasonSuperseded, auditCtx); err != nil {
		t.Fatal(err)
	}
	if got := auditRows(t, "certificate_revoked", cert.ID); len(got) != 1 {
		t.Fatalf("certificate_revoked rows after repeat = %d", len(got))
	}
	requireAudit(t, "certificate_revocation_retried", cert.ID, auditRow{"user", user.ID, "certificate_version", initial.ID, app.ID, cert.ID, auditCtx.CorrelationID, auditCtx.SourceIP, initial.ID})

	// An audit write failure rolls back the lifecycle mutation with it.
	badCtx := certificates.AuditContext{CorrelationID: "not a valid correlation id"}
	if _, err := service.StartLifecycle(ctx, actor, cert.ID, certificates.IssuanceReasonKeyRotation, badCtx); err == nil {
		t.Fatal("key rotation with failing audit write succeeded")
	}
	count, err := certRepo.CountVersions(ctx, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("versions after failed audit = %d, want 2 (mutation must roll back)", count)
	}
	if got := auditRows(t, "certificate_key_rotation_started", cert.ID); len(got) != 1 {
		t.Fatalf("key rotation audit rows after failed audit = %d", len(got))
	}
	if _, err := service.RevokeCertificateVersion(ctx, actor, cert.ID, rotation.ID, certificates.RevocationReasonSuperseded, badCtx); err == nil {
		t.Fatal("revoke with failing audit write succeeded")
	}
	stillValid, err := certRepo.GetVersion(ctx, rotation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillValid.Status != certificates.VersionStatusValid {
		t.Fatalf("version after failed revoke audit = %s, want valid (mutation must roll back)", stillValid.Status)
	}
}

// savepointBeginner runs each service write transaction as a savepoint inside
// the test transaction.
type savepointBeginner struct {
	tx storage.Tx
}

func (b savepointBeginner) Begin(ctx context.Context) (storage.Tx, error) {
	if _, err := b.tx.Exec(ctx, "savepoint certhub_service_tx"); err != nil {
		return nil, err
	}
	return savepointTx(b), nil
}

type savepointTx struct {
	tx storage.Tx
}

func (s savepointTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.tx.Exec(ctx, sql, args...)
}

func (s savepointTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.tx.QueryRow(ctx, sql, args...)
}

func (s savepointTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return s.tx.Query(ctx, sql, args...)
}

func (s savepointTx) Commit(ctx context.Context) error {
	_, err := s.tx.Exec(ctx, "release savepoint certhub_service_tx")
	return err
}

func (s savepointTx) Rollback(ctx context.Context) error {
	_, err := s.tx.Exec(ctx, "rollback to savepoint certhub_service_tx")
	return err
}
