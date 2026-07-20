package storage_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/audit"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestApplicationHardDeleteWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping Application hard-delete integration test")
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

	seedApplicationDeleteDependencies(t, ctx, tx)
	repo := applications.NewRepository(tx)

	t.Run("cascades inactive graph and preserves audit identifiers", func(t *testing.T) {
		appID := "a0000000-0000-4000-8000-000000000001"
		certID := "c0000000-0000-4000-8000-000000000001"
		versionID := "d0000000-0000-4000-8000-000000000001"
		jobID := "e0000000-0000-4000-8000-000000000001"
		challengeID := "f0000000-0000-4000-8000-000000000001"
		auditID := "90000000-0000-4000-8000-000000000001"
		mustExecApplicationDelete(t, ctx, tx, `insert into applications (id, name, display_name) values ($1, 'delete_graph', 'Delete Graph')`, appID)
		mustExecApplicationDelete(t, ctx, tx, `insert into application_domain_scopes (id, application_id, value) values ('a1000000-0000-4000-8000-000000000001', $1, '*.example.com')`, appID)
		mustExecApplicationDelete(t, ctx, tx, `insert into application_tokens (id, application_id, name, token_hash) values ('a2000000-0000-4000-8000-000000000001', $1, 'deploy', $2)`, appID, strings.Repeat("A", 43))
		mustExecApplicationDelete(t, ctx, tx, `insert into application_user_grants (id, application_id, user_id, role) values ('a3000000-0000-4000-8000-000000000001', $1, '10000000-0000-4000-8000-000000000001', 'manager')`, appID)
		mustExecApplicationDelete(t, ctx, tx, `
insert into certificates (id, normalized_sans, key_type, issuer_id, application_id, status, failure_code)
values ($1, array['inactive.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000001', $2, 'failed', 'fixture_failed')`, certID, appID)
		mustExecApplicationDelete(t, ctx, tx, `
insert into certificate_versions (id, certificate_id, version, status, reason, started_at, completed_at, failure_code)
values ($1, $2, 1, 'failed', 'initial_issue', now(), now(), 'fixture_failed')`, versionID, certID)
		mustExecApplicationDelete(t, ctx, tx, `
insert into certificate_issuance_jobs (id, certificate_id, certificate_version_id, reason, status, completed_at)
values ($1, $2, $3, 'initial_issue', 'succeeded', now())`, jobID, certID, versionID)
		mustExecApplicationDelete(t, ctx, tx, `
insert into dns_challenge_records (
    id, issuance_job_id, certificate_id, certificate_version_id, dns_provider_id, dns_provider_zone_id,
    authorization_identifier, record_name, txt_value_encrypted, status, presented_at, validated_at, cleaned_at
) values (
    $1, $2, $3, $4, '30000000-0000-4000-8000-000000000001', '31000000-0000-4000-8000-000000000001',
    'inactive.example.com', '_acme-challenge.inactive.example.com', '{"fixture":true}', 'cleaned', now(), now(), now()
)`, challengeID, jobID, certID, versionID)
		mustExecApplicationDelete(t, ctx, tx, `
insert into certificate_events (id, certificate_id, certificate_version_id, issuance_job_id, event_type, result)
values ('f1000000-0000-4000-8000-000000000001', $1, $2, $3, 'fixture_completed', 'success')`, certID, versionID, jobID)
		mustExecApplicationDelete(t, ctx, tx, `
insert into audit_events (id, identity_type, action, target_type, target_id, scope_application_id, scope_certificate_id, result)
values ($1, 'system', 'fixture_created', 'application', $2, $2, $3, 'success')`, auditID, appID, certID)

		deleted, err := repo.DeleteApplication(ctx, appID)
		if err != nil {
			t.Fatal(err)
		}
		if deleted.DomainScopeCount != 1 || deleted.TokenCount != 1 || deleted.UserGrantCount != 1 || deleted.CertificateCount != 1 {
			t.Fatalf("deletion counts = %#v", deleted)
		}
		for _, table := range []string{
			"applications", "application_domain_scopes", "application_tokens", "application_user_grants",
			"certificates", "certificate_versions", "certificate_issuance_jobs", "dns_challenge_records", "certificate_events",
		} {
			if got := countRowsForApplicationDelete(t, ctx, tx, table, appID, certID); got != 0 {
				t.Fatalf("%s rows after deletion = %d", table, got)
			}
		}
		var targetID, scopeApplicationID, scopeCertificateID string
		if err := tx.QueryRow(ctx, `
select target_id::text, scope_application_id::text, scope_certificate_id::text
from audit_events where id = $1`, auditID).Scan(&targetID, &scopeApplicationID, &scopeCertificateID); err != nil {
			t.Fatal(err)
		}
		if targetID != appID || scopeApplicationID != appID || scopeCertificateID != certID {
			t.Fatalf("historical audit identifiers = %q %q %q", targetID, scopeApplicationID, scopeCertificateID)
		}
	})

	t.Run("active usable version blocks but inactive material does not", func(t *testing.T) {
		tests := []struct {
			name       string
			appID      string
			certID     string
			versionID  string
			certStatus string
			version    string
			notBefore  string
			notAfter   string
			blocked    bool
		}{
			{name: "current", appID: "a0000000-0000-4000-8000-000000000010", certID: "c0000000-0000-4000-8000-000000000010", versionID: "d0000000-0000-4000-8000-000000000010", certStatus: "ready", version: "valid", notBefore: "-1 hour", notAfter: "1 hour", blocked: true},
			{name: "expired", appID: "a0000000-0000-4000-8000-000000000011", certID: "c0000000-0000-4000-8000-000000000011", versionID: "d0000000-0000-4000-8000-000000000011", certStatus: "expired", version: "valid", notBefore: "-2 hours", notAfter: "-1 hour"},
			{name: "not yet valid", appID: "a0000000-0000-4000-8000-000000000012", certID: "c0000000-0000-4000-8000-000000000012", versionID: "d0000000-0000-4000-8000-000000000012", certStatus: "ready", version: "valid", notBefore: "1 hour", notAfter: "2 hours"},
			{name: "revoked", appID: "a0000000-0000-4000-8000-000000000013", certID: "c0000000-0000-4000-8000-000000000013", versionID: "d0000000-0000-4000-8000-000000000013", certStatus: "revoked", version: "revoked", notBefore: "-1 hour", notAfter: "1 hour"},
			{name: "failed parent", appID: "a0000000-0000-4000-8000-000000000014", certID: "c0000000-0000-4000-8000-000000000014", versionID: "d0000000-0000-4000-8000-000000000014", certStatus: "failed", version: "valid", notBefore: "-1 hour", notAfter: "1 hour"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				seedApplicationWithMaterial(t, ctx, tx, tc.appID, tc.certID, tc.versionID, tc.certStatus, tc.version, tc.notBefore, tc.notAfter)
				_, err := repo.DeleteApplication(ctx, tc.appID)
				if tc.blocked {
					var active applications.ApplicationHasActiveCertificatesError
					if !errors.As(err, &active) || active.Count != 1 {
						t.Fatalf("err = %v", err)
					}
					if got := countRowsForApplicationDelete(t, ctx, tx, "applications", tc.appID, tc.certID); got != 1 {
						t.Fatalf("application changed after conflict")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("reserved application is rejected unchanged", func(t *testing.T) {
		systemApp, err := repo.EnsureSystemApplication(ctx, applications.CreateApplicationParams{
			DisplayName: "Certhub Server",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.DeleteApplication(ctx, systemApp.ID); !errors.Is(err, applications.ErrSystemManagedResource) {
			t.Fatalf("err = %v", err)
		}
		if got := countRowsForApplicationDelete(t, ctx, tx, "applications", systemApp.ID, ""); got != 1 {
			t.Fatalf("system application changed after rejection")
		}
	})

	t.Run("busy counts take precedence and preserve state", func(t *testing.T) {
		tests := []struct {
			name           string
			suffix         string
			wantJobs       int64
			wantVersions   int64
			wantChallenges int64
			seed           func(*testing.T, string, string, string)
		}{
			{
				name: "pending job", suffix: "20", wantJobs: 1,
				seed: func(st *testing.T, appID, certID, versionID string) {
					seedApplicationWithMaterial(st, ctx, tx, appID, certID, versionID, "ready", "valid", "-1 hour", "1 hour")
					if _, err := tx.Exec(ctx, `
insert into certificate_issuance_jobs (id, certificate_id, reason, status)
values ('e0000000-0000-4000-8000-000000000020', $1, 'renewal', 'pending')`, certID); err != nil {
						st.Fatal(err)
					}
				},
			},
			{
				name: "issuing version", suffix: "21", wantVersions: 1,
				seed: func(st *testing.T, appID, certID, versionID string) {
					mustExecApplicationDelete(st, ctx, tx, `
insert into applications (id, name, display_name)
values ($1, 'delete_busy_21', 'Delete Busy')`, appID)
					mustExecApplicationDelete(st, ctx, tx, `
insert into certificates (id, normalized_sans, key_type, issuer_id, application_id, status)
values ($1, array['busy.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000001', $2, 'issuing')`, certID, appID)
					mustExecApplicationDelete(st, ctx, tx, `
insert into certificate_versions (id, certificate_id, version, status, reason, started_at)
values ($1, $2, 1, 'issuing', 'initial_issue', now())`, versionID, certID)
				},
			},
			{
				name: "unclean challenge", suffix: "22", wantChallenges: 1,
				seed: func(st *testing.T, appID, certID, versionID string) {
					mustExecApplicationDelete(st, ctx, tx, `
insert into applications (id, name, display_name)
values ($1, 'delete_busy_22', 'Delete Busy')`, appID)
					mustExecApplicationDelete(st, ctx, tx, `
insert into certificates (id, normalized_sans, key_type, issuer_id, application_id, status, failure_code)
values ($1, array['busy.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000001', $2, 'failed', 'fixture_failed')`, certID, appID)
					mustExecApplicationDelete(st, ctx, tx, `
insert into certificate_versions (id, certificate_id, version, status, reason, started_at, completed_at, failure_code)
values ($1, $2, 1, 'failed', 'initial_issue', now(), now(), 'fixture_failed')`, versionID, certID)
					mustExecApplicationDelete(st, ctx, tx, `
insert into certificate_issuance_jobs (id, certificate_id, certificate_version_id, reason, status, completed_at)
values ('e0000000-0000-4000-8000-000000000022', $1, $2, 'initial_issue', 'succeeded', now())`, certID, versionID)
					mustExecApplicationDelete(st, ctx, tx, `
insert into dns_challenge_records (
    id, issuance_job_id, certificate_id, certificate_version_id, dns_provider_id, dns_provider_zone_id,
    authorization_identifier, record_name, txt_value_encrypted, status
) values (
    'f0000000-0000-4000-8000-000000000022', 'e0000000-0000-4000-8000-000000000022', $1, $2,
    '30000000-0000-4000-8000-000000000001', '31000000-0000-4000-8000-000000000001',
    'busy.example.com', '_acme-challenge.busy.example.com', '{"fixture":true}', 'pending'
)`, certID, versionID)
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				appID := "a0000000-0000-4000-8000-0000000000" + tc.suffix
				certID := "c0000000-0000-4000-8000-0000000000" + tc.suffix
				versionID := "d0000000-0000-4000-8000-0000000000" + tc.suffix
				tc.seed(t, appID, certID, versionID)
				_, err := repo.DeleteApplication(ctx, appID)
				var busy applications.ApplicationBusyError
				if !errors.As(err, &busy) ||
					busy.ActiveJobs != tc.wantJobs ||
					busy.IssuingVersions != tc.wantVersions ||
					busy.UncleanChallenges != tc.wantChallenges {
					t.Fatalf("err = %v busy = %#v", err, busy)
				}
				if got := countRowsForApplicationDelete(t, ctx, tx, "applications", appID, certID); got != 1 {
					t.Fatalf("application changed after busy conflict")
				}
			})
		}
	})

	t.Run("audit failure rolls back deletion", func(t *testing.T) {
		appRepo := applications.NewRepository(pool)
		app, err := appRepo.Create(ctx, applications.CreateApplicationParams{
			Name:        "delete_audit_rollback",
			DisplayName: "Delete Audit Rollback",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Exec(context.Background(), `delete from applications where id = $1`, app.ID)
		keys, err := security.NewKeySet(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		service := applications.NewService(applications.ServiceConfig{
			Repository:      appRepo,
			AuditRepository: audit.NewRepository(pool),
			KeySet:          keys,
			Storage:         pool,
		})
		err = service.DeleteApplication(ctx, applications.Actor{
			ID:         "invalid-audit-actor",
			GlobalRole: users.GlobalRoleAdmin,
		}, app.ID, applications.AuditContext{})
		if err == nil {
			t.Fatal("delete unexpectedly succeeded with invalid audit actor")
		}
		if _, err := appRepo.Get(ctx, app.ID); err != nil {
			t.Fatalf("application was not rolled back after audit failure: %v", err)
		}
	})
}

func seedApplicationDeleteDependencies(t *testing.T, ctx context.Context, db storage.DBTX) {
	t.Helper()
	if _, err := db.Exec(ctx, `
insert into users (id, email, display_name)
values ('10000000-0000-4000-8000-000000000001', 'application.delete@example.com', 'Application Delete');
insert into issuers (id, name, directory_url, status, contact_email)
values ('20000000-0000-4000-8000-000000000001', 'application_delete_issuer', 'https://acme.invalid/directory', 'disabled', 'issuer.delete@example.com');
insert into dns_providers (id, name, type, credentials_encrypted, status, zone_mode)
values ('30000000-0000-4000-8000-000000000001', 'application_delete_dns', 'cloudflare', '{"fixture":true}', 'disabled', 'manual');
insert into dns_provider_zones (id, dns_provider_id, zone_name)
values ('31000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 'example.com')`); err != nil {
		t.Fatal(err)
	}
}

func seedApplicationWithMaterial(t *testing.T, ctx context.Context, db storage.DBTX, appID, certID, versionID, certStatus, versionStatus, notBefore, notAfter string) {
	t.Helper()
	failureCode := any(nil)
	revocationReason := any(nil)
	revokedAt := any(nil)
	if certStatus == "failed" {
		failureCode = "fixture_failed"
	}
	if certStatus == "revoked" {
		revocationReason = "cessation_of_operation"
		revokedAt = time.Now().UTC()
	}
	versionRevocationReason := any(nil)
	versionRevokedAt := any(nil)
	if versionStatus == "revoked" {
		versionRevocationReason = "cessation_of_operation"
		versionRevokedAt = time.Now().UTC()
	}
	mustExecApplicationDelete(t, ctx, db, `
insert into applications (id, name, display_name)
values ($1::uuid, 'delete_' || right(replace($1::text, '-', ''), 8), 'Delete Material')`, appID)
	mustExecApplicationDelete(t, ctx, db, `
insert into certificates (
    id, normalized_sans, key_type, issuer_id, application_id, status, failure_code, revocation_reason, revoked_at
) values (
    $1::uuid, array['material.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000001',
    $2::uuid, $3::text, $4::text, $5::text, $6::timestamptz
)`, certID, appID, certStatus, failureCode, revocationReason, revokedAt)
	mustExecApplicationDelete(t, ctx, db, `
insert into certificate_versions (
    id, certificate_id, version, status, reason, cert_pem, chain_pem, fullchain_pem, private_key_pem,
    not_before, not_after, serial_number, fingerprint_sha256, key_fingerprint_sha256, material_etag,
    started_at, completed_at, issued_at, revocation_reason, revoked_at
) values (
    $1::uuid, $2::uuid, 1, $3::text, 'initial_issue', 'CERT', 'CHAIN', 'FULLCHAIN', '{"fixture":true}',
    now() + $4::interval, now() + $5::interval, '01', repeat('a', 64), repeat('b', 64),
    '"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
    now(), now(), now(), $6::text, $7::timestamptz
)`, versionID, certID, versionStatus, notBefore, notAfter, versionRevocationReason, versionRevokedAt)
}

func countRowsForApplicationDelete(t *testing.T, ctx context.Context, db storage.DBTX, table, appID, certID string) int64 {
	t.Helper()
	predicate := "id = $1"
	arg := appID
	switch table {
	case "application_domain_scopes", "application_tokens", "application_user_grants", "certificates":
		predicate = "application_id = $1"
	case "certificate_versions", "certificate_issuance_jobs", "dns_challenge_records", "certificate_events":
		predicate = "certificate_id = $1"
		arg = certID
	}
	var count int64
	if err := db.QueryRow(ctx, "select count(*) from "+table+" where "+predicate, arg).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func mustExecApplicationDelete(t *testing.T, ctx context.Context, db storage.DBTX, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}
