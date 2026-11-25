package migrations

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	migrationfs "github.com/torob/certhub/migrations/postgres"
)

func TestLatestVersionFindsCertificateSANsByteOrderMigration(t *testing.T) {
	latest, err := NewRunner(DefaultDir).LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	if latest != 6 {
		t.Fatalf("latest version = %d", latest)
	}
}

func TestEmbeddedPostgresMigrationsAreOrdered(t *testing.T) {
	matches, err := fs.Glob(migrationfs.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"00001_initial_schema.sql", "00002_certificate_enabled.sql", "00003_certificate_hard_delete.sql", "00004_audit_independence_and_hard_delete.sql", "00005_application_hard_delete.sql", "00006_certificate_sans_byte_order.sql"}
	if len(matches) != len(want) {
		t.Fatalf("embedded migrations = %#v", matches)
	}
	for index := range want {
		if matches[index] != want[index] {
			t.Fatalf("embedded migrations = %#v", matches)
		}
	}
}

func TestRunnerRejectsUnsafeDirectory(t *testing.T) {
	for _, dir := range []string{".", "..", "/tmp/migrations"} {
		if _, err := NewRunner(dir).LatestVersion(); err == nil {
			t.Fatalf("LatestVersion(%q) succeeded", dir)
		}
	}
}

func TestIncompatibleErrorMatchesSentinel(t *testing.T) {
	status := Status{CurrentVersion: 99, LatestVersion: 1, Compatible: false}
	err := IncompatibleError{Status: status}
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("errors.Is(%v, ErrIncompatible) = false", err)
	}
	if !strings.Contains(err.Error(), "current_version=99") || !strings.Contains(err.Error(), "latest_version=1") {
		t.Fatalf("err = %v", err)
	}
}

func TestAcquireMigrationLockUsesPinnedConnection(t *testing.T) {
	state := &migrationLockTestState{}
	db := openMigrationLockTestDB(t, state)
	ctx, cancel := context.WithCancel(context.Background())
	unlock, err := acquireMigrationLock(ctx, db, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.lockConn == 0 {
		t.Fatalf("lock was not acquired")
	}
	if state.unlockConn != state.lockConn {
		t.Fatalf("lock conn=%d unlock conn=%d", state.lockConn, state.unlockConn)
	}
	if state.unlockErrAtCall != nil {
		t.Fatalf("unlock used canceled context: %v", state.unlockErrAtCall)
	}
}

func TestAcquireMigrationLockTimesOut(t *testing.T) {
	state := &migrationLockTestState{locked: true, lockConn: 99}
	db := openMigrationLockTestDB(t, state)
	_, err := acquireMigrationLock(context.Background(), db, 25*time.Millisecond)
	if err == nil {
		t.Fatalf("acquireMigrationLock unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "migration lock timeout") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidatePlatformSchemaAcceptsCurrentLeaseCatalog(t *testing.T) {
	state := &validationTestState{metadata: goodValidationMetadata()}
	db := openValidationTestDB(t, state)
	if err := validatePlatformSchema(context.Background(), db, 2); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePlatformSchemaRejectsColumnDrift(t *testing.T) {
	metadata := goodValidationMetadata()
	for i := range metadata.columns {
		if metadata.columns[i].name == "locked_by" {
			metadata.columns[i].notNull = true
		}
	}
	state := &validationTestState{metadata: metadata}
	db := openValidationTestDB(t, state)
	err := validatePlatformSchema(context.Background(), db, 2)
	if err == nil {
		t.Fatalf("validatePlatformSchema unexpectedly accepted drifted column metadata")
	}
	if !strings.Contains(err.Error(), "locked_by must be nullable") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidatePlatformSchemaRejectsForgedConstraintName(t *testing.T) {
	metadata := goodValidationMetadata()
	for i := range metadata.constraints {
		if metadata.constraints[i].name == "certhub_leases_active_state" {
			metadata.constraints[i].definition = "CHECK (locked_until > updated_at)"
			metadata.constraints[i].columns = []string{"locked_until", "updated_at"}
		}
	}
	state := &validationTestState{metadata: metadata}
	db := openValidationTestDB(t, state)
	err := validatePlatformSchema(context.Background(), db, 2)
	if err == nil {
		t.Fatalf("validatePlatformSchema unexpectedly accepted forged constraint metadata")
	}
	if !strings.Contains(err.Error(), "certhub_leases_active_state has definition") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidatePlatformSchemaRejectsDriftedLockedUntilIndex(t *testing.T) {
	metadata := goodValidationMetadata()
	metadata.index.tableName = "other_table"
	state := &validationTestState{metadata: metadata}
	db := openValidationTestDB(t, state)
	err := validatePlatformSchema(context.Background(), db, 2)
	if err == nil {
		t.Fatalf("validatePlatformSchema unexpectedly accepted drifted index metadata")
	}
	if !strings.Contains(err.Error(), "belongs to other_table") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidationCatalogQueriesPinCurrentSchemaObjects(t *testing.T) {
	for name, tc := range map[string]struct {
		query string
		want  []string
	}{
		"columns": {
			query: leaseColumnsSQL,
			want: []string{
				"pg_catalog.pg_class",
				"n.nspname = current_schema()",
				"c.relname = $1",
				"c.relkind = 'r'",
			},
		},
		"constraints": {
			query: leaseConstraintsSQL,
			want: []string{
				"pg_catalog.pg_constraint",
				"pg_catalog.pg_get_constraintdef",
				"n.nspname = current_schema()",
				"c.relname = $1",
				"unnest(con.conkey)",
			},
		},
		"index": {
			query: leaseLockedUntilIndexSQL,
			want: []string{
				"pg_catalog.pg_index",
				"i.indexrelid = idx.oid",
				"tbl.oid = i.indrelid",
				"idx_n.nspname = current_schema()",
				"tbl_n.nspname = current_schema()",
				"idx.relname = $1",
				"tbl.relname = $2",
				"pg_catalog.pg_get_indexdef",
				"generate_series(1, i.indnkeyatts::integer)",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, want := range tc.want {
				if !strings.Contains(tc.query, want) {
					t.Fatalf("validation query missing %q:\n%s", want, tc.query)
				}
			}
		})
	}
}

func TestPostgresMigrationsApplyIdempotently(t *testing.T) {
	databaseURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping PostgreSQL migration integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db := openMigrationTestDatabase(t, databaseURL)

	if err := withGoose(migrationfs.FS, func() error {
		return goose.UpToContext(ctx, db, ".", 1)
	}); err != nil {
		t.Fatalf("apply released baseline: %v", err)
	}

	runner := NewRunner(DefaultDir)
	before, err := runner.Status(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if before.CurrentVersion != 1 || before.LatestVersion != 6 || before.Pending != 5 || before.Compatible {
		t.Fatalf("version 1 status = %#v", before)
	}
	var enabledColumns int
	if err := db.QueryRowContext(ctx, `
select count(*)
from information_schema.columns
where table_schema = 'public'
  and table_name = 'certificates'
  and column_name = 'enabled'`).Scan(&enabledColumns); err != nil {
		t.Fatal(err)
	}
	if enabledColumns != 0 {
		t.Fatalf("version 1 enabled columns = %d", enabledColumns)
	}
	if _, err := db.ExecContext(ctx, `
insert into applications (id, name, display_name)
values ('10000000-0000-4000-8000-000000000001', 'migration_app', 'Migration App');

insert into users (id, email, display_name)
values ('11000000-0000-4000-8000-000000000001', 'migration.user@example.com', 'Migration User');

insert into issuers (id, name, directory_url, status, contact_email)
values ('20000000-0000-4000-8000-000000000001', 'migration_issuer', 'https://acme.invalid/directory', 'disabled', 'migration.issuer@example.com');

insert into dns_providers (id, name, type, credentials_encrypted, status)
values ('30000000-0000-4000-8000-000000000001', 'migration_cloudflare', 'cloudflare', '{"fixture":true}', 'disabled');

insert into certificates (id, normalized_sans, key_type, issuer_id, application_id, status, failure_code, deleted_at)
values
  ('40000000-0000-4000-8000-000000000001', array['live.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'failed', 'fixture_failure', null),
  ('40000000-0000-4000-8000-000000000002', array['deleted.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'deleted', null, now());

insert into certificate_versions (id, certificate_id, version, status, reason, started_at, completed_at, failure_code)
values
  ('50000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000001', 1, 'failed', 'initial_issue', now(), now(), 'fixture_failure'),
  ('50000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000002', 1, 'failed', 'initial_issue', now(), now(), 'fixture_failure');

insert into certificate_events (id, certificate_id, certificate_version_id, event_type, result)
values
  ('60000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001', 'fixture_failed', 'failure'),
  ('60000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000002', '50000000-0000-4000-8000-000000000002', 'fixture_failed', 'failure');

insert into audit_events (
  id, identity_type, action, target_type, target_id, scope_application_id,
  scope_certificate_id, scope_user_id, scope_dns_provider_id, result, metadata
) values
  ('70000000-0000-4000-8000-000000000001', 'system', 'fixture_created', 'certificate', '40000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000001', '11000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 'success', '{"fixture":"live"}'),
  ('70000000-0000-4000-8000-000000000002', 'system', 'fixture_created', 'certificate', '40000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000002', '11000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 'success', '{"fixture":"deleted"}');
`); err != nil {
		t.Fatalf("seed released baseline: %v", err)
	}

	first, err := runner.Up(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runner.Up(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if first.LatestVersion != second.CurrentVersion || second.Pending != 0 || !second.Compatible {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	if first.CurrentVersion != 6 || first.Pending != 0 || !first.Compatible {
		t.Fatalf("upgraded status = %#v", first)
	}
	var nullable, columnDefault string
	if err := db.QueryRowContext(ctx, `
select is_nullable, column_default
from information_schema.columns
where table_schema = 'public'
  and table_name = 'certificates'
  and column_name = 'enabled'`).Scan(&nullable, &columnDefault); err != nil {
		t.Fatal(err)
	}
	if nullable != "NO" || !strings.Contains(columnDefault, "true") {
		t.Fatalf("enabled column nullable=%q default=%q", nullable, columnDefault)
	}
	var auditForeignKeys, auditScopeIndexes int
	if err := db.QueryRowContext(ctx, `
select count(*)
from pg_catalog.pg_constraint
where conrelid = 'public.audit_events'::regclass
  and contype = 'f'`).Scan(&auditForeignKeys); err != nil {
		t.Fatal(err)
	}
	if auditForeignKeys != 0 {
		t.Fatalf("audit foreign keys = %d", auditForeignKeys)
	}
	if _, err := db.ExecContext(ctx, `
insert into audit_events (
  id, identity_type, action, target_type, target_id, scope_application_id,
  scope_certificate_id, scope_user_id, scope_dns_provider_id, result
) values (
  '70000000-0000-4000-8000-000000000003', 'system', 'orphan_fixture_created', 'certificate',
  'ffffffff-ffff-4fff-8fff-fffffffffff0', 'ffffffff-ffff-4fff-8fff-fffffffffff1',
  'ffffffff-ffff-4fff-8fff-fffffffffff2', 'ffffffff-ffff-4fff-8fff-fffffffffff3',
  'ffffffff-ffff-4fff-8fff-fffffffffff4', 'success'
)`); err != nil {
		t.Fatalf("insert self-contained audit event: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
select count(*)
from pg_catalog.pg_indexes
where schemaname = 'public'
  and tablename = 'audit_events'
  and indexname in (
    'audit_events_scope_application_created_at_idx',
    'audit_events_scope_certificate_created_at_idx',
    'audit_events_scope_user_created_at_idx',
    'audit_events_scope_dns_provider_created_at_idx'
  )`).Scan(&auditScopeIndexes); err != nil {
		t.Fatal(err)
	}
	if auditScopeIndexes != 4 {
		t.Fatalf("audit scope indexes = %d", auditScopeIndexes)
	}
	var deletedCertificates, deletedVersions, deletedEvents int
	if err := db.QueryRowContext(ctx, `select count(*) from certificates where id = '40000000-0000-4000-8000-000000000002'`).Scan(&deletedCertificates); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `select count(*) from certificate_versions where certificate_id = '40000000-0000-4000-8000-000000000002'`).Scan(&deletedVersions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `select count(*) from certificate_events where certificate_id = '40000000-0000-4000-8000-000000000002'`).Scan(&deletedEvents); err != nil {
		t.Fatal(err)
	}
	if deletedCertificates != 0 || deletedVersions != 0 || deletedEvents != 0 {
		t.Fatalf("legacy cleanup certificate=%d versions=%d events=%d", deletedCertificates, deletedVersions, deletedEvents)
	}
	var appScope, certScope, userScope, dnsScope string
	if err := db.QueryRowContext(ctx, `
select scope_application_id::text, scope_certificate_id::text, scope_user_id::text, scope_dns_provider_id::text
from audit_events
where id = '70000000-0000-4000-8000-000000000002'`).Scan(&appScope, &certScope, &userScope, &dnsScope); err != nil {
		t.Fatal(err)
	}
	if appScope != "10000000-0000-4000-8000-000000000001" || certScope != "40000000-0000-4000-8000-000000000002" || userScope != "11000000-0000-4000-8000-000000000001" || dnsScope != "30000000-0000-4000-8000-000000000001" {
		t.Fatalf("retained audit scopes app=%s cert=%s user=%s dns=%s", appScope, certScope, userScope, dnsScope)
	}
	if _, err := db.ExecContext(ctx, `update audit_events set metadata = '{"mutated":true}' where id = '70000000-0000-4000-8000-000000000001'`); err == nil || !strings.Contains(err.Error(), "audit_events are append-only") {
		t.Fatalf("direct audit mutation err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `delete from audit_events where id = '70000000-0000-4000-8000-000000000001'`); err == nil || !strings.Contains(err.Error(), "audit_events are append-only") {
		t.Fatalf("direct audit deletion err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `truncate audit_events`); err == nil || !strings.Contains(err.Error(), "audit_events are append-only") {
		t.Fatalf("direct audit truncation err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `update certificate_events set metadata = '{"mutated":true}' where id = '60000000-0000-4000-8000-000000000001'`); err == nil || !strings.Contains(err.Error(), "certificate_events are append-only") {
		t.Fatalf("direct certificate event mutation err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `delete from certificate_events where id = '60000000-0000-4000-8000-000000000001'`); err == nil || !strings.Contains(err.Error(), "certificate_events are append-only") {
		t.Fatalf("direct certificate event deletion err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `truncate certificate_events`); err == nil || !strings.Contains(err.Error(), "certificate_events are append-only") {
		t.Fatalf("direct certificate event truncation err=%v", err)
	}
	if _, err := db.ExecContext(ctx, `delete from certificates where id = '40000000-0000-4000-8000-000000000001'`); err != nil {
		t.Fatalf("hard delete live certificate: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select scope_certificate_id::text from audit_events where id = '70000000-0000-4000-8000-000000000001'`).Scan(&certScope); err != nil {
		t.Fatal(err)
	}
	if certScope != "40000000-0000-4000-8000-000000000001" {
		t.Fatalf("live hard-delete audit scope = %s", certScope)
	}
}

// sanByteOrderPair is sorted in Go byte order. en_US.utf8 ignores punctuation
// at the first level and sorts the pair the other way.
var sanByteOrderPair = []string{"k2.cf30.e2e.test", "k2b.cf30.e2e.test"}

const (
	sanOrderMigrationVersion = int64(6)
	sanOrderApplicationID    = "10000000-0000-4000-8000-000000000006"
	sanOrderIssuerID         = "20000000-0000-4000-8000-000000000006"
	sanOrderByteCertID       = "40000000-0000-4000-8000-000000000061"
	sanOrderLegacyCertID     = "40000000-0000-4000-8000-000000000062"
	sanOrderInsertCertSQL    = `
insert into certificates (id, normalized_sans, key_type, issuer_id, application_id)
values ($1, $2::text[], 'ecdsa-p256', '20000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000006')`
)

func TestPostgresCertificateSANsByteOrderMigration(t *testing.T) {
	databaseURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping PostgreSQL SAN byte order migration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Prefer en_US.utf8, the postgres image default, because it orders the
	// test SANs against byte order. Fall back to the server default.
	db := openMigrationTestDatabase(t, databaseURL, "template template0 encoding 'UTF8' lc_collate 'en_US.utf8' lc_ctype 'en_US.utf8'")
	migrateTo := func(version int64) error {
		return withGoose(migrationfs.FS, func() error {
			current, err := goose.GetDBVersionContext(ctx, db)
			if err != nil {
				return err
			}
			if version < current {
				return goose.DownToContext(ctx, db, ".", version)
			}
			return goose.UpToContext(ctx, db, ".", version)
		})
	}
	requireVersion := func(want int64) {
		t.Helper()
		var got int64
		if err := withGoose(migrationfs.FS, func() error {
			var err error
			got, err = goose.GetDBVersionContext(ctx, db)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("migration version = %d, want %d", got, want)
		}
	}

	if err := migrateTo(sanOrderMigrationVersion - 1); err != nil {
		t.Fatalf("apply migrations before SAN byte order: %v", err)
	}
	var databaseCollation string
	var localeReversesPair bool
	if err := db.QueryRowContext(ctx, `
select datcollate, $1::text > $2::text
from pg_database
where datname = current_database()`, sanByteOrderPair[0], sanByteOrderPair[1]).Scan(&databaseCollation, &localeReversesPair); err != nil {
		t.Fatal(err)
	}
	t.Logf("database collation=%s reverses %v=%t", databaseCollation, sanByteOrderPair, localeReversesPair)

	if _, err := db.ExecContext(ctx, `
insert into applications (id, name, display_name)
values ('10000000-0000-4000-8000-000000000006', 'san_order_app', 'SAN Order App');

insert into issuers (id, name, directory_url, status, contact_email)
values ('20000000-0000-4000-8000-000000000006', 'san_order_issuer', 'https://acme.invalid/directory', 'disabled', 'san.order@example.com');

insert into certificates (id, normalized_sans, key_type, issuer_id, application_id, status, failure_code)
values
  ('40000000-0000-4000-8000-000000000063', array['api.example.com', 'www.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000006', 'pending', null),
  ('40000000-0000-4000-8000-000000000064', array['*.example.com', 'example.com'], 'rsa-2048', '20000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000006', 'failed', 'fixture_failure'),
  ('40000000-0000-4000-8000-000000000065', array['single.example.com'], 'ecdsa-p256', '20000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000006', 'pending', null);
`); err != nil {
		t.Fatalf("seed certificates before SAN byte order: %v", err)
	}
	existing := loadCertificateSnapshot(ctx, t, db)

	// Before the migration the check follows the database collation.
	_, err := db.ExecContext(ctx, sanOrderInsertCertSQL, sanOrderByteCertID, sanByteOrderPair)
	if localeReversesPair {
		if err == nil || !strings.Contains(err.Error(), "certificates_sans_valid") {
			t.Fatalf("byte-ordered SANs before migration err=%v, want certificates_sans_valid violation", err)
		}
		// A row in locale order was accepted by the previous check. The
		// migration must stop instead of rewriting it.
		if _, err := db.ExecContext(ctx, sanOrderInsertCertSQL, sanOrderLegacyCertID, []string{sanByteOrderPair[1], sanByteOrderPair[0]}); err != nil {
			t.Fatalf("insert locale-ordered SANs before migration: %v", err)
		}
		err := migrateTo(sanOrderMigrationVersion)
		if err == nil || !strings.Contains(err.Error(), "not sorted in byte order") || !strings.Contains(err.Error(), sanOrderLegacyCertID) {
			t.Fatalf("migration with locale-ordered row err=%v", err)
		}
		t.Logf("migration stopped on locale-ordered row: %v", err)
		requireVersion(sanOrderMigrationVersion - 1)
		requireSANCheckSource(ctx, t, db, false)
		var legacySANs string
		if err := db.QueryRowContext(ctx, `select normalized_sans::text from certificates where id = $1`, sanOrderLegacyCertID).Scan(&legacySANs); err != nil {
			t.Fatal(err)
		}
		if legacySANs != "{k2b.cf30.e2e.test,k2.cf30.e2e.test}" {
			t.Fatalf("locale-ordered row was changed: %s", legacySANs)
		}
		if _, err := db.ExecContext(ctx, `delete from certificates where id = $1`, sanOrderLegacyCertID); err != nil {
			t.Fatal(err)
		}
	} else {
		if err != nil {
			t.Fatalf("byte-ordered SANs before migration with byte-order collation: %v", err)
		}
		if _, err := db.ExecContext(ctx, `delete from certificates where id = $1`, sanOrderByteCertID); err != nil {
			t.Fatal(err)
		}
	}

	if err := migrateTo(sanOrderMigrationVersion); err != nil {
		t.Fatalf("apply SAN byte order migration with existing certificates: %v", err)
	}
	requireVersion(sanOrderMigrationVersion)
	requireSANCheckSource(ctx, t, db, true)
	status, err := NewRunner(DefaultDir).Status(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Compatible || status.Pending != 0 {
		t.Fatalf("status after SAN byte order migration = %#v", status)
	}
	if got := loadCertificateSnapshot(ctx, t, db); !sameStringList(got, existing) {
		t.Fatalf("existing certificates changed:\n got %v\nwant %v", got, existing)
	}
	var constraintDefinition string
	if err := db.QueryRowContext(ctx, `
select pg_catalog.pg_get_constraintdef(oid)
from pg_catalog.pg_constraint
where conrelid = 'public.certificates'::regclass
  and conname = 'certificates_sans_valid'`).Scan(&constraintDefinition); err != nil {
		t.Fatal(err)
	}
	if constraintDefinition != "CHECK (certhub_certificate_sans_valid(normalized_sans))" {
		t.Fatalf("certificates_sans_valid definition = %q", constraintDefinition)
	}
	// Updates recheck the constraint, so every existing row must satisfy it.
	if _, err := db.ExecContext(ctx, `update certificates set updated_at = updated_at`); err != nil {
		t.Fatalf("recheck existing certificates: %v", err)
	}
	if _, err := db.ExecContext(ctx, sanOrderInsertCertSQL, sanOrderByteCertID, sanByteOrderPair); err != nil {
		t.Fatalf("insert byte-ordered SANs after migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, sanOrderInsertCertSQL, sanOrderLegacyCertID, []string{sanByteOrderPair[1], sanByteOrderPair[0]}); err == nil || !strings.Contains(err.Error(), "certificates_sans_valid") {
		t.Fatalf("reverse byte order after migration err=%v, want certificates_sans_valid violation", err)
	}
	for _, invalid := range [][]string{
		{"a.example.com", "a.example.com"},
		{"www.example.com", "api.example.com"},
		{"Upper.example.com"},
	} {
		if _, err := db.ExecContext(ctx, sanOrderInsertCertSQL, sanOrderLegacyCertID, invalid); err == nil || !strings.Contains(err.Error(), "certificates_sans_valid") {
			t.Fatalf("SANs %v after migration err=%v, want certificates_sans_valid violation", invalid, err)
		}
	}

	// Rollback restores the collation-dependent check. It must stop while a
	// row exists that only byte order accepts.
	if localeReversesPair {
		err := migrateTo(sanOrderMigrationVersion - 1)
		if err == nil || !strings.Contains(err.Error(), "cannot be rolled back") || !strings.Contains(err.Error(), sanOrderByteCertID) {
			t.Fatalf("rollback with byte-ordered row err=%v", err)
		}
		t.Logf("rollback stopped on byte-ordered row: %v", err)
		requireVersion(sanOrderMigrationVersion)
		requireSANCheckSource(ctx, t, db, true)
	}
	if _, err := db.ExecContext(ctx, `delete from certificates where id = $1`, sanOrderByteCertID); err != nil {
		t.Fatal(err)
	}
	if err := migrateTo(sanOrderMigrationVersion - 1); err != nil {
		t.Fatalf("roll back SAN byte order migration: %v", err)
	}
	requireVersion(sanOrderMigrationVersion - 1)
	requireSANCheckSource(ctx, t, db, false)
	if got := loadCertificateSnapshot(ctx, t, db); !sameStringList(got, existing) {
		t.Fatalf("rollback changed certificates:\n got %v\nwant %v", got, existing)
	}
	if err := migrateTo(sanOrderMigrationVersion); err != nil {
		t.Fatalf("reapply SAN byte order migration: %v", err)
	}
	requireVersion(sanOrderMigrationVersion)
}

// loadCertificateSnapshot returns every certificate row as text, ordered by id.
func loadCertificateSnapshot(ctx context.Context, t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
select id::text || ' ' || normalized_sans::text || ' ' || key_type || ' ' || status || ' ' || updated_at::text
from certificates
order by id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var snapshot []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		snapshot = append(snapshot, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// requireSANCheckSource checks whether the SAN check function compares in byte order.
func requireSANCheckSource(ctx context.Context, t *testing.T, db *sql.DB, wantByteOrder bool) {
	t.Helper()
	var source string
	if err := db.QueryRowContext(ctx, `select prosrc from pg_catalog.pg_proc where oid = 'public.certhub_certificate_sans_valid(text[])'::regprocedure`).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if got := strings.Contains(source, `collate "C"`); got != wantByteOrder {
		t.Fatalf("certhub_certificate_sans_valid byte order=%t, want %t:\n%s", got, wantByteOrder, source)
	}
}

// openMigrationTestDatabase creates an empty database for one test and drops it
// when the test ends. Each createOptions entry is tried in order after
// "create database <name>"; the server defaults are used when none succeeds.
func openMigrationTestDatabase(t *testing.T, databaseURL string, createOptions ...string) *sql.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	adminDB, err := OpenDB(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adminDB.Close() })
	databaseName := fmt.Sprintf("certhub_migration_upgrade_%d_%d", os.Getpid(), upgradeDatabaseSeq.Add(1))
	var createErr error
	for _, options := range append(createOptions, "") {
		if _, createErr = adminDB.ExecContext(ctx, strings.TrimSpace("create database "+databaseName+" "+options)); createErr == nil {
			break
		}
		t.Logf("create migration certification database with %q: %v", options, createErr)
	}
	if createErr != nil {
		t.Fatalf("create migration certification database: %v", createErr)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, `select pg_terminate_backend(pid) from pg_stat_activity where datname = $1 and pid <> pg_backend_pid()`, databaseName)
		if _, err := adminDB.ExecContext(cleanupCtx, "drop database if exists "+databaseName); err != nil {
			t.Errorf("drop migration certification database: %v", err)
		}
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL.Path = "/" + databaseName
	db, err := OpenDB(parsedURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var migrationLockDriverSeq atomic.Uint64
var validationDriverSeq atomic.Uint64
var upgradeDatabaseSeq atomic.Uint64

type migrationLockTestState struct {
	mu              sync.Mutex
	nextConn        int
	locked          bool
	lockConn        int
	unlockConn      int
	closeCount      int
	unlockErrAtCall error
}

type migrationLockTestDriver struct {
	state *migrationLockTestState
}

func (d *migrationLockTestDriver) Open(string) (driver.Conn, error) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	d.state.nextConn++
	return &migrationLockTestConn{id: d.state.nextConn, state: d.state}, nil
}

type migrationLockTestConn struct {
	id     int
	state  *migrationLockTestState
	closed bool
}

func (c *migrationLockTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (c *migrationLockTestConn) Close() error {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.state.closeCount++
	}
	return nil
}

func (c *migrationLockTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

func (c *migrationLockTestConn) QueryContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	switch {
	case strings.Contains(query, "pg_try_advisory_lock"):
		if c.state.locked {
			return &singleBoolRows{value: false}, nil
		}
		c.state.locked = true
		c.state.lockConn = c.id
		return &singleBoolRows{value: true}, nil
	case strings.Contains(query, "pg_advisory_unlock"):
		c.state.unlockErrAtCall = ctx.Err()
		released := c.state.locked && c.state.lockConn == c.id
		if released {
			c.state.locked = false
			c.state.unlockConn = c.id
		}
		return &singleBoolRows{value: released}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}

type singleBoolRows struct {
	value bool
	sent  bool
}

func (r *singleBoolRows) Columns() []string {
	return []string{"ok"}
}

func (r *singleBoolRows) Close() error {
	return nil
}

func (r *singleBoolRows) Next(dest []driver.Value) error {
	if r.sent {
		return io.EOF
	}
	dest[0] = r.value
	r.sent = true
	return nil
}

func openMigrationLockTestDB(t *testing.T, state *migrationLockTestState) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("certhub_migration_lock_test_%d", migrationLockDriverSeq.Add(1))
	sql.Register(name, &migrationLockTestDriver{state: state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type validationMetadata struct {
	columns     []leaseColumn
	constraints []leaseConstraint
	index       leaseIndex
	indexFound  bool
}

type validationTestState struct {
	mu       sync.Mutex
	metadata validationMetadata
	queries  []string
}

type validationTestDriver struct {
	state *validationTestState
}

func (d *validationTestDriver) Open(string) (driver.Conn, error) {
	return &validationTestConn{state: d.state}, nil
}

type validationTestConn struct {
	state *validationTestState
}

func (c *validationTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (c *validationTestConn) Close() error {
	return nil
}

func (c *validationTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

func (c *validationTestConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.queries = append(c.state.queries, query)
	switch {
	case strings.Contains(query, "from pg_catalog.pg_attribute"):
		if err := requireValidationArgs(args, leaseTableName); err != nil {
			return nil, err
		}
		return validationColumnRows(c.state.metadata.columns), nil
	case strings.Contains(query, "from pg_catalog.pg_constraint"):
		if err := requireValidationArgs(args, leaseTableName); err != nil {
			return nil, err
		}
		return validationConstraintRows(c.state.metadata.constraints), nil
	case strings.Contains(query, "join pg_catalog.pg_index"):
		if err := requireValidationArgs(args, leaseLockedUntilIndexName, leaseTableName); err != nil {
			return nil, err
		}
		if !c.state.metadata.indexFound {
			return &staticRows{columns: []string{"index_name"}}, nil
		}
		return validationIndexRows(c.state.metadata.index), nil
	default:
		return nil, fmt.Errorf("unexpected validation query: %s", query)
	}
}

func requireValidationArgs(args []driver.NamedValue, expected ...string) error {
	if len(args) != len(expected) {
		return fmt.Errorf("args = %d, want %d", len(args), len(expected))
	}
	for i, want := range expected {
		if got, ok := args[i].Value.(string); !ok || got != want {
			return fmt.Errorf("arg %d = %#v, want %q", i, args[i].Value, want)
		}
	}
	return nil
}

type staticRows struct {
	columns []string
	values  [][]driver.Value
	next    int
}

func (r *staticRows) Columns() []string {
	return r.columns
}

func (r *staticRows) Close() error {
	return nil
}

func (r *staticRows) Next(dest []driver.Value) error {
	if r.next >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.next])
	r.next++
	return nil
}

func validationColumnRows(columns []leaseColumn) driver.Rows {
	values := make([][]driver.Value, 0, len(columns))
	for _, col := range columns {
		var defaultExpr driver.Value
		if col.defaultExpr != "" {
			defaultExpr = col.defaultExpr
		}
		values = append(values, []driver.Value{col.name, col.dataType, col.notNull, defaultExpr})
	}
	return &staticRows{
		columns: []string{"column_name", "data_type", "not_null", "column_default"},
		values:  values,
	}
}

func validationConstraintRows(constraints []leaseConstraint) driver.Rows {
	values := make([][]driver.Value, 0, len(constraints))
	for _, constraint := range constraints {
		values = append(values, []driver.Value{
			constraint.name,
			constraint.constraintType,
			constraint.definition,
			strings.Join(constraint.columns, ","),
		})
	}
	return &staticRows{
		columns: []string{"constraint_name", "constraint_type", "constraint_definition", "constraint_columns"},
		values:  values,
	}
}

func validationIndexRows(index leaseIndex) driver.Rows {
	return &staticRows{
		columns: []string{"index_name", "table_name", "access_method", "unique", "valid", "ready", "has_expression", "has_predicate", "key_columns", "total_columns", "index_columns"},
		values: [][]driver.Value{{
			index.name,
			index.tableName,
			index.accessMethod,
			index.unique,
			index.valid,
			index.ready,
			index.hasExpression,
			index.hasPredicate,
			index.keyColumns,
			index.totalColumns,
			strings.Join(index.columns, ","),
		}},
	}
}

func goodValidationMetadata() validationMetadata {
	columns := make([]leaseColumn, 0, len(expectedLeaseColumns))
	for _, spec := range expectedLeaseColumns {
		columns = append(columns, leaseColumn{
			name:        spec.name,
			dataType:    spec.dataType,
			notNull:     spec.notNull,
			defaultExpr: spec.defaultExpr,
		})
	}
	constraints := make([]leaseConstraint, 0, len(expectedLeaseConstraints))
	for _, spec := range expectedLeaseConstraints {
		constraints = append(constraints, leaseConstraint{
			name:           spec.name,
			constraintType: spec.constraintType,
			definition:     spec.definition,
			columns:        append([]string(nil), spec.columns...),
		})
	}
	return validationMetadata{
		columns:     columns,
		constraints: constraints,
		index: leaseIndex{
			name:         leaseLockedUntilIndexName,
			tableName:    leaseTableName,
			accessMethod: "btree",
			valid:        true,
			ready:        true,
			keyColumns:   1,
			totalColumns: 1,
			columns:      []string{"locked_until"},
		},
		indexFound: true,
	}
}

func openValidationTestDB(t *testing.T, state *validationTestState) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("certhub_validation_test_%d", validationDriverSeq.Add(1))
	sql.Register(name, &validationTestDriver{state: state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
