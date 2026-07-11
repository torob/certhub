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

func TestLatestVersionFindsCertificateHardDeleteMigration(t *testing.T) {
	latest, err := NewRunner(DefaultDir).LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	if latest != 3 {
		t.Fatalf("latest version = %d", latest)
	}
}

func TestEmbeddedPostgresMigrationsAreOrdered(t *testing.T) {
	matches, err := fs.Glob(migrationfs.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"00001_initial_schema.sql", "00002_certificate_enabled.sql", "00003_certificate_hard_delete.sql"}
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
	adminDB, err := OpenDB(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	databaseName := fmt.Sprintf("certhub_migration_upgrade_%d_%d", os.Getpid(), upgradeDatabaseSeq.Add(1))
	if _, err := adminDB.ExecContext(ctx, "create database "+databaseName); err != nil {
		t.Fatalf("create migration certification database: %v", err)
	}
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL.Path = "/" + databaseName
	db, err := OpenDB(parsedURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = db.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, `select pg_terminate_backend(pid) from pg_stat_activity where datname = $1 and pid <> pg_backend_pid()`, databaseName)
		if _, err := adminDB.ExecContext(cleanupCtx, "drop database if exists "+databaseName); err != nil {
			t.Errorf("drop migration certification database: %v", err)
		}
	}()

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
	if before.CurrentVersion != 1 || before.LatestVersion != 3 || before.Pending != 2 || before.Compatible {
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
	if first.CurrentVersion != 3 || first.Pending != 0 || !first.Compatible {
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
