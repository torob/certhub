package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	migrationfs "certhub/migrations/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

const DefaultDir = "migrations/postgres"

const (
	migrationAdvisoryLockKey = int64(0x4365727448756201)
	migrationLockTimeout     = 30 * time.Second
	migrationUnlockTimeout   = 5 * time.Second
	migrationLockPoll        = 100 * time.Millisecond
)

var (
	ErrIncompatible = errors.New("database schema is incompatible with this binary")
	gooseMu         sync.Mutex
)

type Runner struct {
	Dir string
}

type Status struct {
	CurrentVersion int64
	LatestVersion  int64
	Pending        int
	Compatible     bool
}

type IncompatibleError struct {
	Status Status
}

func (e IncompatibleError) Error() string {
	return fmt.Sprintf("%s: current_version=%d latest_version=%d", ErrIncompatible, e.Status.CurrentVersion, e.Status.LatestVersion)
}

func (e IncompatibleError) Is(target error) bool {
	return target == ErrIncompatible
}

func OpenDB(url string) (*sql.DB, error) {
	if url == "" {
		return nil, errors.New("postgresql url is required")
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("postgresql migration config: %w", err)
	}
	cfg.ConnectTimeout = 5 * time.Second
	return stdlib.OpenDB(*cfg), nil
}

func NewRunner(dir string) Runner {
	if dir == "" {
		dir = DefaultDir
	}
	return Runner{Dir: dir}
}

func (r Runner) Up(ctx context.Context, db *sql.DB) (status Status, err error) {
	if db == nil {
		return Status{}, errors.New("migration database is required")
	}
	fsys, dir, err := r.source()
	if err != nil {
		return Status{}, err
	}
	unlock, err := acquireMigrationLock(ctx, db, migrationLockTimeout)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		if unlockErr := unlock(); err == nil && unlockErr != nil {
			err = unlockErr
		}
	}()
	if err := withGoose(fsys, func() error {
		return goose.UpContext(ctx, db, dir)
	}); err != nil {
		return Status{}, fmt.Errorf("apply migrations: %w", err)
	}
	status, err = r.Status(ctx, db)
	if err != nil {
		return Status{}, err
	}
	if !status.Compatible {
		return status, IncompatibleError{Status: status}
	}
	return status, nil
}

func (r Runner) Status(ctx context.Context, db *sql.DB) (Status, error) {
	if db == nil {
		return Status{}, errors.New("migration database is required")
	}
	fsys, dir, err := r.source()
	if err != nil {
		return Status{}, err
	}
	var current int64
	if err := withGoose(fsys, func() error {
		var err error
		current, err = goose.GetDBVersionContext(ctx, db)
		return err
	}); err != nil {
		return Status{}, fmt.Errorf("migration version: %w", err)
	}
	if err := validatePlatformSchema(ctx, db, current); err != nil {
		return Status{}, err
	}
	latest, err := r.LatestVersion()
	if err != nil {
		return Status{}, err
	}
	pending := 0
	if current < latest {
		var pendingMigrations goose.Migrations
		if err := withGoose(fsys, func() error {
			var err error
			pendingMigrations, err = goose.CollectMigrations(dir, current, latest)
			return err
		}); err != nil {
			return Status{}, fmt.Errorf("collect pending migrations: %w", err)
		}
		pending = pendingMigrations.Len()
	}
	return Status{
		CurrentVersion: current,
		LatestVersion:  latest,
		Pending:        pending,
		Compatible:     current == latest,
	}, nil
}

func (r Runner) LatestVersion() (int64, error) {
	fsys, dir, err := r.source()
	if err != nil {
		return 0, err
	}
	var migrations goose.Migrations
	if err := withGoose(fsys, func() error {
		var err error
		migrations, err = goose.CollectMigrations(dir, 0, maxVersion)
		return err
	}); err != nil {
		return 0, fmt.Errorf("collect migrations: %w", err)
	}
	if migrations.Len() == 0 {
		return 0, nil
	}
	last, err := migrations.Last()
	if err != nil {
		return 0, fmt.Errorf("latest migration: %w", err)
	}
	return last.Version, nil
}

func (r Runner) source() (fs.FS, string, error) {
	if r.Dir == "" {
		return nil, "", errors.New("migration directory is required")
	}
	if r.Dir != DefaultDir {
		return nil, "", errors.New("migration directory must point at migrations/postgres")
	}
	if ok := fs.ValidPath("."); !ok {
		return nil, "", errors.New("embedded migration path is invalid")
	}
	return migrationfs.FS, ".", nil
}

const maxVersion = int64(^uint64(0) >> 1)

func withGoose(fsys fs.FS, fn func() error) error {
	gooseMu.Lock()
	defer gooseMu.Unlock()
	goose.SetLogger(goose.NopLogger())
	goose.SetBaseFS(fsys)
	defer goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migration dialect: %w", err)
	}
	return fn()
}

func acquireMigrationLock(ctx context.Context, db *sql.DB, timeout time.Duration) (func() error, error) {
	if timeout <= 0 {
		return nil, errors.New("migration lock timeout must be positive")
	}
	lockCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := db.Conn(lockCtx)
	if err != nil {
		return nil, fmt.Errorf("migration lock connection: %w", err)
	}
	keepConn := false
	defer func() {
		if !keepConn {
			_ = conn.Close()
		}
	}()
	ticker := time.NewTicker(migrationLockPoll)
	defer ticker.Stop()
	for {
		var acquired bool
		if err := conn.QueryRowContext(lockCtx, `select pg_try_advisory_lock($1)`, migrationAdvisoryLockKey).Scan(&acquired); err != nil {
			return nil, fmt.Errorf("migration lock acquire: %w", err)
		}
		if acquired {
			keepConn = true
			var once sync.Once
			var unlockErr error
			return func() error {
				once.Do(func() {
					unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationUnlockTimeout)
					if unlockCtx.Err() != nil {
						cancel()
						unlockCtx, cancel = context.WithTimeout(context.Background(), migrationUnlockTimeout)
					}
					defer cancel()
					var released bool
					if err := conn.QueryRowContext(unlockCtx, `select pg_advisory_unlock($1)`, migrationAdvisoryLockKey).Scan(&released); err != nil {
						unlockErr = fmt.Errorf("migration lock release: %w", err)
					} else if !released {
						unlockErr = errors.New("migration lock was not held by this session")
					}
					if err := conn.Close(); unlockErr == nil && err != nil {
						unlockErr = fmt.Errorf("migration lock connection close: %w", err)
					}
				})
				return unlockErr
			}, nil
		}
		select {
		case <-lockCtx.Done():
			return nil, fmt.Errorf("migration lock timeout: %w", lockCtx.Err())
		case <-ticker.C:
		}
	}
}

func validatePlatformSchema(ctx context.Context, db *sql.DB, current int64) error {
	if current < 1 {
		return nil
	}
	columns, err := loadLeaseColumns(ctx, db, leaseTableName)
	if err != nil {
		return fmt.Errorf("validate platform schema: %w", err)
	}
	if err := validateLeaseColumns(columns); err != nil {
		return fmt.Errorf("validate platform schema: %w", err)
	}

	constraints, err := loadLeaseConstraints(ctx, db, leaseTableName)
	if err != nil {
		return fmt.Errorf("validate platform schema: %w", err)
	}
	if err := validateLeaseConstraints(constraints); err != nil {
		return fmt.Errorf("validate platform schema: %w", err)
	}

	index, ok, err := loadLeaseLockedUntilIndex(ctx, db)
	if err != nil {
		return fmt.Errorf("validate platform schema: %w", err)
	}
	if !ok {
		return errors.New("validate platform schema: certhub_leases_locked_until_idx index is missing")
	}
	if err := validateLeaseLockedUntilIndex(index); err != nil {
		return fmt.Errorf("validate platform schema: %w", err)
	}

	return nil
}

const (
	leaseTableName            = "certhub_leases"
	leaseLockedUntilIndexName = "certhub_leases_locked_until_idx"
)

type leaseColumn struct {
	name        string
	dataType    string
	notNull     bool
	defaultExpr string
}

type leaseColumnSpec struct {
	name        string
	dataType    string
	notNull     bool
	defaultExpr string
}

var expectedLeaseColumns = []leaseColumnSpec{
	{name: "name", dataType: "text", notNull: true},
	{name: "locked_by", dataType: "text"},
	{name: "locked_until", dataType: "timestamp with time zone", notNull: true},
	{name: "generation", dataType: "bigint", notNull: true, defaultExpr: "1"},
	{name: "lease_token", dataType: "uuid"},
	{name: "created_at", dataType: "timestamp with time zone", notNull: true, defaultExpr: "now()"},
	{name: "updated_at", dataType: "timestamp with time zone", notNull: true, defaultExpr: "now()"},
}

const leaseColumnsSQL = `
select a.attname,
       pg_catalog.format_type(a.atttypid, a.atttypmod),
       a.attnotnull,
       pg_catalog.pg_get_expr(d.adbin, d.adrelid)
from pg_catalog.pg_attribute a
join pg_catalog.pg_class c on c.oid = a.attrelid
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
left join pg_catalog.pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
where n.nspname = current_schema()
  and c.relname = $1
  and c.relkind = 'r'
  and a.attnum > 0
  and not a.attisdropped
order by a.attnum`

func loadLeaseColumns(ctx context.Context, db *sql.DB, tableName string) ([]leaseColumn, error) {
	rows, err := db.QueryContext(ctx, leaseColumnsSQL, tableName)
	if err != nil {
		return nil, fmt.Errorf("load %s columns: %w", tableName, err)
	}
	defer rows.Close()

	var columns []leaseColumn
	for rows.Next() {
		var col leaseColumn
		var defaultExpr sql.NullString
		if err := rows.Scan(&col.name, &col.dataType, &col.notNull, &defaultExpr); err != nil {
			return nil, fmt.Errorf("load %s columns: %w", tableName, err)
		}
		if defaultExpr.Valid {
			col.defaultExpr = defaultExpr.String
		}
		columns = append(columns, col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load %s columns: %w", tableName, err)
	}
	return columns, nil
}

func validateLeaseColumns(columns []leaseColumn) error {
	if len(columns) == 0 {
		return fmt.Errorf("%s table is missing", leaseTableName)
	}
	present := make(map[string]leaseColumn, len(columns))
	for _, col := range columns {
		present[col.name] = col
	}
	var missing []string
	for _, spec := range expectedLeaseColumns {
		if _, ok := present[spec.name]; !ok {
			missing = append(missing, spec.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s missing columns: %s", leaseTableName, strings.Join(missing, ", "))
	}
	for _, spec := range expectedLeaseColumns {
		col := present[spec.name]
		if col.dataType != spec.dataType {
			return fmt.Errorf("%s column %s has type %s, want %s", leaseTableName, spec.name, col.dataType, spec.dataType)
		}
		if col.notNull != spec.notNull {
			if spec.notNull {
				return fmt.Errorf("%s column %s must be not null", leaseTableName, spec.name)
			}
			return fmt.Errorf("%s column %s must be nullable", leaseTableName, spec.name)
		}
		if normalizeCatalogDefault(col.defaultExpr) != normalizeCatalogDefault(spec.defaultExpr) {
			if spec.defaultExpr == "" {
				return fmt.Errorf("%s column %s must not have a default", leaseTableName, spec.name)
			}
			return fmt.Errorf("%s column %s has default %q, want %q", leaseTableName, spec.name, col.defaultExpr, spec.defaultExpr)
		}
	}
	return nil
}

type leaseConstraint struct {
	name           string
	constraintType string
	definition     string
	columns        []string
}

type leaseConstraintSpec struct {
	name           string
	constraintType string
	definition     string
	columns        []string
}

var expectedLeaseConstraints = []leaseConstraintSpec{
	{
		name:           "certhub_leases_pkey",
		constraintType: "p",
		definition:     "PRIMARY KEY (name)",
		columns:        []string{"name"},
	},
	{
		name:           "certhub_leases_lease_token_unique",
		constraintType: "u",
		definition:     "UNIQUE (lease_token)",
		columns:        []string{"lease_token"},
	},
	{
		name:           "certhub_leases_name_format",
		constraintType: "c",
		definition:     "CHECK (name ~ '^[a-z][a-z0-9_.:-]{0,127}$')",
		columns:        []string{"name"},
	},
	{
		name:           "certhub_leases_locked_by_format",
		constraintType: "c",
		definition:     "CHECK (locked_by IS NULL OR locked_by ~ '^[a-z][a-z0-9_.:-]{0,63}/[a-z][a-z0-9_.:-]{0,63}$')",
		columns:        []string{"locked_by"},
	},
	{
		name:           "certhub_leases_active_state",
		constraintType: "c",
		definition:     "CHECK ((locked_by IS NULL AND lease_token IS NULL AND locked_until <= updated_at) OR (locked_by IS NOT NULL AND lease_token IS NOT NULL AND locked_until > updated_at))",
		columns:        []string{"locked_by", "locked_until", "lease_token", "updated_at"},
	},
	{
		name:           "certhub_leases_generation_positive",
		constraintType: "c",
		definition:     "CHECK (generation > 0)",
		columns:        []string{"generation"},
	},
}

const leaseConstraintsSQL = `
select con.conname,
       con.contype::text,
       pg_catalog.pg_get_constraintdef(con.oid, false),
       coalesce(string_agg(att.attname, ',' order by con_key.ordinality), '')
from pg_catalog.pg_constraint con
join pg_catalog.pg_class c on c.oid = con.conrelid
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
left join lateral unnest(con.conkey) with ordinality as con_key(attnum, ordinality) on true
left join pg_catalog.pg_attribute att on att.attrelid = c.oid and att.attnum = con_key.attnum
where n.nspname = current_schema()
  and c.relname = $1
  and c.relkind = 'r'
group by con.oid, con.conname, con.contype
order by con.conname`

func loadLeaseConstraints(ctx context.Context, db *sql.DB, tableName string) ([]leaseConstraint, error) {
	rows, err := db.QueryContext(ctx, leaseConstraintsSQL, tableName)
	if err != nil {
		return nil, fmt.Errorf("load %s constraints: %w", tableName, err)
	}
	defer rows.Close()

	var constraints []leaseConstraint
	for rows.Next() {
		var constraint leaseConstraint
		var columns string
		if err := rows.Scan(&constraint.name, &constraint.constraintType, &constraint.definition, &columns); err != nil {
			return nil, fmt.Errorf("load %s constraints: %w", tableName, err)
		}
		constraint.columns = splitCatalogColumns(columns)
		constraints = append(constraints, constraint)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load %s constraints: %w", tableName, err)
	}
	return constraints, nil
}

func validateLeaseConstraints(constraints []leaseConstraint) error {
	present := make(map[string]leaseConstraint, len(constraints))
	for _, constraint := range constraints {
		present[constraint.name] = constraint
	}
	var missing []string
	for _, spec := range expectedLeaseConstraints {
		if _, ok := present[spec.name]; !ok {
			missing = append(missing, spec.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s missing constraints: %s", leaseTableName, strings.Join(missing, ", "))
	}
	for _, spec := range expectedLeaseConstraints {
		constraint := present[spec.name]
		if constraint.constraintType != spec.constraintType {
			return fmt.Errorf("%s constraint %s has type %s, want %s", leaseTableName, spec.name, constraint.constraintType, spec.constraintType)
		}
		if normalizeCatalogConstraint(constraint.definition) != normalizeCatalogConstraint(spec.definition) {
			return fmt.Errorf("%s constraint %s has definition %q, want %q", leaseTableName, spec.name, constraint.definition, spec.definition)
		}
		if !sameStringSet(constraint.columns, spec.columns) {
			return fmt.Errorf("%s constraint %s covers columns %s, want %s", leaseTableName, spec.name, strings.Join(constraint.columns, ", "), strings.Join(spec.columns, ", "))
		}
	}
	return nil
}

type leaseIndex struct {
	name          string
	tableName     string
	accessMethod  string
	unique        bool
	valid         bool
	ready         bool
	hasExpression bool
	hasPredicate  bool
	keyColumns    int64
	totalColumns  int64
	columns       []string
}

const leaseLockedUntilIndexSQL = `
select idx.relname,
       tbl.relname,
       am.amname,
       i.indisunique,
       i.indisvalid,
       i.indisready,
       i.indexprs is not null,
       i.indpred is not null,
       i.indnkeyatts::bigint,
       i.indnatts::bigint,
       coalesce(string_agg(pg_catalog.pg_get_indexdef(i.indexrelid, idx_key.position, false), ',' order by idx_key.position), '')
from pg_catalog.pg_class idx
join pg_catalog.pg_namespace idx_n on idx_n.oid = idx.relnamespace
join pg_catalog.pg_index i on i.indexrelid = idx.oid
join pg_catalog.pg_class tbl on tbl.oid = i.indrelid
join pg_catalog.pg_namespace tbl_n on tbl_n.oid = tbl.relnamespace
join pg_catalog.pg_am am on am.oid = idx.relam
left join lateral generate_series(1, i.indnkeyatts::integer) as idx_key(position) on true
where idx_n.nspname = current_schema()
  and tbl_n.nspname = current_schema()
  and idx.relname = $1
  and tbl.relname = $2
  and idx.relkind = 'i'
  and tbl.relkind = 'r'
group by idx.relname, tbl.relname, am.amname, i.indisunique, i.indisvalid, i.indisready, i.indexprs, i.indpred, i.indnkeyatts, i.indnatts`

func loadLeaseLockedUntilIndex(ctx context.Context, db *sql.DB) (leaseIndex, bool, error) {
	rows, err := db.QueryContext(ctx, leaseLockedUntilIndexSQL, leaseLockedUntilIndexName, leaseTableName)
	if err != nil {
		return leaseIndex{}, false, fmt.Errorf("load %s index: %w", leaseLockedUntilIndexName, err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return leaseIndex{}, false, fmt.Errorf("load %s index: %w", leaseLockedUntilIndexName, err)
		}
		return leaseIndex{}, false, nil
	}
	var index leaseIndex
	var columns string
	if err := rows.Scan(
		&index.name,
		&index.tableName,
		&index.accessMethod,
		&index.unique,
		&index.valid,
		&index.ready,
		&index.hasExpression,
		&index.hasPredicate,
		&index.keyColumns,
		&index.totalColumns,
		&columns,
	); err != nil {
		return leaseIndex{}, false, fmt.Errorf("load %s index: %w", leaseLockedUntilIndexName, err)
	}
	if rows.Next() {
		return leaseIndex{}, false, fmt.Errorf("load %s index: duplicate index metadata", leaseLockedUntilIndexName)
	}
	if err := rows.Err(); err != nil {
		return leaseIndex{}, false, fmt.Errorf("load %s index: %w", leaseLockedUntilIndexName, err)
	}
	index.columns = splitCatalogColumns(columns)
	return index, true, nil
}

func validateLeaseLockedUntilIndex(index leaseIndex) error {
	if index.name != leaseLockedUntilIndexName {
		return fmt.Errorf("%s index metadata has name %s", leaseLockedUntilIndexName, index.name)
	}
	if index.tableName != leaseTableName {
		return fmt.Errorf("%s index belongs to %s, want %s", leaseLockedUntilIndexName, index.tableName, leaseTableName)
	}
	if index.accessMethod != "btree" {
		return fmt.Errorf("%s index uses access method %s, want btree", leaseLockedUntilIndexName, index.accessMethod)
	}
	if index.unique {
		return fmt.Errorf("%s index must not be unique", leaseLockedUntilIndexName)
	}
	if !index.valid || !index.ready {
		return fmt.Errorf("%s index must be valid and ready", leaseLockedUntilIndexName)
	}
	if index.hasExpression {
		return fmt.Errorf("%s index must not be an expression index", leaseLockedUntilIndexName)
	}
	if index.hasPredicate {
		return fmt.Errorf("%s index must not be partial", leaseLockedUntilIndexName)
	}
	if index.keyColumns != 1 || index.totalColumns != 1 {
		return fmt.Errorf("%s index must contain exactly locked_until", leaseLockedUntilIndexName)
	}
	if !sameStringList(index.columns, []string{"locked_until"}) {
		return fmt.Errorf("%s index covers columns %s, want locked_until", leaseLockedUntilIndexName, strings.Join(index.columns, ", "))
	}
	return nil
}

func splitCatalogColumns(columns string) []string {
	if columns == "" {
		return nil
	}
	return strings.Split(columns, ",")
}

func normalizeCatalogDefault(expr string) string {
	return strings.ToLower(strings.Join(strings.Fields(expr), ""))
}

func normalizeCatalogConstraint(expr string) string {
	normalized := strings.ToLower(strings.Join(strings.Fields(expr), ""))
	normalized = strings.ReplaceAll(normalized, "::text", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	return normalized
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, value := range a {
		seen[value]++
	}
	for _, value := range b {
		seen[value]--
		if seen[value] < 0 {
			return false
		}
	}
	return true
}

func sameStringList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
