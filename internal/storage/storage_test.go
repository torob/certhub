package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeBeginner struct {
	tx  *fakeTx
	err error
}

func (f fakeBeginner) Begin(context.Context) (Tx, error) {
	return f.tx, f.err
}

type fakeTx struct {
	committed         bool
	rolledBack        bool
	commitErr         error
	row               pgx.Row
	query             string
	args              []any
	rollback          context.Context
	rollbackErrAtCall error
}

func (f *fakeTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (f *fakeTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	f.query = query
	f.args = args
	if f.row != nil {
		return f.row
	}
	return fakeRow{}
}

func (f *fakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeTx) Commit(context.Context) error {
	f.committed = true
	return f.commitErr
}

func (f *fakeTx) Rollback(ctx context.Context) error {
	f.rolledBack = true
	f.rollback = ctx
	f.rollbackErrAtCall = ctx.Err()
	return nil
}

func TestWithTxCommitAndRollback(t *testing.T) {
	ctx := context.Background()
	tx := &fakeTx{}
	if err := WithTx(ctx, fakeBeginner{tx: tx}, func(context.Context, Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !tx.committed || tx.rolledBack {
		t.Fatalf("commit path committed=%v rolledBack=%v", tx.committed, tx.rolledBack)
	}

	tx = &fakeTx{}
	want := errors.New("fail")
	if err := WithTx(ctx, fakeBeginner{tx: tx}, func(context.Context, Tx) error { return want }); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
	if tx.committed || !tx.rolledBack {
		t.Fatalf("rollback path committed=%v rolledBack=%v", tx.committed, tx.rolledBack)
	}
}

func TestWithTxRollbackUsesFreshContextAfterCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tx := &fakeTx{}
	want := errors.New("fail")
	err := WithTx(ctx, fakeBeginner{tx: tx}, func(context.Context, Tx) error {
		cancel()
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
	if !tx.rolledBack {
		t.Fatalf("transaction was not rolled back")
	}
	if tx.rollback == nil {
		t.Fatalf("rollback context was not captured")
	}
	if err := tx.rollbackErrAtCall; err != nil {
		t.Fatalf("rollback used canceled context: %v", err)
	}
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *bool:
			*d = r.values[i].(bool)
		case *string:
			*d = r.values[i].(string)
		case *time.Time:
			*d = r.values[i].(time.Time)
		case *int64:
			*d = r.values[i].(int64)
		default:
			return errors.New("unsupported scan target")
		}
	}
	return nil
}

type fakeQueryRower struct {
	query string
	args  []any
	row   pgx.Row
}

func (f *fakeQueryRower) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	f.query = query
	f.args = args
	return f.row
}

func TestTryAdvisoryXactLockRequiresTransaction(t *testing.T) {
	tx := &fakeTx{row: fakeRow{values: []any{true}}}
	ok, err := TryAdvisoryXactLock(context.Background(), tx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.Contains(tx.query, "pg_try_advisory_xact_lock") || tx.args[0].(int64) != 42 {
		t.Fatalf("ok=%v query=%q args=%#v", ok, tx.query, tx.args)
	}
}

func TestAcquireLeaseBuildsReclaimableLeaseQuery(t *testing.T) {
	until := time.Now().Add(time.Minute)
	token := "12345678-1234-4234-9234-123456789abc"
	db := &fakeQueryRower{row: fakeRow{values: []any{"worker.refresh", "worker/main-1", until, int64(7), token}}}
	grant, ok, err := AcquireLease(context.Background(), db, Lease{Name: "worker.refresh", LockedBy: "worker/main-1", LockedUntil: until})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("lease was not acquired")
	}
	if grant.Generation != 7 || grant.Name != "worker.refresh" || grant.LockedBy != "worker/main-1" || grant.Token != token {
		t.Fatalf("grant = %#v", grant)
	}
	if !strings.Contains(db.query, "on conflict") || !strings.Contains(db.query, "locked_until <= now()") {
		t.Fatalf("query does not reclaim expired leases: %s", db.query)
	}
	if !strings.Contains(db.query, "generation = certhub_leases.generation + 1") {
		t.Fatalf("query does not fence lease generations: %s", db.query)
	}
	if !strings.Contains(db.query, "lease_token = excluded.lease_token") {
		t.Fatalf("query does not refresh lease tokens: %s", db.query)
	}
	if db.args[0] != "worker.refresh" || db.args[1] != "worker/main-1" || !db.args[2].(time.Time).Equal(until) {
		t.Fatalf("args = %#v", db.args)
	}
	if tokenArg, ok := db.args[3].(string); !ok || !leaseTokenRE.MatchString(tokenArg) {
		t.Fatalf("lease token arg = %#v", db.args[3])
	}
}

func TestAcquireLeaseReturnsFalseOnNoRows(t *testing.T) {
	db := &fakeQueryRower{row: fakeRow{err: pgx.ErrNoRows}}
	grant, ok, err := AcquireLease(context.Background(), db, Lease{Name: "worker.refresh", LockedBy: "worker/main-1", LockedUntil: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("contended lease unexpectedly acquired")
	}
	if grant != (LeaseGrant{}) {
		t.Fatalf("grant = %#v", grant)
	}
}

type fakeExecer struct {
	query string
	args  []any
	tag   pgconn.CommandTag
	err   error
}

func (f *fakeExecer) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	f.query = query
	f.args = args
	if f.tag.String() == "" {
		f.tag = pgconn.NewCommandTag("DELETE 1")
	}
	return f.tag, f.err
}

func TestReleaseLeaseUsesGenerationCAS(t *testing.T) {
	db := &fakeExecer{}
	token := "12345678-1234-4234-9234-123456789abc"
	ok, err := ReleaseLease(context.Background(), db, LeaseGrant{Name: "worker.refresh", LockedBy: "worker/main-1", Generation: 9, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("lease was not released")
	}
	if strings.Contains(strings.ToLower(db.query), "delete from certhub_leases") {
		t.Fatalf("release deleted lease history: %s", db.query)
	}
	if !strings.Contains(db.query, "generation = $3") || !strings.Contains(db.query, "lease_token = $4::uuid") {
		t.Fatalf("query does not use generation/token CAS: %s", db.query)
	}
	if !strings.Contains(db.query, "locked_by = null") || !strings.Contains(db.query, "lease_token = null") || !strings.Contains(db.query, "'-infinity'::timestamptz") {
		t.Fatalf("query does not move the lease to a free expired state: %s", db.query)
	}
	if db.args[0] != "worker.refresh" || db.args[1] != "worker/main-1" || db.args[2] != int64(9) || db.args[3] != token {
		t.Fatalf("args = %#v", db.args)
	}
}

func TestLeaseValidation(t *testing.T) {
	for _, lease := range []Lease{
		{Name: "Bad", LockedBy: "worker/main-1", LockedUntil: time.Now().Add(time.Minute)},
		{Name: "worker.refresh", LockedUntil: time.Now().Add(time.Minute)},
		{Name: "worker.refresh", LockedBy: "worker-1", LockedUntil: time.Now().Add(time.Minute)},
		{Name: "worker.refresh", LockedBy: "worker/main-1"},
		{Name: "worker.refresh", LockedBy: "worker/main-1", LockedUntil: time.Now().Add(-time.Second)},
	} {
		if _, _, err := AcquireLease(context.Background(), &fakeQueryRower{}, lease); err == nil {
			t.Fatalf("AcquireLease(%#v) succeeded", lease)
		}
	}
}

func TestReleaseLeaseValidation(t *testing.T) {
	for _, grant := range []LeaseGrant{
		{Name: "Bad", LockedBy: "worker/main-1", Generation: 1, Token: "12345678-1234-4234-9234-123456789abc"},
		{Name: "worker.refresh", LockedBy: "worker-1", Generation: 1, Token: "12345678-1234-4234-9234-123456789abc"},
		{Name: "worker.refresh", LockedBy: "worker/main-1", Token: "12345678-1234-4234-9234-123456789abc"},
		{Name: "worker.refresh", LockedBy: "worker/main-1", Generation: 1},
	} {
		if _, err := ReleaseLease(context.Background(), &fakeExecer{}, grant); err == nil {
			t.Fatalf("ReleaseLease(%#v) succeeded", grant)
		}
	}
}

func TestSanitizeErrorHidesPostgresConstraintDetails(t *testing.T) {
	err := SanitizeError(&pgconn.PgError{
		Code:    "23505",
		Message: "duplicate key value violates unique constraint",
		Detail:  "Key (token_hash)=(secret-token-value) already exists.",
	})
	if err == nil {
		t.Fatal("SanitizeError returned nil")
	}
	if strings.Contains(err.Error(), "secret-token-value") || strings.Contains(err.Error(), "token_hash") {
		t.Fatalf("sanitized error leaked detail: %v", err)
	}
	if !strings.Contains(err.Error(), "SQLSTATE 23505") {
		t.Fatalf("sanitized error lost stable code: %v", err)
	}
}
