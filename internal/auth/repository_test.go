package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/storage"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRotateAccessTokenTxLocksHistoryAndSession(t *testing.T) {
	now := time.Now()
	oldHash := strings.Repeat("A", 43)
	newAccessHash := strings.Repeat("B", 43)
	db := &fakeTx{
		rows: []pgx.Row{
			fakeRow{values: tokenRowValues(now, oldHash, SessionTokenStatusActive)},
			fakeRow{values: sessionRowValues(now, oldHash, SessionStatusActive)},
			fakeRow{values: sessionRowValues(now, newAccessHash, SessionStatusActive)},
		},
	}
	rotated, err := RotateAccessTokenTx(context.Background(), db, RotateAccessTokenParams{
		CurrentAccessTokenHash: oldHash,
		NewAccessTokenHash:     newAccessHash,
		AccessExpiresAt:        now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessTokenHash != newAccessHash {
		t.Fatalf("rotated session access hash = %q", rotated.AccessTokenHash)
	}
	if len(db.queries) < 2 || !strings.Contains(db.queries[0], "for update") || !strings.Contains(db.queries[1], "for update") {
		t.Fatalf("rotation did not lock token history and session: %#v", db.queries)
	}
	if len(db.execs) != 2 || !strings.Contains(db.execs[0], "status = 'rotated'") || !strings.Contains(db.execs[1], "insert into user_session_token_history") {
		t.Fatalf("rotation execs = %#v", db.execs)
	}
}

func TestRotateAccessTokenCommitsReuseRevocation(t *testing.T) {
	now := time.Now()
	oldHash := strings.Repeat("A", 43)
	tx := &fakeTx{
		rows: []pgx.Row{
			fakeRow{values: tokenRowValues(now, oldHash, SessionTokenStatusRotated)},
		},
	}
	repo := NewRepository(&fakeBeginner{tx: tx})
	_, err := repo.RotateAccessToken(context.Background(), RotateAccessTokenParams{
		CurrentAccessTokenHash: oldHash,
		NewAccessTokenHash:     strings.Repeat("B", 43),
		AccessExpiresAt:        now.Add(5 * time.Minute),
	})
	if !errors.Is(err, ErrAccessTokenReused) {
		t.Fatalf("err = %v", err)
	}
	if !tx.committed || tx.rolledBack {
		t.Fatalf("reuse path committed=%v rolledBack=%v", tx.committed, tx.rolledBack)
	}
	if len(tx.execs) != 3 || !strings.Contains(tx.execs[0], "status = 'reused'") || !strings.Contains(tx.execs[1], "status = 'revoked'") || !strings.Contains(tx.execs[2], "revoked_reason") {
		t.Fatalf("reuse execs = %#v", tx.execs)
	}
}

func TestRotateAccessTokenRejectsExpiredAccessToken(t *testing.T) {
	now := time.Now()
	oldHash := strings.Repeat("A", 43)
	db := &fakeTx{
		rows: []pgx.Row{
			fakeRow{values: tokenRowValuesWithExpiry(now, oldHash, SessionTokenStatusActive, now.Add(-time.Second))},
			fakeRow{values: sessionRowValues(now, oldHash, SessionStatusActive)},
		},
	}
	_, err := RotateAccessTokenTx(context.Background(), db, RotateAccessTokenParams{
		CurrentAccessTokenHash: oldHash,
		NewAccessTokenHash:     strings.Repeat("B", 43),
		AccessExpiresAt:        now.Add(5 * time.Minute),
	})
	if !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("err = %v", err)
	}
	if len(db.execs) != 1 || !strings.Contains(db.execs[0], "status = 'expired'") {
		t.Fatalf("expired token execs = %#v", db.execs)
	}
}

func TestRotateAccessTokenRejectsExpiredSession(t *testing.T) {
	now := time.Now()
	oldHash := strings.Repeat("A", 43)
	db := &fakeTx{
		rows: []pgx.Row{
			fakeRow{values: tokenRowValues(now, oldHash, SessionTokenStatusActive)},
			fakeRow{values: sessionRowValuesWithExpiry(now, oldHash, SessionStatusActive, now.Add(-time.Second))},
		},
	}
	_, err := RotateAccessTokenTx(context.Background(), db, RotateAccessTokenParams{
		CurrentAccessTokenHash: oldHash,
		NewAccessTokenHash:     strings.Repeat("B", 43),
		AccessExpiresAt:        now.Add(5 * time.Minute),
	})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v", err)
	}
}

type fakeBeginner struct {
	tx *fakeTx
}

func (f *fakeBeginner) Begin(context.Context) (storage.Tx, error) {
	return f.tx, nil
}

func (f *fakeBeginner) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return f.tx.Exec(ctx, query, args...)
}

func (f *fakeBeginner) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return f.tx.QueryRow(ctx, query, args...)
}

func (f *fakeBeginner) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return f.tx.Query(ctx, query, args...)
}

type fakeTx struct {
	rows       []pgx.Row
	queries    []string
	execs      []string
	committed  bool
	rolledBack bool
}

func (f *fakeTx) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, query)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (f *fakeTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	f.queries = append(f.queries, strings.ToLower(query))
	if len(f.rows) == 0 {
		return fakeRow{err: pgx.ErrNoRows}
	}
	row := f.rows[0]
	f.rows = f.rows[1:]
	return row
}

func (f *fakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeTx) Commit(context.Context) error {
	f.committed = true
	return nil
}

func (f *fakeTx) Rollback(context.Context) error {
	f.rolledBack = true
	return nil
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("scan destination count mismatch")
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = r.values[i].(string)
		case *time.Time:
			*d = r.values[i].(time.Time)
		case *sql.NullString:
			if r.values[i] == nil {
				*d = sql.NullString{}
			} else {
				*d = sql.NullString{String: r.values[i].(string), Valid: true}
			}
		case *sql.NullTime:
			if r.values[i] == nil {
				*d = sql.NullTime{}
			} else {
				*d = sql.NullTime{Time: r.values[i].(time.Time), Valid: true}
			}
		default:
			return errors.New("unsupported scan target")
		}
	}
	return nil
}

func tokenRowValues(now time.Time, hash string, status SessionTokenStatus) []any {
	return tokenRowValuesWithExpiry(now, hash, status, now.Add(time.Hour))
}

func tokenRowValuesWithExpiry(now time.Time, hash string, status SessionTokenStatus, expiresAt time.Time) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		hash,
		string(status),
		now.Add(-time.Minute),
		expiresAt,
		nil,
		nil,
	}
}

func sessionRowValues(now time.Time, accessHash string, status SessionStatus) []any {
	return sessionRowValuesWithExpiry(now, accessHash, status, now.Add(time.Hour))
}

func sessionRowValuesWithExpiry(now time.Time, accessHash string, status SessionStatus, sessionExpiresAt time.Time) []any {
	return []any{
		"22345678-1234-4234-9234-123456789abc",
		"32345678-1234-4234-9234-123456789abc",
		string(AuthMethodPassword),
		accessHash,
		string(status),
		now.Add(-time.Minute),
		now.Add(5 * time.Minute),
		sessionExpiresAt,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	}
}
