package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"certhub/internal/storage"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRotateRefreshTokenTxLocksHistoryAndSession(t *testing.T) {
	now := time.Now()
	oldHash := strings.Repeat("A", 43)
	newAccessHash := strings.Repeat("B", 43)
	newRefreshHash := strings.Repeat("C", 43)
	db := &fakeTx{
		rows: []pgx.Row{
			fakeRow{values: refreshRowValues(now, oldHash, RefreshTokenStatusActive)},
			fakeRow{values: sessionRowValues(now, oldHash, SessionStatusActive, nil)},
			fakeRow{values: sessionRowValues(now, newRefreshHash, SessionStatusActive, &newAccessHash)},
		},
	}
	rotated, err := RotateRefreshTokenTx(context.Background(), db, RotateRefreshTokenParams{
		CurrentRefreshTokenHash: oldHash,
		NewAccessTokenHash:      newAccessHash,
		NewRefreshTokenHash:     newRefreshHash,
		AccessExpiresAt:         now.Add(5 * time.Minute),
		RefreshExpiresAt:        now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshTokenHash != newRefreshHash {
		t.Fatalf("rotated session refresh hash = %q", rotated.RefreshTokenHash)
	}
	if len(db.queries) < 2 || !strings.Contains(db.queries[0], "for update") || !strings.Contains(db.queries[1], "for update") {
		t.Fatalf("rotation did not lock refresh history and session: %#v", db.queries)
	}
	if len(db.execs) != 2 || !strings.Contains(db.execs[0], "status = 'rotated'") || !strings.Contains(db.execs[1], "insert into user_session_refresh_tokens") {
		t.Fatalf("rotation execs = %#v", db.execs)
	}
}

func TestRotateRefreshTokenCommitsReuseRevocation(t *testing.T) {
	now := time.Now()
	oldHash := strings.Repeat("A", 43)
	tx := &fakeTx{
		rows: []pgx.Row{
			fakeRow{values: refreshRowValues(now, oldHash, RefreshTokenStatusRotated)},
		},
	}
	repo := NewRepository(&fakeBeginner{tx: tx})
	_, err := repo.RotateRefreshToken(context.Background(), RotateRefreshTokenParams{
		CurrentRefreshTokenHash: oldHash,
		NewAccessTokenHash:      strings.Repeat("B", 43),
		NewRefreshTokenHash:     strings.Repeat("C", 43),
		AccessExpiresAt:         now.Add(5 * time.Minute),
		RefreshExpiresAt:        now.Add(time.Hour),
	})
	if !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("err = %v", err)
	}
	if !tx.committed || tx.rolledBack {
		t.Fatalf("reuse path committed=%v rolledBack=%v", tx.committed, tx.rolledBack)
	}
	if len(tx.execs) != 3 || !strings.Contains(tx.execs[0], "status = 'reused'") || !strings.Contains(tx.execs[1], "status = 'revoked'") || !strings.Contains(tx.execs[2], "revoked_reason") {
		t.Fatalf("reuse execs = %#v", tx.execs)
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

func refreshRowValues(now time.Time, hash string, status RefreshTokenStatus) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		hash,
		string(status),
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
		nil,
	}
}

func sessionRowValues(now time.Time, refreshHash string, status SessionStatus, accessHash *string) []any {
	if accessHash == nil {
		value := strings.Repeat("D", 43)
		accessHash = &value
	}
	return []any{
		"22345678-1234-4234-9234-123456789abc",
		"32345678-1234-4234-9234-123456789abc",
		string(AuthMethodPassword),
		*accessHash,
		refreshHash,
		string(status),
		now.Add(-time.Minute),
		now.Add(5 * time.Minute),
		now.Add(time.Hour),
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	}
}
