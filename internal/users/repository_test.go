package users

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

func TestCreateUserNormalizesEmailAndUsesParameterizedInsert(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: userRowValues(now, "user@example.com", "User Name")}}
	repo := NewRepository(db)
	created, err := repo.Create(context.Background(), CreateUserParams{
		ID:          "12345678-1234-4234-9234-123456789abc",
		Email:       "USER@Example.COM",
		DisplayName: "User Name",
		GlobalRole:  GlobalRoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Email != "user@example.com" {
		t.Fatalf("email = %q", created.Email)
	}
	if !strings.Contains(db.query, "insert into users") || strings.Contains(db.query, "USER@Example.COM") {
		t.Fatalf("query is not a parameterized user insert: %s", db.query)
	}
	if db.args[1] != "user@example.com" {
		t.Fatalf("args = %#v", db.args)
	}
}

func TestUpdateUserBuildsOnlyKnownColumns(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: userRowValues(now, "user@example.com", "Renamed")}}
	repo := NewRepository(db)
	_, err := repo.Update(context.Background(), "12345678-1234-4234-9234-123456789abc", UpdateUserParams{
		DisplayName: storage.SetString("Renamed"),
		Status:      storage.SetString(string(StatusDisabled)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.query, "display_name = $1") || !strings.Contains(db.query, "status = $2") {
		t.Fatalf("update query missing expected setters: %s", db.query)
	}
	setClause := strings.Split(db.query, "where id")[0]
	if strings.Contains(setClause, "oidc_issuer") || strings.Contains(setClause, "password_hash =") {
		t.Fatalf("update query touched unexpected columns: %s", db.query)
	}
	if db.args[0] != "Renamed" || db.args[1] != string(StatusDisabled) {
		t.Fatalf("args = %#v", db.args)
	}
}

func TestUserValidationRejectsPartialOIDCLink(t *testing.T) {
	issuer := "https://issuer.example.com"
	repo := NewRepository(&fakeDB{})
	_, err := repo.Create(context.Background(), CreateUserParams{
		ID:          "12345678-1234-4234-9234-123456789abc",
		Email:       "user@example.com",
		DisplayName: "User Name",
		OIDCIssuer:  &issuer,
	})
	if err == nil {
		t.Fatalf("partial OIDC link was accepted")
	}
}

type fakeDB struct {
	query string
	args  []any
	row   pgx.Row
}

func (f *fakeDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (f *fakeDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	f.query = query
	f.args = args
	if f.row != nil {
		return f.row
	}
	return fakeRow{err: pgx.ErrNoRows}
}

func (f *fakeDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
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
		case *bool:
			*d = r.values[i].(bool)
		case *time.Time:
			*d = r.values[i].(time.Time)
		case *int64:
			*d = r.values[i].(int64)
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

func userRowValues(now time.Time, email, displayName string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		email,
		displayName,
		nil,
		false,
		nil,
		nil,
		nil,
		nil,
		string(GlobalRoleAdmin),
		string(StatusActive),
		now,
		now,
		nil,
		int64(0),
	}
}
