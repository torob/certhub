package applications

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCreateApplicationNormalizesTrustedSourceCIDRs(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: applicationRowValues(now, []string{"203.0.113.0/24", "203.0.113.10/32"})}}
	repo := NewRepository(db)
	app, err := repo.Create(context.Background(), CreateApplicationParams{
		ID:                 "12345678-1234-4234-9234-123456789abc",
		Name:               "api_app",
		DisplayName:        "API App",
		TrustedSourceCIDRs: []string{"203.0.113.10", "203.0.113.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(app.TrustedSourceCIDRs) != 2 || app.CertificateCount != 2 {
		t.Fatalf("application read model = %#v", app)
	}
	if !strings.Contains(db.query, "$7::cidr[]") {
		t.Fatalf("insert does not cast CIDR array: %s", db.query)
	}
	cidrs := db.args[6].([]string)
	if cidrs[0] != "203.0.113.0/24" || cidrs[1] != "203.0.113.10/32" {
		t.Fatalf("cidr args = %#v", cidrs)
	}
}

func TestCreateApplicationRejectsReservedNormalName(t *testing.T) {
	repo := NewRepository(&fakeDB{})
	_, err := repo.Create(context.Background(), CreateApplicationParams{
		ID:          "12345678-1234-4234-9234-123456789abc",
		Name:        "certhub_server",
		DisplayName: "Certhub Server",
	})
	if err == nil {
		t.Fatalf("reserved normal application name was accepted")
	}
}

func TestAddDomainScopeNormalizesIDNWildcard(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		"*.xn--bcher-kva.example",
		now,
		nil,
	}}}
	repo := NewRepository(db)
	scope, err := repo.AddDomainScope(context.Background(), AddDomainScopeParams{
		ID:            "12345678-1234-4234-9234-123456789abc",
		ApplicationID: "22345678-1234-4234-9234-123456789abc",
		Value:         "*.Bücher.Example.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Value != "*.xn--bcher-kva.example" || scope.Kind != DomainScopeKindWildcard {
		t.Fatalf("scope = %#v", scope)
	}
	if db.args[2] != "*.xn--bcher-kva.example" {
		t.Fatalf("args = %#v", db.args)
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
		case *[]string:
			*d = append([]string(nil), r.values[i].([]string)...)
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

func applicationRowValues(now time.Time, cidrs []string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"api_app",
		"API App",
		string(StatusActive),
		nil,
		nil,
		cidrs,
		now,
		now,
		int64(0),
		int64(0),
		int64(0),
		int64(2),
		int64(len(cidrs)),
	}
}
