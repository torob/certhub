package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAppendDefaultsMetadataAndUsesScopeColumns(t *testing.T) {
	now := time.Now()
	scopeApplicationID := "22345678-1234-4234-9234-123456789abc"
	db := &fakeDB{row: fakeRow{values: eventRowValues(now, json.RawMessage(`{}`), &scopeApplicationID)}}
	repo := NewRepository(db)
	event, err := repo.Append(context.Background(), AppendEventParams{
		ID:                 "12345678-1234-4234-9234-123456789abc",
		IdentityType:       IdentityTypeSystem,
		Action:             "application_created",
		TargetType:         "application",
		TargetID:           &scopeApplicationID,
		ScopeApplicationID: &scopeApplicationID,
		Result:             ResultSuccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(event.Metadata) != `{}` {
		t.Fatalf("metadata = %s", event.Metadata)
	}
	if !strings.Contains(db.query, "scope_application_id") || strings.Contains(db.query, "raw_token") {
		t.Fatalf("append query = %s", db.query)
	}
	if string(db.args[13].([]byte)) != `{}` {
		t.Fatalf("metadata arg = %#v", db.args[13])
	}
}

func TestListAuditQueryShape(t *testing.T) {
	scopeApplicationID := "22345678-1234-4234-9234-123456789abc"
	db := &fakeDB{rows: fakeRows{}}
	repo := NewRepository(db)
	_, err := repo.List(context.Background(), ListEventsParams{
		ScopeApplicationID: &scopeApplicationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.query, "scope_application_id = $1") || strings.Contains(db.query, "metadata") && strings.Contains(db.query, "where metadata") {
		t.Fatalf("list query does not use structured scope columns: %s", db.query)
	}
}

func TestAppendRejectsSystemIdentityID(t *testing.T) {
	id := "22345678-1234-4234-9234-123456789abc"
	repo := NewRepository(&fakeDB{})
	_, err := repo.Append(context.Background(), AppendEventParams{
		ID:           "12345678-1234-4234-9234-123456789abc",
		IdentityType: IdentityTypeSystem,
		IdentityID:   &id,
		Action:       "user_created",
		TargetType:   "user",
		Result:       ResultSuccess,
	})
	if err == nil {
		t.Fatalf("system identity_id was accepted")
	}
}

type fakeDB struct {
	query string
	args  []any
	row   pgx.Row
	rows  pgx.Rows
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

func (f *fakeDB) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	f.query = query
	f.args = args
	if f.rows != nil {
		return f.rows, nil
	}
	return fakeRows{}, nil
}

type fakeRows struct{}

func (fakeRows) Close()                                       {}
func (fakeRows) Err() error                                   { return nil }
func (fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT 0") }
func (fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (fakeRows) Next() bool                                   { return false }
func (fakeRows) Scan(...any) error                            { return errors.New("no rows") }
func (fakeRows) Values() ([]any, error)                       { return nil, errors.New("no rows") }
func (fakeRows) RawValues() [][]byte                          { return nil }
func (fakeRows) Conn() *pgx.Conn                              { return nil }

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
		case *[]byte:
			*d = append([]byte(nil), r.values[i].([]byte)...)
		case *sql.NullString:
			if r.values[i] == nil {
				*d = sql.NullString{}
			} else {
				*d = sql.NullString{String: r.values[i].(string), Valid: true}
			}
		default:
			return errors.New("unsupported scan target")
		}
	}
	return nil
}

func eventRowValues(now time.Time, metadata json.RawMessage, scopeApplicationID *string) []any {
	var scope any
	if scopeApplicationID != nil {
		scope = *scopeApplicationID
	}
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		string(IdentityTypeSystem),
		nil,
		"application_created",
		"application",
		scope,
		scope,
		nil,
		nil,
		nil,
		string(ResultSuccess),
		nil,
		nil,
		[]byte(metadata),
		now,
	}
}
