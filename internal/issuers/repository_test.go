package issuers

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

func TestCreateIssuerNormalizesEmailAndDefaultsDisabled(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: issuerRowValues(now, "admin@example.com", string(StatusDisabled))}}
	repo := NewRepository(db)
	issuer, err := repo.Create(context.Background(), CreateIssuerParams{
		ID:           "12345678-1234-4234-9234-123456789abc",
		Name:         "letsencrypt_staging",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Environment:  EnvironmentStaging,
		ContactEmail: "ADMIN@Example.COM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if issuer.ContactEmail != "admin@example.com" || issuer.Status != StatusDisabled {
		t.Fatalf("issuer = %#v", issuer)
	}
	if strings.Contains(db.query, "ADMIN@Example.COM") {
		t.Fatalf("query contains unsanitized email: %s", db.query)
	}
	if db.args[6] != string(StatusDisabled) || db.args[8] != "admin@example.com" {
		t.Fatalf("args = %#v", db.args)
	}
}

func TestCreateIssuerRejectsActiveWithoutAccount(t *testing.T) {
	repo := NewRepository(&fakeDB{})
	_, err := repo.Create(context.Background(), CreateIssuerParams{
		ID:           "12345678-1234-4234-9234-123456789abc",
		Name:         "letsencrypt_production",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Environment:  EnvironmentProduction,
		Status:       StatusActive,
		ContactEmail: "admin@example.com",
	})
	if err == nil {
		t.Fatalf("active issuer without account was accepted")
	}
}

func TestUpdateIssuerOnlyTouchesMutableColumns(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: issuerRowValues(now, "ops@example.com", string(StatusDisabled))}}
	repo := NewRepository(db)
	_, err := repo.Update(context.Background(), "12345678-1234-4234-9234-123456789abc", UpdateIssuerParams{
		IsDefault:            storage.SetBool(true),
		RenewalWindowSeconds: storage.SetInt(1209600),
		ContactEmail:         storage.SetString("OPS@Example.COM"),
	})
	if err != nil {
		t.Fatal(err)
	}
	setClause := strings.Split(db.query, "where id")[0]
	for _, forbidden := range []string{"name =", "type =", "directory_url =", "environment ="} {
		if strings.Contains(setClause, forbidden) {
			t.Fatalf("immutable column appeared in update: %s", db.query)
		}
	}
	if db.args[0] != true || db.args[1] != 1209600 || db.args[2] != "ops@example.com" {
		t.Fatalf("args = %#v", db.args)
	}
}

func TestCreateACMEAccountStoresEncryptedPrivateKey(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: acmeAccountRowValues(now, `{"kid":"key"}`, string(ACMEAccountStatusActive))}}
	repo := NewRepository(db)
	account, err := repo.CreateACMEAccount(context.Background(), CreateACMEAccountParams{
		ID:                     "12345678-1234-4234-9234-123456789abc",
		IssuerID:               "22345678-1234-4234-9234-123456789abc",
		Email:                  "ACME@Example.COM",
		AccountURL:             "https://acme.example.com/acct/1",
		PrivateKeyPEMEncrypted: `{"kid":"key"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.Email != "acme@example.com" || account.PrivateKeyPEMEncrypted != `{"kid":"key"}` {
		t.Fatalf("account = %#v", account)
	}
	if db.args[4] != `{"kid":"key"}` {
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
		case *bool:
			*d = r.values[i].(bool)
		case *int:
			*d = r.values[i].(int)
		case *int64:
			*d = r.values[i].(int64)
		case *time.Time:
			*d = r.values[i].(time.Time)
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

func issuerRowValues(now time.Time, email, status string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"letsencrypt_staging",
		string(TypeACME),
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		string(EnvironmentStaging),
		false,
		status,
		2592000,
		email,
		now,
		now,
		int64(0),
		false,
	}
}

func acmeAccountRowValues(now time.Time, encryptedKey, status string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		"acme@example.com",
		"https://acme.example.com/acct/1",
		encryptedKey,
		status,
		now,
		now,
	}
}
