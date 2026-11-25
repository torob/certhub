package storage_test

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
)

// byteOrderedSANs is sorted in Go byte order. Locale collations such as
// en_US.utf8 ignore punctuation at the first level and sort the pair the other
// way, so a database check that uses the default collation rejects it.
var byteOrderedSANs = []string{"k2.cf30.e2e.test", "k2b.cf30.e2e.test"}

func TestCertificateSANByteOrderWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping certificate SAN byte order integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrationDB, err := migrations.OpenDB(url)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close()
	if _, err := migrations.NewRunner(migrations.DefaultDir).Up(ctx, migrationDB); err != nil {
		t.Fatal(err)
	}

	pool, err := storage.Open(ctx, storage.Config{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	var databaseCollation string
	var localeOrdersPairInReverse bool
	if err := tx.QueryRow(ctx, `
select datcollate, $1::text > $2::text
from pg_database
where datname = current_database()`, byteOrderedSANs[0], byteOrderedSANs[1]).Scan(&databaseCollation, &localeOrdersPairInReverse); err != nil {
		t.Fatal(err)
	}
	t.Logf("database collation=%s default collation orders %v in reverse=%t", databaseCollation, byteOrderedSANs, localeOrdersPairInReverse)

	app, err := applications.NewRepository(tx).Create(ctx, applications.CreateApplicationParams{
		Name:        "san_byte_order_app",
		DisplayName: "SAN Byte Order App",
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := issuers.NewRepository(tx).Create(ctx, issuers.CreateIssuerParams{
		Name:         "san_byte_order_issuer",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ContactEmail: "san.byte.order@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	certRepo := certificates.NewRepository(tx)
	cert, err := certRepo.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
		ApplicationID:  app.ID,
		IssuerID:       issuer.ID,
		NormalizedSANs: []string{byteOrderedSANs[1], byteOrderedSANs[0]},
	})
	if err != nil {
		t.Fatalf("create certificate with SANs %v: %v", byteOrderedSANs, err)
	}
	if !slices.Equal(cert.NormalizedSANs, byteOrderedSANs) {
		t.Fatalf("stored normalized_sans = %v, want %v", cert.NormalizedSANs, byteOrderedSANs)
	}

	reused, err := certRepo.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
		ApplicationID:  app.ID,
		IssuerID:       issuer.ID,
		NormalizedSANs: byteOrderedSANs,
	})
	if err != nil {
		t.Fatalf("reuse certificate with SANs %v: %v", byteOrderedSANs, err)
	}
	if reused.ID != cert.ID {
		t.Fatalf("certificate identity was not reused: %s != %s", reused.ID, cert.ID)
	}

	listed, err := certRepo.List(ctx, certificates.ListCertificatesParams{
		ApplicationID:  &app.ID,
		NormalizedSANs: []string{byteOrderedSANs[1], byteOrderedSANs[0]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != cert.ID {
		t.Fatalf("lookup by normalized_sans = %#v, want certificate %s", listed, cert.ID)
	}

	// The check must use byte order whatever collation reaches it, so the
	// result does not depend on the database default collation.
	collations, err := availableSANCollations(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, collation := range collations {
		quoted := pgx.Identifier{collation}.Sanitize()
		var ordered, reversed bool
		if err := tx.QueryRow(ctx, `
select public.certhub_certificate_sans_valid($1::text[] collate `+quoted+`),
       public.certhub_certificate_sans_valid($2::text[] collate `+quoted+`)`,
			byteOrderedSANs, []string{byteOrderedSANs[1], byteOrderedSANs[0]}).Scan(&ordered, &reversed); err != nil {
			t.Fatalf("evaluate SAN check with collation %s: %v", collation, err)
		}
		if !ordered || reversed {
			t.Fatalf("SAN check with collation %s: byte order valid=%t reverse order valid=%t", collation, ordered, reversed)
		}
	}
}

// availableSANCollations returns the collations that this server can use to
// evaluate the SAN check. en_US.utf8 is the default of the postgres image and
// orders the test SANs against byte order.
func availableSANCollations(ctx context.Context, tx storage.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `
select collname
from pg_catalog.pg_collation
where collname in ('C', 'en_US.utf8', 'und-x-icu')
  and collencoding in (-1, pg_catalog.pg_char_to_encoding(pg_catalog.getdatabaseencoding()))
order by collname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
