package dnsproviders

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

func TestCreateProviderStoresCredentialsButDoesNotReturnThem(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: providerRowValues(now, nil, nil)}}
	repo := NewRepository(db)
	provider, err := repo.Create(context.Background(), CreateProviderParams{
		ID:                   "12345678-1234-4234-9234-123456789abc",
		Name:                 "cloudflare_main",
		Type:                 ProviderTypeCloudflare,
		CredentialsEncrypted: `{"ciphertext":"secret"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name != "cloudflare_main" || provider.ZoneMode != ZoneModeManual {
		t.Fatalf("provider = %#v", provider)
	}
	if db.args[3] != `{"ciphertext":"secret"}` {
		t.Fatalf("args = %#v", db.args)
	}
	returning := strings.Split(db.query, "returning ")[1]
	if strings.Contains(returning, "credentials_encrypted") {
		t.Fatalf("provider returning leaks credentials: %s", db.query)
	}
}

func TestReplaceCredentialsStillReturnsNonSecretProvider(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: providerRowValues(now, nil, nil)}}
	repo := NewRepository(db)
	if _, err := repo.ReplaceCredentials(context.Background(), "12345678-1234-4234-9234-123456789abc", `{"ciphertext":"new"}`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.query, "credentials_encrypted = $1") {
		t.Fatalf("replace query = %s", db.query)
	}
	returning := strings.Split(db.query, "returning ")[1]
	if strings.Contains(returning, "credentials_encrypted") {
		t.Fatalf("replace returning leaks credentials: %s", db.query)
	}
}

func TestUpdateProviderOnlyTouchesMutableColumns(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: providerRowValues(now, nil, nil)}}
	repo := NewRepository(db)
	_, err := repo.Update(context.Background(), "12345678-1234-4234-9234-123456789abc", UpdateProviderParams{
		ZoneMode: storage.SetString(string(ZoneModeAuto)),
		Status:   storage.SetString(string(StatusDisabled)),
	})
	if err != nil {
		t.Fatal(err)
	}
	setClause := strings.Split(db.query, "where id")[0]
	for _, forbidden := range []string{"name =", "type =", "credentials_encrypted ="} {
		if strings.Contains(setClause, forbidden) {
			t.Fatalf("unexpected provider setter: %s", db.query)
		}
	}
}

func TestAddZoneNormalizesDNSName(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: zoneRowValues(now, "xn--bcher-kva.example")}}
	repo := NewRepository(db)
	zone, err := repo.AddZone(context.Background(), AddZoneParams{
		ID:            "12345678-1234-4234-9234-123456789abc",
		DNSProviderID: "22345678-1234-4234-9234-123456789abc",
		ZoneName:      "Bücher.Example.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if zone.ZoneName != "xn--bcher-kva.example" || db.args[1] != "xn--bcher-kva.example" {
		t.Fatalf("zone = %#v args = %#v", zone, db.args)
	}
	if !strings.Contains(db.query, "p.zone_mode = 'manual'") {
		t.Fatalf("manual mode guard missing: %s", db.query)
	}
}

func TestFindZoneForDNSNameUsesLabelBoundarySuffix(t *testing.T) {
	now := time.Now()
	values := append(zoneRowValues(now, "example.com"), providerRowValues(now, nil, nil)...)
	db := &fakeDB{row: fakeRow{values: values}}
	repo := NewRepository(db)
	match, err := repo.FindZoneForDNSName(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if match.Zone.ZoneName != "example.com" {
		t.Fatalf("match = %#v", match)
	}
	if !strings.Contains(db.query, "$1 = z.zone_name or $1 like '%.' || z.zone_name") ||
		!strings.Contains(db.query, "order by length(z.zone_name) desc") {
		t.Fatalf("boundary suffix query missing: %s", db.query)
	}
}

func TestCompleteRefreshJobSuccessBuildsAtomicReplaceAndRejectsDuplicates(t *testing.T) {
	now := time.Now()
	db := &fakeDB{row: fakeRow{values: refreshJobRowValues(now, string(RefreshJobStatusSucceeded), nil, nil, int32(2))}}
	repo := NewRepository(db)
	job, err := repo.CompleteRefreshJobSuccess(context.Background(), CompleteRefreshJobParams{
		JobID:         "12345678-1234-4234-9234-123456789abc",
		DNSProviderID: "22345678-1234-4234-9234-123456789abc",
		WorkerID:      "worker-1",
		ZoneNames:     []string{"example.com", "api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != RefreshJobStatusSucceeded {
		t.Fatalf("job = %#v", job)
	}
	for _, required := range []string{"with job_claim", "locked_by = $5", "locked_until > now()", "conflict as", "delete from dns_provider_zones", "insert into dns_provider_zones", "dns_provider_zone_conflict"} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("refresh completion query missing %q: %s", required, db.query)
		}
	}
	_, err = repo.CompleteRefreshJobSuccess(context.Background(), CompleteRefreshJobParams{
		JobID:         "12345678-1234-4234-9234-123456789abc",
		DNSProviderID: "22345678-1234-4234-9234-123456789abc",
		WorkerID:      "worker-1",
		ZoneNames:     []string{"example.com", "EXAMPLE.com."},
	})
	if err == nil {
		t.Fatalf("duplicate refresh zones were accepted")
	}
}

func TestClaimRefreshJobUsesRowLevelLocking(t *testing.T) {
	now := time.Now()
	worker := "worker-1"
	lockedUntil := now.Add(time.Minute)
	db := &fakeDB{row: fakeRow{values: refreshJobRowValues(now, string(RefreshJobStatusRunning), &worker, &lockedUntil, nil)}}
	repo := NewRepository(db)
	if _, err := repo.ClaimNextRefreshJob(context.Background(), ClaimRefreshJobParams{
		WorkerID:    worker,
		LockedUntil: lockedUntil,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.query, "for update skip locked") || !strings.Contains(db.query, "locked_until <= now()") {
		t.Fatalf("claim query missing lease locking: %s", db.query)
	}
}

func TestFailRefreshJobRequiresWorkerLease(t *testing.T) {
	now := time.Now()
	worker := "worker-1"
	lockedUntil := now.Add(time.Minute)
	db := &fakeDB{row: fakeRow{values: refreshJobRowValues(now, string(RefreshJobStatusFailed), &worker, &lockedUntil, nil)}}
	repo := NewRepository(db)
	if _, err := repo.FailRefreshJob(context.Background(), FailRefreshJobParams{
		JobID:          "12345678-1234-4234-9234-123456789abc",
		DNSProviderID:  "22345678-1234-4234-9234-123456789abc",
		WorkerID:       worker,
		FailureCode:    "dns_zone_discovery_failed",
		FailureMessage: ptr("zone discovery failed"),
	}); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"locked_by = $5", "locked_until > now()", "j.status = 'running'"} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("refresh failure query missing %q: %s", required, db.query)
		}
	}
}

func ptr(value string) *string {
	return &value
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
		case *sql.NullTime:
			if r.values[i] == nil {
				*d = sql.NullTime{}
			} else {
				*d = sql.NullTime{Time: r.values[i].(time.Time), Valid: true}
			}
		case *sql.NullInt32:
			if r.values[i] == nil {
				*d = sql.NullInt32{}
			} else {
				*d = sql.NullInt32{Int32: r.values[i].(int32), Valid: true}
			}
		default:
			return errors.New("unsupported scan target")
		}
	}
	return nil
}

func providerRowValues(now time.Time, failureCode, failureMessage *string) []any {
	var codeValue, messageValue any
	if failureCode != nil {
		codeValue = *failureCode
	}
	if failureMessage != nil {
		messageValue = *failureMessage
	}
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"cloudflare_main",
		string(ProviderTypeCloudflare),
		string(ZoneModeManual),
		nil,
		string(RefreshStatusIdle),
		codeValue,
		messageValue,
		string(StatusActive),
		now,
		now,
		int64(0),
	}
}

func zoneRowValues(now time.Time, zoneName string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		zoneName,
		now,
	}
}

func refreshJobRowValues(now time.Time, status string, lockedBy *string, lockedUntil *time.Time, discoveredCount any) []any {
	var lockedByValue, lockedUntilValue any
	if lockedBy != nil {
		lockedByValue = *lockedBy
	}
	if lockedUntil != nil {
		lockedUntilValue = *lockedUntil
	}
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		status,
		lockedByValue,
		lockedUntilValue,
		now,
		now,
		discoveredCount,
		nil,
		nil,
		nil,
		nil,
		now,
		now,
	}
}
