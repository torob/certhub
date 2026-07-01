package certificates

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

func TestCreateOrReuseNormalizesIdentityAndUsesPartialConflict(t *testing.T) {
	now := testTime()
	db := &fakeDB{row: fakeRow{values: certificateRowValues(now, []string{"api.example.com", "www.example.com"}, string(StatusPending), nil, nil)}}
	repo := NewRepository(db)
	cert, err := repo.CreateOrReuse(context.Background(), CreateOrReuseCertificateParams{
		ID:             "12345678-1234-4234-9234-123456789abc",
		ApplicationID:  "22345678-1234-4234-9234-123456789abc",
		IssuerID:       "32345678-1234-4234-9234-123456789abc",
		NormalizedSANs: []string{"WWW.Example.COM.", "api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyType != KeyTypeECDSAP256 || cert.NormalizedSANs[0] != "api.example.com" {
		t.Fatalf("certificate = %#v", cert)
	}
	if cert.IssuerName != "letsencrypt_production" {
		t.Fatalf("issuer_name = %q", cert.IssuerName)
	}
	if got := db.args[3].([]string); got[0] != "api.example.com" || got[1] != "www.example.com" {
		t.Fatalf("normalized args = %#v", db.args)
	}
	for _, required := range []string{
		"on conflict (application_id, normalized_sans, key_type, issuer_id) where deleted_at is null",
		"returning id, normalized_sans",
	} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("create query missing %q: %s", required, db.query)
		}
	}
}

func TestCertificateCountQuerySupportsAccessibleApplicationsAndExpiry(t *testing.T) {
	expiresBefore := testTime().Add(30 * 24 * time.Hour)
	db := &fakeDB{row: fakeRow{values: []any{int64(3)}}}
	repo := NewRepository(db)
	total, err := repo.Count(context.Background(), ListCertificatesParams{
		ApplicationIDs: []string{
			"22345678-1234-4234-9234-123456789abc",
			"32345678-1234-4234-9234-123456789abc",
		},
		ExpiresBefore: &expiresBefore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total = %d", total)
	}
	for _, required := range []string{
		"c.application_id in ($1, $2)",
		"select v.not_after <= $3",
		"v.status = 'valid'",
		"order by v.version desc",
		"c.deleted_at is null",
	} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("count query missing %q: %s", required, db.query)
		}
	}
}

func TestLatestValidVersionSelectsNewestValidMetadata(t *testing.T) {
	now := testTime()
	db := &fakeDB{row: fakeRow{values: certificateVersionRowValues(now, string(VersionStatusValid), string(IssuanceReasonRenewal), nil)}}
	repo := NewRepository(db)
	version, err := repo.LatestValidVersion(context.Background(), "22345678-1234-4234-9234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	if version.Status != VersionStatusValid || version.Reason != IssuanceReasonRenewal {
		t.Fatalf("version = %#v", version)
	}
	for _, required := range []string{"v.status = 'valid'", "order by v.version desc", "limit 1"} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("latest version query missing %q: %s", required, db.query)
		}
	}
}

func TestCreateIssuingVersionReusesExistingAndUpdatesParentState(t *testing.T) {
	now := testTime()
	db := &fakeDB{row: fakeRow{values: certificateVersionRowValues(now, string(VersionStatusIssuing), string(IssuanceReasonRenewal), nil)}}
	repo := NewRepository(db)
	version, err := repo.CreateIssuingVersion(context.Background(), CreateIssuingVersionParams{
		ID:            "12345678-1234-4234-9234-123456789abc",
		CertificateID: "22345678-1234-4234-9234-123456789abc",
		Reason:        IssuanceReasonRenewal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if version.Status != VersionStatusIssuing || version.Reason != IssuanceReasonRenewal {
		t.Fatalf("version = %#v", version)
	}
	for _, required := range []string{"for update", "v.status = 'issuing'", "union all", "failure_code = null"} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("create version query missing %q: %s", required, db.query)
		}
	}
	if db.args[3] != string(StatusRenewing) {
		t.Fatalf("parent status arg = %#v", db.args)
	}
}

func TestEnsureAndClaimIssuanceJobsUseActiveVersionLease(t *testing.T) {
	now := testTime()
	versionID := "32345678-1234-4234-9234-123456789abc"
	db := &fakeDB{row: fakeRow{values: issuanceJobRowValues(now, string(JobStatusPending), &versionID, nil)}}
	repo := NewRepository(db)
	if _, err := repo.EnsureIssuanceJob(context.Background(), EnsureIssuanceJobParams{
		ID:                   "12345678-1234-4234-9234-123456789abc",
		CertificateID:        "22345678-1234-4234-9234-123456789abc",
		CertificateVersionID: &versionID,
		Reason:               JobReasonInitialIssue,
		NextRunAt:            now,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.query, "on conflict (certificate_version_id)") ||
		!strings.Contains(db.query, "status in ('pending', 'running')") {
		t.Fatalf("ensure job query missing active uniqueness: %s", db.query)
	}

	worker := "worker-1"
	lockedUntil := time.Now().Add(time.Minute)
	db.row = fakeRow{values: issuanceJobRowValues(now, string(JobStatusRunning), &versionID, &worker)}
	if _, err := repo.ClaimNextIssuanceJob(context.Background(), ClaimIssuanceJobParams{
		WorkerID:    worker,
		LockedUntil: lockedUntil,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.query, "for update skip locked") || !strings.Contains(db.query, "locked_until <= now()") {
		t.Fatalf("claim query missing lease locking: %s", db.query)
	}
}

func TestRecordDNSChallengeNormalizesAndUsesExactValueConflict(t *testing.T) {
	now := testTime()
	db := &fakeDB{row: fakeRow{values: dnsChallengeRowValues(now, string(DNSChallengeStatusPresented), nil, nil)}}
	repo := NewRepository(db)
	record, err := repo.RecordDNSChallenge(context.Background(), RecordDNSChallengeParams{
		ID:                      "12345678-1234-4234-9234-123456789abc",
		IssuanceJobID:           "22345678-1234-4234-9234-123456789abc",
		CertificateID:           "32345678-1234-4234-9234-123456789abc",
		CertificateVersionID:    "42345678-1234-4234-9234-123456789abc",
		DNSProviderID:           "52345678-1234-4234-9234-123456789abc",
		DNSProviderZoneID:       "62345678-1234-4234-9234-123456789abc",
		AuthorizationIdentifier: "API.Example.COM.",
		RecordName:              "_acme-challenge.API.Example.COM.",
		TXTValueEncrypted:       `{"version":"1"}`,
		Status:                  DNSChallengeStatusPresented,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.AuthorizationIdentifier != "api.example.com" || record.RecordName != "_acme-challenge.api.example.com" {
		t.Fatalf("record = %#v", record)
	}
	if !strings.Contains(db.query, "on conflict (issuance_job_id, record_name, txt_value_encrypted)") {
		t.Fatalf("dns challenge query missing exact-value conflict: %s", db.query)
	}
}

func testTime() time.Time {
	return time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
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
		case *int:
			*d = r.values[i].(int)
		case *int64:
			*d = r.values[i].(int64)
		case *time.Time:
			*d = r.values[i].(time.Time)
		case *[]string:
			*d = r.values[i].([]string)
		case *[]byte:
			*d = r.values[i].([]byte)
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

func certificateRowValues(now time.Time, sans []string, status string, failureCode, failureMessage *string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		sans,
		string(KeyTypeECDSAP256),
		"32345678-1234-4234-9234-123456789abc",
		"letsencrypt_production",
		"22345678-1234-4234-9234-123456789abc",
		status,
		stringValue(failureCode),
		stringValue(failureMessage),
		nil,
		nil,
		nil,
		now,
		now,
		nil,
		int64(0),
	}
}

func certificateVersionRowValues(now time.Time, status, reason string, materialETag *string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		1,
		status,
		reason,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		stringValue(materialETag),
		nil,
		nil,
		nil,
		0,
		nil,
		nil,
		nil,
		now,
		now,
		now,
		nil,
		nil,
		nil,
		nil,
	}
}

func issuanceJobRowValues(now time.Time, status string, certificateVersionID, lockedBy *string) []any {
	var lockedUntil any
	if lockedBy != nil {
		lockedUntil = now.Add(time.Minute)
	}
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		stringValue(certificateVersionID),
		string(JobReasonInitialIssue),
		status,
		1,
		stringValue(lockedBy),
		lockedUntil,
		now,
		nil,
		nil,
		nil,
		nil,
		now,
		now,
	}
}

func dnsChallengeRowValues(now time.Time, status string, failureCode, failureMessage *string) []any {
	return []any{
		"12345678-1234-4234-9234-123456789abc",
		"22345678-1234-4234-9234-123456789abc",
		"32345678-1234-4234-9234-123456789abc",
		"42345678-1234-4234-9234-123456789abc",
		"52345678-1234-4234-9234-123456789abc",
		"62345678-1234-4234-9234-123456789abc",
		"api.example.com",
		"_acme-challenge.api.example.com",
		`{"version":"1"}`,
		status,
		now,
		nil,
		nil,
		stringValue(failureCode),
		stringValue(failureMessage),
		now,
		now,
	}
}

func stringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
