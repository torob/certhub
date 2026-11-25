package storage_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/dnsproviders"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
)

func TestDNSZoneRefreshKeepsChallengeReferencedZonesWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping DNS zone refresh integration test")
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

	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := dnsproviders.NewRepository(tx)
	lister := &zoneRefreshFakeLister{}
	service := dnsproviders.NewService(dnsproviders.ServiceConfig{
		Repository:  statementScopedDNSStore{Store: repo, tx: tx},
		KeySet:      keys,
		ZoneListers: dnsproviders.ZoneListerRegistry{dnsproviders.ProviderTypeCloudflare: lister},
	})
	createProvider := func(t *testing.T, id, name string) dnsproviders.Provider {
		t.Helper()
		credentials, err := keys.SealDatabaseValue([]byte(`{"api_token":"zone-refresh-fixture-token"}`), "v1:table=dns_providers:column=credentials_encrypted:row_id="+id)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := repo.Create(ctx, dnsproviders.CreateProviderParams{
			ID:                   id,
			Name:                 name,
			Type:                 dnsproviders.ProviderTypeCloudflare,
			CredentialsEncrypted: credentials,
			ZoneMode:             dnsproviders.ZoneModeAuto,
		})
		if err != nil {
			t.Fatal(err)
		}
		return provider
	}
	runRefresh := func(t *testing.T, providerID string, zones []string) (dnsproviders.RefreshJob, error) {
		t.Helper()
		queued, err := repo.EnsureRefreshJob(ctx, dnsproviders.EnsureRefreshJobParams{DNSProviderID: providerID})
		if err != nil {
			t.Fatal(err)
		}
		lister.zones = zones
		_, processed, runErr := service.CompleteNextRefreshJob(ctx, "zone-refresh-test-worker")
		if !processed {
			t.Fatalf("refresh job %s was not processed: %v", queued.ID, runErr)
		}
		stored, err := repo.GetRefreshJob(ctx, queued.ID)
		if err != nil {
			t.Fatal(err)
		}
		return stored, runErr
	}
	zoneNames := func(t *testing.T, providerID string) map[string]string {
		t.Helper()
		zones, err := repo.ListZones(ctx, providerID, storage.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, zone := range zones {
			out[zone.ZoneName] = zone.ID
		}
		return out
	}

	t.Run("zone referenced by a challenge record is kept and new zones are added", func(t *testing.T) {
		provider := createProvider(t, "3a000000-0000-4000-8000-000000000001", "zone_refresh_fk_dns")
		initial, err := runRefresh(t, provider.ID, []string{"used.example.org", "unused.example.org"})
		if err != nil || initial.Status != dnsproviders.RefreshJobStatusSucceeded {
			t.Fatalf("initial refresh job = %#v err = %v", initial, err)
		}
		usedZoneID := zoneNames(t, provider.ID)["used.example.org"]
		if usedZoneID == "" {
			t.Fatalf("initial zones = %#v", zoneNames(t, provider.ID))
		}
		seedZoneRefreshChallengeRecord(t, ctx, tx, provider.ID, usedZoneID)

		refreshed, err := runRefresh(t, provider.ID, []string{"new.example.org"})
		if err != nil {
			t.Fatalf("refresh without referenced zone returned error: %v (job status %s)", err, refreshed.Status)
		}
		if refreshed.Status != dnsproviders.RefreshJobStatusSucceeded || refreshed.DiscoveredZoneCount == nil || *refreshed.DiscoveredZoneCount != 1 {
			t.Fatalf("refresh job = %#v", refreshed)
		}
		zones := zoneNames(t, provider.ID)
		if zones["used.example.org"] != usedZoneID {
			t.Fatalf("challenge-referenced zone was not kept with the same id: %#v", zones)
		}
		if _, ok := zones["new.example.org"]; !ok {
			t.Fatalf("newly discovered zone was not added: %#v", zones)
		}
		if _, ok := zones["unused.example.org"]; ok || len(zones) != 2 {
			t.Fatalf("unreferenced stale zone was not removed: %#v", zones)
		}
		stored, err := repo.Get(ctx, provider.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.ZoneRefreshStatus != "succeeded" || stored.ZoneRefreshFailureCode != nil {
			t.Fatalf("provider refresh state = %s %v", stored.ZoneRefreshStatus, stored.ZoneRefreshFailureCode)
		}
	})

	t.Run("refresh that cannot be applied marks the job failed", func(t *testing.T) {
		provider := createProvider(t, "3a000000-0000-4000-8000-000000000002", "zone_refresh_fail_dns")
		initial, err := runRefresh(t, provider.ID, []string{"kept.example.org"})
		if err != nil || initial.Status != dnsproviders.RefreshJobStatusSucceeded {
			t.Fatalf("initial refresh job = %#v err = %v", initial, err)
		}

		failed, err := runRefresh(t, provider.ID, []string{"kept.example.org", "invalid_zone!"})
		if err != nil {
			t.Fatalf("failed refresh returned error instead of a failed job: %v (job status %s)", err, failed.Status)
		}
		if failed.Status != dnsproviders.RefreshJobStatusFailed || failed.FailureCode == nil || *failed.FailureCode != dnsproviders.FailureCodeZoneRefreshFailed {
			t.Fatalf("refresh job = %#v", failed)
		}
		if failed.LockedBy != nil || failed.LockedUntil != nil || failed.CompletedAt == nil {
			t.Fatalf("failed refresh job still holds a lease: %#v", failed)
		}
		stored, err := repo.Get(ctx, provider.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.ZoneRefreshStatus != "failed" || stored.ZoneRefreshFailureCode == nil || *stored.ZoneRefreshFailureCode != dnsproviders.FailureCodeZoneRefreshFailed {
			t.Fatalf("provider refresh state = %s %v", stored.ZoneRefreshStatus, stored.ZoneRefreshFailureCode)
		}
		if zones := zoneNames(t, provider.ID); len(zones) != 1 || zones["kept.example.org"] == "" {
			t.Fatalf("zones were not preserved after failed refresh: %#v", zones)
		}
	})
}

type zoneRefreshFakeLister struct {
	zones []string
}

func (l *zoneRefreshFakeLister) ListZones(context.Context, json.RawMessage) ([]string, error) {
	return append([]string(nil), l.zones...), nil
}

// statementScopedDNSStore runs the refresh completion statement inside a
// savepoint, so a failed statement behaves like an autocommit statement on the
// production pool and does not abort the surrounding test transaction.
type statementScopedDNSStore struct {
	dnsproviders.Store
	tx storage.Tx
}

func (s statementScopedDNSStore) CompleteRefreshJobSuccess(ctx context.Context, params dnsproviders.CompleteRefreshJobParams) (dnsproviders.RefreshJob, error) {
	if _, err := s.tx.Exec(ctx, `savepoint zone_refresh_complete`); err != nil {
		return dnsproviders.RefreshJob{}, err
	}
	job, err := s.Store.CompleteRefreshJobSuccess(ctx, params)
	if err != nil {
		if _, rollbackErr := s.tx.Exec(ctx, `rollback to savepoint zone_refresh_complete`); rollbackErr != nil {
			return dnsproviders.RefreshJob{}, rollbackErr
		}
		return dnsproviders.RefreshJob{}, err
	}
	if _, err := s.tx.Exec(ctx, `release savepoint zone_refresh_complete`); err != nil {
		return dnsproviders.RefreshJob{}, err
	}
	return job, nil
}

func seedZoneRefreshChallengeRecord(t *testing.T, ctx context.Context, db storage.DBTX, providerID, zoneID string) {
	t.Helper()
	issuerID := "3b000000-0000-4000-8000-000000000001"
	appID := "3c000000-0000-4000-8000-000000000001"
	certID := "3d000000-0000-4000-8000-000000000001"
	versionID := "3e000000-0000-4000-8000-000000000001"
	jobID := "3f000000-0000-4000-8000-000000000001"
	mustExecApplicationDelete(t, ctx, db, `
insert into issuers (id, name, directory_url, status, contact_email)
values ($1, 'zone_refresh_fk_issuer', 'https://acme.invalid/directory', 'disabled', 'zone.refresh@example.com')`, issuerID)
	mustExecApplicationDelete(t, ctx, db, `insert into applications (id, name, display_name) values ($1, 'zone_refresh_fk_app', 'Zone Refresh FK')`, appID)
	mustExecApplicationDelete(t, ctx, db, `
insert into certificates (id, normalized_sans, key_type, issuer_id, application_id, status, failure_code)
values ($1, array['www.used.example.org'], 'ecdsa-p256', $2, $3, 'failed', 'fixture_failed')`, certID, issuerID, appID)
	mustExecApplicationDelete(t, ctx, db, `
insert into certificate_versions (id, certificate_id, version, status, reason, started_at, completed_at, failure_code)
values ($1, $2, 1, 'failed', 'initial_issue', now(), now(), 'fixture_failed')`, versionID, certID)
	mustExecApplicationDelete(t, ctx, db, `
insert into certificate_issuance_jobs (id, certificate_id, certificate_version_id, reason, status, completed_at)
values ($1, $2, $3, 'initial_issue', 'succeeded', now())`, jobID, certID, versionID)
	mustExecApplicationDelete(t, ctx, db, `
insert into dns_challenge_records (
    id, issuance_job_id, certificate_id, certificate_version_id, dns_provider_id, dns_provider_zone_id,
    authorization_identifier, record_name, txt_value_encrypted, status, presented_at, validated_at, cleaned_at
) values (
    '3a100000-0000-4000-8000-000000000001', $1, $2, $3, $4, $5,
    'www.used.example.org', '_acme-challenge.www.used.example.org', '{"fixture":true}', 'cleaned', now(), now(), now()
)`, jobID, certID, versionID, providerID, zoneID)
}
