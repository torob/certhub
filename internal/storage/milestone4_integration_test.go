package storage_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/torob/certhub/internal/dnsproviders"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
)

func TestMilestone4RepositoriesWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping Milestone 4 repository integration test")
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

	issuerRepo := issuers.NewRepository(tx)
	issuer, err := issuerRepo.Create(ctx, issuers.CreateIssuerParams{
		Name:         "m4_issuer",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Environment:  issuers.EnvironmentStaging,
		ContactEmail: "M4.Issuer@Example.COM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.Update(ctx, issuer.ID, issuers.UpdateIssuerParams{
		Status: storage.SetString(string(issuers.StatusActive)),
	}); err == nil {
		t.Fatalf("activated issuer without active ACME account")
	}
	if _, err := issuerRepo.CreateACMEAccount(ctx, issuers.CreateACMEAccountParams{
		IssuerID:               issuer.ID,
		Email:                  "m4.issuer@example.com",
		AccountURL:             "https://acme-staging-v02.api.letsencrypt.org/acct/123",
		PrivateKeyPEMEncrypted: `{"version":"1"}`,
	}); err != nil {
		t.Fatal(err)
	}
	issuer, err = issuerRepo.Update(ctx, issuer.ID, issuers.UpdateIssuerParams{
		Status:    storage.SetString(string(issuers.StatusActive)),
		IsDefault: storage.SetBool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !issuer.IsDefault || issuer.Status != issuers.StatusActive || !issuer.ActiveACMEAccount {
		t.Fatalf("issuer = %#v", issuer)
	}

	dnsRepo := dnsproviders.NewRepository(tx)
	manual, err := dnsRepo.Create(ctx, dnsproviders.CreateProviderParams{
		Name:                 "m4_cloudflare",
		Type:                 dnsproviders.ProviderTypeCloudflare,
		CredentialsEncrypted: `{"version":"1"}`,
		ZoneMode:             dnsproviders.ZoneModeManual,
	})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := dnsRepo.AddZone(ctx, dnsproviders.AddZoneParams{
		DNSProviderID: manual.ID,
		ZoneName:      "Example.COM.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if zone.ZoneName != "example.com" {
		t.Fatalf("zone = %#v", zone)
	}
	match, err := dnsRepo.FindZoneForDNSName(ctx, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if match.Provider.ID != manual.ID || match.Zone.ZoneName != "example.com" {
		t.Fatalf("match = %#v", match)
	}

	autoProvider, err := dnsRepo.Create(ctx, dnsproviders.CreateProviderParams{
		Name:                 "m4_arvancloud",
		Type:                 dnsproviders.ProviderTypeArvanCloud,
		CredentialsEncrypted: `{"version":"1"}`,
		ZoneMode:             dnsproviders.ZoneModeAuto,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dnsRepo.AddZone(ctx, dnsproviders.AddZoneParams{
		DNSProviderID: autoProvider.ID,
		ZoneName:      "auto.example.net",
	}); err == nil {
		t.Fatalf("manual add succeeded for auto-mode provider")
	}
	job, err := dnsRepo.EnsureRefreshJob(ctx, dnsproviders.EnsureRefreshJobParams{DNSProviderID: autoProvider.ID})
	if err != nil {
		t.Fatal(err)
	}
	sameJob, err := dnsRepo.EnsureRefreshJob(ctx, dnsproviders.EnsureRefreshJobParams{DNSProviderID: autoProvider.ID})
	if err != nil {
		t.Fatal(err)
	}
	if sameJob.ID != job.ID {
		t.Fatalf("ensure refresh job was not idempotent: %s != %s", sameJob.ID, job.ID)
	}
	claimed, err := dnsRepo.ClaimNextRefreshJob(ctx, dnsproviders.ClaimRefreshJobParams{
		WorkerID:    "m4-test-worker",
		LockedUntil: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := dnsRepo.CompleteRefreshJobSuccess(ctx, dnsproviders.CompleteRefreshJobParams{
		JobID:         claimed.ID,
		DNSProviderID: autoProvider.ID,
		WorkerID:      "m4-test-worker",
		ZoneNames:     []string{"auto.example.net", "deep.auto.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != dnsproviders.RefreshJobStatusSucceeded || completed.DiscoveredZoneCount == nil || *completed.DiscoveredZoneCount != 2 {
		t.Fatalf("completed job = %#v", completed)
	}
	repeatJob, err := dnsRepo.EnsureRefreshJob(ctx, dnsproviders.EnsureRefreshJobParams{DNSProviderID: autoProvider.ID})
	if err != nil {
		t.Fatal(err)
	}
	claimedRepeat, err := dnsRepo.ClaimNextRefreshJob(ctx, dnsproviders.ClaimRefreshJobParams{
		WorkerID:    "m4-test-worker",
		LockedUntil: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimedRepeat.ID != repeatJob.ID {
		t.Fatalf("claimed repeat job = %#v want %s", claimedRepeat, repeatJob.ID)
	}
	repeated, err := dnsRepo.CompleteRefreshJobSuccess(ctx, dnsproviders.CompleteRefreshJobParams{
		JobID:         claimedRepeat.ID,
		DNSProviderID: autoProvider.ID,
		WorkerID:      "m4-test-worker",
		ZoneNames:     []string{"auto.example.net", "deep.auto.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Status != dnsproviders.RefreshJobStatusSucceeded || repeated.DiscoveredZoneCount == nil || *repeated.DiscoveredZoneCount != 2 {
		t.Fatalf("repeated job = %#v", repeated)
	}

	conflictJob, err := dnsRepo.EnsureRefreshJob(ctx, dnsproviders.EnsureRefreshJobParams{DNSProviderID: autoProvider.ID})
	if err != nil {
		t.Fatal(err)
	}
	claimedConflict, err := dnsRepo.ClaimNextRefreshJob(ctx, dnsproviders.ClaimRefreshJobParams{
		WorkerID:    "m4-test-worker",
		LockedUntil: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimedConflict.ID != conflictJob.ID {
		t.Fatalf("claimed job = %#v want %s", claimedConflict, conflictJob.ID)
	}
	failed, err := dnsRepo.CompleteRefreshJobSuccess(ctx, dnsproviders.CompleteRefreshJobParams{
		JobID:         claimedConflict.ID,
		DNSProviderID: autoProvider.ID,
		WorkerID:      "m4-test-worker",
		ZoneNames:     []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != dnsproviders.RefreshJobStatusFailed || failed.FailureCode == nil || *failed.FailureCode != dnsproviders.FailureCodeZoneConflict {
		t.Fatalf("conflict job = %#v", failed)
	}
	zones, err := dnsRepo.ListZones(ctx, autoProvider.ID, storage.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("auto zones were not preserved after conflict: %#v", zones)
	}
}
