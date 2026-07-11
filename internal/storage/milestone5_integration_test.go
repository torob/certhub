package storage_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/dnsproviders"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestMilestone5CertificateLifecycleRepositoryWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping Milestone 5 certificate lifecycle integration test")
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

	appRepo := applications.NewRepository(tx)
	app, err := appRepo.Create(ctx, applications.CreateApplicationParams{
		Name:        "m5_app",
		DisplayName: "M5 App",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appRepo.AddDomainScope(ctx, applications.AddDomainScopeParams{
		ApplicationID: app.ID,
		Value:         "*.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	issuerRepo := issuers.NewRepository(tx)
	issuer, err := issuerRepo.Create(ctx, issuers.CreateIssuerParams{
		Name:         "m5_issuer",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ContactEmail: "m5.issuer@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.CreateACMEAccount(ctx, issuers.CreateACMEAccountParams{
		IssuerID:               issuer.ID,
		Email:                  "m5.issuer@example.com",
		AccountURL:             "https://acme-staging-v02.api.letsencrypt.org/acct/m5",
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

	dnsRepo := dnsproviders.NewRepository(tx)
	provider, err := dnsRepo.Create(ctx, dnsproviders.CreateProviderParams{
		Name:                 "m5_cloudflare",
		Type:                 dnsproviders.ProviderTypeCloudflare,
		CredentialsEncrypted: `{"version":"1"}`,
		ZoneMode:             dnsproviders.ZoneModeManual,
	})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := dnsRepo.AddZone(ctx, dnsproviders.AddZoneParams{
		DNSProviderID: provider.ID,
		ZoneName:      "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	certRepo := certificates.NewRepository(tx)
	cert, err := certRepo.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
		ApplicationID:  app.ID,
		IssuerID:       issuer.ID,
		NormalizedSANs: []string{"WWW.Example.COM.", "api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sameCert, err := certRepo.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
		ApplicationID:  app.ID,
		IssuerID:       issuer.ID,
		NormalizedSANs: []string{"api.example.com", "www.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sameCert.ID != cert.ID {
		t.Fatalf("certificate identity was not reused: %s != %s", sameCert.ID, cert.ID)
	}
	total, err := certRepo.Count(ctx, certificates.ListCertificatesParams{ApplicationID: &app.ID})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("certificate count = %d", total)
	}

	version, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
		CertificateID: cert.ID,
		Reason:        certificates.IssuanceReasonInitialIssue,
	})
	if err != nil {
		t.Fatal(err)
	}
	sameVersion, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
		CertificateID: cert.ID,
		Reason:        certificates.IssuanceReasonInitialIssue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sameVersion.ID != version.ID {
		t.Fatalf("issuing version was not reused: %s != %s", sameVersion.ID, version.ID)
	}

	job, err := certRepo.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
		CertificateID:        cert.ID,
		CertificateVersionID: &version.ID,
		Reason:               certificates.JobReasonInitialIssue,
	})
	if err != nil {
		t.Fatal(err)
	}
	sameJob, err := certRepo.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
		CertificateID:        cert.ID,
		CertificateVersionID: &version.ID,
		Reason:               certificates.JobReasonInitialIssue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sameJob.ID != job.ID {
		t.Fatalf("issuance job was not reused: %s != %s", sameJob.ID, job.ID)
	}
	claimed, err := certRepo.ClaimNextIssuanceJob(ctx, certificates.ClaimIssuanceJobParams{
		WorkerID:    "m5-worker",
		LockedUntil: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != job.ID || claimed.Status != certificates.JobStatusRunning {
		t.Fatalf("claimed job = %#v", claimed)
	}

	challenge, err := certRepo.RecordDNSChallenge(ctx, certificates.RecordDNSChallengeParams{
		IssuanceJobID:           claimed.ID,
		CertificateID:           cert.ID,
		CertificateVersionID:    version.ID,
		DNSProviderID:           provider.ID,
		DNSProviderZoneID:       zone.ID,
		AuthorizationIdentifier: "api.example.com",
		RecordName:              "_acme-challenge.api.example.com",
		TXTValueEncrypted:       `{"version":"1","kind":"txt"}`,
		Status:                  certificates.DNSChallengeStatusValidated,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certRepo.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{
		ID:     challenge.ID,
		Status: certificates.DNSChallengeStatusCleanupPending,
	}); err != nil {
		t.Fatal(err)
	}
	cleaned, err := certRepo.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{
		ID:     challenge.ID,
		Status: certificates.DNSChallengeStatusCleaned,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleaned.CleanedAt == nil {
		t.Fatalf("cleaned challenge missing cleaned_at: %#v", cleaned)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	stored, err := certRepo.StoreMaterial(ctx, certificates.StoreMaterialParams{
		CertificateVersionID:   version.ID,
		CertPEM:                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
		ChainPEM:               "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
		FullchainPEM:           "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
		PrivateKeyPEMEncrypted: `{"version":"1","kind":"private-key"}`,
		NotBefore:              notBefore,
		NotAfter:               notAfter,
		SerialNumber:           "01",
		FingerprintSHA256:      "1111111111111111111111111111111111111111111111111111111111111111",
		KeyFingerprintSHA256:   "2222222222222222222222222222222222222222222222222222222222222222",
		MaterialETag:           `"cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != certificates.VersionStatusValid || stored.MaterialETag == nil {
		t.Fatalf("stored material = %#v", stored)
	}
	latest, err := certRepo.GetLatestValidMaterial(ctx, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != version.ID || latest.PrivateKeyPEMEncrypted == nil {
		t.Fatalf("latest material = %#v", latest)
	}
	succeeded, err := certRepo.SucceedIssuanceJob(ctx, certificates.SucceedIssuanceJobParams{
		JobID:    claimed.ID,
		WorkerID: "m5-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if succeeded.Status != certificates.JobStatusSucceeded {
		t.Fatalf("succeeded job = %#v", succeeded)
	}

	renewalVersion, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
		CertificateID: cert.ID,
		Reason:        certificates.IssuanceReasonRenewal,
	})
	if err != nil {
		t.Fatal(err)
	}
	renewalJob, err := certRepo.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
		CertificateID:        cert.ID,
		CertificateVersionID: &renewalVersion.ID,
		Reason:               certificates.JobReasonRenewal,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimedRenewal, err := certRepo.ClaimNextIssuanceJob(ctx, certificates.ClaimIssuanceJobParams{
		WorkerID:    "m5-worker",
		LockedUntil: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimedRenewal.ID != renewalJob.ID {
		t.Fatalf("claimed renewal job = %#v want %s", claimedRenewal, renewalJob.ID)
	}
	renewalFailure := "renewal dns validation failed"
	if _, err := certRepo.FailIssuanceJob(ctx, certificates.FailIssuanceJobParams{
		JobID:          claimedRenewal.ID,
		WorkerID:       "m5-worker",
		FailureCode:    "dns_validation_failed",
		FailureMessage: &renewalFailure,
	}); err != nil {
		t.Fatal(err)
	}
	readyAfterRenewalFailure, err := certRepo.Get(ctx, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if readyAfterRenewalFailure.Status != certificates.StatusReady || readyAfterRenewalFailure.FailureCode != nil || readyAfterRenewalFailure.FailureMessage != nil {
		t.Fatalf("parent certificate after renewal failure = %#v", readyAfterRenewalFailure)
	}

	event, err := certRepo.RecordEvent(ctx, certificates.RecordEventParams{
		CertificateID:        cert.ID,
		CertificateVersionID: &version.ID,
		IssuanceJobID:        &claimed.ID,
		EventType:            "certificate_issuance_succeeded",
		Metadata:             []byte(`{"version":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := certRepo.ListEvents(ctx, certificates.ListEventsParams{CertificateID: cert.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %#v", events)
	}

	failedCert, err := certRepo.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
		ApplicationID:  app.ID,
		IssuerID:       issuer.ID,
		NormalizedSANs: []string{"fail.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	failedVersion, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
		CertificateID: failedCert.ID,
		Reason:        certificates.IssuanceReasonInitialIssue,
	})
	if err != nil {
		t.Fatal(err)
	}
	failedJob, err := certRepo.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
		CertificateID:        failedCert.ID,
		CertificateVersionID: &failedVersion.ID,
		Reason:               certificates.JobReasonInitialIssue,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimedFailed, err := certRepo.ClaimNextIssuanceJob(ctx, certificates.ClaimIssuanceJobParams{
		WorkerID:    "m5-worker",
		LockedUntil: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimedFailed.ID != failedJob.ID {
		t.Fatalf("claimed failed job = %#v want %s", claimedFailed, failedJob.ID)
	}
	failureMessage := "dns validation failed: provider rejected challenge"
	failedJob, err = certRepo.FailIssuanceJob(ctx, certificates.FailIssuanceJobParams{
		JobID:          claimedFailed.ID,
		WorkerID:       "m5-worker",
		FailureCode:    "dns_validation_failed",
		FailureMessage: &failureMessage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if failedJob.Status != certificates.JobStatusFailed || failedJob.FailureCode == nil || *failedJob.FailureCode != "dns_validation_failed" || failedJob.FailureMessage == nil || *failedJob.FailureMessage != failureMessage {
		t.Fatalf("failed job = %#v", failedJob)
	}
	failedVersion, err = certRepo.GetVersion(ctx, failedVersion.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failedVersion.Status != certificates.VersionStatusFailed || failedVersion.FailureCode == nil || *failedVersion.FailureCode != "dns_validation_failed" || failedVersion.FailureMessage == nil || *failedVersion.FailureMessage != failureMessage {
		t.Fatalf("failed version = %#v", failedVersion)
	}
	failedCert, err = certRepo.Get(ctx, failedCert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failedCert.Status != certificates.StatusFailed || failedCert.FailureCode == nil || *failedCert.FailureCode != "dns_validation_failed" || failedCert.FailureMessage == nil || *failedCert.FailureMessage != failureMessage {
		t.Fatalf("failed certificate = %#v", failedCert)
	}

	auditRepo := audit.NewRepository(tx)
	preDeleteAudit, err := auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:       audit.IdentityTypeSystem,
		Action:             "fixture_created",
		TargetType:         "certificate",
		TargetID:           &cert.ID,
		ScopeApplicationID: &app.ID,
		ScopeCertificateID: &cert.ID,
		Result:             audit.ResultSuccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	certService := certificates.NewService(certificates.ServiceConfig{
		Repository:        certRepo,
		ApplicationReader: appRepo,
		IssuerReader:      issuerRepo,
		AuditRepository:   auditRepo,
	})
	adminID := "80000000-0000-4000-8000-000000000001"
	if err := certService.DeleteCertificate(ctx, certificates.Actor{ID: adminID, GlobalRole: users.GlobalRoleAdmin}, cert.ID, true, &certificates.AuditContext{CorrelationID: "m5-hard-delete"}); err != nil {
		t.Fatalf("hard delete certificate: %v", err)
	}
	var certificatesRemaining, versionsRemaining, jobsRemaining, challengesRemaining, eventsRemaining int
	if err := tx.QueryRow(ctx, `
select
  (select count(*) from certificates where id = $1),
  (select count(*) from certificate_versions where certificate_id = $1),
  (select count(*) from certificate_issuance_jobs where certificate_id = $1),
  (select count(*) from dns_challenge_records where certificate_id = $1),
  (select count(*) from certificate_events where certificate_id = $1)`, cert.ID).Scan(
		&certificatesRemaining,
		&versionsRemaining,
		&jobsRemaining,
		&challengesRemaining,
		&eventsRemaining,
	); err != nil {
		t.Fatal(err)
	}
	if certificatesRemaining != 0 || versionsRemaining != 0 || jobsRemaining != 0 || challengesRemaining != 0 || eventsRemaining != 0 {
		t.Fatalf("hard delete leftovers certificate=%d versions=%d jobs=%d challenges=%d events=%d", certificatesRemaining, versionsRemaining, jobsRemaining, challengesRemaining, eventsRemaining)
	}
	var retainedCertificateScope string
	if err := tx.QueryRow(ctx, `select scope_certificate_id::text from audit_events where id = $1`, preDeleteAudit.ID).Scan(&retainedCertificateScope); err != nil {
		t.Fatal(err)
	}
	if retainedCertificateScope != cert.ID {
		t.Fatalf("retained audit certificate scope = %s, want %s", retainedCertificateScope, cert.ID)
	}
	var deletionAudits int
	if err := tx.QueryRow(ctx, `
select count(*)
from audit_events
where action = 'certificate_deleted'
  and identity_id = $1
  and scope_application_id = $2
  and scope_certificate_id is null
  and metadata->>'certificate_id' = $3`, adminID, app.ID, cert.ID).Scan(&deletionAudits); err != nil {
		t.Fatal(err)
	}
	if deletionAudits != 1 {
		t.Fatalf("certificate deletion audits = %d", deletionAudits)
	}
	if _, err := certRepo.RecordEvent(ctx, certificates.RecordEventParams{
		CertificateID:        failedCert.ID,
		CertificateVersionID: &failedVersion.ID,
		IssuanceJobID:        &failedJob.ID,
		EventType:            "fixture_failed",
		Result:               certificates.EventResultFailure,
	}); err != nil {
		t.Fatal(err)
	}
	if err := certService.DeleteCertificate(ctx, certificates.Actor{ID: adminID, GlobalRole: users.GlobalRoleAdmin}, failedCert.ID, false, nil); err != nil {
		t.Fatalf("normal hard delete failed certificate: %v", err)
	}
	if err := tx.QueryRow(ctx, `select count(*) from certificates where id = $1`, failedCert.ID).Scan(&certificatesRemaining); err != nil {
		t.Fatal(err)
	}
	if certificatesRemaining != 0 {
		t.Fatalf("normally deleted certificate remains = %d", certificatesRemaining)
	}
	if err := tx.QueryRow(ctx, `
select count(*)
from audit_events
where action = 'certificate_deleted'
  and identity_id = $1
  and metadata->>'certificate_id' = $2
  and metadata->>'force' = 'false'`, adminID, failedCert.ID).Scan(&deletionAudits); err != nil {
		t.Fatal(err)
	}
	if deletionAudits != 1 {
		t.Fatalf("normal certificate deletion audits = %d", deletionAudits)
	}
}
