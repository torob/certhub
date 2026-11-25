package storage_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
)

func TestListRenewalCandidatesRespectsOverlapAndFailureBackoffWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping renewal candidate integration test")
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

	app, err := applications.NewRepository(tx).Create(ctx, applications.CreateApplicationParams{
		Name:        "renewal_candidates_app",
		DisplayName: "Renewal Candidates App",
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerRepo := issuers.NewRepository(tx)
	issuer, err := issuerRepo.Create(ctx, issuers.CreateIssuerParams{
		Name:         "renewal_candidates_issuer",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ContactEmail: "renewal.candidates@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.CreateACMEAccount(ctx, issuers.CreateACMEAccountParams{
		IssuerID:               issuer.ID,
		Email:                  "renewal.candidates@example.com",
		AccountURL:             "https://acme-staging-v02.api.letsencrypt.org/acct/renewal-candidates",
		PrivateKeyPEMEncrypted: `{"version":"1"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.Update(ctx, issuer.ID, issuers.UpdateIssuerParams{
		Status: storage.SetString(string(issuers.StatusActive)),
	}); err != nil {
		t.Fatal(err)
	}

	certRepo := certificates.NewRepository(tx)
	etagSeq := 0
	issueValidVersion := func(t *testing.T, certificateID string, reason certificates.IssuanceReason, notAfter time.Time) certificates.CertificateVersion {
		t.Helper()
		version, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
			CertificateID: certificateID,
			Reason:        reason,
		})
		if err != nil {
			t.Fatal(err)
		}
		etagSeq++
		stored, err := certRepo.StoreMaterial(ctx, certificates.StoreMaterialParams{
			CertificateVersionID:   version.ID,
			CertPEM:                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
			ChainPEM:               "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
			FullchainPEM:           "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
			PrivateKeyPEMEncrypted: `{"version":"1","kind":"private-key"}`,
			NotBefore:              time.Now().Add(-time.Hour),
			NotAfter:               notAfter,
			SerialNumber:           fmt.Sprintf("%02x", etagSeq),
			FingerprintSHA256:      strings.Repeat("1", 64),
			KeyFingerprintSHA256:   strings.Repeat("2", 64),
			MaterialETag:           `"cth-mat-v1.` + fmt.Sprintf("%043d", etagSeq) + `"`,
		})
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status != certificates.VersionStatusValid {
			t.Fatalf("stored version = %#v", stored)
		}
		return stored
	}
	failRenewalVersion := func(t *testing.T, certificateID string, completedAgo time.Duration) {
		t.Helper()
		version, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
			CertificateID: certificateID,
			Reason:        certificates.IssuanceReasonRenewal,
		})
		if err != nil {
			t.Fatal(err)
		}
		if version.Reason != certificates.IssuanceReasonRenewal || version.Status != certificates.VersionStatusIssuing {
			t.Fatalf("renewal version = %#v", version)
		}
		if _, err := tx.Exec(ctx, `
update certificate_versions
set status = 'failed',
    failure_code = 'acme_order_failed',
    failure_message = 'fixture',
    completed_at = now() - ($2 * interval '1 second'),
    updated_at = now()
where id = $1`, version.ID, int64(completedAgo/time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	newCertificate := func(t *testing.T, san string) certificates.Certificate {
		t.Helper()
		cert, err := certRepo.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
			ApplicationID:  app.ID,
			IssuerID:       issuer.ID,
			NormalizedSANs: []string{san},
		})
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	isCandidate := func(t *testing.T, certificateID string) bool {
		t.Helper()
		candidates, err := certRepo.ListRenewalCandidates(ctx, storage.MaxListLimit)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range candidates {
			if candidate.CertificateID == certificateID {
				return true
			}
		}
		return false
	}

	t.Run("single valid version inside window is a candidate", func(t *testing.T) {
		cert := newCertificate(t, "single.renewal.example.com")
		issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue, time.Now().Add(10*24*time.Hour))
		if !isCandidate(t, cert.ID) {
			t.Fatal("certificate with one valid version inside the renewal window is not a renewal candidate")
		}
	})

	t.Run("two active valid versions are not a candidate", func(t *testing.T) {
		cert := newCertificate(t, "overlap.renewal.example.com")
		issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue, time.Now().Add(5*24*time.Hour))
		issueValidVersion(t, cert.ID, certificates.IssuanceReasonKeyRotation, time.Now().Add(10*24*time.Hour))
		if isCandidate(t, cert.ID) {
			t.Fatal("certificate with two active valid versions is a renewal candidate; the renewal would exceed the overlap limit")
		}
	})

	t.Run("expired older version does not block renewal", func(t *testing.T) {
		cert := newCertificate(t, "expired-older.renewal.example.com")
		older := issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue, time.Now().Add(5*24*time.Hour))
		issueValidVersion(t, cert.ID, certificates.IssuanceReasonKeyRotation, time.Now().Add(10*24*time.Hour))
		if _, err := tx.Exec(ctx, `update certificate_versions set not_before = now() - interval '90 days', not_after = now() - interval '1 hour' where id = $1`, older.ID); err != nil {
			t.Fatal(err)
		}
		if !isCandidate(t, cert.ID) {
			t.Fatal("certificate whose older valid version expired is not a renewal candidate")
		}
	})

	t.Run("recent failed renewal backs off", func(t *testing.T) {
		cert := newCertificate(t, "recent-failure.renewal.example.com")
		issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue, time.Now().Add(10*24*time.Hour))
		failRenewalVersion(t, cert.ID, 10*time.Minute)
		if isCandidate(t, cert.ID) {
			t.Fatalf("certificate with a renewal failed 10 minutes ago is a renewal candidate; want backoff of %s", certificates.RenewalFailureBackoff)
		}
	})

	t.Run("failed renewal older than backoff is a candidate", func(t *testing.T) {
		cert := newCertificate(t, "old-failure.renewal.example.com")
		issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue, time.Now().Add(10*24*time.Hour))
		failRenewalVersion(t, cert.ID, certificates.RenewalFailureBackoff+time.Minute)
		if !isCandidate(t, cert.ID) {
			t.Fatal("certificate whose last renewal failed before the backoff window is not a renewal candidate")
		}
	})
}
