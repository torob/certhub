package storage_test

import (
	"context"
	"errors"
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
	"github.com/torob/certhub/internal/users"
)

func TestRevokeCertificateVersionParentStatusWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping certificate revoke parent status integration test")
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

	user, err := users.NewRepository(tx).Create(ctx, users.CreateUserParams{
		Email:       "revoke.parent@example.com",
		DisplayName: "Revoke Parent User",
		GlobalRole:  users.GlobalRoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	app, err := applications.NewRepository(tx).Create(ctx, applications.CreateApplicationParams{
		Name:        "revoke_parent_app",
		DisplayName: "Revoke Parent App",
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerRepo := issuers.NewRepository(tx)
	issuer, err := issuerRepo.Create(ctx, issuers.CreateIssuerParams{
		Name:         "revoke_parent_issuer",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ContactEmail: "revoke.parent@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	certRepo := certificates.NewRepository(tx)
	etagSeq := 0
	issueValidVersion := func(t *testing.T, certificateID string, reason certificates.IssuanceReason) certificates.CertificateVersion {
		t.Helper()
		version, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
			CertificateID: certificateID,
			Reason:        reason,
		})
		if err != nil {
			t.Fatal(err)
		}
		etagSeq++
		suffix := fmt.Sprintf("%043d", etagSeq)
		stored, err := certRepo.StoreMaterial(ctx, certificates.StoreMaterialParams{
			CertificateVersionID:   version.ID,
			CertPEM:                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
			ChainPEM:               "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
			FullchainPEM:           "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
			PrivateKeyPEMEncrypted: `{"version":"1","kind":"private-key"}`,
			NotBefore:              time.Now().Add(-time.Hour),
			NotAfter:               time.Now().Add(90 * 24 * time.Hour),
			SerialNumber:           fmt.Sprintf("%02x", etagSeq),
			FingerprintSHA256:      strings.Repeat("1", 64),
			KeyFingerprintSHA256:   strings.Repeat("2", 64),
			MaterialETag:           `"cth-mat-v1.` + suffix + `"`,
		})
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status != certificates.VersionStatusValid {
			t.Fatalf("stored version = %#v", stored)
		}
		return stored
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
	revoke := func(t *testing.T, certificateID, versionID string) {
		t.Helper()
		revoked, _, err := certRepo.RevokeCertificateVersion(ctx, certificates.RevokeCertificateVersionParams{
			CertificateID:        certificateID,
			CertificateVersionID: versionID,
			Reason:               certificates.RevocationReasonKeyCompromise,
			RevokedByUserID:      user.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if revoked.Status != certificates.VersionStatusRevoked {
			t.Fatalf("revoked version = %#v", revoked)
		}
	}

	t.Run("only usable version revoked sets parent revoked", func(t *testing.T) {
		cert := newCertificate(t, "only.revoke.example.com")
		version := issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue)

		revoke(t, cert.ID, version.ID)

		parent, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if parent.Status != certificates.StatusRevoked {
			t.Fatalf("parent status after revoking only usable version = %q, want %q", parent.Status, certificates.StatusRevoked)
		}
		if parent.RevocationReason == nil || *parent.RevocationReason != certificates.RevocationReasonKeyCompromise || parent.RevokedAt == nil || parent.RevokedByUserID == nil || *parent.RevokedByUserID != user.ID {
			t.Fatalf("parent revocation metadata = reason %v at %v by %v", parent.RevocationReason, parent.RevokedAt, parent.RevokedByUserID)
		}
		if _, err := certRepo.GetLatestValidMaterial(ctx, cert.ID); !errors.Is(err, storage.ErrNoRows) {
			t.Fatalf("latest valid material after revoke err = %v, want no rows", err)
		}

		// Repeating the revoke keeps the parent revoked and its original metadata.
		revoke(t, cert.ID, version.ID)
		repeated, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if repeated.Status != certificates.StatusRevoked || repeated.RevokedAt == nil || !repeated.RevokedAt.Equal(*parent.RevokedAt) {
			t.Fatalf("parent after repeated revoke = %#v", repeated)
		}

		// Reissue from the revoked parent clears parent revocation metadata.
		reissued := issueValidVersion(t, cert.ID, certificates.IssuanceReasonReissue)
		afterReissue, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if afterReissue.Status != certificates.StatusReady || afterReissue.RevocationReason != nil || afterReissue.RevokedAt != nil || afterReissue.RevokedByUserID != nil {
			t.Fatalf("parent after reissue = %#v", afterReissue)
		}
		latest, err := certRepo.GetLatestValidMaterial(ctx, cert.ID)
		if err != nil || latest.ID != reissued.ID {
			t.Fatalf("latest valid material after reissue = %#v, %v", latest, err)
		}
	})

	t.Run("ready parent stays ready when another usable version remains", func(t *testing.T) {
		cert := newCertificate(t, "keep.revoke.example.com")
		older := issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue)
		newer := issueValidVersion(t, cert.ID, certificates.IssuanceReasonRenewal)

		revoke(t, cert.ID, newer.ID)

		parent, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if parent.Status != certificates.StatusReady || parent.RevocationReason != nil || parent.RevokedAt != nil || parent.RevokedByUserID != nil {
			t.Fatalf("parent after revoking newer version = %#v", parent)
		}
		latest, err := certRepo.GetLatestValidMaterial(ctx, cert.ID)
		if err != nil || latest.ID != older.ID {
			t.Fatalf("latest valid material = %#v, %v; want version %s", latest, err, older.ID)
		}
	})

	t.Run("failed parent without other usable version becomes revoked", func(t *testing.T) {
		cert := newCertificate(t, "failed.revoke.example.com")
		version := issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue)
		if _, err := tx.Exec(ctx, `update certificates set status = 'failed', failure_code = 'dns_validation_failed', failure_message = 'fixture' where id = $1`, cert.ID); err != nil {
			t.Fatal(err)
		}

		revoke(t, cert.ID, version.ID)

		parent, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if parent.Status != certificates.StatusRevoked || parent.FailureCode != nil || parent.FailureMessage != nil || parent.RevokedAt == nil {
			t.Fatalf("failed parent after revoke = %#v", parent)
		}
	})

	t.Run("in-progress parent status is preserved", func(t *testing.T) {
		cert := newCertificate(t, "renewing.revoke.example.com")
		active := issueValidVersion(t, cert.ID, certificates.IssuanceReasonInitialIssue)
		if _, err := certRepo.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
			CertificateID: cert.ID,
			Reason:        certificates.IssuanceReasonRenewal,
		}); err != nil {
			t.Fatal(err)
		}
		renewing, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if renewing.Status != certificates.StatusRenewing {
			t.Fatalf("parent status before revoke = %q, want %q", renewing.Status, certificates.StatusRenewing)
		}

		revoke(t, cert.ID, active.ID)

		parent, err := certRepo.Get(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if parent.Status != certificates.StatusRenewing || parent.RevocationReason != nil || parent.RevokedAt != nil {
			t.Fatalf("parent after revoking active version during renewal = status %q reason %v at %v, want %q without revocation metadata", parent.Status, parent.RevocationReason, parent.RevokedAt, certificates.StatusRenewing)
		}
		// The issuance worker can still report progress for the in-progress parent.
		updated, err := certRepo.UpdateCertificateIssuanceStatus(ctx, certificates.UpdateCertificateIssuanceStatusParams{
			CertificateID: cert.ID,
			Status:        certificates.StatusValidatingDNS,
		})
		if err != nil {
			t.Fatalf("update issuance status after revoke: %v", err)
		}
		if updated.Status != certificates.StatusValidatingDNS {
			t.Fatalf("parent after issuance status update = %q", updated.Status)
		}
	})
}
