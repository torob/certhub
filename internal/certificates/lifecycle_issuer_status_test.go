package certificates

import (
	"context"
	"errors"
	"testing"
	"time"

	issuerdomain "github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

// disableFixtureIssuer makes the Certificate's issuer disabled. The issuer
// keeps its ACME account, so only the status stops issuance.
func disableFixtureIssuer(fixture lifecycleServiceFixture) {
	issuers := fixture.service.issuers.(lifecycleIssuers)
	issuers.issuer.Status = issuerdomain.StatusDisabled
	fixture.service.issuers = issuers
}

func TestStartLifecycleWithDisabledIssuerIsRejected(t *testing.T) {
	renewalDue := time.Now().UTC().Add(10 * 24 * time.Hour)
	cases := []struct {
		name   string
		reason IssuanceReason
		setup  func(lifecycleServiceFixture)
	}{
		{
			name:   "renewal inside the window",
			reason: IssuanceReasonRenewal,
			setup: func(f lifecycleServiceFixture) {
				f.store.material = validMaterialVersion(renewalDue)
				f.store.versions = []CertificateVersion{f.store.material}
			},
		},
		{
			name:   "renewal with an issuing renewal version",
			reason: IssuanceReasonRenewal,
			setup: func(f lifecycleServiceFixture) {
				f.store.material = validMaterialVersion(renewalDue)
				issuing := CertificateVersion{ID: "62345678-1234-4234-9234-123456789abc", CertificateID: f.store.cert.ID, Version: 3, Status: VersionStatusIssuing, Reason: IssuanceReasonRenewal}
				f.store.versions = []CertificateVersion{issuing, f.store.material}
			},
		},
		{
			name:   "key rotation",
			reason: IssuanceReasonKeyRotation,
			setup: func(f lifecycleServiceFixture) {
				f.store.material = validMaterialVersion(time.Now().UTC().Add(60 * 24 * time.Hour))
				f.store.versions = []CertificateVersion{f.store.material}
			},
		},
		{
			name:   "reissue",
			reason: IssuanceReasonReissue,
			setup: func(f lifecycleServiceFixture) {
				f.store.materialErr = storage.ErrNoRows
				f.store.cert.Status = StatusExpired
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newLifecycleServiceFixture()
			tc.setup(fixture)
			disableFixtureIssuer(fixture)

			_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, tc.reason, AuditContext{})
			if !errors.Is(err, ErrIssuerDisabled) {
				t.Fatalf("err = %v, want ErrIssuerDisabled", err)
			}
			if fixture.store.createVersionCalls != 0 || len(fixture.store.ensureJobCalls) != 0 {
				t.Fatalf("disabled issuer started work: versions=%d jobs=%#v", fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
			}
			if len(fixture.audit.events) != 0 {
				t.Fatalf("rejected lifecycle wrote audit events: %#v", fixture.audit.events)
			}
		})
	}
}

func TestStartLifecycleWithActiveIssuerStillStarts(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.materialErr = storage.ErrNoRows
	fixture.store.cert.Status = StatusExpired

	version, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonReissue, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if version.Reason != IssuanceReasonReissue || fixture.store.createVersionCalls != 1 || len(fixture.store.ensureJobCalls) != 1 {
		t.Fatalf("version=%#v create=%d jobs=%#v", version, fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
	}
}
