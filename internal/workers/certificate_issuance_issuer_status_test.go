package workers

import (
	"context"
	"testing"

	"github.com/torob/certhub/internal/certificates"
	issuerdomain "github.com/torob/certhub/internal/issuers"
)

// A job can be queued before an admin disables the issuer. The worker must not
// start ACME work for it, although the issuer still has an active ACME account.
func TestIssuanceWithDisabledIssuerFailsBeforeACMEOrder(t *testing.T) {
	cases := []struct {
		job     certificates.JobReason
		version certificates.IssuanceReason
	}{
		{certificates.JobReasonInitialIssue, certificates.IssuanceReasonInitialIssue},
		{certificates.JobReasonRenewal, certificates.IssuanceReasonRenewal},
		{certificates.JobReasonKeyRotation, certificates.IssuanceReasonKeyRotation},
		{certificates.JobReasonReissue, certificates.IssuanceReasonReissue},
	}
	for _, tc := range cases {
		t.Run(string(tc.job), func(t *testing.T) {
			fixture := newIssuanceWorkerFixture(t)
			configureSuccessfulIssuance(t, &fixture)
			issuers := fixture.service.Issuers.(fakeIssuerStore)
			issuers.issuer.Status = issuerdomain.StatusDisabled
			fixture.service.Issuers = issuers
			fixture.store.claimJob.Reason = tc.job
			fixture.version.Reason = tc.version
			fixture.store.version = fixture.version

			job, processed, err := fixture.service.CompleteNextIssuanceJob(context.Background(), "worker-1")
			if err == nil {
				t.Fatal("expected issuance failure")
			}
			if !processed {
				t.Fatal("expected job to be processed")
			}
			if job.Status != certificates.JobStatusFailed {
				t.Fatalf("job status = %s", job.Status)
			}
			if fixture.order.finalizeCalls != 0 || len(fixture.recorder.events) != 0 {
				t.Fatalf("ACME/DNS work started with a disabled issuer: finalize=%d events=%#v", fixture.order.finalizeCalls, fixture.recorder.events)
			}
			if len(fixture.store.storeMaterialCalls) != 0 {
				t.Fatalf("store material calls = %#v", fixture.store.storeMaterialCalls)
			}
			if len(fixture.store.failJobCalls) != 1 || fixture.store.failJobCalls[0].FailureCode != "issuer_not_configured" {
				t.Fatalf("fail job calls = %#v, want one issuer_not_configured failure", fixture.store.failJobCalls)
			}
		})
	}
}
