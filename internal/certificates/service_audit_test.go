package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auditdomain "github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

const auditTestUserID = "a2345678-1234-4234-9234-123456789abc"

var auditTestContext = AuditContext{CorrelationID: "req_lifecycle_audit", SourceIP: "203.0.113.7"}

type wantAuditEvent struct {
	action        string
	identityType  auditdomain.IdentityType
	identityID    string
	targetType    string
	targetID      string
	applicationID string
	certificateID string
	metadata      map[string]any
}

func requireSingleAuditEvent(t *testing.T, events []auditdomain.AppendEventParams, want wantAuditEvent) {
	t.Helper()
	if len(events) != 1 {
		actions := make([]string, 0, len(events))
		for _, event := range events {
			actions = append(actions, event.Action)
		}
		t.Fatalf("audit actions = %v, want exactly [%s]", actions, want.action)
	}
	got := events[0]
	if got.Action != want.action || got.IdentityType != want.identityType || got.Result != auditdomain.ResultSuccess || got.TargetType != want.targetType {
		t.Fatalf("audit event = action %q identity %q result %q target type %q, want %q %q success %q", got.Action, got.IdentityType, got.Result, got.TargetType, want.action, want.identityType, want.targetType)
	}
	if got.IdentityID == nil || *got.IdentityID != want.identityID {
		t.Fatalf("audit identity_id = %v, want %s", got.IdentityID, want.identityID)
	}
	if got.CorrelationID == nil || *got.CorrelationID != auditTestContext.CorrelationID || got.SourceIP == nil || *got.SourceIP != auditTestContext.SourceIP {
		t.Fatalf("audit correlation_id = %v source_ip = %v, want %#v", got.CorrelationID, got.SourceIP, auditTestContext)
	}
	if got.TargetID == nil || *got.TargetID != want.targetID {
		t.Fatalf("audit target_id = %v, want %s", got.TargetID, want.targetID)
	}
	if got.ScopeApplicationID == nil || *got.ScopeApplicationID != want.applicationID {
		t.Fatalf("audit scope_application_id = %v, want %s", got.ScopeApplicationID, want.applicationID)
	}
	if got.ScopeCertificateID == nil || *got.ScopeCertificateID != want.certificateID {
		t.Fatalf("audit scope_certificate_id = %v, want %s", got.ScopeCertificateID, want.certificateID)
	}
	metadata := map[string]any{}
	if len(got.Metadata) > 0 {
		if err := json.Unmarshal(got.Metadata, &metadata); err != nil {
			t.Fatalf("audit metadata %s: %v", got.Metadata, err)
		}
	}
	for key, value := range want.metadata {
		if metadata[key] != value {
			t.Fatalf("audit metadata[%q] = %#v, want %#v (metadata %s)", key, metadata[key], value, got.Metadata)
		}
	}
}

func auditTestActor() Actor {
	return Actor{ID: auditTestUserID, GlobalRole: userdomain.GlobalRoleAdmin}
}

func TestEnsureWritesCertificateCreatedAudit(t *testing.T) {
	t.Run("user", func(t *testing.T) {
		fixture := newLifecycleServiceFixture()
		fixture.store.newCertificate = true

		result, err := fixture.service.EnsureForUser(context.Background(), auditTestActor(), fixture.store.cert.ApplicationID, Criteria{
			Domains: fixture.store.cert.NormalizedSANs,
			KeyType: string(fixture.store.cert.KeyType),
			Issuer:  "letsencrypt",
		}, auditTestContext)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Accepted {
			t.Fatalf("ensure result = %#v, want accepted", result)
		}
		requireSingleAuditEvent(t, fixture.audit.events, wantAuditEvent{
			action:        "certificate_created",
			identityType:  auditdomain.IdentityTypeUser,
			identityID:    auditTestUserID,
			targetType:    "certificate",
			targetID:      result.Certificate.ID,
			applicationID: fixture.store.cert.ApplicationID,
			certificateID: result.Certificate.ID,
			metadata:      map[string]any{"issuance_reason": string(IssuanceReasonInitialIssue)},
		})
	})

	t.Run("application token", func(t *testing.T) {
		fixture := newLifecycleServiceFixture()
		fixture.store.newCertificate = true

		result, err := fixture.service.EnsureForApplicationToken(context.Background(), ApplicationActor{ApplicationID: fixture.store.cert.ApplicationID, TokenID: "b2345678-1234-4234-9234-123456789abc"}, Criteria{
			Domains: fixture.store.cert.NormalizedSANs,
			KeyType: string(fixture.store.cert.KeyType),
			Issuer:  "letsencrypt",
		}, auditTestContext)
		if err != nil {
			t.Fatal(err)
		}
		requireSingleAuditEvent(t, fixture.audit.events, wantAuditEvent{
			action:        "certificate_created",
			identityType:  auditdomain.IdentityTypeApplication,
			identityID:    fixture.store.cert.ApplicationID,
			targetType:    "certificate",
			targetID:      result.Certificate.ID,
			applicationID: fixture.store.cert.ApplicationID,
			certificateID: result.Certificate.ID,
			metadata:      map[string]any{"application_token_id": "b2345678-1234-4234-9234-123456789abc"},
		})
	})
}

func TestEnsureExistingPendingCertificateWritesIssuanceStartedAudit(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.cert.Status = StatusPending

	result, err := fixture.service.EnsureForApplicationToken(context.Background(), ApplicationActor{ApplicationID: fixture.store.cert.ApplicationID}, Criteria{
		Domains: fixture.store.cert.NormalizedSANs,
		KeyType: string(fixture.store.cert.KeyType),
		Issuer:  "letsencrypt",
	}, auditTestContext)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || fixture.store.createVersionCalls != 1 {
		t.Fatalf("ensure result = %#v create=%d", result, fixture.store.createVersionCalls)
	}
	requireSingleAuditEvent(t, fixture.audit.events, wantAuditEvent{
		action:        "certificate_issuance_started",
		identityType:  auditdomain.IdentityTypeApplication,
		identityID:    fixture.store.cert.ApplicationID,
		targetType:    "certificate_version",
		targetID:      deref(fixture.store.ensureJobCalls[0].CertificateVersionID),
		applicationID: fixture.store.cert.ApplicationID,
		certificateID: fixture.store.cert.ID,
		metadata:      map[string]any{"issuance_reason": string(IssuanceReasonInitialIssue)},
	})
}

func TestEnsureWithoutStateChangeWritesNoAudit(t *testing.T) {
	t.Run("ready certificate", func(t *testing.T) {
		fixture := newLifecycleServiceFixture()
		if _, err := fixture.service.EnsureForApplicationToken(context.Background(), ApplicationActor{ApplicationID: fixture.store.cert.ApplicationID}, Criteria{
			Domains: fixture.store.cert.NormalizedSANs,
			KeyType: string(fixture.store.cert.KeyType),
			Issuer:  "letsencrypt",
		}, auditTestContext); err != nil {
			t.Fatal(err)
		}
		if len(fixture.audit.events) != 0 {
			t.Fatalf("audit events = %#v, want none", fixture.audit.events)
		}
	})
	t.Run("issuance already in progress", func(t *testing.T) {
		fixture := newLifecycleServiceFixture()
		fixture.store.cert.Status = StatusIssuing
		fixture.store.issuingVersion = &CertificateVersion{ID: "62345678-1234-4234-9234-123456789abc", CertificateID: fixture.store.cert.ID, Version: 1, Status: VersionStatusIssuing, Reason: IssuanceReasonInitialIssue}
		if _, err := fixture.service.EnsureForApplicationToken(context.Background(), ApplicationActor{ApplicationID: fixture.store.cert.ApplicationID}, Criteria{
			Domains: fixture.store.cert.NormalizedSANs,
			KeyType: string(fixture.store.cert.KeyType),
			Issuer:  "letsencrypt",
		}, auditTestContext); err != nil {
			t.Fatal(err)
		}
		if len(fixture.audit.events) != 0 {
			t.Fatalf("audit events = %#v, want none", fixture.audit.events)
		}
	})
}

func TestStartLifecycleWritesStartedAudit(t *testing.T) {
	tests := []struct {
		reason IssuanceReason
		action string
		setup  func(*lifecycleServiceFixture)
	}{
		{
			reason: IssuanceReasonRenewal,
			action: "certificate_renewal_started",
			setup: func(f *lifecycleServiceFixture) {
				f.store.material = validMaterialVersion(time.Now().UTC().Add(30*24*time.Hour - time.Second))
				f.store.versions = []CertificateVersion{f.store.material}
			},
		},
		{
			reason: IssuanceReasonKeyRotation,
			action: "certificate_key_rotation_started",
			setup: func(f *lifecycleServiceFixture) {
				f.store.material = validMaterialVersion(time.Now().UTC().Add(60 * 24 * time.Hour))
				f.store.versions = []CertificateVersion{f.store.material}
			},
		},
		{
			reason: IssuanceReasonReissue,
			action: "certificate_issuance_started",
			setup: func(f *lifecycleServiceFixture) {
				f.store.materialErr = storage.ErrNoRows
				f.store.cert.Status = StatusRevoked
			},
		},
	}
	for _, tc := range tests {
		t.Run(string(tc.reason), func(t *testing.T) {
			fixture := newLifecycleServiceFixture()
			tc.setup(&fixture)

			version, err := fixture.service.StartLifecycle(context.Background(), auditTestActor(), fixture.store.cert.ID, tc.reason, auditTestContext)
			if err != nil {
				t.Fatal(err)
			}
			requireSingleAuditEvent(t, fixture.audit.events, wantAuditEvent{
				action:        tc.action,
				identityType:  auditdomain.IdentityTypeUser,
				identityID:    auditTestUserID,
				targetType:    "certificate_version",
				targetID:      version.ID,
				applicationID: fixture.store.cert.ApplicationID,
				certificateID: fixture.store.cert.ID,
				metadata: map[string]any{
					"certificate_version_id": version.ID,
					"issuance_reason":        string(tc.reason),
				},
			})
		})
	}
}

func TestStartLifecycleAlreadyInProgressWritesNoAudit(t *testing.T) {
	for _, reason := range []IssuanceReason{IssuanceReasonRenewal, IssuanceReasonKeyRotation} {
		t.Run(string(reason), func(t *testing.T) {
			fixture := newLifecycleServiceFixture()
			fixture.store.material = validMaterialVersion(time.Now().UTC().Add(30*24*time.Hour - time.Second))
			inProgress := CertificateVersion{ID: "62345678-1234-4234-9234-123456789abc", CertificateID: fixture.store.cert.ID, Version: 3, Status: VersionStatusIssuing, Reason: reason}
			fixture.store.versions = []CertificateVersion{inProgress, fixture.store.material}
			fixture.store.issuingVersion = &inProgress

			version, err := fixture.service.StartLifecycle(context.Background(), auditTestActor(), fixture.store.cert.ID, reason, auditTestContext)
			if err != nil {
				t.Fatal(err)
			}
			if version.ID != inProgress.ID {
				t.Fatalf("version = %#v, want in-progress version", version)
			}
			if len(fixture.audit.events) != 0 {
				t.Fatalf("audit events = %#v, want none for an in-progress %s", fixture.audit.events, reason)
			}
		})
	}
}

func TestRevokeCertificateVersionWritesAudit(t *testing.T) {
	pending := ACMERemoteRevocationPending
	failed := ACMERemoteRevocationFailed
	succeeded := ACMERemoteRevocationSucceeded
	notRequired := ACMERemoteRevocationNotRequired
	tests := []struct {
		name       string
		changed    bool
		acmeStatus *ACMERemoteRevocationStatus
		action     string
	}{
		{name: "first revoke", changed: true, acmeStatus: &pending, action: "certificate_revoked"},
		{name: "retry failed acme revocation", acmeStatus: &failed, action: "certificate_revocation_retried"},
		{name: "retry pending acme revocation", acmeStatus: &pending, action: "certificate_revocation_retried"},
		{name: "acme revocation succeeded", acmeStatus: &succeeded},
		{name: "acme revocation not required", acmeStatus: &notRequired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newLifecycleServiceFixture()
			revoked := validMaterialVersion(time.Now().UTC().Add(24 * time.Hour))
			revoked.Status = VersionStatusRevoked
			reason := RevocationReasonKeyCompromise
			revoked.RevocationReason = &reason
			revoked.ACMERevocationStatus = tc.acmeStatus
			fixture.store.revokeResult = revoked
			fixture.store.revokeChanged = tc.changed

			if _, err := fixture.service.RevokeCertificateVersion(context.Background(), auditTestActor(), fixture.store.cert.ID, revoked.ID, RevocationReasonKeyCompromise, auditTestContext); err != nil {
				t.Fatal(err)
			}
			if tc.action == "" {
				if len(fixture.audit.events) != 0 {
					t.Fatalf("audit events = %#v, want none", fixture.audit.events)
				}
				return
			}
			requireSingleAuditEvent(t, fixture.audit.events, wantAuditEvent{
				action:        tc.action,
				identityType:  auditdomain.IdentityTypeUser,
				identityID:    auditTestUserID,
				targetType:    "certificate_version",
				targetID:      revoked.ID,
				applicationID: fixture.store.cert.ApplicationID,
				certificateID: fixture.store.cert.ID,
				metadata: map[string]any{
					"certificate_version_id": revoked.ID,
					"revocation_reason":      string(RevocationReasonKeyCompromise),
					"acme_revocation_status": string(*tc.acmeStatus),
				},
			})
		})
	}
}

func TestLifecycleAuditFailureFailsMutation(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.material = validMaterialVersion(time.Now().UTC().Add(60 * 24 * time.Hour))
	fixture.store.versions = []CertificateVersion{fixture.store.material}
	auditErr := errors.New("audit unavailable")
	fixture.audit.err = auditErr

	if _, err := fixture.service.StartLifecycle(context.Background(), auditTestActor(), fixture.store.cert.ID, IssuanceReasonKeyRotation, auditTestContext); !errors.Is(err, auditErr) {
		t.Fatalf("err = %v, want audit failure", err)
	}
}
