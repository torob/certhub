package certificates

import (
	"context"
	"errors"
	"testing"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	issuerdomain "github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

func TestStartLifecycleRenewalBeforeWindowReturnsNotDue(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	notAfter := time.Now().UTC().Add(60 * 24 * time.Hour)
	fixture.store.material = validMaterialVersion(notAfter)
	fixture.store.versions = []CertificateVersion{fixture.store.material}

	_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonRenewal)
	var notDue RenewalNotDueError
	if !errors.As(err, &notDue) {
		t.Fatalf("err = %v, want RenewalNotDueError", err)
	}
	if notDue.Certificate.ID != fixture.store.cert.ID || notDue.Version.Version != fixture.store.material.Version {
		t.Fatalf("not due details = %#v", notDue)
	}
	if fixture.store.createVersionCalls != 0 || len(fixture.store.ensureJobCalls) != 0 {
		t.Fatalf("created renewal before window: create=%d jobs=%#v", fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
	}
}

func TestDisabledCertificateBlocksNewLifecycleButKeepsValidMaterial(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.cert.Enabled = false
	fixture.store.material = validMaterialVersion(time.Now().UTC().Add(24 * time.Hour))
	fixture.store.versions = []CertificateVersion{fixture.store.material}

	for _, reason := range []IssuanceReason{IssuanceReasonRenewal, IssuanceReasonKeyRotation, IssuanceReasonReissue} {
		_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, reason)
		var state StateError
		if !errors.As(err, &state) || !errors.Is(state.Err, ErrCertificateDisabled) {
			t.Fatalf("reason=%s err=%v, want disabled state", reason, err)
		}
	}
	if fixture.store.createVersionCalls != 0 || len(fixture.store.ensureJobCalls) != 0 {
		t.Fatalf("disabled certificate created work: versions=%d jobs=%#v", fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
	}

	result, err := fixture.service.MaterialMetadataForID(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID)
	if err != nil || result.MaterialETag == "" {
		t.Fatalf("disabled valid material metadata = %#v err=%v", result, err)
	}
}

func TestEnsureDisabledCertificateDoesNotCreateWork(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.cert.Enabled = false
	fixture.store.cert.Status = StatusPending

	result, err := fixture.service.EnsureForUser(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ApplicationID, Criteria{
		Domains: fixture.store.cert.NormalizedSANs,
		KeyType: string(fixture.store.cert.KeyType),
		Issuer:  "letsencrypt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted || result.Certificate.Enabled || fixture.store.createVersionCalls != 0 || len(fixture.store.ensureJobCalls) != 0 {
		t.Fatalf("disabled ensure result=%#v versions=%d jobs=%#v", result, fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
	}
}

func TestStartLifecycleRenewalInsideWindowCreatesVersionAndJob(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	notAfter := time.Now().UTC().Add(30*24*time.Hour - time.Second)
	fixture.store.material = validMaterialVersion(notAfter)
	fixture.store.versions = []CertificateVersion{fixture.store.material}

	version, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonRenewal)
	if err != nil {
		t.Fatal(err)
	}
	if version.Reason != IssuanceReasonRenewal || version.Status != VersionStatusIssuing {
		t.Fatalf("version = %#v", version)
	}
	if fixture.store.createVersionCalls != 1 || fixture.store.createVersionReason != IssuanceReasonRenewal {
		t.Fatalf("create calls = %d reason=%s", fixture.store.createVersionCalls, fixture.store.createVersionReason)
	}
	if len(fixture.store.ensureJobCalls) != 1 || fixture.store.ensureJobCalls[0].Reason != JobReasonRenewal {
		t.Fatalf("jobs = %#v", fixture.store.ensureJobCalls)
	}
}

func TestStartLifecycleRenewalWithoutActiveVersionRequiresReissue(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.materialErr = storage.ErrNoRows
	fixture.store.cert.Status = StatusExpired

	_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonRenewal)
	var state StateError
	if !errors.As(err, &state) || !errors.Is(state.Err, ErrCertificateNoActiveVersion) {
		t.Fatalf("err = %v, want no active version state", err)
	}
	version, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonReissue)
	if err != nil {
		t.Fatal(err)
	}
	if version.Reason != IssuanceReasonReissue || fixture.store.createVersionCalls != 1 {
		t.Fatalf("version=%#v create=%d", version, fixture.store.createVersionCalls)
	}
}

func TestStartLifecycleReissueFromRevokedParentCreatesVersion(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	reason := RevocationReasonCessationOfOperation
	revokedAt := time.Now().UTC().Add(-time.Hour)
	revokedBy := "92345678-1234-4234-9234-123456789abc"
	fixture.store.materialErr = storage.ErrNoRows
	fixture.store.cert.Status = StatusRevoked
	fixture.store.cert.RevocationReason = &reason
	fixture.store.cert.RevokedAt = &revokedAt
	fixture.store.cert.RevokedByUserID = &revokedBy

	version, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonReissue)
	if err != nil {
		t.Fatal(err)
	}
	if version.Reason != IssuanceReasonReissue || fixture.store.createVersionCalls != 1 {
		t.Fatalf("version=%#v create=%d", version, fixture.store.createVersionCalls)
	}
	if len(fixture.store.ensureJobCalls) != 1 || fixture.store.ensureJobCalls[0].Reason != JobReasonReissue {
		t.Fatalf("jobs = %#v", fixture.store.ensureJobCalls)
	}
}

func TestStartLifecycleRotateKeyWithoutActiveVersionRequiresReissue(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.materialErr = storage.ErrNoRows
	fixture.store.cert.Status = StatusExpired

	_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonKeyRotation)
	var state StateError
	if !errors.As(err, &state) || !errors.Is(state.Err, ErrCertificateNoActiveVersion) {
		t.Fatalf("err = %v, want no active version state", err)
	}
	if fixture.store.createVersionCalls != 0 {
		t.Fatalf("create calls = %d", fixture.store.createVersionCalls)
	}
}

func TestStartLifecycleReissueWithActiveVersionConflicts(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.material = validMaterialVersion(time.Now().UTC().Add(24 * time.Hour))
	fixture.store.versions = []CertificateVersion{fixture.store.material}

	_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonReissue)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want conflict", err)
	}
	if fixture.store.createVersionCalls != 0 {
		t.Fatalf("create calls = %d", fixture.store.createVersionCalls)
	}
}

func TestStartLifecycleReissueWithIssuingVersionConflicts(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	fixture.store.materialErr = storage.ErrNoRows
	fixture.store.cert.Status = StatusFailed
	fixture.store.cert.HasIssuingVersion = true
	fixture.store.versions = []CertificateVersion{{
		ID:            "62345678-1234-4234-9234-123456789abc",
		CertificateID: fixture.store.cert.ID,
		Version:       3,
		Status:        VersionStatusIssuing,
		Reason:        IssuanceReasonReissue,
	}}

	_, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonReissue)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want conflict", err)
	}
	if fixture.store.createVersionCalls != 0 {
		t.Fatalf("create calls = %d", fixture.store.createVersionCalls)
	}
}

func TestStartLifecycleRotateKeyBypassesRenewalWindow(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	notAfter := time.Now().UTC().Add(60 * 24 * time.Hour)
	fixture.store.material = validMaterialVersion(notAfter)
	fixture.store.versions = []CertificateVersion{fixture.store.material}

	version, err := fixture.service.StartLifecycle(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ID, IssuanceReasonKeyRotation)
	if err != nil {
		t.Fatal(err)
	}
	if version.Reason != IssuanceReasonKeyRotation || fixture.store.createVersionReason != IssuanceReasonKeyRotation {
		t.Fatalf("version=%#v reason=%s", version, fixture.store.createVersionReason)
	}
}

func TestMaterialMetadataDoesNotEnqueueRenewalInsideWindow(t *testing.T) {
	fixture := newLifecycleServiceFixture()
	notAfter := time.Now().UTC().Add(30*24*time.Hour - time.Second)
	fixture.store.material = validMaterialVersion(notAfter)
	fixture.store.versions = []CertificateVersion{fixture.store.material}

	result, err := fixture.service.MaterialMetadataForCriteria(context.Background(), ApplicationActor{ApplicationID: fixture.store.cert.ApplicationID}, Criteria{
		Domains: fixture.store.cert.NormalizedSANs,
		KeyType: string(fixture.store.cert.KeyType),
		Issuer:  "letsencrypt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.MaterialETag == "" {
		t.Fatalf("metadata = %#v", result)
	}
	if fixture.store.createVersionCalls != 0 {
		t.Fatalf("create calls = %d reason=%s", fixture.store.createVersionCalls, fixture.store.createVersionReason)
	}
	if len(fixture.store.ensureJobCalls) != 0 {
		t.Fatalf("jobs = %#v", fixture.store.ensureJobCalls)
	}
}

type lifecycleServiceFixture struct {
	service *Service
	store   *lifecycleStore
}

func newLifecycleServiceFixture() lifecycleServiceFixture {
	cert := Certificate{
		ID:             "12345678-1234-4234-9234-123456789abc",
		Enabled:        true,
		ApplicationID:  "22345678-1234-4234-9234-123456789abc",
		IssuerID:       "32345678-1234-4234-9234-123456789abc",
		Status:         StatusReady,
		NormalizedSANs: []string{"api.example.com"},
		KeyType:        KeyTypeECDSAP256,
	}
	store := &lifecycleStore{cert: cert}
	apps := lifecycleApps{
		app: appdomain.Application{ID: cert.ApplicationID, Status: appdomain.StatusActive},
		scopes: []appdomain.DomainScope{{
			ID:            "42345678-1234-4234-9234-123456789abc",
			ApplicationID: cert.ApplicationID,
			Value:         "api.example.com",
			Kind:          appdomain.DomainScopeKindExact,
		}},
	}
	issuers := lifecycleIssuers{issuer: issuerdomain.Issuer{
		ID:                   cert.IssuerID,
		Name:                 "letsencrypt",
		Status:               issuerdomain.StatusActive,
		RenewalWindowSeconds: 2592000,
	}}
	return lifecycleServiceFixture{
		service: NewService(ServiceConfig{Repository: store, ApplicationReader: apps, IssuerReader: issuers}),
		store:   store,
	}
}

func validMaterialVersion(notAfter time.Time) CertificateVersion {
	notBefore := time.Now().UTC().Add(-24 * time.Hour)
	certPEM := "cert"
	chainPEM := "chain"
	fullchainPEM := "fullchain"
	privateKey := `{"version":"1"}`
	serial := "01"
	fp := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	kfp := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	etag := `"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`
	issuedAt := time.Now().UTC()
	return CertificateVersion{
		ID:                     "52345678-1234-4234-9234-123456789abc",
		CertificateID:          "12345678-1234-4234-9234-123456789abc",
		Version:                2,
		Status:                 VersionStatusValid,
		Reason:                 IssuanceReasonInitialIssue,
		CertPEM:                &certPEM,
		ChainPEM:               &chainPEM,
		FullchainPEM:           &fullchainPEM,
		PrivateKeyPEMEncrypted: &privateKey,
		NotBefore:              &notBefore,
		NotAfter:               &notAfter,
		SerialNumber:           &serial,
		FingerprintSHA256:      &fp,
		KeyFingerprintSHA256:   &kfp,
		MaterialETag:           &etag,
		IssuedAt:               &issuedAt,
	}
}

type lifecycleStore struct {
	cert                Certificate
	material            CertificateVersion
	materialErr         error
	versions            []CertificateVersion
	events              []Event
	createVersionCalls  int
	createVersionReason IssuanceReason
	ensureJobCalls      []EnsureIssuanceJobParams
}

func (s *lifecycleStore) CreateOrReuse(context.Context, CreateOrReuseCertificateParams) (Certificate, error) {
	return s.cert, nil
}

func (s *lifecycleStore) Get(context.Context, string) (Certificate, error) {
	return s.cert, nil
}

func (s *lifecycleStore) UpdateEnabled(_ context.Context, params UpdateCertificateEnabledParams) (Certificate, bool, error) {
	changed := s.cert.Enabled != params.Enabled
	s.cert.Enabled = params.Enabled
	return s.cert, changed, nil
}

func (s *lifecycleStore) List(context.Context, ListCertificatesParams) ([]Certificate, error) {
	return []Certificate{s.cert}, nil
}

func (s *lifecycleStore) Count(context.Context, ListCertificatesParams) (int64, error) {
	return 1, nil
}

func (s *lifecycleStore) LatestValidVersion(context.Context, string) (CertificateVersion, error) {
	return s.material, s.materialErr
}

func (s *lifecycleStore) ListVersions(context.Context, ListVersionsParams) ([]CertificateVersion, error) {
	return append([]CertificateVersion(nil), s.versions...), nil
}

func (s *lifecycleStore) CountVersions(context.Context, string) (int64, error) {
	return int64(len(s.versions)), nil
}

func (s *lifecycleStore) ListEvents(context.Context, ListEventsParams) ([]Event, error) {
	return append([]Event(nil), s.events...), nil
}

func (s *lifecycleStore) CountEvents(context.Context, ListEventsParams) (int64, error) {
	return int64(len(s.events)), nil
}

func (s *lifecycleStore) GetVersion(context.Context, string) (CertificateVersion, error) {
	if len(s.versions) > 0 {
		return s.versions[0], nil
	}
	return s.material, s.materialErr
}

func (s *lifecycleStore) GetLatestValidMaterial(context.Context, string) (CertificateVersion, error) {
	return s.material, s.materialErr
}

func (s *lifecycleStore) CreateIssuingVersion(_ context.Context, params CreateIssuingVersionParams) (CertificateVersion, error) {
	s.createVersionCalls++
	s.createVersionReason = params.Reason
	return CertificateVersion{
		ID:            "62345678-1234-4234-9234-123456789abc",
		CertificateID: params.CertificateID,
		Version:       3,
		Status:        VersionStatusIssuing,
		Reason:        params.Reason,
	}, nil
}

func (s *lifecycleStore) EnsureIssuanceJob(_ context.Context, params EnsureIssuanceJobParams) (IssuanceJob, error) {
	s.ensureJobCalls = append(s.ensureJobCalls, params)
	return IssuanceJob{ID: "72345678-1234-4234-9234-123456789abc", Reason: params.Reason}, nil
}

func (s *lifecycleStore) RevokeCertificateVersion(context.Context, RevokeCertificateVersionParams) (CertificateVersion, error) {
	return CertificateVersion{}, errors.New("not implemented")
}

func (s *lifecycleStore) DeleteCertificate(context.Context, DeleteCertificateParams) (Certificate, error) {
	return Certificate{}, errors.New("not implemented")
}

type lifecycleApps struct {
	app    appdomain.Application
	scopes []appdomain.DomainScope
}

func (a lifecycleApps) Get(context.Context, string) (appdomain.Application, error) {
	return a.app, nil
}

func (a lifecycleApps) GetByName(context.Context, string) (appdomain.Application, error) {
	return a.app, nil
}

func (a lifecycleApps) GetGrant(context.Context, string, string) (appdomain.UserGrant, error) {
	return appdomain.UserGrant{Role: appdomain.GrantRoleManager}, nil
}

func (a lifecycleApps) ListAccessibleApplicationIDs(context.Context, string) ([]string, error) {
	return []string{a.app.ID}, nil
}

func (a lifecycleApps) ListDomainScopes(context.Context, string, storage.ListOptions) ([]appdomain.DomainScope, error) {
	return append([]appdomain.DomainScope(nil), a.scopes...), nil
}

type lifecycleIssuers struct {
	issuer issuerdomain.Issuer
}

func (i lifecycleIssuers) Get(context.Context, string) (issuerdomain.Issuer, error) {
	return i.issuer, nil
}

func (i lifecycleIssuers) GetByName(context.Context, string) (issuerdomain.Issuer, error) {
	return i.issuer, nil
}

func (i lifecycleIssuers) GetActiveDefault(context.Context) (issuerdomain.Issuer, error) {
	return i.issuer, nil
}
