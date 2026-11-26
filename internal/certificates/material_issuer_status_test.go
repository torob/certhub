package certificates

import (
	"context"
	"errors"
	"testing"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	issuerdomain "github.com/torob/certhub/internal/issuers"
	userdomain "github.com/torob/certhub/internal/users"
)

// namedIssuers resolves issuers by name, like the issuer repository.
// GetByName returns every issuer status; GetActiveDefault returns only an
// active default issuer.
type namedIssuers struct {
	byName map[string]issuerdomain.Issuer
}

func (i namedIssuers) Get(_ context.Context, id string) (issuerdomain.Issuer, error) {
	for _, issuer := range i.byName {
		if issuer.ID == id {
			return issuer, nil
		}
	}
	return issuerdomain.Issuer{}, errors.New("issuer not found")
}

func (i namedIssuers) GetByName(_ context.Context, name string) (issuerdomain.Issuer, error) {
	issuer, ok := i.byName[name]
	if !ok {
		return issuerdomain.Issuer{}, errors.New("issuer not found")
	}
	return issuer, nil
}

func (i namedIssuers) GetActiveDefault(context.Context) (issuerdomain.Issuer, error) {
	for _, issuer := range i.byName {
		if issuer.IsDefault && issuer.Status == issuerdomain.StatusActive {
			return issuer, nil
		}
	}
	return issuerdomain.Issuer{}, errors.New("no active default issuer")
}

type disabledIssuerFixture struct {
	service *Service
	store   *lifecycleStore
}

// newDisabledIssuerFixture builds a ready certificate with one valid version.
// Its issuer "letsencrypt" was the default issuer and is now disabled.
func newDisabledIssuerFixture(t *testing.T) disabledIssuerFixture {
	t.Helper()
	base := newLifecycleServiceFixture()
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	version := validMaterialVersion(time.Now().UTC().Add(60 * 24 * time.Hour))
	sealed, err := keys.SealDatabaseValue([]byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"), certificatePrivateKeyAAD(version.ID))
	if err != nil {
		t.Fatal(err)
	}
	version.PrivateKeyPEMEncrypted = &sealed
	base.store.material = version
	base.store.versions = []CertificateVersion{version}
	issuers := namedIssuers{byName: map[string]issuerdomain.Issuer{
		"letsencrypt": {
			ID:                   base.store.cert.IssuerID,
			Name:                 "letsencrypt",
			Status:               issuerdomain.StatusDisabled,
			IsDefault:            true,
			RenewalWindowSeconds: 2592000,
		},
	}}
	service := NewService(ServiceConfig{Repository: base.store, ApplicationReader: base.service.apps, IssuerReader: issuers, AuditRepository: base.audit, KeySet: keys})
	return disabledIssuerFixture{service: service, store: base.store}
}

func (f disabledIssuerFixture) criteria(issuer string) Criteria {
	return Criteria{Domains: f.store.cert.NormalizedSANs, KeyType: string(f.store.cert.KeyType), Issuer: issuer}
}

func (f disabledIssuerFixture) actor() ApplicationActor {
	return ApplicationActor{ApplicationID: f.store.cert.ApplicationID}
}

func TestMaterialForCriteriaReturnsValidMaterialOfDisabledIssuer(t *testing.T) {
	fixture := newDisabledIssuerFixture(t)

	result, err := fixture.service.MaterialForCriteria(context.Background(), fixture.actor(), fixture.criteria("letsencrypt"), AuditContext{})
	if err != nil {
		t.Fatalf("material lookup with a disabled named issuer: err=%v, want the existing valid material", err)
	}
	if result.Material.MaterialETag != *fixture.store.material.MaterialETag || result.Material.IssuerName != "letsencrypt" {
		t.Fatalf("material = %#v", result.Material)
	}

	metadata, err := fixture.service.MaterialMetadataForCriteria(context.Background(), fixture.actor(), fixture.criteria("letsencrypt"))
	if err != nil {
		t.Fatalf("metadata lookup with a disabled named issuer: err=%v, want the existing valid material", err)
	}
	if metadata.MaterialETag != *fixture.store.material.MaterialETag {
		t.Fatalf("metadata = %#v", metadata)
	}
	if fixture.store.createVersionCalls != 0 || len(fixture.store.ensureJobCalls) != 0 {
		t.Fatalf("lookup created work: versions=%d jobs=%#v", fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
	}
}

func TestMaterialForCriteriaUnknownIssuerIsInvalidRequest(t *testing.T) {
	fixture := newDisabledIssuerFixture(t)

	if _, err := fixture.service.MaterialForCriteria(context.Background(), fixture.actor(), fixture.criteria("missing_issuer"), AuditContext{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("material lookup with an unknown issuer: err=%v, want ErrInvalidRequest", err)
	}
	if _, err := fixture.service.MaterialMetadataForCriteria(context.Background(), fixture.actor(), fixture.criteria("missing_issuer")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("metadata lookup with an unknown issuer: err=%v, want ErrInvalidRequest", err)
	}
}

func TestMaterialForCriteriaOmittedIssuerNeedsActiveDefault(t *testing.T) {
	fixture := newDisabledIssuerFixture(t)

	if _, err := fixture.service.MaterialForCriteria(context.Background(), fixture.actor(), fixture.criteria(""), AuditContext{}); !errors.Is(err, ErrIssuerNotConfigured) {
		t.Fatalf("material lookup without issuer and no active default: err=%v, want ErrIssuerNotConfigured", err)
	}
	if _, err := fixture.service.MaterialMetadataForCriteria(context.Background(), fixture.actor(), fixture.criteria("")); !errors.Is(err, ErrIssuerNotConfigured) {
		t.Fatalf("metadata lookup without issuer and no active default: err=%v, want ErrIssuerNotConfigured", err)
	}
}

func TestEnsureWithDisabledIssuerIsStillRejected(t *testing.T) {
	fixture := newDisabledIssuerFixture(t)

	if _, err := fixture.service.EnsureForApplicationToken(context.Background(), fixture.actor(), fixture.criteria("letsencrypt"), AuditContext{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("application create with a disabled issuer: err=%v, want ErrInvalidRequest", err)
	}
	if _, err := fixture.service.EnsureForUser(context.Background(), Actor{GlobalRole: userdomain.GlobalRoleAdmin}, fixture.store.cert.ApplicationID, fixture.criteria("letsencrypt"), AuditContext{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("user create with a disabled issuer: err=%v, want ErrInvalidRequest", err)
	}
	if _, err := fixture.service.EnsureForApplicationToken(context.Background(), fixture.actor(), fixture.criteria(""), AuditContext{}); !errors.Is(err, ErrIssuerNotConfigured) {
		t.Fatalf("application create without issuer and no active default: err=%v, want ErrIssuerNotConfigured", err)
	}
	if fixture.store.createVersionCalls != 0 || len(fixture.store.ensureJobCalls) != 0 {
		t.Fatalf("rejected create made work: versions=%d jobs=%#v", fixture.store.createVersionCalls, fixture.store.ensureJobCalls)
	}
}
