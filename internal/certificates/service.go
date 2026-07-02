package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	auditdomain "github.com/torob/certhub/internal/audit"
	security "github.com/torob/certhub/internal/crypto"
	issuerdomain "github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
	"github.com/torob/certhub/pkg/certcriteria"
	tlsmaterial "github.com/torob/certhub/pkg/material"
)

var (
	ErrCertificateServiceUnavailable = errors.New("certificate service unavailable")
	ErrInvalidRequest                = errors.New("invalid request")
	ErrForbidden                     = errors.New("forbidden")
	ErrNotFound                      = errors.New("not found")
	ErrConflict                      = errors.New("conflict")
	ErrRenewalNotDue                 = errors.New("renewal not due")
	ErrIssuerNotConfigured           = errors.New("issuer not configured")
	ErrDomainNotAuthorized           = errors.New("domain not authorized")
	ErrSystemManagedResource         = errors.New("system managed resource")
	ErrCertificateNotReady           = errors.New("certificate not ready")
	ErrCertificateExpired            = errors.New("certificate expired")
	ErrCertificateIssuanceFailed     = errors.New("certificate issuance failed")
	ErrCertificateRevoked            = errors.New("certificate revoked")
)

type Store interface {
	CreateOrReuse(context.Context, CreateOrReuseCertificateParams) (Certificate, error)
	Get(context.Context, string) (Certificate, error)
	List(context.Context, ListCertificatesParams) ([]Certificate, error)
	Count(context.Context, ListCertificatesParams) (int64, error)
	LatestValidVersion(context.Context, string) (CertificateVersion, error)
	ListVersions(context.Context, ListVersionsParams) ([]CertificateVersion, error)
	CountVersions(context.Context, string) (int64, error)
	GetLatestValidMaterial(context.Context, string) (CertificateVersion, error)
	CreateIssuingVersion(context.Context, CreateIssuingVersionParams) (CertificateVersion, error)
	EnsureIssuanceJob(context.Context, EnsureIssuanceJobParams) (IssuanceJob, error)
	RevokeCertificate(context.Context, RevokeCertificateParams) (Certificate, error)
	DeleteCertificate(context.Context, DeleteCertificateParams) (Certificate, error)
}

type ApplicationReader interface {
	Get(context.Context, string) (appdomain.Application, error)
	GetByName(context.Context, string) (appdomain.Application, error)
	GetGrant(context.Context, string, string) (appdomain.UserGrant, error)
	ListAccessibleApplicationIDs(context.Context, string) ([]string, error)
	ListDomainScopes(context.Context, string, storage.ListOptions) ([]appdomain.DomainScope, error)
}

type IssuerReader interface {
	Get(context.Context, string) (issuerdomain.Issuer, error)
	GetByName(context.Context, string) (issuerdomain.Issuer, error)
	GetActiveDefault(context.Context) (issuerdomain.Issuer, error)
}

type AuditRepository interface {
	Append(context.Context, auditdomain.AppendEventParams) (auditdomain.Event, error)
}

type ServiceConfig struct {
	Repository        Store
	ApplicationReader ApplicationReader
	IssuerReader      IssuerReader
	AuditRepository   AuditRepository
	KeySet            *security.KeySet
	Storage           storage.Beginner
}

type Service struct {
	repo    Store
	apps    ApplicationReader
	issuers IssuerReader
	audit   AuditRepository
	keys    *security.KeySet
	tx      storage.Beginner
}

type Actor struct {
	ID         string
	GlobalRole userdomain.GlobalRole
}

type ApplicationActor struct {
	ApplicationID string
	TokenID       string
}

type AuditContext struct {
	CorrelationID string
	SourceIP      string
}

type Criteria struct {
	Domains []string
	KeyType string
	Issuer  string
}

type ListParams struct {
	storage.ListOptions
	ApplicationID *string
	Application   string
	Domain        string
	Status        *Status
	KeyType       *KeyType
	Issuer        string
	IssuerID      *string
	ExpiresBefore *time.Time
}

type EnsureResult struct {
	Certificate Certificate
	Accepted    bool
}

type ListResult struct {
	Certificates []Certificate
	Limit        int
	Offset       int
	Total        int64
}

type VersionListResult struct {
	Versions []CertificateVersion
	Limit    int
	Offset   int
	Total    int64
}

type MaterialResult struct {
	Certificate Certificate
	Version     CertificateVersion
	Material    tlsmaterial.TLSMaterial
}

type MaterialMetadataResult struct {
	Certificate  Certificate
	Version      CertificateVersion
	MaterialETag string
}

type StateError struct {
	Err         error
	Certificate Certificate
	Version     *CertificateVersion
}

type RenewalNotDueError struct {
	Certificate      Certificate
	Version          CertificateVersion
	RenewalNotBefore time.Time
}

func (e RenewalNotDueError) Error() string {
	return ErrRenewalNotDue.Error()
}

func (e RenewalNotDueError) Unwrap() error {
	return ErrRenewalNotDue
}

func (e StateError) Error() string {
	return e.Err.Error()
}

func (e StateError) Unwrap() error {
	return e.Err
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{repo: cfg.Repository, apps: cfg.ApplicationReader, issuers: cfg.IssuerReader, audit: cfg.AuditRepository, keys: cfg.KeySet, tx: cfg.Storage}
}

func (s *Service) EnsureForApplicationToken(ctx context.Context, actor ApplicationActor, criteria Criteria) (EnsureResult, error) {
	app, err := s.apps.Get(ctx, actor.ApplicationID)
	if err != nil {
		return EnsureResult{}, ErrNotFound
	}
	if systemManagedApplication(app) {
		return EnsureResult{}, ErrSystemManagedResource
	}
	return s.ensure(ctx, actor.ApplicationID, criteria, "", nil)
}

func (s *Service) EnsureForUser(ctx context.Context, actor Actor, applicationID string, criteria Criteria) (EnsureResult, error) {
	app, err := s.requireApplicationRole(ctx, actor, applicationID, appdomain.GrantRoleManager, false)
	if err != nil {
		return EnsureResult{}, err
	}
	if systemManagedApplication(app) {
		return EnsureResult{}, ErrSystemManagedResource
	}
	return s.ensure(ctx, applicationID, criteria, actor.ID, nil)
}

func (s *Service) ListCertificates(ctx context.Context, actor Actor, params ListParams) (ListResult, error) {
	if err := s.ready(); err != nil {
		return ListResult{}, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListResult{}, ErrInvalidRequest
	}
	base, err := s.listParams(ctx, params)
	if err != nil {
		return ListResult{}, err
	}
	var certs []Certificate
	var total int64
	if actor.admin() {
		certs, err = s.repo.List(ctx, base)
		if err == nil {
			total, err = s.repo.Count(ctx, base)
		}
		if err != nil {
			return ListResult{}, classifyReadError(err)
		}
		if err := s.attachLatestVersions(ctx, certs); err != nil {
			return ListResult{}, err
		}
		return ListResult{Certificates: certs, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
	}
	ids, err := s.apps.ListAccessibleApplicationIDs(ctx, actor.ID)
	if err != nil {
		return ListResult{}, classifyReadError(err)
	}
	if base.ApplicationID != nil {
		if !slices.Contains(ids, *base.ApplicationID) {
			return ListResult{Limit: opts.Limit, Offset: opts.Offset, Total: 0}, nil
		}
		certs, err = s.repo.List(ctx, base)
		if err == nil {
			total, err = s.repo.Count(ctx, base)
		}
		if err != nil {
			return ListResult{}, classifyReadError(err)
		}
		if err := s.attachLatestVersions(ctx, certs); err != nil {
			return ListResult{}, err
		}
		return ListResult{Certificates: certs, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
	}
	if len(ids) == 0 {
		return ListResult{Limit: opts.Limit, Offset: opts.Offset, Total: 0}, nil
	}
	base.ApplicationIDs = ids
	certs, err = s.repo.List(ctx, base)
	if err == nil {
		total, err = s.repo.Count(ctx, base)
	}
	if err != nil {
		return ListResult{}, classifyReadError(err)
	}
	if err := s.attachLatestVersions(ctx, certs); err != nil {
		return ListResult{}, err
	}
	return ListResult{Certificates: certs, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) GetCertificate(ctx context.Context, actor Actor, id string) (Certificate, error) {
	cert, err := s.visibleCertificate(ctx, actor, id, roleViewer, false)
	if err != nil {
		return Certificate{}, err
	}
	if cert.DeletedAt != nil || cert.Status == StatusDeleted {
		return Certificate{}, ErrNotFound
	}
	certs := []Certificate{cert}
	if err := s.attachLatestVersions(ctx, certs); err != nil {
		return Certificate{}, err
	}
	return certs[0], nil
}

func (s *Service) GetCertificateForEvents(ctx context.Context, actor Actor, id string) (Certificate, error) {
	return s.visibleCertificate(ctx, actor, id, roleViewer, true)
}

func (s *Service) ListVersions(ctx context.Context, actor Actor, certificateID string, opts storage.ListOptions) (VersionListResult, error) {
	cert, err := s.visibleCertificate(ctx, actor, certificateID, roleViewer, false)
	if err != nil {
		return VersionListResult{}, err
	}
	if cert.DeletedAt != nil || cert.Status == StatusDeleted {
		return VersionListResult{}, ErrNotFound
	}
	normalized, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return VersionListResult{}, ErrInvalidRequest
	}
	versions, err := s.repo.ListVersions(ctx, ListVersionsParams{ListOptions: normalized, CertificateID: certificateID})
	if err != nil {
		return VersionListResult{}, classifyReadError(err)
	}
	total, err := s.repo.CountVersions(ctx, certificateID)
	if err != nil {
		return VersionListResult{}, classifyReadError(err)
	}
	return VersionListResult{Versions: versions, Limit: normalized.Limit, Offset: normalized.Offset, Total: total}, nil
}

func (s *Service) MaterialForCriteria(ctx context.Context, actor ApplicationActor, criteria Criteria, _ AuditContext) (MaterialResult, error) {
	normalized, issuer, err := s.normalizeCriteria(ctx, criteria)
	if err != nil {
		return MaterialResult{}, err
	}
	if err := s.requireDomainCoverage(ctx, actor.ApplicationID, normalized.Domains); err != nil {
		return MaterialResult{}, err
	}
	cert, err := s.findCertificate(ctx, actor.ApplicationID, issuer.ID, normalized)
	if err != nil {
		return MaterialResult{}, err
	}
	return s.materialForCertificate(ctx, cert, issuer)
}

func (s *Service) MaterialMetadataForCriteria(ctx context.Context, actor ApplicationActor, criteria Criteria) (MaterialMetadataResult, error) {
	normalized, issuer, err := s.normalizeCriteria(ctx, criteria)
	if err != nil {
		return MaterialMetadataResult{}, err
	}
	if err := s.requireDomainCoverage(ctx, actor.ApplicationID, normalized.Domains); err != nil {
		return MaterialMetadataResult{}, err
	}
	cert, err := s.findCertificate(ctx, actor.ApplicationID, issuer.ID, normalized)
	if err != nil {
		return MaterialMetadataResult{}, err
	}
	return s.materialMetadataForCertificate(ctx, cert)
}

func (s *Service) MaterialForID(ctx context.Context, actor Actor, certificateID string, _ AuditContext) (MaterialResult, error) {
	cert, err := s.visibleCertificate(ctx, actor, certificateID, roleCertificateReader, false)
	if err != nil {
		return MaterialResult{}, err
	}
	issuer, err := s.issuers.Get(ctx, cert.IssuerID)
	if err != nil {
		return MaterialResult{}, classifyReadError(err)
	}
	return s.materialForCertificate(ctx, cert, issuer)
}

func (s *Service) MaterialMetadataForID(ctx context.Context, actor Actor, certificateID string) (MaterialMetadataResult, error) {
	cert, err := s.visibleCertificate(ctx, actor, certificateID, roleCertificateReader, false)
	if err != nil {
		return MaterialMetadataResult{}, err
	}
	return s.materialMetadataForCertificate(ctx, cert)
}

func (s *Service) StartLifecycle(ctx context.Context, actor Actor, certificateID string, reason IssuanceReason) (CertificateVersion, error) {
	var version CertificateVersion
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		cert, err := txsvc.visibleCertificate(ctx, actor, certificateID, roleManager, false)
		if err != nil {
			return err
		}
		app, err := txsvc.apps.Get(ctx, cert.ApplicationID)
		if err != nil {
			return ErrNotFound
		}
		if systemManagedApplication(app) {
			return ErrSystemManagedResource
		}
		if cert.Status == StatusDeleted {
			return ErrNotFound
		}
		if cert.Status == StatusRevoked && cert.RevocationReason != nil && *cert.RevocationReason == RevocationReasonKeyCompromise && reason != IssuanceReasonKeyRotation {
			return ErrConflict
		}
		if err := txsvc.requireDomainCoverage(ctx, cert.ApplicationID, cert.NormalizedSANs); err != nil {
			return err
		}
		if reason == IssuanceReasonRenewal {
			existing, ok, err := txsvc.latestIssuingVersion(ctx, certificateID)
			if err != nil {
				return err
			}
			if ok {
				if existing.Reason != IssuanceReasonRenewal {
					return ErrConflict
				}
				version = existing
				_, err = txsvc.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
					CertificateID:        cert.ID,
					CertificateVersionID: &version.ID,
					Reason:               JobReasonRenewal,
					NextRunAt:            time.Now().UTC(),
				})
				if err != nil {
					return classifyWriteError(err)
				}
				return nil
			}
			issuer, err := txsvc.issuers.Get(ctx, cert.IssuerID)
			if err != nil {
				return classifyReadError(err)
			}
			if err := txsvc.requireRenewalWindow(ctx, cert, issuer); err != nil {
				return err
			}
		}
		version, err = txsvc.repo.CreateIssuingVersion(ctx, CreateIssuingVersionParams{CertificateID: certificateID, Reason: reason})
		if err != nil {
			return classifyWriteError(err)
		}
		if version.Reason != reason {
			return ErrConflict
		}
		jobReason := JobReasonRenewal
		if reason == IssuanceReasonKeyRotation {
			jobReason = JobReasonKeyRotation
		}
		_, err = txsvc.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
			CertificateID:        cert.ID,
			CertificateVersionID: &version.ID,
			Reason:               jobReason,
			NextRunAt:            time.Now().UTC(),
		})
		if err != nil {
			return classifyWriteError(err)
		}
		return nil
	})
	return version, err
}

func (s *Service) RevokeCertificate(ctx context.Context, actor Actor, certificateID string, reason RevocationReason) (Certificate, error) {
	var cert Certificate
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		current, err := txsvc.visibleCertificate(ctx, actor, certificateID, roleManager, false)
		if err != nil {
			return err
		}
		app, err := txsvc.apps.Get(ctx, current.ApplicationID)
		if err != nil {
			return ErrNotFound
		}
		if systemManagedApplication(app) {
			return ErrSystemManagedResource
		}
		cert, err = txsvc.repo.RevokeCertificate(ctx, RevokeCertificateParams{ID: certificateID, Reason: reason, RevokedByUserID: actor.ID})
		if err != nil {
			return classifyWriteError(err)
		}
		if _, err := txsvc.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
			CertificateID: cert.ID,
			Reason:        JobReasonRevocationRetry,
			NextRunAt:     time.Now().UTC(),
		}); err != nil {
			return classifyWriteError(err)
		}
		return nil
	})
	return cert, err
}

func (s *Service) DeleteCertificate(ctx context.Context, actor Actor, certificateID string, revoke bool, reason RevocationReason) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		cert, err := txsvc.visibleCertificate(ctx, actor, certificateID, roleManager, true)
		if err != nil {
			return err
		}
		app, err := txsvc.apps.Get(ctx, cert.ApplicationID)
		if err != nil {
			return ErrNotFound
		}
		if systemManagedApplication(app) {
			return ErrSystemManagedResource
		}
		if revoke {
			if _, err := txsvc.repo.RevokeCertificate(ctx, RevokeCertificateParams{ID: certificateID, Reason: reason, RevokedByUserID: actor.ID}); err != nil {
				return classifyWriteError(err)
			}
			if _, err := txsvc.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
				CertificateID: cert.ID,
				Reason:        JobReasonRevocationRetry,
				NextRunAt:     time.Now().UTC(),
			}); err != nil {
				return classifyWriteError(err)
			}
		}
		if _, err := txsvc.repo.DeleteCertificate(ctx, DeleteCertificateParams{ID: certificateID}); err != nil {
			return classifyWriteError(err)
		}
		return nil
	})
}

func (s *Service) ensure(ctx context.Context, applicationID string, criteria Criteria, _ string, _ *AuditContext) (EnsureResult, error) {
	var result EnsureResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		normalized, issuer, err := txsvc.normalizeCriteria(ctx, criteria)
		if err != nil {
			return err
		}
		if err := txsvc.requireDomainCoverage(ctx, applicationID, normalized.Domains); err != nil {
			return err
		}
		cert, err := txsvc.repo.CreateOrReuse(ctx, CreateOrReuseCertificateParams{
			ApplicationID:  applicationID,
			IssuerID:       issuer.ID,
			NormalizedSANs: normalized.Domains,
			KeyType:        KeyType(normalized.KeyType),
			Status:         StatusPending,
		})
		if err != nil {
			return classifyWriteError(err)
		}
		result.Certificate = cert
		if cert.Status == StatusFailed || cert.Status == StatusRevoked || cert.Status == StatusReady || cert.Status == StatusDeleted {
			return nil
		}
		version, err := txsvc.repo.CreateIssuingVersion(ctx, CreateIssuingVersionParams{
			CertificateID: cert.ID,
			Reason:        IssuanceReasonInitialIssue,
		})
		if err != nil {
			return classifyWriteError(err)
		}
		_, err = txsvc.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
			CertificateID:        cert.ID,
			CertificateVersionID: &version.ID,
			Reason:               JobReasonInitialIssue,
			NextRunAt:            time.Now().UTC(),
		})
		if err != nil {
			return classifyWriteError(err)
		}
		result.Accepted = true
		updated, err := txsvc.repo.Get(ctx, cert.ID)
		if err == nil {
			result.Certificate = updated
		}
		return nil
	})
	return result, err
}

func (s *Service) latestIssuingVersion(ctx context.Context, certificateID string) (CertificateVersion, bool, error) {
	versions, err := s.repo.ListVersions(ctx, ListVersionsParams{CertificateID: certificateID, ListOptions: storage.ListOptions{Limit: 1}})
	if err != nil {
		return CertificateVersion{}, false, classifyReadError(err)
	}
	if len(versions) == 0 || versions[0].Status != VersionStatusIssuing {
		return CertificateVersion{}, false, nil
	}
	return versions[0], true, nil
}

func (s *Service) requireRenewalWindow(ctx context.Context, cert Certificate, issuer issuerdomain.Issuer) error {
	version, err := s.repo.GetLatestValidMaterial(ctx, cert.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNoRows) {
			return nil
		}
		return classifyReadError(err)
	}
	if version.NotAfter == nil {
		return nil
	}
	notBefore := renewalNotBefore(*version.NotAfter, issuer)
	if time.Now().UTC().Before(notBefore) {
		return RenewalNotDueError{Certificate: cert, Version: version, RenewalNotBefore: notBefore}
	}
	return nil
}

func (s *Service) normalizeCriteria(ctx context.Context, in Criteria) (certcriteria.Normalized, issuerdomain.Issuer, error) {
	normalized, err := certcriteria.Normalize(certcriteria.Criteria{Domains: in.Domains, KeyType: in.KeyType, Issuer: in.Issuer})
	if err != nil {
		return certcriteria.Normalized{}, issuerdomain.Issuer{}, ErrInvalidRequest
	}
	issuer, err := s.selectIssuer(ctx, normalized.Issuer)
	if err != nil {
		return certcriteria.Normalized{}, issuerdomain.Issuer{}, err
	}
	return normalized, issuer, nil
}

func (s *Service) selectIssuer(ctx context.Context, name string) (issuerdomain.Issuer, error) {
	if name != "" {
		issuer, err := s.issuers.GetByName(ctx, name)
		if err != nil || issuer.Status != issuerdomain.StatusActive {
			return issuerdomain.Issuer{}, ErrInvalidRequest
		}
		return issuer, nil
	}
	issuer, err := s.issuers.GetActiveDefault(ctx)
	if err != nil {
		return issuerdomain.Issuer{}, ErrIssuerNotConfigured
	}
	if issuer.Status != issuerdomain.StatusActive {
		return issuerdomain.Issuer{}, ErrIssuerNotConfigured
	}
	return issuer, nil
}

func (s *Service) listParams(ctx context.Context, params ListParams) (ListCertificatesParams, error) {
	out := ListCertificatesParams{ListOptions: params.ListOptions}
	if params.Status != nil {
		out.Status = params.Status
	}
	if params.KeyType != nil {
		out.KeyType = params.KeyType
	}
	if params.ExpiresBefore != nil {
		out.ExpiresBefore = params.ExpiresBefore
	}
	if params.ApplicationID != nil {
		out.ApplicationID = params.ApplicationID
	}
	if params.Application != "" && out.ApplicationID == nil {
		app, err := s.applicationBySelector(ctx, params.Application)
		if err != nil {
			return ListCertificatesParams{}, err
		}
		out.ApplicationID = &app.ID
	}
	if params.IssuerID != nil {
		out.IssuerID = params.IssuerID
	}
	if params.Issuer != "" && out.IssuerID == nil {
		issuer, err := s.issuers.GetByName(ctx, params.Issuer)
		if err != nil {
			return ListCertificatesParams{}, ErrInvalidRequest
		}
		out.IssuerID = &issuer.ID
	}
	if params.Domain != "" {
		normalized, err := storage.NormalizeCertificateIdentifier(params.Domain)
		if err != nil {
			return ListCertificatesParams{}, ErrInvalidRequest
		}
		out.NormalizedSANs = []string{normalized}
	}
	return out, nil
}

func (s *Service) attachLatestVersions(ctx context.Context, certs []Certificate) error {
	for i := range certs {
		version, err := s.repo.LatestValidVersion(ctx, certs[i].ID)
		if err != nil {
			if errors.Is(err, storage.ErrNoRows) {
				continue
			}
			return classifyReadError(err)
		}
		certs[i].LatestVersion = &version
	}
	return nil
}

func (s *Service) applicationBySelector(ctx context.Context, selector string) (appdomain.Application, error) {
	if storage.ValidateUUID(selector, "application_id") == nil {
		app, err := s.apps.Get(ctx, selector)
		if err != nil {
			return appdomain.Application{}, ErrNotFound
		}
		return app, nil
	}
	app, err := s.apps.GetByName(ctx, selector)
	if err != nil {
		return appdomain.Application{}, ErrInvalidRequest
	}
	return app, nil
}

func (s *Service) findCertificate(ctx context.Context, applicationID, issuerID string, normalized certcriteria.Normalized) (Certificate, error) {
	params := ListCertificatesParams{
		ListOptions:    storage.ListOptions{Limit: 1},
		ApplicationID:  &applicationID,
		IssuerID:       &issuerID,
		KeyType:        ptr(KeyType(normalized.KeyType)),
		NormalizedSANs: normalized.Domains,
	}
	certs, err := s.repo.List(ctx, params)
	if err != nil {
		return Certificate{}, classifyReadError(err)
	}
	if len(certs) == 0 {
		return Certificate{}, ErrNotFound
	}
	return certs[0], nil
}

func (s *Service) materialForCertificate(ctx context.Context, cert Certificate, issuer issuerdomain.Issuer) (MaterialResult, error) {
	if cert.Status == StatusDeleted || cert.DeletedAt != nil {
		return MaterialResult{}, ErrNotFound
	}
	version, err := s.repo.GetLatestValidMaterial(ctx, cert.ID)
	if err != nil {
		_ = s.enqueueRenewalRecovery(ctx, cert, issuer)
		return MaterialResult{}, s.materialStateError(ctx, cert)
	}
	privateKey, err := s.decryptPrivateKey(version)
	if err != nil {
		return MaterialResult{}, ErrCertificateServiceUnavailable
	}
	material, ok := buildMaterial(cert, issuer, version, privateKey)
	if !ok {
		return MaterialResult{}, s.materialStateError(ctx, cert)
	}
	_ = s.enqueueRenewalIfDue(ctx, cert, issuer, version)
	return MaterialResult{Certificate: cert, Version: version, Material: material}, nil
}

func (s *Service) materialMetadataForCertificate(ctx context.Context, cert Certificate) (MaterialMetadataResult, error) {
	if cert.Status == StatusDeleted || cert.DeletedAt != nil {
		return MaterialMetadataResult{}, ErrNotFound
	}
	version, err := s.repo.GetLatestValidMaterial(ctx, cert.ID)
	if err != nil {
		issuer, issuerErr := s.issuers.Get(ctx, cert.IssuerID)
		if issuerErr == nil {
			_ = s.enqueueRenewalRecovery(ctx, cert, issuer)
		}
		return MaterialMetadataResult{}, s.materialStateError(ctx, cert)
	}
	if version.MaterialETag == nil || *version.MaterialETag == "" {
		return MaterialMetadataResult{}, s.materialStateError(ctx, cert)
	}
	issuer, err := s.issuers.Get(ctx, cert.IssuerID)
	if err == nil {
		_ = s.enqueueRenewalIfDue(ctx, cert, issuer, version)
	}
	return MaterialMetadataResult{Certificate: cert, Version: version, MaterialETag: *version.MaterialETag}, nil
}

func (s *Service) enqueueRenewalIfDue(ctx context.Context, cert Certificate, issuer issuerdomain.Issuer, version CertificateVersion) error {
	if issuer.Status != issuerdomain.StatusActive || version.NotAfter == nil {
		return nil
	}
	if time.Now().UTC().Before(renewalNotBefore(*version.NotAfter, issuer)) {
		return nil
	}
	if err := s.requireDomainCoverage(ctx, cert.ApplicationID, cert.NormalizedSANs); err != nil {
		return nil
	}
	issuing, ok, err := s.latestIssuingVersion(ctx, cert.ID)
	if err != nil || (ok && issuing.Reason != IssuanceReasonRenewal) {
		return err
	}
	if ok {
		_, err = s.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
			CertificateID:        cert.ID,
			CertificateVersionID: &issuing.ID,
			Reason:               JobReasonRenewal,
			NextRunAt:            time.Now().UTC(),
		})
		return err
	}
	renewal, err := s.repo.CreateIssuingVersion(ctx, CreateIssuingVersionParams{CertificateID: cert.ID, Reason: IssuanceReasonRenewal})
	if err != nil {
		return err
	}
	if renewal.Reason != IssuanceReasonRenewal {
		return ErrConflict
	}
	_, err = s.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
		CertificateID:        cert.ID,
		CertificateVersionID: &renewal.ID,
		Reason:               JobReasonRenewal,
		NextRunAt:            time.Now().UTC(),
	})
	return err
}

func (s *Service) enqueueRenewalRecovery(ctx context.Context, cert Certificate, issuer issuerdomain.Issuer) error {
	if issuer.Status != issuerdomain.StatusActive || cert.Status == StatusRevoked || cert.Status == StatusFailed || cert.Status == StatusDeleted || cert.DeletedAt != nil {
		return nil
	}
	if err := s.requireDomainCoverage(ctx, cert.ApplicationID, cert.NormalizedSANs); err != nil {
		return nil
	}
	issuing, ok, err := s.latestIssuingVersion(ctx, cert.ID)
	if err != nil || (ok && issuing.Reason != IssuanceReasonRenewal) {
		return err
	}
	if ok {
		_, err = s.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
			CertificateID:        cert.ID,
			CertificateVersionID: &issuing.ID,
			Reason:               JobReasonRenewal,
			NextRunAt:            time.Now().UTC(),
		})
		return err
	}
	renewal, err := s.repo.CreateIssuingVersion(ctx, CreateIssuingVersionParams{CertificateID: cert.ID, Reason: IssuanceReasonRenewal})
	if err != nil {
		return err
	}
	if renewal.Reason != IssuanceReasonRenewal {
		return ErrConflict
	}
	_, err = s.repo.EnsureIssuanceJob(ctx, EnsureIssuanceJobParams{
		CertificateID:        cert.ID,
		CertificateVersionID: &renewal.ID,
		Reason:               JobReasonRenewal,
		NextRunAt:            time.Now().UTC(),
	})
	return err
}

func (s *Service) materialStateError(ctx context.Context, cert Certificate) error {
	if cert.Status == StatusRevoked {
		return StateError{Err: ErrCertificateRevoked, Certificate: cert}
	}
	if cert.Status == StatusFailed {
		return StateError{Err: ErrCertificateIssuanceFailed, Certificate: cert}
	}
	versions, err := s.repo.ListVersions(ctx, ListVersionsParams{CertificateID: cert.ID, ListOptions: storage.ListOptions{Limit: 1}})
	if err == nil && len(versions) > 0 {
		latest := versions[0]
		if latest.Status == VersionStatusIssuing {
			return StateError{Err: ErrCertificateNotReady, Certificate: cert, Version: &latest}
		}
		if latest.Status == VersionStatusFailed {
			return StateError{Err: ErrCertificateIssuanceFailed, Certificate: cert, Version: &latest}
		}
		return StateError{Err: ErrCertificateExpired, Certificate: cert, Version: &latest}
	}
	return StateError{Err: ErrCertificateNotReady, Certificate: cert}
}

func (s *Service) decryptPrivateKey(version CertificateVersion) (string, error) {
	if s.keys == nil || version.PrivateKeyPEMEncrypted == nil {
		return "", errors.New("private key unavailable")
	}
	plaintext, err := s.keys.OpenDatabaseValue(*version.PrivateKeyPEMEncrypted, certificatePrivateKeyAAD(version.ID))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *Service) AuditPrivateKeyRead(ctx context.Context, identityType auditdomain.IdentityType, identityID string, cert Certificate, version CertificateVersion, auditCtx AuditContext) error {
	if s.audit == nil {
		return nil
	}
	metadata, _ := json.Marshal(map[string]any{
		"certificate_version_id": version.ID,
		"version":                version.Version,
		"material_etag":          deref(version.MaterialETag),
	})
	_, err := s.audit.Append(ctx, auditdomain.AppendEventParams{
		IdentityType:       identityType,
		IdentityID:         &identityID,
		Action:             "private_key_read",
		TargetType:         "certificate_version",
		TargetID:           &version.ID,
		ScopeApplicationID: &cert.ApplicationID,
		ScopeCertificateID: &cert.ID,
		Result:             auditdomain.ResultSuccess,
		CorrelationID:      optionalString(auditCtx.CorrelationID),
		SourceIP:           optionalString(auditCtx.SourceIP),
		Metadata:           metadata,
	})
	return err
}

func (s *Service) visibleCertificate(ctx context.Context, actor Actor, id string, required roleRequirement, includeDeleted bool) (Certificate, error) {
	if err := s.ready(); err != nil {
		return Certificate{}, err
	}
	cert, err := s.repo.Get(ctx, id)
	if err != nil {
		return Certificate{}, ErrNotFound
	}
	if !includeDeleted && (cert.Status == StatusDeleted || cert.DeletedAt != nil) {
		return Certificate{}, ErrNotFound
	}
	if actor.admin() {
		return cert, nil
	}
	grant, err := s.apps.GetGrant(ctx, cert.ApplicationID, actor.ID)
	if err != nil {
		return Certificate{}, ErrNotFound
	}
	if !grantAllows(grant.Role, required) {
		return Certificate{}, ErrForbidden
	}
	return cert, nil
}

func (s *Service) requireApplicationRole(ctx context.Context, actor Actor, applicationID string, required appdomain.GrantRole, allowSystem bool) (appdomain.Application, error) {
	app, err := s.apps.Get(ctx, applicationID)
	if err != nil {
		return appdomain.Application{}, ErrNotFound
	}
	if app.Status != appdomain.StatusActive {
		return appdomain.Application{}, ErrNotFound
	}
	if !allowSystem && systemManagedApplication(app) {
		return appdomain.Application{}, ErrSystemManagedResource
	}
	if actor.admin() {
		return app, nil
	}
	grant, err := s.apps.GetGrant(ctx, applicationID, actor.ID)
	if err != nil {
		return appdomain.Application{}, ErrForbidden
	}
	if required == appdomain.GrantRoleManager && grant.Role != appdomain.GrantRoleManager {
		return appdomain.Application{}, ErrForbidden
	}
	return app, nil
}

func (s *Service) requireDomainCoverage(ctx context.Context, applicationID string, domains []string) error {
	scopes, err := s.apps.ListDomainScopes(ctx, applicationID, storage.ListOptions{Limit: storage.MaxListLimit})
	if err != nil {
		return classifyReadError(err)
	}
	coverage, err := appdomain.ScopesCoverIdentifiers(scopes, domains)
	if err != nil {
		return ErrInvalidRequest
	}
	if len(coverage.UncoveredIdentifiers) > 0 {
		return ErrDomainNotAuthorized
	}
	return nil
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil || s.apps == nil || s.issuers == nil {
		return ErrCertificateServiceUnavailable
	}
	return nil
}

func (s *Service) withWriteTx(ctx context.Context, fn func(*Service) error) error {
	if s.tx == nil {
		return fn(s)
	}
	return storage.WithTx(ctx, s.tx, func(ctx context.Context, tx storage.Tx) error {
		txsvc := *s
		txsvc.repo = NewRepository(tx)
		txsvc.apps = appdomain.NewRepository(tx)
		txsvc.issuers = issuerdomain.NewRepository(tx)
		if s.audit != nil {
			txsvc.audit = auditdomain.NewRepository(tx)
		}
		txsvc.tx = nil
		return fn(&txsvc)
	})
}

type roleRequirement int

const (
	roleViewer roleRequirement = iota
	roleCertificateReader
	roleManager
)

func grantAllows(role appdomain.GrantRole, required roleRequirement) bool {
	switch required {
	case roleViewer:
		return role == appdomain.GrantRoleViewer || role == appdomain.GrantRoleCertificateReader || role == appdomain.GrantRoleManager
	case roleCertificateReader:
		return role == appdomain.GrantRoleCertificateReader || role == appdomain.GrantRoleManager
	case roleManager:
		return role == appdomain.GrantRoleManager
	default:
		return false
	}
}

func buildMaterial(cert Certificate, issuer issuerdomain.Issuer, version CertificateVersion, privateKey string) (tlsmaterial.TLSMaterial, bool) {
	required := []*string{version.CertPEM, version.ChainPEM, version.FullchainPEM, version.SerialNumber, version.FingerprintSHA256, version.KeyFingerprintSHA256, version.MaterialETag}
	for _, value := range required {
		if value == nil || *value == "" {
			return tlsmaterial.TLSMaterial{}, false
		}
	}
	if version.NotBefore == nil || version.NotAfter == nil || privateKey == "" {
		return tlsmaterial.TLSMaterial{}, false
	}
	return tlsmaterial.TLSMaterial{
		CertificateID:        cert.ID,
		ApplicationID:        cert.ApplicationID,
		Domains:              cert.NormalizedSANs,
		KeyType:              string(cert.KeyType),
		IssuerID:             cert.IssuerID,
		IssuerName:           issuer.Name,
		Version:              version.Version,
		CertPEM:              *version.CertPEM,
		ChainPEM:             *version.ChainPEM,
		FullchainPEM:         *version.FullchainPEM,
		PrivateKeyPEM:        privateKey,
		NotBefore:            *version.NotBefore,
		NotAfter:             *version.NotAfter,
		SerialNumber:         *version.SerialNumber,
		FingerprintSHA256:    *version.FingerprintSHA256,
		KeyFingerprintSHA256: *version.KeyFingerprintSHA256,
		MaterialETag:         *version.MaterialETag,
	}, true
}

func certificatePrivateKeyAAD(versionID string) string {
	return "v1:table=certificate_versions:column=private_key_pem:row_id=" + versionID
}

func (a Actor) admin() bool {
	return a.GlobalRole == userdomain.GlobalRoleAdmin
}

func systemManagedApplication(app appdomain.Application) bool {
	return app.SystemKind != nil && *app.SystemKind == appdomain.SystemKindCerthubServer
}

func renewalNotBefore(notAfter time.Time, issuer issuerdomain.Issuer) time.Time {
	return notAfter.Add(-time.Duration(issuer.RenewalWindowSeconds) * time.Second)
}

func classifyReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNoRows) {
		return ErrNotFound
	}
	if strings.Contains(err.Error(), "must be") || strings.Contains(err.Error(), "invalid") {
		return ErrInvalidRequest
	}
	return err
}

func classifyWriteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNoRows) {
		return ErrNotFound
	}
	if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "constraint") {
		return ErrConflict
	}
	if strings.Contains(err.Error(), "must be") || strings.Contains(err.Error(), "invalid") {
		return ErrInvalidRequest
	}
	return err
}

func ptr[T any](v T) *T {
	return &v
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
