package selfcert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"certhub/internal/applications"
	"certhub/internal/audit"
	"certhub/internal/certificates"
	"certhub/internal/config"
	security "certhub/internal/crypto"
	"certhub/internal/issuers"
	"certhub/internal/storage"
	"certhub/pkg/certcriteria"
	tlsmaterial "certhub/pkg/material"
)

var (
	ErrDisabled          = errors.New("server self-certificate sync is disabled")
	ErrIssuerUnavailable = errors.New("server self-certificate issuer is unavailable")
	ErrMaterialPending   = errors.New("server self-certificate material is pending")
)

type ApplicationStore interface {
	EnsureSystemApplication(context.Context, applications.CreateApplicationParams) (applications.Application, error)
	ReplaceSystemDomainScopes(context.Context, string, string) ([]applications.DomainScope, error)
}

type CertificateStore interface {
	CreateOrReuse(context.Context, certificates.CreateOrReuseCertificateParams) (certificates.Certificate, error)
	List(context.Context, certificates.ListCertificatesParams) ([]certificates.Certificate, error)
	GetLatestValidMaterial(context.Context, string) (certificates.CertificateVersion, error)
	CreateIssuingVersion(context.Context, certificates.CreateIssuingVersionParams) (certificates.CertificateVersion, error)
	EnsureIssuanceJob(context.Context, certificates.EnsureIssuanceJobParams) (certificates.IssuanceJob, error)
	DeleteCertificate(context.Context, certificates.DeleteCertificateParams) (certificates.Certificate, error)
}

type IssuerStore interface {
	GetByName(context.Context, string) (issuers.Issuer, error)
}

type AuditAppender interface {
	Append(context.Context, audit.AppendEventParams) (audit.Event, error)
}

type TLSReloader interface {
	ReloadIfChanged() error
}

type RuntimeConfig struct {
	Enabled      bool
	Hostname     string
	OutputDir    string
	Issuer       string
	KeyType      string
	SyncInterval time.Duration
}

func RuntimeConfigFromConfig(cfg *config.Config) RuntimeConfig {
	if cfg == nil {
		return RuntimeConfig{}
	}
	return RuntimeConfig{
		Enabled:      cfg.SelfCertificate.SyncEnabled,
		Hostname:     cfg.Server.PublicHostname,
		OutputDir:    cfg.SelfCertificate.OutputDir,
		Issuer:       cfg.SelfCertificate.Issuer,
		KeyType:      cfg.SelfCertificate.KeyType,
		SyncInterval: time.Duration(cfg.SelfCertificate.SyncIntervalSeconds) * time.Second,
	}
}

type ServiceConfig struct {
	Runtime     RuntimeConfig
	DB          storage.DBTX
	Storage     storage.Beginner
	KeySet      *security.KeySet
	TLSReloader TLSReloader
	LogWriter   io.Writer
}

type Service struct {
	cfg    ServiceConfig
	status Status
}

type DesiredState struct {
	Application applications.Application
	Certificate certificates.Certificate
	Issuer      issuers.Issuer
	Hostname    string
	KeyType     certificates.KeyType
}

type Result struct {
	ApplicationID        string
	CertificateID        string
	CertificateVersionID string
	MaterialETag         string
	Published            bool
	ReleaseDir           string
}

func NewService(cfg ServiceConfig) *Service {
	if cfg.LogWriter == nil {
		cfg.LogWriter = io.Discard
	}
	return &Service{cfg: cfg, status: Status{State: "pending", Reason: "not_synced"}}
}

func (s *Service) Status() Status {
	return s.status.snapshot()
}

func (s *Service) Metrics() Metrics {
	return s.status.metrics()
}

func (s *Service) SyncOnce(ctx context.Context) (Result, error) {
	if s == nil || !s.cfg.Runtime.Enabled {
		return Result{}, ErrDisabled
	}
	if s.cfg.DB == nil || s.cfg.Storage == nil || s.cfg.KeySet == nil {
		err := errors.New("server self-certificate dependencies are unavailable")
		s.status.record("failed", "dependencies_unavailable", err)
		return Result{}, err
	}

	var desired DesiredState
	err := storage.WithTx(ctx, s.cfg.Storage, func(ctx context.Context, tx storage.Tx) error {
		reconciler := Reconciler{
			Runtime: s.cfg.Runtime,
			Apps:    applications.NewRepository(tx),
			Certs:   certificates.NewRepository(tx),
			Issuers: issuers.NewRepository(tx),
		}
		var err error
		desired, err = reconciler.ReconcileDesired(ctx)
		return err
	})
	if err != nil {
		s.status.record("failed", failureReason(err), err)
		return Result{}, err
	}

	reconciler := Reconciler{
		Runtime: s.cfg.Runtime,
		Certs:   certificates.NewRepository(s.cfg.DB),
		Issuers: issuers.NewRepository(s.cfg.DB),
		KeySet:  s.cfg.KeySet,
	}
	material, version, err := reconciler.LatestMaterial(ctx, desired.Certificate)
	if err != nil {
		s.status.record("pending", failureReason(err), err)
		return Result{
			ApplicationID: desired.Application.ID,
			CertificateID: desired.Certificate.ID,
		}, err
	}

	published, err := Publish(ctx, PublishOptions{
		OutputDir: s.cfg.Runtime.OutputDir,
		Material:  material,
		Now:       time.Now,
	})
	if err != nil {
		s.status.record("failed", "publish_failed", err)
		return Result{}, err
	}
	if s.cfg.TLSReloader != nil {
		if err := s.cfg.TLSReloader.ReloadIfChanged(); err != nil {
			s.status.record("failed", "tls_reload_failed", err)
			return Result{}, err
		}
	}
	if err := appendSyncedAudit(ctx, audit.NewRepository(s.cfg.DB), desired, version, material, published); err != nil {
		s.status.record("failed", "audit_failed", err)
		return Result{}, err
	}
	result := Result{
		ApplicationID:        desired.Application.ID,
		CertificateID:        desired.Certificate.ID,
		CertificateVersionID: version.ID,
		MaterialETag:         material.MaterialETag,
		Published:            true,
		ReleaseDir:           published.ReleaseDir,
	}
	s.status.recordSuccess(result)
	return result, nil
}

type Reconciler struct {
	Runtime RuntimeConfig
	Apps    ApplicationStore
	Certs   CertificateStore
	Issuers IssuerStore
	KeySet  *security.KeySet
}

func (r Reconciler) ReconcileDesired(ctx context.Context) (DesiredState, error) {
	if !r.Runtime.Enabled {
		return DesiredState{}, ErrDisabled
	}
	normalized, err := certcriteria.Normalize(certcriteria.Criteria{
		Domains: []string{r.Runtime.Hostname},
		KeyType: r.Runtime.KeyType,
		Issuer:  r.Runtime.Issuer,
	})
	if err != nil {
		return DesiredState{}, err
	}
	issuer, err := r.Issuers.GetByName(ctx, normalized.Issuer)
	if err != nil || issuer.Status != issuers.StatusActive {
		return DesiredState{}, ErrIssuerUnavailable
	}
	description := "Certhub serving certificate managed by process configuration."
	app, err := r.Apps.EnsureSystemApplication(ctx, applications.CreateApplicationParams{
		DisplayName: "Certhub Server",
		Description: &description,
	})
	if err != nil {
		return DesiredState{}, err
	}
	if _, err := r.Apps.ReplaceSystemDomainScopes(ctx, app.ID, normalized.Domains[0]); err != nil {
		return DesiredState{}, err
	}
	certs, err := r.Certs.List(ctx, certificates.ListCertificatesParams{
		ListOptions:   storage.ListOptions{Limit: storage.MaxListLimit},
		ApplicationID: &app.ID,
	})
	if err != nil {
		return DesiredState{}, err
	}
	var desired *certificates.Certificate
	for i := range certs {
		cert := certs[i]
		if matchesDesired(cert, issuer.ID, normalized) {
			if desired == nil {
				desired = &cert
			}
			continue
		}
		if _, err := r.Certs.DeleteCertificate(ctx, certificates.DeleteCertificateParams{ID: cert.ID}); err != nil {
			return DesiredState{}, err
		}
	}
	if desired == nil {
		cert, err := r.Certs.CreateOrReuse(ctx, certificates.CreateOrReuseCertificateParams{
			ApplicationID:  app.ID,
			IssuerID:       issuer.ID,
			NormalizedSANs: normalized.Domains,
			KeyType:        certificates.KeyType(normalized.KeyType),
			Status:         certificates.StatusPending,
		})
		if err != nil {
			return DesiredState{}, err
		}
		desired = &cert
	}
	if shouldEnsureInitialIssuance(*desired) {
		version, err := r.Certs.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
			CertificateID: desired.ID,
			Reason:        certificates.IssuanceReasonInitialIssue,
		})
		if err != nil {
			return DesiredState{}, err
		}
		if _, err := r.Certs.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
			CertificateID:        desired.ID,
			CertificateVersionID: &version.ID,
			Reason:               certificates.JobReasonInitialIssue,
			NextRunAt:            time.Now().UTC(),
		}); err != nil {
			return DesiredState{}, err
		}
	}
	return DesiredState{
		Application: app,
		Certificate: *desired,
		Issuer:      issuer,
		Hostname:    normalized.Domains[0],
		KeyType:     certificates.KeyType(normalized.KeyType),
	}, nil
}

func (r Reconciler) LatestMaterial(ctx context.Context, cert certificates.Certificate) (tlsmaterial.TLSMaterial, certificates.CertificateVersion, error) {
	if cert.Status == certificates.StatusDeleted || cert.DeletedAt != nil || cert.Status == certificates.StatusRevoked {
		return tlsmaterial.TLSMaterial{}, certificates.CertificateVersion{}, ErrMaterialPending
	}
	version, err := r.Certs.GetLatestValidMaterial(ctx, cert.ID)
	if err != nil {
		return tlsmaterial.TLSMaterial{}, certificates.CertificateVersion{}, ErrMaterialPending
	}
	if r.KeySet == nil || version.PrivateKeyPEMEncrypted == nil {
		return tlsmaterial.TLSMaterial{}, certificates.CertificateVersion{}, ErrMaterialPending
	}
	privateKey, err := r.KeySet.OpenDatabaseValue(*version.PrivateKeyPEMEncrypted, privateKeyAAD(version.ID))
	if err != nil {
		return tlsmaterial.TLSMaterial{}, certificates.CertificateVersion{}, err
	}
	issuer, err := r.Issuers.GetByName(ctx, r.Runtime.Issuer)
	if err != nil {
		return tlsmaterial.TLSMaterial{}, certificates.CertificateVersion{}, ErrIssuerUnavailable
	}
	material, ok := buildMaterial(cert, issuer, version, string(privateKey))
	if !ok {
		return tlsmaterial.TLSMaterial{}, certificates.CertificateVersion{}, ErrMaterialPending
	}
	return material, version, nil
}

func appendSyncedAudit(ctx context.Context, appender AuditAppender, desired DesiredState, version certificates.CertificateVersion, material tlsmaterial.TLSMaterial, published PublishResult) error {
	if appender == nil {
		return nil
	}
	metadata, _ := json.Marshal(map[string]any{
		"certificate_version_id": version.ID,
		"version":                version.Version,
		"material_etag":          material.MaterialETag,
		"release_dir":            filepath.Base(published.ReleaseDir),
		"current_symlink":        "current",
		"files": []map[string]any{
			{"name": "cert.pem", "mode": "0644"},
			{"name": "chain.pem", "mode": "0644"},
			{"name": "fullchain.pem", "mode": "0644"},
			{"name": "privkey.pem", "mode": "0600"},
			{"name": ".certhub-material.json", "mode": "0644"},
		},
	})
	targetID := version.ID
	_, err := appender.Append(ctx, audit.AppendEventParams{
		IdentityType:       audit.IdentityTypeSystem,
		Action:             "server_self_certificate_synced",
		TargetType:         "certificate_version",
		TargetID:           &targetID,
		ScopeApplicationID: &desired.Application.ID,
		ScopeCertificateID: &desired.Certificate.ID,
		Result:             audit.ResultSuccess,
		Metadata:           metadata,
	})
	return err
}

func matchesDesired(cert certificates.Certificate, issuerID string, normalized certcriteria.Normalized) bool {
	if cert.IssuerID != issuerID || cert.KeyType != certificates.KeyType(normalized.KeyType) {
		return false
	}
	if len(cert.NormalizedSANs) != len(normalized.Domains) {
		return false
	}
	for i := range normalized.Domains {
		if cert.NormalizedSANs[i] != normalized.Domains[i] {
			return false
		}
	}
	return true
}

func shouldEnsureInitialIssuance(cert certificates.Certificate) bool {
	switch cert.Status {
	case certificates.StatusPending, certificates.StatusValidatingDNS, certificates.StatusIssuing:
		return true
	default:
		return false
	}
}

func buildMaterial(cert certificates.Certificate, issuer issuers.Issuer, version certificates.CertificateVersion, privateKey string) (tlsmaterial.TLSMaterial, bool) {
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

func privateKeyAAD(versionID string) string {
	return "v1:table=certificate_versions:column=private_key_pem:row_id=" + versionID
}

func failureReason(err error) string {
	switch {
	case errors.Is(err, ErrIssuerUnavailable):
		return "issuer_unavailable"
	case errors.Is(err, ErrMaterialPending):
		return "material_pending"
	default:
		return "sync_failed"
	}
}

type Status struct {
	mu           sync.Mutex
	State        string
	Reason       string
	LastError    string
	LastSuccess  time.Time
	LastETag     string
	SuccessTotal int64
	FailureTotal int64
	PendingTotal int64
}

type Metrics struct {
	SuccessTotal int64
	FailureTotal int64
	PendingTotal int64
	LastSuccess  time.Time
}

func (s *Status) snapshot() Status {
	if s == nil {
		return Status{State: "disabled", Reason: "disabled"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{State: s.State, Reason: s.Reason, LastError: s.LastError, LastSuccess: s.LastSuccess, LastETag: s.LastETag, SuccessTotal: s.SuccessTotal, FailureTotal: s.FailureTotal, PendingTotal: s.PendingTotal}
}

func (s *Status) metrics() Metrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Metrics{SuccessTotal: s.SuccessTotal, FailureTotal: s.FailureTotal, PendingTotal: s.PendingTotal, LastSuccess: s.LastSuccess}
}

func (s *Status) record(state, reason string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = state
	s.Reason = reason
	s.LastETag = ""
	if err != nil {
		s.LastError = security.RedactString(err.Error())
	}
	switch state {
	case "pending":
		s.PendingTotal++
	case "failed":
		s.FailureTotal++
	}
}

func (s *Status) recordSuccess(result Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = "ok"
	s.Reason = "synced"
	s.LastError = ""
	s.LastETag = result.MaterialETag
	s.LastSuccess = time.Now().UTC()
	s.SuccessTotal++
}

func (s Status) ReadinessStatus() string {
	if s.State == "" {
		return "pending"
	}
	if s.State == "ok" {
		return "ok"
	}
	return "failed"
}

func (s Status) Error() string {
	if s.LastError != "" {
		return s.LastError
	}
	if s.Reason != "" {
		return s.Reason
	}
	return fmt.Sprintf("state=%s", s.State)
}
