package workers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	acmedomain "github.com/torob/certhub/internal/acme"
	"github.com/torob/certhub/internal/certificates"
	security "github.com/torob/certhub/internal/crypto"
	dnsdomain "github.com/torob/certhub/internal/dnsproviders"
	issuerdomain "github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
)

const (
	defaultIssuanceLeaseDuration = 20 * time.Minute
	defaultDNSChallengeTTL       = 120
	defaultIssuanceMaxAttempts   = 5
	defaultIssuanceRetryBackoff  = 30 * time.Second
)

type CertificateIssuanceStore interface {
	ClaimNextIssuanceJob(context.Context, certificates.ClaimIssuanceJobParams) (certificates.IssuanceJob, error)
	Get(context.Context, string) (certificates.Certificate, error)
	GetVersion(context.Context, string) (certificates.CertificateVersion, error)
	ListVersions(context.Context, certificates.ListVersionsParams) ([]certificates.CertificateVersion, error)
	CreateIssuingVersion(context.Context, certificates.CreateIssuingVersionParams) (certificates.CertificateVersion, error)
	AttachIssuingVersionToJob(context.Context, certificates.AttachIssuingVersionToJobParams) (certificates.IssuanceJob, error)
	PrepareIssuingVersion(context.Context, certificates.PrepareIssuingVersionParams) (certificates.CertificateVersion, error)
	UpdateCertificateIssuanceStatus(context.Context, certificates.UpdateCertificateIssuanceStatusParams) (certificates.Certificate, error)
	StoreMaterial(context.Context, certificates.StoreMaterialParams) (certificates.CertificateVersion, error)
	EnsureIssuanceJob(context.Context, certificates.EnsureIssuanceJobParams) (certificates.IssuanceJob, error)
	SucceedIssuanceJob(context.Context, certificates.SucceedIssuanceJobParams) (certificates.IssuanceJob, error)
	FailIssuanceJob(context.Context, certificates.FailIssuanceJobParams) (certificates.IssuanceJob, error)
	RecordDNSChallenge(context.Context, certificates.RecordDNSChallengeParams) (certificates.DNSChallengeRecord, error)
	MarkDNSChallengePresented(context.Context, certificates.MarkDNSChallengePresentedParams) (certificates.DNSChallengeRecord, error)
	MarkDNSChallengeCleanup(context.Context, certificates.MarkDNSChallengeCleanupParams) (certificates.DNSChallengeRecord, error)
	ListDNSChallenges(context.Context, certificates.ListDNSChallengesParams) ([]certificates.DNSChallengeRecord, error)
	MarkACMERevocationSucceeded(context.Context, certificates.MarkACMERevocationParams) (certificates.CertificateVersion, error)
	MarkACMERevocationFailed(context.Context, certificates.MarkACMERevocationParams) (certificates.CertificateVersion, error)
	RecordEvent(context.Context, certificates.RecordEventParams) (certificates.Event, error)
}

type IssuanceIssuerStore interface {
	Get(context.Context, string) (issuerdomain.Issuer, error)
	GetActiveACMEAccount(context.Context, string) (issuerdomain.ACMEAccount, error)
}

type IssuanceDNSStore interface {
	FindZoneForDNSName(context.Context, string) (dnsdomain.ZoneMatch, error)
	Get(context.Context, string) (dnsdomain.Provider, error)
	GetCredentialsEncrypted(context.Context, string) (string, error)
	ListZones(context.Context, string, storage.ListOptions) ([]dnsdomain.Zone, error)
}

type CertificateIssuanceService struct {
	Certificates       CertificateIssuanceStore
	Issuers            IssuanceIssuerStore
	DNSProviders       IssuanceDNSStore
	OrderManager       acmedomain.OrderManager
	Cloudflare         dnsdomain.CloudflareChallengeOperator
	ArvanCloud         dnsdomain.ArvanCloudChallengeOperator
	KeySet             *security.KeySet
	LeaseDuration      time.Duration
	OrderTimeout       time.Duration
	PropagationTimeout time.Duration
	PropagationPoll    time.Duration
	DNSChallengeTTL    int
	TXTVisible         func(context.Context, string, string) (bool, error)
	MaxAttempts        int
	RetryBackoff       time.Duration
}

type CertificateIssuanceConfig struct {
	Service      *CertificateIssuanceService
	Concurrency  int
	PollInterval time.Duration
	LogWriter    io.Writer
	WorkerPrefix string
}

type CertificateIssuanceRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type issuanceFailure struct {
	code       string
	err        error
	redactions []string
}

func (e issuanceFailure) Error() string { return e.err.Error() }
func (e issuanceFailure) Unwrap() error { return e.err }

func StartCertificateIssuanceWorkers(ctx context.Context, cfg CertificateIssuanceConfig) (*CertificateIssuanceRunner, error) {
	if cfg.Service == nil {
		return nil, fmt.Errorf("certificate issuance service is required")
	}
	if cfg.Concurrency <= 0 {
		return nil, fmt.Errorf("certificate issuance worker concurrency must be positive")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.LogWriter == nil {
		cfg.LogWriter = io.Discard
	}
	if cfg.WorkerPrefix == "" {
		cfg.WorkerPrefix = "cert-issuer"
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runner := &CertificateIssuanceRunner{cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		workerID := fmt.Sprintf("%s-%d", cfg.WorkerPrefix, i+1)
		go func() {
			defer wg.Done()
			runCertificateIssuanceWorker(workerCtx, cfg.Service, cfg.PollInterval, cfg.LogWriter, workerID)
		}()
	}
	go func() {
		wg.Wait()
		close(runner.done)
	}()
	return runner, nil
}

func (r *CertificateIssuanceRunner) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *CertificateIssuanceService) CompleteNextIssuanceJob(ctx context.Context, workerID string) (certificates.IssuanceJob, bool, error) {
	if err := s.ready(); err != nil {
		return certificates.IssuanceJob{}, false, err
	}
	lease := s.LeaseDuration
	if lease <= 0 {
		lease = defaultIssuanceLeaseDuration
	}
	job, err := s.Certificates.ClaimNextIssuanceJob(ctx, certificates.ClaimIssuanceJobParams{
		WorkerID:    workerID,
		LockedUntil: time.Now().UTC().Add(lease),
	})
	if err != nil {
		if errors.Is(err, storage.ErrNoRows) {
			return certificates.IssuanceJob{}, false, nil
		}
		return certificates.IssuanceJob{}, false, err
	}
	_ = s.recordEvent(ctx, job, "certificate_issuance_started", certificates.EventResultSuccess, nil)
	if err := s.completeClaimedJob(ctx, workerID, job); err != nil {
		_ = s.cleanupRecordedChallenges(ctx, job)
		code, message := sanitizedFailure(err)
		retryable := retryableIssuanceFailure(code)
		failed, failErr := s.Certificates.FailIssuanceJob(ctx, certificates.FailIssuanceJobParams{
			JobID:          job.ID,
			WorkerID:       workerID,
			FailureCode:    code,
			FailureMessage: &message,
			Retryable:      retryable,
			MaxAttempts:    s.maxAttempts(),
			RetryAfter:     s.retryBackoff(job.Attempt),
		})
		_ = s.recordEvent(ctx, job, "certificate_issuance_failed", certificates.EventResultFailure, map[string]any{
			"failure_code":             code,
			"failure_message":          message,
			"retryable":                retryable,
			"job_status_after_failure": string(failed.Status),
			"next_run_at":              failed.NextRunAt,
		})
		if failErr != nil {
			return failed, true, failErr
		}
		return failed, true, err
	}
	succeeded, err := s.Certificates.SucceedIssuanceJob(ctx, certificates.SucceedIssuanceJobParams{JobID: job.ID, WorkerID: workerID})
	if err != nil {
		return succeeded, true, err
	}
	_ = s.recordEvent(ctx, job, "certificate_issuance_succeeded", certificates.EventResultSuccess, nil)
	if shouldEnqueueDNSCleanup(job.Reason) {
		if _, err := s.Certificates.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
			CertificateID: job.CertificateID,
			Reason:        certificates.JobReasonDNSCleanup,
			NextRunAt:     time.Now().UTC(),
		}); err != nil {
			_ = s.recordEvent(ctx, job, "certificate_dns_cleanup_enqueue_failed", certificates.EventResultFailure, map[string]any{
				"failure_code": "dns_cleanup_enqueue_failed",
			})
		}
	}
	return succeeded, true, nil
}

func shouldEnqueueDNSCleanup(reason certificates.JobReason) bool {
	switch reason {
	case certificates.JobReasonInitialIssue, certificates.JobReasonRenewal, certificates.JobReasonKeyRotation, certificates.JobReasonReissue:
		return true
	default:
		return false
	}
}

func runCertificateIssuanceWorker(ctx context.Context, service *CertificateIssuanceService, pollInterval time.Duration, logWriter io.Writer, workerID string) {
	for {
		processed, err := completeOneCertificateIssuanceJob(ctx, service, workerID)
		if err != nil {
			fmt.Fprintf(logWriter, "certificate issuance worker failed worker_id=%s error=%s\n", workerID, security.RedactString(err.Error()))
		}
		if processed && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func completeOneCertificateIssuanceJob(ctx context.Context, service *CertificateIssuanceService, workerID string) (bool, error) {
	_, processed, err := service.CompleteNextIssuanceJob(ctx, workerID)
	if err != nil {
		if ctx.Err() != nil {
			return false, nil
		}
		return processed, err
	}
	return processed, nil
}

func (s *CertificateIssuanceService) ready() error {
	switch {
	case s == nil, s.Certificates == nil, s.Issuers == nil, s.DNSProviders == nil, s.OrderManager == nil, s.KeySet == nil:
		return fmt.Errorf("certificate issuance service dependencies are required")
	case s.Cloudflare == nil:
		return fmt.Errorf("cloudflare challenge operator is required")
	case s.ArvanCloud == nil:
		return fmt.Errorf("arvancloud challenge operator is required")
	default:
		return nil
	}
}

func (s *CertificateIssuanceService) completeClaimedJob(ctx context.Context, workerID string, job certificates.IssuanceJob) error {
	if job.Reason == certificates.JobReasonDNSCleanup {
		return s.cleanupPendingChallenges(ctx)
	}
	if job.Reason == certificates.JobReasonRevocationRetry {
		return s.completeRevocationRetry(ctx, job)
	}
	cert, err := s.Certificates.Get(ctx, job.CertificateID)
	if err != nil {
		return issuanceFailure{code: "certificate_not_found", err: err}
	}
	version, job, err := s.ensureJobVersion(ctx, workerID, job)
	if err != nil {
		return err
	}
	if version.Status == certificates.VersionStatusValid {
		return nil
	}
	if version.Status != certificates.VersionStatusIssuing {
		return issuanceFailure{code: "certificate_version_not_issuing", err: fmt.Errorf("certificate version status is %s", version.Status)}
	}
	issuer, err := s.Issuers.Get(ctx, cert.IssuerID)
	if err != nil {
		return issuanceFailure{code: "issuer_not_configured", err: err}
	}
	account, err := s.Issuers.GetActiveACMEAccount(ctx, issuer.ID)
	if err != nil {
		return issuanceFailure{code: "issuer_account_not_configured", err: err}
	}
	accountKeyPEM, err := s.KeySet.OpenDatabaseValue(account.PrivateKeyPEMEncrypted, acmeAccountPrivateKeyAAD(account.ID))
	if err != nil {
		return issuanceFailure{code: "issuer_account_unavailable", err: err}
	}
	signer, privateKeyPEM, keyFingerprint, err := s.versionPrivateKey(version, cert.KeyType)
	if err != nil {
		return err
	}
	orderParams := acmedomain.OrderClientParams{
		DirectoryURL:         issuer.DirectoryURL,
		AccountURL:           account.AccountURL,
		AccountPrivateKeyPEM: accountKeyPEM,
	}
	order, err := s.orderForVersion(ctx, orderParams, version, cert.NormalizedSANs)
	if err != nil {
		return err
	}
	encryptedKey := deref(version.PrivateKeyPEMEncrypted)
	if encryptedKey == "" {
		encryptedKey, err = s.KeySet.SealDatabaseValue([]byte(privateKeyPEM), certificatePrivateKeyAAD(version.ID))
		if err != nil {
			return issuanceFailure{code: "private_key_encrypt_failed", err: err}
		}
	}
	version, err = s.Certificates.PrepareIssuingVersion(ctx, certificates.PrepareIssuingVersionParams{
		CertificateVersionID:   version.ID,
		PrivateKeyPEMEncrypted: encryptedKey,
		KeyFingerprintSHA256:   keyFingerprint,
		ACMEOrderURL:           order.URL,
	})
	if err != nil {
		return issuanceFailure{code: "certificate_version_prepare_failed", err: err}
	}
	_, _ = s.Certificates.UpdateCertificateIssuanceStatus(ctx, certificates.UpdateCertificateIssuanceStatusParams{CertificateID: cert.ID, Status: certificates.StatusValidatingDNS})
	if err := s.presentAndValidate(ctx, orderParams, job, version, order); err != nil {
		return err
	}
	_, _ = s.Certificates.UpdateCertificateIssuanceStatus(ctx, certificates.UpdateCertificateIssuanceStatusParams{CertificateID: cert.ID, Status: certificates.StatusIssuing})
	csrDER, err := csrForCertificate(signer, cert.NormalizedSANs)
	if err != nil {
		return issuanceFailure{code: "csr_generation_failed", err: err}
	}
	bundle, err := s.finalizeOrder(ctx, orderParams, order, csrDER)
	if err != nil {
		return err
	}
	material, err := materialFromBundle(bundle, privateKeyPEM, keyFingerprint, s.KeySet)
	if err != nil {
		return err
	}
	_, err = s.Certificates.StoreMaterial(ctx, certificates.StoreMaterialParams{
		JobID:                  job.ID,
		WorkerID:               workerID,
		CertificateVersionID:   version.ID,
		CertPEM:                material.certPEM,
		ChainPEM:               material.chainPEM,
		FullchainPEM:           material.fullchainPEM,
		PrivateKeyPEMEncrypted: encryptedKey,
		NotBefore:              material.notBefore,
		NotAfter:               material.notAfter,
		SerialNumber:           material.serialNumber,
		FingerprintSHA256:      material.fingerprint,
		KeyFingerprintSHA256:   keyFingerprint,
		MaterialETag:           material.etag,
		ACMEOrderURL:           &order.URL,
		CertificateURL:         optionalString(bundle.CertificateURL),
	})
	if err != nil {
		return issuanceFailure{code: "certificate_material_store_failed", err: err}
	}
	return nil
}

func (s *CertificateIssuanceService) ensureJobVersion(ctx context.Context, workerID string, job certificates.IssuanceJob) (certificates.CertificateVersion, certificates.IssuanceJob, error) {
	if job.CertificateVersionID != nil && *job.CertificateVersionID != "" {
		version, err := s.Certificates.GetVersion(ctx, *job.CertificateVersionID)
		if err != nil {
			return certificates.CertificateVersion{}, job, issuanceFailure{code: "certificate_version_not_found", err: err}
		}
		return version, job, nil
	}
	reason := certificates.IssuanceReasonInitialIssue
	switch job.Reason {
	case certificates.JobReasonRenewal:
		reason = certificates.IssuanceReasonRenewal
	case certificates.JobReasonKeyRotation:
		reason = certificates.IssuanceReasonKeyRotation
	case certificates.JobReasonReissue:
		reason = certificates.IssuanceReasonReissue
	}
	version, err := s.Certificates.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
		CertificateID: job.CertificateID,
		Reason:        reason,
	})
	if err != nil {
		return certificates.CertificateVersion{}, job, issuanceFailure{code: "certificate_version_create_failed", err: err}
	}
	attached, err := s.Certificates.AttachIssuingVersionToJob(ctx, certificates.AttachIssuingVersionToJobParams{
		JobID:                job.ID,
		WorkerID:             workerID,
		CertificateVersionID: version.ID,
	})
	if err != nil {
		return certificates.CertificateVersion{}, job, issuanceFailure{code: "issuance_job_update_failed", err: err}
	}
	job = attached
	return version, job, nil
}

func (s *CertificateIssuanceService) completeRevocationRetry(ctx context.Context, job certificates.IssuanceJob) error {
	cert, err := s.Certificates.Get(ctx, job.CertificateID)
	if err != nil {
		return issuanceFailure{code: "certificate_not_found", err: err}
	}
	issuer, err := s.Issuers.Get(ctx, cert.IssuerID)
	if err != nil {
		return issuanceFailure{code: "issuer_not_configured", err: err}
	}
	account, err := s.Issuers.GetActiveACMEAccount(ctx, issuer.ID)
	if err != nil {
		return issuanceFailure{code: "issuer_account_not_configured", err: err}
	}
	accountKeyPEM, err := s.KeySet.OpenDatabaseValue(account.PrivateKeyPEMEncrypted, acmeAccountPrivateKeyAAD(account.ID))
	if err != nil {
		return issuanceFailure{code: "issuer_account_unavailable", err: err}
	}
	versions, err := s.Certificates.ListVersions(ctx, certificates.ListVersionsParams{
		CertificateID: cert.ID,
		ListOptions:   storage.ListOptions{Limit: storage.MaxListLimit},
	})
	if err != nil {
		return issuanceFailure{code: "certificate_versions_unavailable", err: err}
	}
	params := acmedomain.OrderClientParams{
		DirectoryURL:         issuer.DirectoryURL,
		AccountURL:           account.AccountURL,
		AccountPrivateKeyPEM: accountKeyPEM,
	}
	var retryErr error
	for _, version := range versions {
		if version.Status != certificates.VersionStatusRevoked || version.CertPEM == nil {
			continue
		}
		if version.ACMERevocationStatus != nil && *version.ACMERevocationStatus == certificates.ACMERemoteRevocationSucceeded {
			continue
		}
		certDER, err := firstCertificateDER(*version.CertPEM)
		if err != nil {
			msg := optionalMessage(err)
			_, _ = s.Certificates.MarkACMERevocationFailed(ctx, certificates.MarkACMERevocationParams{CertificateVersionID: version.ID, FailureCode: "acme_revocation_certificate_invalid", FailureMessage: msg})
			retryErr = errors.Join(retryErr, issuanceFailure{code: "acme_revocation_certificate_invalid", err: err})
			continue
		}
		orderCtx, cancel := s.orderContext(ctx)
		err = s.OrderManager.RevokeCertificate(orderCtx, acmedomain.RevokeCertificateParams{
			OrderClientParams: params,
			CertificateDER:    certDER,
			Reason:            0,
		})
		cancel()
		if err != nil {
			msg := optionalMessage(err)
			_, _ = s.Certificates.MarkACMERevocationFailed(ctx, certificates.MarkACMERevocationParams{CertificateVersionID: version.ID, FailureCode: "acme_revocation_failed", FailureMessage: msg})
			retryErr = errors.Join(retryErr, issuanceFailure{code: "acme_revocation_failed", err: err})
			continue
		}
		if _, err := s.Certificates.MarkACMERevocationSucceeded(ctx, certificates.MarkACMERevocationParams{CertificateVersionID: version.ID}); err != nil {
			retryErr = errors.Join(retryErr, issuanceFailure{code: "acme_revocation_record_failed", err: err})
		}
	}
	return retryErr
}

func (s *CertificateIssuanceService) orderForVersion(ctx context.Context, params acmedomain.OrderClientParams, version certificates.CertificateVersion, sans []string) (acmedomain.Order, error) {
	orderCtx, cancel := s.orderContext(ctx)
	defer cancel()
	if version.ACMEOrderURL != nil && *version.ACMEOrderURL != "" {
		order, err := s.OrderManager.FetchOrder(orderCtx, acmedomain.FetchOrderParams{OrderClientParams: params, OrderURL: *version.ACMEOrderURL})
		if err != nil {
			return acmedomain.Order{}, issuanceFailure{code: "acme_order_fetch_failed", err: err}
		}
		return order, nil
	}
	order, err := s.OrderManager.CreateOrder(orderCtx, acmedomain.CreateOrderParams{OrderClientParams: params, Identifiers: sans})
	if err != nil {
		return acmedomain.Order{}, issuanceFailure{code: "acme_order_create_failed", err: err}
	}
	if order.URL == "" || order.FinalizeURL == "" {
		return acmedomain.Order{}, issuanceFailure{code: "acme_order_invalid", err: errors.New("acme order is missing required URLs")}
	}
	return order, nil
}

func (s *CertificateIssuanceService) presentAndValidate(ctx context.Context, params acmedomain.OrderClientParams, job certificates.IssuanceJob, version certificates.CertificateVersion, order acmedomain.Order) error {
	if len(order.AuthorizationURLs) == 0 {
		return issuanceFailure{code: "acme_authorization_missing", err: errors.New("acme order has no authorizations")}
	}
	challenges := make([]dnsAuthorizationChallenge, 0, len(order.AuthorizationURLs))
	for _, authzURL := range order.AuthorizationURLs {
		authz, err := s.OrderManager.FetchAuthorization(ctx, acmedomain.FetchAuthorizationParams{OrderClientParams: params, AuthorizationURL: authzURL})
		if err != nil {
			return issuanceFailure{code: "acme_authorization_fetch_failed", err: err}
		}
		if strings.EqualFold(authz.Status, "valid") {
			continue
		}
		if authz.DNSChallenge == nil {
			return issuanceFailure{code: "dns_challenge_missing", err: errors.New("acme authorization has no dns-01 challenge")}
		}
		challenge, err := s.ensureChallengeRecord(ctx, job, version, authz)
		if err != nil {
			return err
		}
		challenges = append(challenges, challenge)
	}
	for i := range challenges {
		if !challengeNeedsPresent(challenges[i].record.Status) {
			continue
		}
		if err := s.presentDNSChallenge(ctx, challenges[i].provider, challenges[i].op); err != nil {
			return err
		}
		record, err := s.Certificates.MarkDNSChallengePresented(ctx, certificates.MarkDNSChallengePresentedParams{ID: challenges[i].record.ID})
		if err != nil {
			return issuanceFailure{code: "dns_challenge_record_update_failed", err: err}
		}
		challenges[i].record = record
	}
	for _, challenge := range challenges {
		if err := s.waitForPropagation(ctx, challenge.op.RecordName, challenge.op.TXTValue); err != nil {
			return err
		}
	}
	for _, challenge := range challenges {
		if err := s.OrderManager.AcceptChallenge(ctx, acmedomain.AcceptChallengeParams{
			OrderClientParams: params,
			ChallengeURL:      challenge.authz.DNSChallenge.URL,
			Token:             challenge.authz.DNSChallenge.Token,
		}); err != nil {
			return issuanceFailure{code: "dns_validation_failed", err: err, redactions: []string{challenge.authz.DNSChallenge.Token, challenge.op.TXTValue}}
		}
		if _, err := s.Certificates.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{
			ID:     challenge.record.ID,
			Status: certificates.DNSChallengeStatusCleanupPending,
		}); err != nil {
			return issuanceFailure{code: "dns_challenge_record_update_failed", err: err}
		}
	}
	return nil
}

type dnsAuthorizationChallenge struct {
	authz    acmedomain.Authorization
	record   certificates.DNSChallengeRecord
	op       dnsdomain.DNS01ChallengeOperation
	provider dnsdomain.Provider
}

func (s *CertificateIssuanceService) ensureChallengeRecord(ctx context.Context, job certificates.IssuanceJob, version certificates.CertificateVersion, authz acmedomain.Authorization) (dnsAuthorizationChallenge, error) {
	dnsName, err := authorizationDNSName(authz)
	if err != nil {
		return dnsAuthorizationChallenge{}, issuanceFailure{code: "acme_authorization_invalid", err: err}
	}
	recordName := "_acme-challenge." + dnsName
	txtValue := authz.DNSChallenge.TXTValue
	match, err := s.DNSProviders.FindZoneForDNSName(ctx, dnsName)
	if err != nil {
		return dnsAuthorizationChallenge{}, issuanceFailure{code: "dns_provider_not_found", err: err}
	}
	op := dnsdomain.DNS01ChallengeOperation{
		ZoneName:   match.Zone.ZoneName,
		RecordName: recordName,
		TXTValue:   txtValue,
		TTL:        s.dnsChallengeTTL(),
	}
	record, err := s.findExistingChallenge(ctx, job.ID, recordName, txtValue)
	if err != nil {
		return dnsAuthorizationChallenge{}, err
	}
	if record.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return dnsAuthorizationChallenge{}, issuanceFailure{code: "dns_challenge_record_create_failed", err: err}
		}
		encrypted, err := s.KeySet.SealDatabaseValue([]byte(txtValue), dnsChallengeTXTValueAAD(id))
		if err != nil {
			return dnsAuthorizationChallenge{}, issuanceFailure{code: "dns_challenge_encrypt_failed", err: err}
		}
		record, err = s.Certificates.RecordDNSChallenge(ctx, certificates.RecordDNSChallengeParams{
			ID:                      id,
			IssuanceJobID:           job.ID,
			CertificateID:           job.CertificateID,
			CertificateVersionID:    version.ID,
			DNSProviderID:           match.Provider.ID,
			DNSProviderZoneID:       match.Zone.ID,
			AuthorizationIdentifier: authz.Identifier,
			RecordName:              recordName,
			TXTValueEncrypted:       encrypted,
			Status:                  certificates.DNSChallengeStatusPending,
		})
		if err != nil {
			return dnsAuthorizationChallenge{}, issuanceFailure{code: "dns_challenge_record_create_failed", err: err}
		}
	}
	return dnsAuthorizationChallenge{authz: authz, record: record, op: op, provider: match.Provider}, nil
}

func challengeNeedsPresent(status certificates.DNSChallengeStatus) bool {
	switch status {
	case certificates.DNSChallengeStatusPresented, certificates.DNSChallengeStatusValidated, certificates.DNSChallengeStatusCleanupPending:
		return false
	default:
		return true
	}
}

func (s *CertificateIssuanceService) findExistingChallenge(ctx context.Context, jobID, recordName, txtValue string) (certificates.DNSChallengeRecord, error) {
	records, err := s.Certificates.ListDNSChallenges(ctx, certificates.ListDNSChallengesParams{IssuanceJobID: &jobID, ListOptions: storage.ListOptions{Limit: storage.MaxListLimit}})
	if err != nil {
		return certificates.DNSChallengeRecord{}, issuanceFailure{code: "dns_challenge_record_read_failed", err: err}
	}
	for _, record := range records {
		if record.RecordName != recordName {
			continue
		}
		plaintext, err := s.KeySet.OpenDatabaseValue(record.TXTValueEncrypted, dnsChallengeTXTValueAAD(record.ID))
		if err != nil {
			return certificates.DNSChallengeRecord{}, issuanceFailure{code: "dns_challenge_decrypt_failed", err: err}
		}
		if string(plaintext) == txtValue {
			return record, nil
		}
	}
	return certificates.DNSChallengeRecord{}, nil
}

func (s *CertificateIssuanceService) presentDNSChallenge(ctx context.Context, provider dnsdomain.Provider, op dnsdomain.DNS01ChallengeOperation) error {
	credentials, err := s.providerCredentials(ctx, provider)
	if err != nil {
		return err
	}
	switch provider.Type {
	case dnsdomain.ProviderTypeCloudflare:
		var creds dnsdomain.CloudflareCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return issuanceFailure{code: "dns_provider_credentials_invalid", err: err}
		}
		if err := s.Cloudflare.Present(ctx, creds, op); err != nil {
			return issuanceFailure{code: "dns_challenge_present_failed", err: err, redactions: []string{op.TXTValue}}
		}
	case dnsdomain.ProviderTypeArvanCloud:
		var creds dnsdomain.ArvanCloudCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return issuanceFailure{code: "dns_provider_credentials_invalid", err: err}
		}
		if err := s.ArvanCloud.Present(ctx, creds, op); err != nil {
			return issuanceFailure{code: "dns_challenge_present_failed", err: err, redactions: []string{op.TXTValue}}
		}
	default:
		return issuanceFailure{code: "dns_provider_unsupported", err: fmt.Errorf("unsupported dns provider type %s", provider.Type)}
	}
	return nil
}

func (s *CertificateIssuanceService) cleanupRecordedChallenges(ctx context.Context, job certificates.IssuanceJob) error {
	records, err := s.Certificates.ListDNSChallenges(ctx, certificates.ListDNSChallengesParams{IssuanceJobID: &job.ID, ListOptions: storage.ListOptions{Limit: storage.MaxListLimit}})
	if err != nil {
		return err
	}
	return s.cleanupChallenges(ctx, records)
}

func (s *CertificateIssuanceService) cleanupPendingChallenges(ctx context.Context) error {
	var cleanupErr error
	for _, status := range []certificates.DNSChallengeStatus{certificates.DNSChallengeStatusCleanupPending, certificates.DNSChallengeStatusCleanupFailed} {
		status := status
		records, err := s.Certificates.ListDNSChallenges(ctx, certificates.ListDNSChallengesParams{Status: &status, ListOptions: storage.ListOptions{Limit: storage.MaxListLimit}})
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, issuanceFailure{code: "dns_challenge_record_read_failed", err: err})
			continue
		}
		cleanupErr = errors.Join(cleanupErr, s.cleanupChallenges(ctx, records))
	}
	return cleanupErr
}

func (s *CertificateIssuanceService) cleanupChallenges(ctx context.Context, records []certificates.DNSChallengeRecord) error {
	var cleanupErr error
	for _, record := range records {
		if record.Status == certificates.DNSChallengeStatusCleaned {
			continue
		}
		txt, err := s.KeySet.OpenDatabaseValue(record.TXTValueEncrypted, dnsChallengeTXTValueAAD(record.ID))
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, issuanceFailure{code: "dns_challenge_decrypt_failed", err: err})
			_, _ = s.Certificates.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{ID: record.ID, Status: certificates.DNSChallengeStatusCleanupFailed, FailureCode: "dns_challenge_decrypt_failed", FailureMessage: optionalMessage(err)})
			continue
		}
		provider, err := s.DNSProviders.Get(ctx, record.DNSProviderID)
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, issuanceFailure{code: "dns_provider_not_found", err: err})
			_, _ = s.Certificates.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{ID: record.ID, Status: certificates.DNSChallengeStatusCleanupFailed, FailureCode: "dns_provider_not_found", FailureMessage: optionalMessage(err)})
			continue
		}
		zone, err := s.recordedZone(ctx, record)
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, issuanceFailure{code: "dns_provider_zone_not_found", err: err})
			_, _ = s.Certificates.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{ID: record.ID, Status: certificates.DNSChallengeStatusCleanupFailed, FailureCode: "dns_provider_zone_not_found", FailureMessage: optionalMessage(err)})
			continue
		}
		op := dnsdomain.DNS01ChallengeOperation{ZoneName: zone.ZoneName, RecordName: record.RecordName, TXTValue: string(txt), TTL: s.dnsChallengeTTL()}
		if err := s.cleanupDNSChallenge(ctx, provider, op); err != nil {
			failure := issuanceFailure{code: "dns_challenge_cleanup_failed", err: err, redactions: []string{op.TXTValue}}
			cleanupErr = errors.Join(cleanupErr, failure)
			_, _ = s.Certificates.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{ID: record.ID, Status: certificates.DNSChallengeStatusCleanupFailed, FailureCode: "dns_challenge_cleanup_failed", FailureMessage: optionalMessage(failure)})
			continue
		}
		_, _ = s.Certificates.MarkDNSChallengeCleanup(ctx, certificates.MarkDNSChallengeCleanupParams{ID: record.ID, Status: certificates.DNSChallengeStatusCleaned})
	}
	return cleanupErr
}

func (s *CertificateIssuanceService) cleanupDNSChallenge(ctx context.Context, provider dnsdomain.Provider, op dnsdomain.DNS01ChallengeOperation) error {
	credentials, err := s.providerCredentials(ctx, provider)
	if err != nil {
		return err
	}
	switch provider.Type {
	case dnsdomain.ProviderTypeCloudflare:
		var creds dnsdomain.CloudflareCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return err
		}
		return s.Cloudflare.CleanUp(ctx, creds, op)
	case dnsdomain.ProviderTypeArvanCloud:
		var creds dnsdomain.ArvanCloudCredentials
		if err := json.Unmarshal(credentials, &creds); err != nil {
			return err
		}
		return s.ArvanCloud.CleanUp(ctx, creds, op)
	default:
		return fmt.Errorf("unsupported dns provider type %s", provider.Type)
	}
}

func (s *CertificateIssuanceService) recordEvent(ctx context.Context, job certificates.IssuanceJob, eventType string, result certificates.EventResult, metadata map[string]any) error {
	if s == nil || s.Certificates == nil {
		return nil
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["job_reason"] = string(job.Reason)
	metadata["job_attempt"] = job.Attempt
	raw, err := json.Marshal(metadata)
	if err != nil {
		raw = []byte(`{}`)
	}
	_, err = s.Certificates.RecordEvent(ctx, certificates.RecordEventParams{
		CertificateID:        job.CertificateID,
		CertificateVersionID: job.CertificateVersionID,
		IssuanceJobID:        &job.ID,
		EventType:            eventType,
		Result:               result,
		Metadata:             raw,
	})
	return err
}

func (s *CertificateIssuanceService) providerCredentials(ctx context.Context, provider dnsdomain.Provider) ([]byte, error) {
	encrypted, err := s.DNSProviders.GetCredentialsEncrypted(ctx, provider.ID)
	if err != nil {
		return nil, issuanceFailure{code: "dns_provider_credentials_unavailable", err: err}
	}
	plaintext, err := s.KeySet.OpenDatabaseValue(encrypted, dnsProviderCredentialsAAD(provider.ID))
	if err != nil {
		return nil, issuanceFailure{code: "dns_provider_credentials_unavailable", err: err}
	}
	return plaintext, nil
}

func (s *CertificateIssuanceService) recordedZone(ctx context.Context, record certificates.DNSChallengeRecord) (dnsdomain.Zone, error) {
	zones, err := s.DNSProviders.ListZones(ctx, record.DNSProviderID, storage.ListOptions{Limit: storage.MaxListLimit})
	if err != nil {
		return dnsdomain.Zone{}, err
	}
	for _, zone := range zones {
		if zone.ID == record.DNSProviderZoneID {
			return zone, nil
		}
	}
	return dnsdomain.Zone{}, storage.ErrNoRows
}

func (s *CertificateIssuanceService) finalizeOrder(ctx context.Context, params acmedomain.OrderClientParams, order acmedomain.Order, csrDER []byte) (acmedomain.CertificateBundle, error) {
	orderCtx, cancel := s.orderContext(ctx)
	defer cancel()
	bundle, err := s.OrderManager.FinalizeOrder(orderCtx, acmedomain.FinalizeOrderParams{OrderClientParams: params, FinalizeURL: order.FinalizeURL, CSRDER: csrDER, Bundle: true})
	if err != nil {
		return acmedomain.CertificateBundle{}, issuanceFailure{code: "acme_finalize_failed", err: err}
	}
	if len(bundle.DERChain) == 0 && bundle.CertificateURL != "" {
		chain, err := s.OrderManager.FetchCertificate(orderCtx, acmedomain.FetchCertificateParams{OrderClientParams: params, CertificateURL: bundle.CertificateURL, Bundle: true})
		if err != nil {
			return acmedomain.CertificateBundle{}, issuanceFailure{code: "acme_certificate_fetch_failed", err: err}
		}
		bundle.DERChain = chain
	}
	return bundle, nil
}

func (s *CertificateIssuanceService) orderContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := s.OrderTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return context.WithTimeout(ctx, timeout)
}

func (s *CertificateIssuanceService) waitForPropagation(ctx context.Context, recordName, txtValue string) error {
	poll := s.PropagationPoll
	timeout := s.PropagationTimeout
	if poll <= 0 {
		poll = 5 * time.Second
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if timeout > 0 && poll > timeout {
		poll = timeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		visible := s.TXTVisible
		if visible == nil {
			visible = dnsTXTVisible
		}
		ok, err := visible(ctx, recordName, txtValue)
		if err == nil && ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return issuanceFailure{code: "dns_propagation_timeout", err: errors.New("dns challenge TXT record did not propagate before timeout")}
		case <-ticker.C:
		}
	}
}

func (s *CertificateIssuanceService) dnsChallengeTTL() int {
	if s.DNSChallengeTTL > 0 {
		return s.DNSChallengeTTL
	}
	return defaultDNSChallengeTTL
}

func (s *CertificateIssuanceService) versionPrivateKey(version certificates.CertificateVersion, keyType certificates.KeyType) (crypto.Signer, string, string, error) {
	if version.PrivateKeyPEMEncrypted != nil && *version.PrivateKeyPEMEncrypted != "" {
		plaintext, err := s.KeySet.OpenDatabaseValue(*version.PrivateKeyPEMEncrypted, certificatePrivateKeyAAD(version.ID))
		if err != nil {
			return nil, "", "", issuanceFailure{code: "private_key_decrypt_failed", err: err}
		}
		signer, err := parsePrivateKeyPEM(plaintext)
		if err != nil {
			return nil, "", "", issuanceFailure{code: "private_key_parse_failed", err: err}
		}
		fingerprint, err := keyFingerprint(signer.Public())
		if err != nil {
			return nil, "", "", issuanceFailure{code: "private_key_parse_failed", err: err}
		}
		return signer, string(plaintext), fingerprint, nil
	}
	signer, privateKeyPEM, err := generatePrivateKey(keyType)
	if err != nil {
		return nil, "", "", err
	}
	fingerprint, err := keyFingerprint(signer.Public())
	if err != nil {
		return nil, "", "", issuanceFailure{code: "private_key_generation_failed", err: err}
	}
	return signer, privateKeyPEM, fingerprint, nil
}

func generatePrivateKey(keyType certificates.KeyType) (crypto.Signer, string, error) {
	var key any
	var err error
	switch keyType {
	case certificates.KeyTypeRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case certificates.KeyTypeRSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case certificates.KeyTypeRSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case certificates.KeyTypeECDSAP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, "", issuanceFailure{code: "private_key_generation_failed", err: err}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", issuanceFailure{code: "private_key_generation_failed", err: err}
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, "", issuanceFailure{code: "private_key_generation_failed", err: errors.New("generated key is not a signer")}
	}
	return signer, string(pem.EncodeToMemory(block)), nil
}

func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key PEM is invalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if ec, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return ec, nil
		}
		if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
			return rsaKey, nil
		}
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key type is unsupported")
	}
	return signer, nil
}

func firstCertificateDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
		return nil, errors.New("certificate PEM is invalid")
	}
	return block.Bytes, nil
}

func keyFingerprint(publicKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func csrForCertificate(signer crypto.Signer, sans []string) ([]byte, error) {
	if signer == nil || len(sans) == 0 {
		return nil, errors.New("csr input is invalid")
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: sans[0]},
		DNSNames: sans,
	}
	return x509.CreateCertificateRequest(rand.Reader, template, signer)
}

type parsedMaterial struct {
	certPEM      string
	chainPEM     string
	fullchainPEM string
	notBefore    time.Time
	notAfter     time.Time
	serialNumber string
	fingerprint  string
	etag         string
}

func materialFromBundle(bundle acmedomain.CertificateBundle, privateKeyPEM, keyFingerprint string, keys *security.KeySet) (parsedMaterial, error) {
	if len(bundle.DERChain) == 0 {
		return parsedMaterial{}, issuanceFailure{code: "acme_certificate_empty", err: errors.New("acme returned no certificate chain")}
	}
	leaf, err := x509.ParseCertificate(bundle.DERChain[0])
	if err != nil {
		return parsedMaterial{}, issuanceFailure{code: "acme_certificate_invalid", err: err}
	}
	var certPEM, chainPEM, fullchainPEM strings.Builder
	for i, der := range bundle.DERChain {
		encoded := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if i == 0 {
			certPEM.WriteString(encoded)
		} else {
			chainPEM.WriteString(encoded)
		}
		fullchainPEM.WriteString(encoded)
	}
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	if privateKeyPEM == "" {
		return parsedMaterial{}, issuanceFailure{code: "private_key_unavailable", err: errors.New("private key is unavailable")}
	}
	etag := keys.MaterialETag(materialDescriptor(certPEM.String(), chainPEM.String(), fullchainPEM.String(), privateKeyPEM))
	return parsedMaterial{
		certPEM:      certPEM.String(),
		chainPEM:     chainPEM.String(),
		fullchainPEM: fullchainPEM.String(),
		notBefore:    leaf.NotBefore,
		notAfter:     leaf.NotAfter,
		serialNumber: leaf.SerialNumber.String(),
		fingerprint:  fingerprint,
		etag:         etag,
	}, nil
}

func materialDescriptor(certPEM, chainPEM, fullchainPEM, privateKeyPEM string) string {
	return strings.Join([]string{
		"cth-material-v1",
		"cert_pem_sha256=" + sha256String(certPEM),
		"chain_pem_sha256=" + sha256String(chainPEM),
		"fullchain_pem_sha256=" + sha256String(fullchainPEM),
		"private_key_pem_sha256=" + sha256String(privateKeyPEM),
	}, "\n")
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func dnsTXTVisible(ctx context.Context, recordName, txtValue string) (bool, error) {
	resolver := net.DefaultResolver
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	values, err := resolver.LookupTXT(lookupCtx, recordName)
	if err != nil {
		return false, err
	}
	for _, value := range values {
		if value == txtValue {
			return true, nil
		}
	}
	return false, nil
}

func retryableIssuanceFailure(code string) bool {
	switch code {
	case "dns_validation_failed", "dns_provider_not_found", "dns_challenge_present_failed", "dns_challenge_record_read_failed",
		"dns_provider_credentials_unavailable", "dns_provider_zone_not_found", "dns_propagation_timeout",
		"acme_order_fetch_failed", "acme_order_create_failed", "acme_authorization_fetch_failed",
		"acme_finalize_failed", "acme_certificate_fetch_failed", "issuer_account_unavailable",
		"acme_revocation_failed", "acme_revocation_record_failed", "dns_challenge_cleanup_failed":
		return true
	default:
		return false
	}
}

func (s *CertificateIssuanceService) maxAttempts() int {
	if s.MaxAttempts > 0 {
		return s.MaxAttempts
	}
	return defaultIssuanceMaxAttempts
}

func (s *CertificateIssuanceService) retryBackoff(attempt int) time.Duration {
	base := s.RetryBackoff
	if base <= 0 {
		base = defaultIssuanceRetryBackoff
	}
	if attempt <= 1 {
		return base
	}
	if attempt > 6 {
		attempt = 6
	}
	return base * time.Duration(1<<(attempt-1))
}

func authorizationDNSName(authz acmedomain.Authorization) (string, error) {
	identifier := strings.TrimPrefix(authz.Identifier, "*.")
	return storage.NormalizeDNSName(identifier)
}

func sanitizedFailure(err error) (string, string) {
	code := "issuance_failed"
	var redactions []string
	var failure issuanceFailure
	if errors.As(err, &failure) && failure.code != "" {
		code = failure.code
		redactions = failure.redactions
	}
	message := security.RedactValues(err.Error(), redactions...)
	if message == "" {
		message = code
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	return code, message
}

func optionalMessage(err error) *string {
	if err == nil {
		return nil
	}
	_, message := sanitizedFailure(err)
	return &message
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func certificatePrivateKeyAAD(versionID string) string {
	return "v1:table=certificate_versions:column=private_key_pem:row_id=" + versionID
}

func acmeAccountPrivateKeyAAD(accountID string) string {
	return "v1:table=acme_accounts:column=private_key_pem:row_id=" + accountID
}

func dnsProviderCredentialsAAD(providerID string) string {
	return "v1:table=dns_providers:column=credentials_encrypted:row_id=" + providerID
}

func dnsChallengeTXTValueAAD(recordID string) string {
	return "v1:table=dns_challenge_records:column=txt_value_encrypted:row_id=" + recordID
}

func selfSignedCertificateDER(csrDER []byte, signer crypto.Signer, notBefore, notAfter time.Time) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
}
