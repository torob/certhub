package workers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/certificates"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
)

const defaultRenewalScanLimit = 100

type CertificateRenewalStore interface {
	ListRenewalCandidates(context.Context, int) ([]certificates.RenewalCandidate, error)
	CreateIssuingVersion(context.Context, certificates.CreateIssuingVersionParams) (certificates.CertificateVersion, error)
	EnsureIssuanceJob(context.Context, certificates.EnsureIssuanceJobParams) (certificates.IssuanceJob, error)
}

type CertificateRenewalApplicationStore interface {
	ListDomainScopes(context.Context, string, storage.ListOptions) ([]appdomain.DomainScope, error)
}

type CertificateRenewalConfig struct {
	Store        CertificateRenewalStore
	Applications CertificateRenewalApplicationStore
	PollInterval time.Duration
	LogWriter    io.Writer
	WorkerPrefix string
}

type CertificateRenewalRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func StartCertificateRenewalWorker(ctx context.Context, cfg CertificateRenewalConfig) (*CertificateRenewalRunner, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("certificate renewal store is required")
	}
	if cfg.Applications == nil {
		return nil, fmt.Errorf("certificate renewal application store is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	if cfg.LogWriter == nil {
		cfg.LogWriter = io.Discard
	}
	if cfg.WorkerPrefix == "" {
		cfg.WorkerPrefix = "cert-renewal"
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runner := &CertificateRenewalRunner{cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runCertificateRenewalWorker(workerCtx, cfg.Store, cfg.Applications, cfg.PollInterval, cfg.LogWriter, cfg.WorkerPrefix+"-1")
	}()
	go func() {
		wg.Wait()
		close(runner.done)
	}()
	return runner, nil
}

func (r *CertificateRenewalRunner) Stop(ctx context.Context) error {
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

func runCertificateRenewalWorker(ctx context.Context, store CertificateRenewalStore, apps CertificateRenewalApplicationStore, pollInterval time.Duration, logWriter io.Writer, workerID string) {
	for {
		if err := enqueueDueCertificateRenewals(ctx, store, apps); err != nil && ctx.Err() == nil {
			fmt.Fprintf(logWriter, "certificate renewal worker failed worker_id=%s error=%s\n", workerID, security.RedactString(err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func enqueueDueCertificateRenewals(ctx context.Context, store CertificateRenewalStore, apps CertificateRenewalApplicationStore) error {
	candidates, err := store.ListRenewalCandidates(ctx, defaultRenewalScanLimit)
	if err != nil {
		return err
	}
	var joined error
	for _, candidate := range candidates {
		covered, err := renewalDomainsCovered(ctx, apps, candidate)
		if err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		if !covered {
			continue
		}
		version, err := store.CreateIssuingVersion(ctx, certificates.CreateIssuingVersionParams{
			CertificateID: candidate.CertificateID,
			Reason:        certificates.IssuanceReasonRenewal,
		})
		if err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		if version.Reason != certificates.IssuanceReasonRenewal {
			continue
		}
		if _, err := store.EnsureIssuanceJob(ctx, certificates.EnsureIssuanceJobParams{
			CertificateID:        candidate.CertificateID,
			CertificateVersionID: &version.ID,
			Reason:               certificates.JobReasonRenewal,
			NextRunAt:            time.Now().UTC(),
		}); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func renewalDomainsCovered(ctx context.Context, apps CertificateRenewalApplicationStore, candidate certificates.RenewalCandidate) (bool, error) {
	scopes, err := apps.ListDomainScopes(ctx, candidate.ApplicationID, storage.ListOptions{Limit: storage.MaxListLimit})
	if err != nil {
		return false, err
	}
	coverage, err := appdomain.ScopesCoverIdentifiers(scopes, candidate.NormalizedSANs)
	if err != nil {
		return false, err
	}
	return len(coverage.UncoveredIdentifiers) == 0, nil
}

var _ CertificateRenewalStore = certificates.Repository{}
var _ CertificateRenewalApplicationStore = appdomain.Repository{}
