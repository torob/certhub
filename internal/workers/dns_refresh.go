package workers

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/dnsproviders"
)

type DNSRefreshService interface {
	CompleteNextRefreshJob(context.Context, string) (dnsproviders.RefreshJob, bool, error)
}

type DNSRefreshConfig struct {
	Service      DNSRefreshService
	Concurrency  int
	PollInterval time.Duration
	LogWriter    io.Writer
	WorkerPrefix string
}

type DNSRefreshRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func StartDNSRefreshWorkers(ctx context.Context, cfg DNSRefreshConfig) (*DNSRefreshRunner, error) {
	if cfg.Service == nil {
		return nil, fmt.Errorf("dns refresh service is required")
	}
	if cfg.Concurrency <= 0 {
		return nil, fmt.Errorf("dns refresh worker concurrency must be positive")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.LogWriter == nil {
		cfg.LogWriter = io.Discard
	}
	if cfg.WorkerPrefix == "" {
		cfg.WorkerPrefix = "dns-refresh"
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runner := &DNSRefreshRunner{cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		workerID := fmt.Sprintf("%s-%d", cfg.WorkerPrefix, i+1)
		go func() {
			defer wg.Done()
			runDNSRefreshWorker(workerCtx, cfg.Service, cfg.PollInterval, cfg.LogWriter, workerID)
		}()
	}
	go func() {
		wg.Wait()
		close(runner.done)
	}()
	return runner, nil
}

func (r *DNSRefreshRunner) Stop(ctx context.Context) error {
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

func runDNSRefreshWorker(ctx context.Context, service DNSRefreshService, pollInterval time.Duration, logWriter io.Writer, workerID string) {
	for {
		processed, err := completeOneDNSRefreshJob(ctx, service, workerID)
		if err != nil {
			fmt.Fprintf(logWriter, "dns refresh worker failed worker_id=%s error=%s\n", workerID, security.RedactString(err.Error()))
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

func completeOneDNSRefreshJob(ctx context.Context, service DNSRefreshService, workerID string) (bool, error) {
	_, processed, err := service.CompleteNextRefreshJob(ctx, workerID)
	if err != nil {
		if ctx.Err() != nil {
			return false, nil
		}
		return processed, err
	}
	return processed, nil
}
