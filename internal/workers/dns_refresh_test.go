package workers

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"certhub/internal/dnsproviders"
)

func TestDNSRefreshWorkersDrainJobsAndStop(t *testing.T) {
	service := &fakeDNSRefreshService{remaining: 2}
	runner, err := StartDNSRefreshWorkers(context.Background(), DNSRefreshConfig{
		Service:      service,
		Concurrency:  1,
		PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		service.mu.Lock()
		defer service.mu.Unlock()
		return service.completed == 2
	})
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRefreshWorkerLogsSanitizedErrors(t *testing.T) {
	var log bytes.Buffer
	service := &fakeDNSRefreshService{err: errors.New("provider token=DNS-CREDENTIAL-CANARY failed")}
	runner, err := StartDNSRefreshWorkers(context.Background(), DNSRefreshConfig{
		Service:      service,
		Concurrency:  1,
		PollInterval: time.Hour,
		LogWriter:    &log,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return log.Len() > 0
	})
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "DNS-CREDENTIAL-CANARY") {
		t.Fatalf("worker log leaked secret: %s", log.String())
	}
}

type fakeDNSRefreshService struct {
	mu        sync.Mutex
	remaining int
	completed int
	err       error
}

func (f *fakeDNSRefreshService) CompleteNextRefreshJob(context.Context, string) (dnsproviders.RefreshJob, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return dnsproviders.RefreshJob{}, false, f.err
	}
	if f.remaining == 0 {
		return dnsproviders.RefreshJob{}, false, nil
	}
	f.remaining--
	f.completed++
	return dnsproviders.RefreshJob{}, true, nil
}

func waitFor(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition was not met before %s", timeout)
}
