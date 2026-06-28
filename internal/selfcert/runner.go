package selfcert

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	security "github.com/torob/certhub/internal/crypto"
)

type Syncer interface {
	SyncOnce(context.Context) (Result, error)
}

type RunnerConfig struct {
	Syncer       Syncer
	PollInterval time.Duration
	LogWriter    io.Writer
}

type Runner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func Start(ctx context.Context, cfg RunnerConfig) (*Runner, error) {
	if cfg.Syncer == nil {
		return nil, fmt.Errorf("server self-certificate syncer is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	if cfg.LogWriter == nil {
		cfg.LogWriter = io.Discard
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runner := &Runner{cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		run(workerCtx, cfg.Syncer, cfg.PollInterval, cfg.LogWriter)
	}()
	go func() {
		wg.Wait()
		close(runner.done)
	}()
	return runner, nil
}

func (r *Runner) Stop(ctx context.Context) error {
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

func run(ctx context.Context, syncer Syncer, interval time.Duration, logWriter io.Writer) {
	for {
		if _, err := syncer.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(logWriter, "server self-certificate sync failed reason=%s error=%s\n", failureReason(err), security.RedactString(err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
