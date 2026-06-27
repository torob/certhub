package operator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type Runtime struct {
	Config Config
	Kube   interface {
		KubernetesClient
		CertificateLister
		CertificateWatcher
		DefaultNamespace() string
	}
	Backend BackendClient
	Logger  *slog.Logger
	Metrics *Metrics
}

func NewInClusterRuntime(ctx context.Context, cfg Config) (*Runtime, error) {
	kube, err := NewInClusterRESTKubeClient()
	if err != nil {
		return nil, err
	}
	if cfg.TokenNamespace == "" {
		cfg.TokenNamespace = kube.DefaultNamespace()
	}
	backend, err := NewHTTPBackendFromConfig(ctx, kube, cfg)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		Config:  cfg,
		Kube:    kube,
		Backend: backend,
		Metrics: NewMetrics(),
	}, nil
}

func (r *Runtime) Run(ctx context.Context, stderr io.Writer) error {
	if r == nil || r.Kube == nil || r.Backend == nil {
		return errors.New("operator runtime is not configured")
	}
	logger := r.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	metrics := r.Metrics
	if metrics == nil {
		metrics = NewMetrics()
	}
	reconciler := NewReconciler(r.Kube, r.Backend)
	reconciler.Metrics = metrics
	reconciler.AllowedSecretNames = append([]string(nil), r.Config.AllowedSecretNames...)
	if r.Config.ResyncInterval > 0 {
		reconciler.ResyncInterval = r.Config.ResyncInterval
	}
	if r.Config.ReconcileBackoff > 0 {
		reconciler.Backoff = r.Config.ReconcileBackoff
	}
	server := &http.Server{Addr: r.Config.MetricsBindAddr, Handler: metricsMux(metrics)}
	errc := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	nextDelay, err := r.reconcileAll(ctx, reconciler, logger)
	if err != nil {
		return err
	}
	watchCh, err := r.Kube.WatchCertificateChanges(ctx, r.Config.WatchNamespace)
	if err != nil {
		return err
	}
	timer := time.NewTimer(nextDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return fmt.Errorf("metrics server failed: %w", err)
		case _, ok := <-watchCh:
			if !ok {
				watchCh, _ = r.Kube.WatchCertificateChanges(ctx, r.Config.WatchNamespace)
				continue
			}
			nextDelay, err = r.reconcileAll(ctx, reconciler, logger)
			if err != nil {
				logger.Error("operator reconcile sweep failed", "error", Sanitize(err.Error()))
				nextDelay = r.Config.ReconcileBackoff
			}
			resetTimer(timer, nextDelay)
		case <-timer.C:
			nextDelay, err = r.reconcileAll(ctx, reconciler, logger)
			if err != nil {
				logger.Error("operator reconcile sweep failed", "error", Sanitize(err.Error()))
				nextDelay = r.Config.ReconcileBackoff
			}
			resetTimer(timer, nextDelay)
		}
	}
}

func (r *Runtime) reconcileAll(ctx context.Context, reconciler *Reconciler, logger *slog.Logger) (time.Duration, error) {
	items, err := r.Kube.ListCertificates(ctx, r.Config.WatchNamespace)
	if err != nil {
		return r.Config.ReconcileBackoff, err
	}
	nextDelay := r.Config.ResyncInterval
	for _, cert := range items {
		reconcileID := fmt.Sprintf("operator-%s-%d", cert.Metadata.UID, time.Now().UTC().UnixNano())
		reconciler.NewRequestID = func(*CerthubCertificate) string { return reconcileID }
		start := time.Now()
		result, err := reconciler.Reconcile(ctx, cert)
		reconciler.Metrics.ObserveReconcileDuration(time.Since(start).Seconds())
		resultLabel := result.Result
		if resultLabel == "" {
			resultLabel = "unknown"
		}
		attrs := []any{"namespace", cert.Metadata.Namespace, "name", cert.Metadata.Name, "reconcile_id", reconcileID, "result", resultLabel, "result_requeue_after", result.RequeueAfter.String()}
		if result.BackendCode != "" {
			attrs = append(attrs, "backend_error_code", result.BackendCode)
		}
		if cert.Status.CertificateID != "" {
			attrs = append(attrs, "certificate_id", cert.Status.CertificateID)
		}
		if result.RequeueAfter > 0 && result.RequeueAfter < nextDelay {
			nextDelay = result.RequeueAfter
		}
		if err != nil {
			attrs = append(attrs, "error", Sanitize(err.Error()))
			logger.Error("CerthubCertificate reconcile failed", attrs...)
			continue
		}
		logger.Info("CerthubCertificate reconciled", attrs...)
	}
	if nextDelay <= 0 {
		nextDelay = r.Config.ResyncInterval
	}
	return nextDelay, nil
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

func metricsMux(metrics *Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}
