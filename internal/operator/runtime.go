package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/torob/certhub/pkg/netretry"
)

type Runtime struct {
	Config Config
	Kube   interface {
		KubernetesClient
		CertificateLister
		CertificateWatcher
	}
	Backend BackendClient
	Logger  *slog.Logger
	Metrics *Metrics

	watchInputs map[string]string
}

type namespacedCertificateWatchEvent struct {
	namespace string
	event     CertificateWatchEvent
}

func NewInClusterRuntime(ctx context.Context, cfg Config) (*Runtime, error) {
	kube, err := NewInClusterRESTKubeClient()
	if err != nil {
		return nil, err
	}
	kube.retry = cfg.RetryPolicy
	kube.client = netretry.NewClient(kube.httpClient, cfg.RetryPolicy)
	backend, err := NewHTTPBackendFromConfig(cfg)
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
		logger.Error("operator initial reconcile sweep failed", "error", Sanitize(err.Error()))
		nextDelay = r.Config.ReconcileBackoff
	}
	watchCtx, cancelWatches := context.WithCancel(ctx)
	defer cancelWatches()
	watchCh, err := r.watchCertificateChanges(watchCtx)
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
		case change := <-watchCh:
			if !r.shouldReconcileWatchEvent(change.namespace, change.event) {
				continue
			}
			nextDelay, err = r.reconcileNamespace(ctx, reconciler, logger, change.namespace)
			if err != nil {
				logger.Error("operator namespace reconcile failed", "namespace", change.namespace, "error", Sanitize(err.Error()))
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
	nextDelay := r.Config.ResyncInterval
	var reconcileErrors []error
	for _, namespace := range r.watchNamespaces() {
		delay, err := r.reconcileNamespace(ctx, reconciler, logger, namespace)
		if delay > 0 && (nextDelay <= 0 || delay < nextDelay) {
			nextDelay = delay
		}
		if err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile namespace %q: %w", namespace, err))
		}
	}
	if nextDelay <= 0 {
		nextDelay = r.Config.ReconcileBackoff
	}
	return nextDelay, errors.Join(reconcileErrors...)
}

func (r *Runtime) reconcileNamespace(ctx context.Context, reconciler *Reconciler, logger *slog.Logger, namespace string) (time.Duration, error) {
	items, err := r.Kube.ListCertificates(ctx, namespace)
	if err != nil {
		return r.Config.ReconcileBackoff, err
	}
	nextDelay := r.Config.ResyncInterval
	for _, cert := range items {
		r.rememberCertificateInput(cert)
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

func (r *Runtime) watchNamespaces() []string {
	if len(r.Config.WatchNamespaces) == 0 {
		return []string{""}
	}
	return r.Config.WatchNamespaces
}

func (r *Runtime) watchCertificateChanges(ctx context.Context) (<-chan namespacedCertificateWatchEvent, error) {
	namespaces := r.watchNamespaces()
	events := make(chan namespacedCertificateWatchEvent, len(namespaces))
	for _, namespace := range namespaces {
		watch, err := r.Kube.WatchCertificateChanges(ctx, namespace)
		if err != nil {
			return nil, fmt.Errorf("watch namespace %q: %w", namespace, err)
		}
		go r.forwardNamespaceWatch(ctx, namespace, watch, events)
	}
	return events, nil
}

func (r *Runtime) forwardNamespaceWatch(ctx context.Context, namespace string, watch <-chan CertificateWatchEvent, events chan<- namespacedCertificateWatchEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watch:
			if !ok {
				if ctx.Err() != nil {
					return
				}
				timer := time.NewTimer(5 * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				next, err := r.Kube.WatchCertificateChanges(ctx, namespace)
				if err != nil {
					continue
				}
				watch = next
				continue
			}
			select {
			case events <- namespacedCertificateWatchEvent{namespace: namespace, event: event}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (r *Runtime) rememberCertificateInput(cert *CerthubCertificate) {
	if cert == nil {
		return
	}
	if r.watchInputs == nil {
		r.watchInputs = make(map[string]string)
	}
	r.watchInputs[certificateWatchKey(cert)] = certificateReconcileInput(cert)
}

func (r *Runtime) shouldReconcileWatchEvent(namespace string, event CertificateWatchEvent) bool {
	cert := event.Certificate
	if cert == nil {
		return false
	}
	if cert.Metadata.Namespace == "" {
		cert.Metadata.Namespace = namespace
	}
	key := certificateWatchKey(cert)
	if r.watchInputs == nil {
		r.watchInputs = make(map[string]string)
	}
	if event.Type == "DELETED" {
		delete(r.watchInputs, key)
		return false
	}
	if event.Type != "ADDED" && event.Type != "MODIFIED" {
		return false
	}
	next := certificateReconcileInput(cert)
	previous, known := r.watchInputs[key]
	r.watchInputs[key] = next
	return !known || previous != next
}

func certificateWatchKey(cert *CerthubCertificate) string {
	return cert.Metadata.Namespace + "/" + cert.Metadata.Name + "/" + cert.Metadata.UID
}

func certificateReconcileInput(cert *CerthubCertificate) string {
	value := struct {
		Spec              CerthubCertificateSpec `json:"spec"`
		RetryID           string                 `json:"retryId,omitempty"`
		Finalizers        []string               `json:"finalizers,omitempty"`
		DeletionTimestamp *time.Time             `json:"deletionTimestamp,omitempty"`
	}{
		Spec:              cert.Spec,
		RetryID:           cert.Metadata.Annotations[AnnotationRetryID],
		Finalizers:        cert.Metadata.Finalizers,
		DeletionTimestamp: cert.Metadata.DeletionTimestamp,
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
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
