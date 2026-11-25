package operator

import (
	"container/heap"
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
		CertificateGetter
		CertificateWatcher
	}
	Backend BackendClient
	Logger  *slog.Logger
	Metrics *Metrics
}

type namespacedCertificateWatchEvent struct {
	namespace string
	event     CertificateWatchEvent
}

// maxReconcileBackoffDoublings caps the per-Certificate failure backoff at
// ReconcileBackoff * 2^5 (32m with the 1m default), and never above
// ResyncInterval.
const maxReconcileBackoffDoublings = 5

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

	sched := r.newScheduler(reconciler, logger)
	if err := sched.resyncAll(ctx); err != nil {
		logger.Error("operator initial list failed", "error", Sanitize(err.Error()))
	}
	watchCtx, cancelWatches := context.WithCancel(ctx)
	defer cancelWatches()
	watchCh, err := r.watchCertificateChanges(watchCtx)
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		sched.reconcileDue(ctx)
		if ctx.Err() != nil {
			return nil
		}
		resetTimer(timer, sched.nextWake().Sub(sched.now()))
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return fmt.Errorf("metrics server failed: %w", err)
		case change := <-watchCh:
			sched.handleWatchEvent(ctx, change)
		case <-timer.C:
			if !sched.now().Before(sched.nextResync) {
				if err := sched.resyncAll(ctx); err != nil {
					logger.Error("operator periodic list failed", "error", Sanitize(err.Error()))
				}
			}
		}
	}
}

// scheduler keeps one queue entry per CerthubCertificate, keyed by
// namespace/name, with its own due time and failure count. The runtime loop
// sleeps until the earliest due entry or the next periodic list, so the
// requeue delay of one Certificate never reconciles another one.
type scheduler struct {
	runtime    *Runtime
	reconciler *Reconciler
	logger     *slog.Logger
	now        func() time.Time

	entries        map[string]*scheduledCertificate
	queue          scheduleHeap
	nextResync     time.Time
	resyncFailures int
}

type scheduledCertificate struct {
	key       string
	namespace string
	name      string
	// scope is the watched namespace ("" for cluster scope) whose list and
	// watch own this entry.
	scope    string
	uid      string
	input    string
	due      time.Time
	failures int
	index    int
}

func (r *Runtime) newScheduler(reconciler *Reconciler, logger *slog.Logger) *scheduler {
	return &scheduler{
		runtime:    r,
		reconciler: reconciler,
		logger:     logger,
		now:        time.Now,
		entries:    make(map[string]*scheduledCertificate),
	}
}

func (r *Runtime) resyncInterval() time.Duration {
	if r.Config.ResyncInterval > 0 {
		return r.Config.ResyncInterval
	}
	return 6 * time.Hour
}

func (r *Runtime) reconcileBackoff() time.Duration {
	if r.Config.ReconcileBackoff > 0 {
		return r.Config.ReconcileBackoff
	}
	return time.Minute
}

// failureBackoff returns the requeue delay after the given number of
// consecutive failures: ReconcileBackoff doubled per failure, capped.
func (r *Runtime) failureBackoff(failures int) time.Duration {
	base := r.reconcileBackoff()
	limit := base << maxReconcileBackoffDoublings
	if resync := r.resyncInterval(); limit > resync {
		limit = max(base, resync)
	}
	delay := base
	for i := 1; i < failures && delay < limit; i++ {
		delay *= 2
	}
	return min(delay, limit)
}

// resyncAll lists every watched namespace. It is the safety net for missed
// watch events: new or changed Certificates become due now, and queue entries
// whose Certificate is gone are dropped. Unchanged Certificates keep their
// own due time, so the list does not call the backend for them.
func (s *scheduler) resyncAll(ctx context.Context) error {
	var listErrors []error
	for _, namespace := range s.runtime.watchNamespaces() {
		if err := s.resyncNamespace(ctx, namespace); err != nil {
			listErrors = append(listErrors, fmt.Errorf("list namespace %q: %w", namespace, err))
		}
	}
	if len(listErrors) > 0 {
		s.resyncFailures++
		s.nextResync = s.now().Add(s.runtime.failureBackoff(s.resyncFailures))
	} else {
		s.resyncFailures = 0
		s.nextResync = s.now().Add(s.runtime.resyncInterval())
	}
	return errors.Join(listErrors...)
}

func (s *scheduler) resyncNamespace(ctx context.Context, scope string) error {
	items, err := s.runtime.Kube.ListCertificates(ctx, scope)
	if err != nil {
		return err
	}
	listed := make(map[string]struct{}, len(items))
	for _, cert := range items {
		if cert.Metadata.Namespace == "" {
			cert.Metadata.Namespace = scope
		}
		listed[certificateKey(cert.Metadata.Namespace, cert.Metadata.Name)] = struct{}{}
		s.observe(scope, cert)
	}
	for key, entry := range s.entries {
		if entry.scope != scope {
			continue
		}
		if _, ok := listed[key]; !ok {
			s.forget(entry)
		}
	}
	return nil
}

// observe records the latest reconcile input of a Certificate. A new
// Certificate, a re-created one (new UID), or a changed input is due now with
// a fresh failure count. A status-only change keeps the current due time.
func (s *scheduler) observe(scope string, cert *CerthubCertificate) {
	key := certificateKey(cert.Metadata.Namespace, cert.Metadata.Name)
	input := certificateReconcileInput(cert)
	entry, ok := s.entries[key]
	if !ok {
		entry = &scheduledCertificate{
			key:       key,
			namespace: cert.Metadata.Namespace,
			name:      cert.Metadata.Name,
			scope:     scope,
			uid:       cert.Metadata.UID,
			input:     input,
			due:       s.now(),
		}
		s.entries[key] = entry
		heap.Push(&s.queue, entry)
		return
	}
	if entry.uid == cert.Metadata.UID && entry.input == input {
		return
	}
	entry.uid = cert.Metadata.UID
	entry.input = input
	entry.failures = 0
	s.schedule(entry, s.now())
}

func (s *scheduler) forget(entry *scheduledCertificate) {
	if current, ok := s.entries[entry.key]; !ok || current != entry {
		return
	}
	delete(s.entries, entry.key)
	heap.Remove(&s.queue, entry.index)
	s.reconciler.Metrics.ClearCertificateConditions(entry.namespace, entry.name)
}

func (s *scheduler) schedule(entry *scheduledCertificate, due time.Time) {
	entry.due = due
	heap.Fix(&s.queue, entry.index)
}

func (s *scheduler) handleWatchEvent(ctx context.Context, change namespacedCertificateWatchEvent) {
	if change.event.Type == WatchEventRelist {
		if err := s.resyncNamespace(ctx, change.namespace); err != nil {
			s.logger.Error("operator namespace list after expired watch failed", "namespace", change.namespace, "error", Sanitize(err.Error()))
			s.nextResync = s.now()
		}
		return
	}
	cert := change.event.Certificate
	if cert == nil {
		return
	}
	if cert.Metadata.Namespace == "" {
		cert.Metadata.Namespace = change.namespace
	}
	switch change.event.Type {
	case "DELETED":
		entry, ok := s.entries[certificateKey(cert.Metadata.Namespace, cert.Metadata.Name)]
		if ok && (entry.uid == cert.Metadata.UID || cert.Metadata.UID == "") {
			s.forget(entry)
		}
	case "ADDED", "MODIFIED":
		s.observe(change.namespace, cert)
	}
}

// nextWake returns the earliest time at which a Certificate is due or the
// periodic list must run.
func (s *scheduler) nextWake() time.Time {
	wake := s.nextResync
	if len(s.queue) > 0 && s.queue[0].due.Before(wake) {
		wake = s.queue[0].due
	}
	return wake
}

// reconcileDue reconciles every Certificate whose due time has passed. Each
// one is read fresh from the Kubernetes API, so a Certificate deleted while
// its DELETED event was missed is dropped instead of reconciled.
func (s *scheduler) reconcileDue(ctx context.Context) {
	for len(s.queue) > 0 && ctx.Err() == nil && !s.queue[0].due.After(s.now()) {
		entry := s.queue[0]
		cert, err := s.runtime.Kube.GetCertificate(ctx, entry.namespace, entry.name)
		if errors.Is(err, ErrNotFound) {
			s.forget(entry)
			continue
		}
		if err != nil {
			entry.failures++
			delay := s.runtime.failureBackoff(entry.failures)
			s.logger.Error("CerthubCertificate read failed", "namespace", entry.namespace, "name", entry.name, "result_requeue_after", delay.String(), "error", Sanitize(err.Error()))
			s.schedule(entry, s.now().Add(delay))
			continue
		}
		if cert.Metadata.Namespace == "" {
			cert.Metadata.Namespace = entry.namespace
		}
		if cert.Metadata.UID != entry.uid {
			entry.uid = cert.Metadata.UID
			entry.failures = 0
		}
		result, err := s.reconcile(ctx, cert)
		// Record the input after Reconcile, so the watch event for the
		// operator's own finalizer patch does not trigger a second reconcile.
		entry.input = certificateReconcileInput(cert)
		var delay time.Duration
		switch {
		case err != nil || result.RetryWithBackoff:
			entry.failures++
			delay = s.runtime.failureBackoff(entry.failures)
		case result.RequeueAfter > 0:
			entry.failures = 0
			delay = result.RequeueAfter
		default:
			entry.failures = 0
			delay = s.runtime.resyncInterval()
		}
		s.schedule(entry, s.now().Add(delay))
	}
}

func (s *scheduler) reconcile(ctx context.Context, cert *CerthubCertificate) (Result, error) {
	reconciler := s.reconciler
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
	if err != nil {
		attrs = append(attrs, "error", Sanitize(err.Error()))
		s.logger.Error("CerthubCertificate reconcile failed", attrs...)
		return result, err
	}
	s.logger.Info("CerthubCertificate reconciled", attrs...)
	return result, nil
}

// scheduleHeap is a min-heap of queue entries ordered by due time.
type scheduleHeap []*scheduledCertificate

func (h scheduleHeap) Len() int { return len(h) }

func (h scheduleHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }

func (h scheduleHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *scheduleHeap) Push(x any) {
	entry := x.(*scheduledCertificate)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *scheduleHeap) Pop() any {
	old := *h
	entry := old[len(old)-1]
	old[len(old)-1] = nil
	entry.index = -1
	*h = old[:len(old)-1]
	return entry
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

func certificateKey(namespace, name string) string {
	return namespace + "/" + name
}

func certificateReconcileInput(cert *CerthubCertificate) string {
	value := struct {
		Spec              CerthubCertificateSpec `json:"spec"`
		Generation        int64                  `json:"generation,omitempty"`
		RetryID           string                 `json:"retryId,omitempty"`
		Finalizers        []string               `json:"finalizers,omitempty"`
		DeletionTimestamp *time.Time             `json:"deletionTimestamp,omitempty"`
	}{
		Spec:              cert.Spec,
		Generation:        cert.Metadata.Generation,
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
