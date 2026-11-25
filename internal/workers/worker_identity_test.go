package workers

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/dnsproviders"
	"github.com/torob/certhub/internal/storage"
)

// Two server replicas start their workers with the same default config. The
// worker IDs fence job leases (locked_by), so the replicas must never share one.
func TestCertificateIssuanceWorkersUseDisjointIDsAcrossProcesses(t *testing.T) {
	first := startRecordingIssuanceRunner(t)
	second := startRecordingIssuanceRunner(t)
	assertDisjointWorkerIDs(t, first.ids(), second.ids())
}

func TestDNSRefreshWorkersUseDisjointIDsAcrossProcesses(t *testing.T) {
	first := startRecordingDNSRefreshRunner(t)
	second := startRecordingDNSRefreshRunner(t)
	assertDisjointWorkerIDs(t, first.ids(), second.ids())
}

func TestCertificateRenewalWorkersUseDisjointIDsAcrossProcesses(t *testing.T) {
	first := startRecordingRenewalRunner(t)
	second := startRecordingRenewalRunner(t)
	assertDisjointWorkerIDs(t, first.ids(), second.ids())
}

const identityTestConcurrency = 3

func assertDisjointWorkerIDs(t *testing.T, first, second []string) {
	t.Helper()
	seen := make(map[string]bool, len(first))
	for _, id := range first {
		seen[id] = true
	}
	for _, id := range second {
		if seen[id] {
			t.Fatalf("worker ID %q is used by both processes: first=%v second=%v", id, first, second)
		}
	}
}

type workerIDRecorder struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (r *workerIDRecorder) record(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = make(map[string]bool)
	}
	r.seen[id] = true
}

func (r *workerIDRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

func (r *workerIDRecorder) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.seen))
	for id := range r.seen {
		out = append(out, id)
	}
	return out
}

type recordingIssuanceStore struct {
	CertificateIssuanceStore
	recorder *workerIDRecorder
}

func (s recordingIssuanceStore) ClaimNextIssuanceJob(_ context.Context, params certificates.ClaimIssuanceJobParams) (certificates.IssuanceJob, error) {
	s.recorder.record(params.WorkerID)
	return certificates.IssuanceJob{}, storage.ErrNoRows
}

func startRecordingIssuanceRunner(t *testing.T) *workerIDRecorder {
	t.Helper()
	recorder := &workerIDRecorder{}
	fixture := newIssuanceWorkerFixture(t)
	service := fixture.service
	service.Certificates = recordingIssuanceStore{recorder: recorder}
	runner, err := StartCertificateIssuanceWorkers(context.Background(), CertificateIssuanceConfig{
		Service:      service,
		Concurrency:  identityTestConcurrency,
		PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	stopRunnerOnCleanup(t, runner.Stop)
	waitFor(t, time.Second, func() bool { return recorder.count() == identityTestConcurrency })
	return recorder
}

type recordingDNSRefreshService struct {
	recorder *workerIDRecorder
}

func (s recordingDNSRefreshService) CompleteNextRefreshJob(_ context.Context, workerID string) (dnsproviders.RefreshJob, bool, error) {
	s.recorder.record(workerID)
	return dnsproviders.RefreshJob{}, false, nil
}

func startRecordingDNSRefreshRunner(t *testing.T) *workerIDRecorder {
	t.Helper()
	recorder := &workerIDRecorder{}
	runner, err := StartDNSRefreshWorkers(context.Background(), DNSRefreshConfig{
		Service:      recordingDNSRefreshService{recorder: recorder},
		Concurrency:  identityTestConcurrency,
		PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	stopRunnerOnCleanup(t, runner.Stop)
	waitFor(t, time.Second, func() bool { return recorder.count() == identityTestConcurrency })
	return recorder
}

// The renewal scanner does not claim leases, but it reports its worker ID in
// logs; it must still identify its process.
type failingRenewalStore struct {
	CertificateRenewalStore
}

func (failingRenewalStore) ListRenewalCandidates(context.Context, int) ([]certificates.RenewalCandidate, error) {
	return nil, errors.New("renewal scan failed")
}

var renewalLogWorkerIDRE = regexp.MustCompile(`worker_id=(\S+)`)

type renewalLogRecorder struct {
	recorder *workerIDRecorder
}

func (w renewalLogRecorder) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		if match := renewalLogWorkerIDRE.FindStringSubmatch(line); match != nil {
			w.recorder.record(match[1])
		}
	}
	return len(p), nil
}

func startRecordingRenewalRunner(t *testing.T) *workerIDRecorder {
	t.Helper()
	recorder := &workerIDRecorder{}
	runner, err := StartCertificateRenewalWorker(context.Background(), CertificateRenewalConfig{
		Store: failingRenewalStore{},
		Applications: struct {
			CertificateRenewalApplicationStore
		}{},
		PollInterval: time.Hour,
		LogWriter:    renewalLogRecorder{recorder: recorder},
	})
	if err != nil {
		t.Fatal(err)
	}
	stopRunnerOnCleanup(t, runner.Stop)
	waitFor(t, time.Second, func() bool { return recorder.count() == 1 })
	return recorder
}

func stopRunnerOnCleanup(t *testing.T, stop func(context.Context) error) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := stop(ctx); err != nil {
			t.Errorf("stop runner: %v", err)
		}
	})
}

func TestNewInstanceIDIsRandomAndFitsWorkerIDFormat(t *testing.T) {
	first, err := NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("NewInstanceID returned %q twice", first)
	}
	suffix := regexp.MustCompile(`(^|-)[0-9a-f]{16}$`)
	for _, id := range []string{first, second} {
		if len(id) > maxInstanceIDLength || !instanceIDRE.MatchString(id) || !suffix.MatchString(id) {
			t.Fatalf("instance ID %q has an unexpected format", id)
		}
	}
}

func TestSanitizeInstanceHostname(t *testing.T) {
	tests := map[string]string{
		"":                                "",
		"certhub-server-7d9f8b6c4-abcde":  "certhub-server-7d9f8b6c4-abcde",
		"Node_01.Example.COM":             "node-01-example-com",
		"--\tweird host\n--":              "weird-host",
		strings.Repeat("a", 39) + "-tail": strings.Repeat("a", 39),
	}
	for input, want := range tests {
		if got := sanitizeInstanceHostname(input); got != want {
			t.Fatalf("sanitizeInstanceHostname(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestWorkerIDsIncludeInstanceAndStayWithinLockedByLimit(t *testing.T) {
	ids, err := workerIDs("cert-issuer", "pod-a-0123456789abcdef", 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cert-issuer-pod-a-0123456789abcdef-1", "cert-issuer-pod-a-0123456789abcdef-2"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("workerIDs = %v, want %v", ids, want)
	}
	generated, err := workerIDs("dns-refresh", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(generated[0], "dns-refresh-") || !strings.HasSuffix(generated[0], "-1") || generated[0] == "dns-refresh-1" {
		t.Fatalf("generated worker ID %q does not include an instance ID", generated[0])
	}
	longest, err := workerIDs("cert-issuer", strings.Repeat("a", maxInstanceIDLength), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(longest[0]) > maxWorkerIDLength {
		t.Fatalf("worker ID length %d exceeds locked_by limit", len(longest[0]))
	}
	for _, bad := range []string{strings.Repeat("a", maxInstanceIDLength+1), "Upper", "-lead", "has space", "tab\t"} {
		if _, err := workerIDs("cert-issuer", bad, 1); err == nil {
			t.Fatalf("workerIDs accepted instance ID %q", bad)
		}
	}
	if _, err := workerIDs(strings.Repeat("p", maxWorkerIDLength), "abc", 1); err == nil {
		t.Fatal("workerIDs accepted a worker ID longer than the locked_by limit")
	}
}

func TestWorkersShareConfiguredInstanceID(t *testing.T) {
	recorder := &workerIDRecorder{}
	fixture := newIssuanceWorkerFixture(t)
	fixture.service.Certificates = recordingIssuanceStore{recorder: recorder}
	runner, err := StartCertificateIssuanceWorkers(context.Background(), CertificateIssuanceConfig{
		Service:      fixture.service,
		Concurrency:  2,
		PollInterval: time.Hour,
		InstanceID:   "replica-a-0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	stopRunnerOnCleanup(t, runner.Stop)
	dnsRecorder := &workerIDRecorder{}
	dnsRunner, err := StartDNSRefreshWorkers(context.Background(), DNSRefreshConfig{
		Service:      recordingDNSRefreshService{recorder: dnsRecorder},
		Concurrency:  1,
		PollInterval: time.Hour,
		InstanceID:   "replica-a-0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	stopRunnerOnCleanup(t, dnsRunner.Stop)
	waitFor(t, time.Second, func() bool { return recorder.count() == 2 && dnsRecorder.count() == 1 })
	got := append(recorder.ids(), dnsRecorder.ids()...)
	for _, want := range []string{"cert-issuer-replica-a-0123456789abcdef-1", "cert-issuer-replica-a-0123456789abcdef-2", "dns-refresh-replica-a-0123456789abcdef-1"} {
		if !strings.Contains(strings.Join(got, ","), want) {
			t.Fatalf("worker IDs %v do not include %q", got, want)
		}
	}
}

func TestStartWorkersRejectsInvalidInstanceID(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	if _, err := StartCertificateIssuanceWorkers(context.Background(), CertificateIssuanceConfig{Service: fixture.service, Concurrency: 1, InstanceID: "Bad ID"}); err == nil {
		t.Fatal("StartCertificateIssuanceWorkers accepted an invalid instance ID")
	}
	if _, err := StartDNSRefreshWorkers(context.Background(), DNSRefreshConfig{Service: recordingDNSRefreshService{recorder: &workerIDRecorder{}}, Concurrency: 1, InstanceID: "Bad ID"}); err == nil {
		t.Fatal("StartDNSRefreshWorkers accepted an invalid instance ID")
	}
	if _, err := StartCertificateRenewalWorker(context.Background(), CertificateRenewalConfig{Store: failingRenewalStore{}, Applications: struct {
		CertificateRenewalApplicationStore
	}{}, InstanceID: "Bad ID"}); err == nil {
		t.Fatal("StartCertificateRenewalWorker accepted an invalid instance ID")
	}
}
