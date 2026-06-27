package operator

import (
	"context"
	stderrors "errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"certhub/pkg/certhubclient"
	certerrors "certhub/pkg/errors"
	"certhub/pkg/material"
)

func TestValidateCertificateSpec(t *testing.T) {
	tests := []struct {
		name string
		spec CerthubCertificateSpec
	}{
		{name: "empty domains", spec: CerthubCertificateSpec{SecretName: "tls"}},
		{name: "bad secret name", spec: CerthubCertificateSpec{Domains: []string{"example.com"}, SecretName: "../tls"}},
		{name: "bad key type", spec: CerthubCertificateSpec{Domains: []string{"example.com"}, SecretName: "tls", KeyType: "ed25519"}},
		{name: "bad issuer", spec: CerthubCertificateSpec{Domains: []string{"example.com"}, SecretName: "tls", Issuer: "LE"}},
		{name: "bad policy", spec: CerthubCertificateSpec{Domains: []string{"example.com"}, SecretName: "tls", SecretDeletionPolicy: "Destroy"}},
		{name: "trimmed string", spec: CerthubCertificateSpec{Domains: []string{" example.com"}, SecretName: "tls"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ValidateCertificateSpec(tt.spec); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
	normalized, err := ValidateCertificateSpec(CerthubCertificateSpec{
		Domains:    []string{"WWW.Example.COM", "*.example.com"},
		SecretName: "gateway-tls",
		KeyType:    "ecdsa-p384",
		Issuer:     "letsencrypt_production",
	})
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if !reflect.DeepEqual(normalized.Domains, []string{"*.example.com", "www.example.com"}) {
		t.Fatalf("domains not normalized: %#v", normalized.Domains)
	}
}

func TestReadySyncWritesTLSSecret(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{materials: []materialResponse{{value: testMaterial("etag-1"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}}}}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.ResyncInterval {
		t.Fatalf("unexpected requeue: %s", result.RequeueAfter)
	}
	secret := kube.secrets["ns/gateway-tls"]
	if secret == nil {
		t.Fatalf("secret was not written")
	}
	if secret.Type != SecretTypeTLS {
		t.Fatalf("secret type = %q", secret.Type)
	}
	if string(secret.Data["tls.crt"]) != "FULLCHAIN" || string(secret.Data["tls.key"]) != "PRIVATEKEY" {
		t.Fatalf("unexpected secret data: %#v", secret.Data)
	}
	if secret.Metadata.Annotations[AnnotationMaterialETag] != "etag-1" {
		t.Fatalf("missing material etag: %#v", secret.Metadata.Annotations)
	}
	if secret.Metadata.Annotations[AnnotationOwnerUID] != cert.Metadata.UID {
		t.Fatalf("missing owner uid: %#v", secret.Metadata.Annotations)
	}
	if secret.Metadata.Labels[LabelManagedBy] != ManagedByValue {
		t.Fatalf("missing managed label: %#v", secret.Metadata.Labels)
	}
	if cert.Status.Phase != PhaseReady || cert.Status.CertificateID != "cert-1" {
		t.Fatalf("unexpected status: %#v", cert.Status)
	}
	if !reflect.DeepEqual(backend.calls, []string{"GetTLSMaterial"}) {
		t.Fatalf("unexpected backend calls: %#v", backend.calls)
	}
}

func TestAllowedSecretNamePolicyRejectsBeforeBackend(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{}
	reconciler := testReconciler(kube, backend)
	reconciler.AllowedSecretNames = []string{"other-tls"}
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 || len(backend.calls) != 0 || kube.writeCount != 0 {
		t.Fatalf("unexpected work for disallowed secret: result=%#v calls=%#v writes=%d", result, backend.calls, kube.writeCount)
	}
	if cert.Status.Phase != PhaseFailed || !hasCondition(cert.Status, ConditionAccepted, ConditionFalse) {
		t.Fatalf("unexpected status: %#v", cert.Status)
	}
}

func TestNoContentLeavesExistingSecretUnchanged(t *testing.T) {
	kube := newFakeKube()
	old := ownedSecret(testCertificate(), "old-etag")
	old.Data["tls.crt"] = []byte("OLD")
	kube.secrets["ns/gateway-tls"] = old
	backend := &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.ResyncInterval {
		t.Fatalf("unexpected requeue: %s", result.RequeueAfter)
	}
	if string(kube.secrets["ns/gateway-tls"].Data["tls.crt"]) != "OLD" {
		t.Fatalf("secret changed on 204")
	}
	if backend.ifNoneMatch != "old-etag" {
		t.Fatalf("If-None-Match = %q", backend.ifNoneMatch)
	}
	if kube.writeCount != 0 {
		t.Fatalf("unexpected secret write")
	}
}

func TestNotFoundEnsuresCertificateOnlyOnce(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{
		materials: []materialResponse{{err: apiError(http.StatusNotFound, certerrors.CodeCertificateNotFound, false, nil)}},
		ensures: []ensureResponse{{
			value: &certhubclient.CertificateResponse{Certificate: certhubclient.Certificate{ID: "cert-created"}},
			meta:  certhubclient.ResponseMeta{StatusCode: http.StatusAccepted, HeaderRetryAfterSeconds: ptr(11)},
		}},
	}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 11*time.Second {
		t.Fatalf("unexpected requeue: %s", result.RequeueAfter)
	}
	if !reflect.DeepEqual(backend.calls, []string{"GetTLSMaterial", "EnsureCertificate"}) {
		t.Fatalf("unexpected backend calls: %#v", backend.calls)
	}
	if cert.Status.CertificateID != "cert-created" || cert.Status.Phase != PhaseIssuing {
		t.Fatalf("unexpected status: %#v", cert.Status)
	}
	if kube.writeCount != 0 {
		t.Fatalf("secret should not be written while material is absent")
	}
}

func TestAuthorizationDeniedSetsConditionAndPreservesSecret(t *testing.T) {
	kube := newFakeKube()
	kube.secrets["ns/gateway-tls"] = ownedSecret(testCertificate(), "old")
	backend := &fakeBackend{
		materials: []materialResponse{{err: apiError(http.StatusForbidden, certerrors.CodeApplicationSourceIPDenied, false, nil)}},
	}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("authorization failure should not aggressively requeue: %s", result.RequeueAfter)
	}
	if cert.Status.Phase != PhaseFailed || !hasCondition(cert.Status, ConditionAuthorizationFailed, ConditionTrue) {
		t.Fatalf("authorization condition missing: %#v", cert.Status)
	}
	if kube.writeCount != 0 || kube.deleteCount != 0 {
		t.Fatalf("secret was mutated on auth failure")
	}
	if strings.Contains(strings.Join(eventMessages(kube.events), "\n"), "cth_app_v1_") {
		t.Fatalf("event leaked token: %#v", kube.events)
	}
}

func TestTerminalBackendMessageIsSanitized(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{
		materials: []materialResponse{{err: apiError(http.StatusConflict, certerrors.CodeCertificateIssuanceFailed, false, nil)}},
	}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	combined := cert.Status.Message + "\n" + strings.Join(eventMessages(kube.events), "\n")
	if strings.Contains(combined, "cth_app_v1_") {
		t.Fatalf("status/event leaked token: %q", combined)
	}
	if !strings.Contains(combined, "[REDACTED_TOKEN]") {
		t.Fatalf("expected redacted message, got %q", combined)
	}
	if kube.writeCount != 0 {
		t.Fatalf("secret should not be written on terminal backend failure")
	}
}

func TestSanitizeRedactsCommonSecretCarriers(t *testing.T) {
	input := `https://user:secret@example.com token=abc password: hunter2 client_secret=s3cr3t api_key: ak key=plain Cookie: session=COOKIESECRET; csrftoken=CSRFSECRET {"data":{"tls.key":"BASE64KEY","tls.crt":"BASE64CRT"},"stringData":{"token":"STRINGTOKEN"},"private_key_pem":"-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"}`
	got := Sanitize(input)
	for _, leak := range []string{"user:secret", "abc", "hunter2", "s3cr3t", "api_key: ak", "key=plain", "COOKIESECRET", "CSRFSECRET", "BASE64KEY", "BASE64CRT", "STRINGTOKEN", `"tls.key"`, "PRIVATE KEY", "SECRET"} {
		if strings.Contains(got, leak) {
			t.Fatalf("Sanitize leaked %q in %q", leak, got)
		}
	}
	for _, marker := range []string{"[REDACTED]", "[REDACTED]@"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("Sanitize missing marker %q in %q", marker, got)
		}
	}
}

func TestUnownedSecretRefusalAvoidsBackendAndWrite(t *testing.T) {
	kube := newFakeKube()
	secret := ownedSecret(testCertificate(), "old")
	secret.Metadata.Annotations[AnnotationOwnerUID] = "other-uid"
	kube.secrets["ns/gateway-tls"] = secret
	backend := &fakeBackend{}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("unexpected requeue: %s", result.RequeueAfter)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend should not be called for unowned target Secret: %#v", backend.calls)
	}
	if kube.writeCount != 0 || cert.Status.Phase != PhaseFailed {
		t.Fatalf("unexpected mutation/status: writes=%d status=%#v", kube.writeCount, cert.Status)
	}
}

func TestForeignOwnerReferenceRefusesSecret(t *testing.T) {
	kube := newFakeKube()
	secret := ownedSecret(testCertificate(), "old")
	secret.Metadata.OwnerReferences = []OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "gateway",
		UID:        "deployment-uid",
	}}
	kube.secrets["ns/gateway-tls"] = secret
	backend := &fakeBackend{}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if len(backend.calls) != 0 || kube.writeCount != 0 {
		t.Fatalf("foreign-owned secret was used: calls=%#v writes=%d", backend.calls, kube.writeCount)
	}
	if cert.Status.Phase != PhaseFailed {
		t.Fatalf("expected failed status, got %#v", cert.Status)
	}
}

func TestWriteTimeOwnershipCheckRejectsSwappedSecret(t *testing.T) {
	cert := testCertificate()
	desired := ownedSecret(cert, "new")
	swapped := ownedSecret(cert, "old")
	swapped.Metadata.Annotations[AnnotationOwnerUID] = "other"
	if err := checkWritableExistingSecret(swapped, desired); err == nil {
		t.Fatalf("write-time check accepted swapped unowned Secret")
	}
}

func TestStatusUpdateFailureRequeues(t *testing.T) {
	kube := newFakeKube()
	kube.statusErr = stderrors.New("status denied")
	backend := &fakeBackend{materials: []materialResponse{{value: testMaterial("etag-1"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}}}}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.Backoff {
		t.Fatalf("status failure should requeue with backoff, got %s", result.RequeueAfter)
	}
}

func TestRetryIDStoredAsHashMarker(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()
	cert.Metadata.Annotations[AnnotationRetryID] = "cth_app_v1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if cert.Status.ObservedRetryID == "" || strings.Contains(cert.Status.ObservedRetryID, "cth_app_v1_") {
		t.Fatalf("retry id was not safely marked: %q", cert.Status.ObservedRetryID)
	}
}

func TestDeletePolicyDeletesOnlyOwnedSecret(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	cert.Spec.SecretDeletionPolicy = PolicyDelete
	kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")
	reconciler := testReconciler(kube, &fakeBackend{})

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if kube.deleteCount != 1 {
		t.Fatalf("expected owned secret deletion, got %d", kube.deleteCount)
	}
	if _, ok := kube.secrets["ns/gateway-tls"]; ok {
		t.Fatalf("secret still present")
	}
	if len(cert.Metadata.Finalizers) != 0 {
		t.Fatalf("finalizer not removed: %#v", cert.Metadata.Finalizers)
	}
	if len(reconciler.Backend.(*fakeBackend).calls) != 0 {
		t.Fatalf("delete called backend: %#v", reconciler.Backend.(*fakeBackend).calls)
	}
}

func TestDeletePolicyRechecksOwnershipAtDeleteTime(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	cert.Spec.SecretDeletionPolicy = PolicyDelete
	owned := ownedSecret(cert, "old")
	swapped := ownedSecret(cert, "old")
	swapped.Metadata.Annotations[AnnotationOwnerUID] = "other"
	kube.secrets["ns/gateway-tls"] = owned
	kube.beforeDelete = func() {
		kube.secrets["ns/gateway-tls"] = swapped
	}
	reconciler := testReconciler(kube, &fakeBackend{})

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.Backoff {
		t.Fatalf("expected backoff for delete race, got %s", result.RequeueAfter)
	}
	if kube.deleteCount != 0 {
		t.Fatalf("swapped secret was deleted")
	}
}

func TestDeletePolicyRetainsUnownedSecret(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	cert.Spec.SecretDeletionPolicy = PolicyDelete
	unowned := ownedSecret(cert, "old")
	unowned.Metadata.Labels[LabelCertificateName] = "other"
	kube.secrets["ns/gateway-tls"] = unowned
	reconciler := testReconciler(kube, &fakeBackend{})

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if kube.deleteCount != 0 {
		t.Fatalf("unowned secret was deleted")
	}
	if _, ok := kube.secrets["ns/gateway-tls"]; !ok {
		t.Fatalf("unowned secret removed")
	}
	if len(cert.Metadata.Finalizers) != 0 {
		t.Fatalf("finalizer not removed after safe retain: %#v", cert.Metadata.Finalizers)
	}
}

func TestRetryAfterFromBackendError(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{
		materials: []materialResponse{{err: apiError(http.StatusConflict, certerrors.CodeCertificateNotReady, true, ptr(17))}},
	}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 17*time.Second {
		t.Fatalf("Retry-After not honored: %s", result.RequeueAfter)
	}
	if cert.Status.Phase != PhaseIssuing || !hasCondition(cert.Status, ConditionSecretSynced, ConditionFalse) {
		t.Fatalf("unexpected status: %#v", cert.Status)
	}
}

func TestRuntimeReconcileAllReturnsShortestRequeue(t *testing.T) {
	kube := newFakeKube()
	kube.certificates = []*CerthubCertificate{testCertificate()}
	backend := &fakeBackend{
		materials: []materialResponse{{err: apiError(http.StatusConflict, certerrors.CodeCertificateNotReady, true, ptr(17))}},
	}
	runtime := &Runtime{
		Config:  Config{WatchNamespace: "ns", ResyncInterval: time.Hour, ReconcileBackoff: 5 * time.Second},
		Kube:    kube,
		Backend: backend,
		Metrics: NewMetrics(),
	}
	reconciler := testReconciler(kube, backend)
	delay, err := runtime.reconcileAll(context.Background(), reconciler, testLogger(t))
	if err != nil {
		t.Fatalf("reconcileAll failed: %v", err)
	}
	if delay != 17*time.Second {
		t.Fatalf("delay = %s; want 17s", delay)
	}
}

func TestRuntimeReconcileAllHonorsErrorRequeue(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	cert.Spec.SecretDeletionPolicy = PolicyDelete
	kube.certificates = []*CerthubCertificate{cert}
	kube.finalizerErr = stderrors.New("finalizer denied")
	runtime := &Runtime{
		Config:  Config{WatchNamespace: "ns", ResyncInterval: time.Hour, ReconcileBackoff: 5 * time.Second},
		Kube:    kube,
		Backend: &fakeBackend{},
		Metrics: NewMetrics(),
	}
	reconciler := testReconciler(kube, &fakeBackend{})
	delay, err := runtime.reconcileAll(context.Background(), reconciler, testLogger(t))
	if err != nil {
		t.Fatalf("reconcileAll failed: %v", err)
	}
	if delay != 5*time.Second {
		t.Fatalf("delay = %s; want backoff from error result", delay)
	}
}

func TestMetricsConditionIsPerResource(t *testing.T) {
	metrics := NewMetrics()
	a := testCertificate()
	a.Status.Conditions = []Condition{{Type: ConditionReady, Status: ConditionTrue}}
	b := testCertificate()
	b.Metadata.Name = "other"
	b.Status.Conditions = []Condition{{Type: ConditionReady, Status: ConditionFalse}}
	metrics.SetCertificateConditions(a)
	metrics.SetCertificateConditions(b)

	lines := metricLines(metrics)
	if !slices.Contains(lines, `certhub_operator_condition{namespace="ns",name="gateway",condition="Ready"} 1`) {
		t.Fatalf("missing gateway condition metric: %#v", lines)
	}
	if !slices.Contains(lines, `certhub_operator_condition{namespace="ns",name="other",condition="Ready"} 0`) {
		t.Fatalf("missing other condition metric: %#v", lines)
	}
}

func TestDeletedCertificateClearsConditionMetrics(t *testing.T) {
	metrics := NewMetrics()
	cert := testCertificate()
	cert.Status.Conditions = []Condition{{Type: ConditionReady, Status: ConditionTrue}}
	metrics.SetCertificateConditions(cert)
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	reconciler := testReconciler(newFakeKube(), &fakeBackend{})
	reconciler.Metrics = metrics

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("delete reconcile failed: %v", err)
	}
	for _, line := range metricLines(metrics) {
		if strings.Contains(line, `name="gateway"`) && strings.Contains(line, "certhub_operator_condition") {
			t.Fatalf("deleted condition metric remained: %#v", metricLines(metrics))
		}
	}
}

func TestConfigAndTokenLoading(t *testing.T) {
	_, err := LoadConfig(func(key string) string {
		values := map[string]string{
			"CERTHUB_URL":               "http://certhub.example",
			"CERTHUB_TOKEN_SECRET_NAME": "app-token",
		}
		return values[key]
	})
	if err == nil {
		t.Fatalf("plain HTTP URL accepted")
	}
	cfg, err := LoadConfig(func(key string) string {
		values := map[string]string{
			"CERTHUB_URL":                    "https://certhub.example",
			"CERTHUB_TOKEN_SECRET_NAMESPACE": "ops",
			"CERTHUB_TOKEN_SECRET_NAME":      "app-token",
			"CERTHUB_TOKEN_SECRET_KEY":       "token",
		}
		return values[key]
	})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	kube := newFakeKube()
	kube.secrets["ops/app-token"] = &Secret{Data: map[string][]byte{"token": []byte("cth_app_v1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")}}
	token, err := LoadApplicationToken(context.Background(), kube, cfg.TokenNamespace, cfg.TokenSecretName, cfg.TokenSecretKey)
	if err != nil {
		t.Fatalf("token load failed: %v", err)
	}
	if !strings.HasPrefix(token, "cth_app_v1_") {
		t.Fatalf("unexpected token: %q", token)
	}
}

func testReconciler(kube *fakeKube, backend *fakeBackend) *Reconciler {
	r := NewReconciler(kube, backend)
	r.ResyncInterval = time.Hour
	r.Backoff = 5 * time.Second
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return now }
	r.NewRequestID = func(*CerthubCertificate) string { return "operator-test-request" }
	return r
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testCertificate() *CerthubCertificate {
	return &CerthubCertificate{
		Metadata: Metadata{
			Name:        "gateway",
			Namespace:   "ns",
			UID:         "uid-1",
			Annotations: map[string]string{},
		},
		Spec: CerthubCertificateSpec{
			Domains:    []string{"gateway.example.com"},
			SecretName: "gateway-tls",
			KeyType:    "ecdsa-p256",
		},
	}
}

func testMaterial(etag string) *material.TLSMaterial {
	return &material.TLSMaterial{
		CertificateID:     "cert-1",
		Domains:           []string{"gateway.example.com"},
		KeyType:           "ecdsa-p256",
		Version:           3,
		FullchainPEM:      "FULLCHAIN",
		PrivateKeyPEM:     "PRIVATEKEY",
		NotBefore:         time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		FingerprintSHA256: "abc123",
		MaterialETag:      etag,
	}
}

func ownedSecret(cert *CerthubCertificate, etag string) *Secret {
	return &Secret{
		Metadata: Metadata{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Metadata.Namespace,
			Labels: map[string]string{
				LabelManagedBy:       ManagedByValue,
				LabelCertificateName: cert.Metadata.Name,
			},
			Annotations: map[string]string{
				AnnotationOwnerUID:     cert.Metadata.UID,
				AnnotationMaterialETag: etag,
			},
			OwnerReferences: []OwnerReference{{
				APIVersion: APIVersion,
				Kind:       Kind,
				Name:       cert.Metadata.Name,
				UID:        cert.Metadata.UID,
			}},
		},
		Type: SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("CERT"),
			"tls.key": []byte("KEY"),
		},
	}
}

func apiError(status int, code string, retryable bool, retryAfter *int) error {
	return certerrors.NewAPIError(status, "req-1", retryAfter, certerrors.Envelope{
		Code:              code,
		Message:           "backend message cth_app_v1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
		Retryable:         retryable,
		RetryAfterSeconds: retryAfter,
	})
}

func ptr(value int) *int {
	return &value
}

func hasCondition(status CerthubCertificateStatus, conditionType, value string) bool {
	for _, condition := range status.Conditions {
		if condition.Type == conditionType && condition.Status == value {
			return true
		}
	}
	return false
}

func eventMessages(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, event := range events {
		out = append(out, event.Message)
	}
	return out
}

func metricLines(metrics *Metrics) []string {
	var b strings.Builder
	req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	rec := &responseRecorder{header: http.Header{}, body: &b}
	metrics.Handler().ServeHTTP(rec, req)
	return strings.Split(strings.TrimSpace(b.String()), "\n")
}

type responseRecorder struct {
	header http.Header
	body   *strings.Builder
	code   int
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.code = statusCode
}

type materialResponse struct {
	value *material.TLSMaterial
	meta  certhubclient.ResponseMeta
	err   error
}

type ensureResponse struct {
	value *certhubclient.CertificateResponse
	meta  certhubclient.ResponseMeta
	err   error
}

type fakeBackend struct {
	calls       []string
	materials   []materialResponse
	ensures     []ensureResponse
	ifNoneMatch string
}

func (f *fakeBackend) GetTLSMaterial(_ context.Context, _ certhubclient.CertificateCriteria, opts certhubclient.RequestOptions) (*material.TLSMaterial, certhubclient.ResponseMeta, error) {
	f.calls = append(f.calls, "GetTLSMaterial")
	f.ifNoneMatch = opts.IfNoneMatch
	if len(f.materials) == 0 {
		return nil, certhubclient.ResponseMeta{}, stderrors.New("unexpected material call")
	}
	next := f.materials[0]
	f.materials = f.materials[1:]
	return next.value, next.meta, next.err
}

func (f *fakeBackend) EnsureCertificate(_ context.Context, _ certhubclient.CertificateCriteria, _ certhubclient.RequestOptions) (*certhubclient.CertificateResponse, certhubclient.ResponseMeta, error) {
	f.calls = append(f.calls, "EnsureCertificate")
	if len(f.ensures) == 0 {
		return nil, certhubclient.ResponseMeta{}, stderrors.New("unexpected ensure call")
	}
	next := f.ensures[0]
	f.ensures = f.ensures[1:]
	return next.value, next.meta, next.err
}

type fakeKube struct {
	secrets       map[string]*Secret
	certificates  []*CerthubCertificate
	statusUpdates int
	writeCount    int
	deleteCount   int
	events        []Event
	statusErr     error
	beforeDelete  func()
	finalizerErr  error
}

func newFakeKube() *fakeKube {
	return &fakeKube{secrets: map[string]*Secret{}}
}

func (f *fakeKube) GetSecret(_ context.Context, namespace, name string) (*Secret, error) {
	secret := f.secrets[namespace+"/"+name]
	if secret == nil {
		return nil, ErrNotFound
	}
	return secret, nil
}

func (f *fakeKube) CreateOrUpdateSecret(_ context.Context, secret *Secret) error {
	f.writeCount++
	f.secrets[secret.Metadata.Namespace+"/"+secret.Metadata.Name] = secret
	return nil
}

func (f *fakeKube) DeleteSecret(_ context.Context, namespace, name string, expected *Secret) error {
	if _, ok := f.secrets[namespace+"/"+name]; !ok {
		return ErrNotFound
	}
	if f.beforeDelete != nil {
		f.beforeDelete()
	}
	if err := checkWritableExistingSecret(f.secrets[namespace+"/"+name], expected); err != nil {
		return err
	}
	f.deleteCount++
	delete(f.secrets, namespace+"/"+name)
	return nil
}

func (f *fakeKube) UpdateStatus(_ context.Context, _ *CerthubCertificate) error {
	f.statusUpdates++
	return f.statusErr
}

func (f *fakeKube) UpdateFinalizers(_ context.Context, cert *CerthubCertificate, finalizers []string) error {
	if f.finalizerErr != nil {
		return f.finalizerErr
	}
	cert.Metadata.Finalizers = append([]string(nil), finalizers...)
	return nil
}

func (f *fakeKube) EmitEvent(_ context.Context, event Event) error {
	f.events = append(f.events, event)
	return nil
}

func (f *fakeKube) ListCertificates(context.Context, string) ([]*CerthubCertificate, error) {
	return f.certificates, nil
}

func (f *fakeKube) WatchCertificateChanges(ctx context.Context, _ string) (<-chan struct{}, error) {
	ch := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (f *fakeKube) DefaultNamespace() string {
	return "ns"
}
