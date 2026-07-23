package operator

import (
	"context"
	stderrors "errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
	certerrors "github.com/torob/certhub/pkg/errors"
	"github.com/torob/certhub/pkg/material"
)

const validOperatorToken = "cth_app_v1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

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
	if !reflect.DeepEqual(secret.Metadata.OwnerReferences, []OwnerReference{certhubOwnerReference(cert)}) {
		t.Fatalf("new Secret owner reference = %#v", secret.Metadata.OwnerReferences)
	}
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("cleanup finalizer not persisted: %#v", cert.Metadata.Finalizers)
	}
	if !reflect.DeepEqual(kube.operations, []string{"finalizer:add", "secret:write"}) {
		t.Fatalf("finalizer was not persisted before Secret ownership: %#v", kube.operations)
	}
	if cert.Status.Phase != PhaseReady || cert.Status.CertificateID != "cert-1" {
		t.Fatalf("unexpected status: %#v", cert.Status)
	}
	if !reflect.DeepEqual(backend.calls, []string{"GetTLSMaterial"}) {
		t.Fatalf("unexpected backend calls: %#v", backend.calls)
	}
}

func TestDeletePolicySyncWritesSecretWithOwnerReference(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{materials: []materialResponse{{value: testMaterial("etag-delete"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}}}}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()
	cert.Spec.SecretDeletionPolicy = PolicyDelete

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	secret := kube.secrets["ns/gateway-tls"]
	if secret == nil || !reflect.DeepEqual(secret.Metadata.OwnerReferences, []OwnerReference{certhubOwnerReference(cert)}) {
		t.Fatalf("Delete policy Secret owner reference = %#v", secret)
	}
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("Delete policy finalizer not added: %#v", cert.Metadata.Finalizers)
	}
}

func TestNoContentMigratesOwnerlessSecretWithoutChangingMaterialOrIdentity(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	old := ownedSecret(cert, "old-etag")
	old.Metadata.OwnerReferences = nil
	old.Metadata.UID = "secret-uid"
	old.Metadata.ResourceVersion = "rv-old"
	old.Metadata.Labels["extra"] = "preserved"
	old.Metadata.Annotations["extra"] = "preserved"
	old.Data["tls.crt"] = []byte("OLD")
	kube.secrets["ns/gateway-tls"] = old
	backend := &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}}
	reconciler := testReconciler(kube, backend)

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
	migrated := kube.secrets["ns/gateway-tls"]
	if kube.clearOwnerReferencesCount != 1 || !reflect.DeepEqual(migrated.Metadata.OwnerReferences, []OwnerReference{certhubOwnerReference(cert)}) {
		t.Fatalf("owner reference was not added: %#v", migrated.Metadata.OwnerReferences)
	}
	if migrated.Metadata.UID != "secret-uid" || migrated.Metadata.ResourceVersion != "rv-old" || migrated.Type != SecretTypeTLS || migrated.Metadata.Labels["extra"] != "preserved" || migrated.Metadata.Annotations["extra"] != "preserved" {
		t.Fatalf("metadata-only migration changed the Secret: %#v", migrated)
	}
	if !reflect.DeepEqual(kube.operations, []string{"finalizer:add", "owner:set"}) {
		t.Fatalf("owner reference attached before finalizer: %#v", kube.operations)
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
	if kube.clearOwnerReferencesCount != 0 {
		t.Fatalf("foreign-owned Secret owner references were modified")
	}
	if cert.Status.Phase != PhaseFailed {
		t.Fatalf("expected failed status, got %#v", cert.Status)
	}
}

func TestOwnerReferenceCleanupFailurePreservesRetainFinalizer(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	cert.Metadata.Finalizers = []string{Finalizer}
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	secret := ownedSecret(cert, "old")
	secret.Metadata.OwnerReferences = []OwnerReference{certhubOwnerReference(cert)}
	kube.secrets["ns/gateway-tls"] = secret
	kube.clearOwnerReferencesErr = stderrors.New("conflict")
	backend := &fakeBackend{}
	reconciler := testReconciler(kube, backend)

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.Backoff || result.Result != "owner_reference_cleanup_failed" {
		t.Fatalf("unexpected cleanup failure result: %#v", result)
	}
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("Retain finalizer was removed before owner-reference cleanup")
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend called after metadata migration failure: %#v", backend.calls)
	}
}

func TestOwnerReferenceMigrationFailurePreservesFinalizerAndSecret(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	secret := ownedSecret(cert, "old")
	secret.Metadata.OwnerReferences = nil
	secret.Metadata.UID = "stable-uid"
	secret.Data["tls.crt"] = []byte("UNCHANGED")
	kube.secrets["ns/gateway-tls"] = secret
	kube.clearOwnerReferencesErr = stderrors.New("patch denied")
	reconciler := testReconciler(kube, &fakeBackend{})

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.Result != "owner_reference_migration_failed" || result.RequeueAfter != reconciler.Backoff {
		t.Fatalf("unexpected migration failure result: %#v", result)
	}
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) || len(secret.Metadata.OwnerReferences) != 0 || secret.Metadata.UID != "stable-uid" || string(secret.Data["tls.crt"]) != "UNCHANGED" {
		t.Fatalf("failed migration changed protected state: cert=%#v secret=%#v", cert.Metadata, secret)
	}
	if len(reconciler.Backend.(*fakeBackend).calls) != 0 {
		t.Fatalf("backend called after migration failure")
	}

	kube.clearOwnerReferencesErr = nil
	reconciler.Backend = &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}}
	result, err = reconciler.Reconcile(context.Background(), cert)
	if err != nil || result.Result != "current" {
		t.Fatalf("migration did not recover after permission restore: result=%#v err=%v", result, err)
	}
	if !reflect.DeepEqual(secret.Metadata.OwnerReferences, []OwnerReference{certhubOwnerReference(cert)}) || secret.Metadata.UID != "stable-uid" || string(secret.Data["tls.crt"]) != "UNCHANGED" {
		t.Fatalf("recovered migration changed Secret identity/material: %#v", secret)
	}
}

func TestFinalizerFailurePreventsSecretOwnership(t *testing.T) {
	kube := newFakeKube()
	kube.finalizerErr = stderrors.New("finalizer denied")
	backend := &fakeBackend{}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()
	secret := ownedSecret(cert, "old")
	secret.Metadata.OwnerReferences = nil
	secret.Metadata.UID = "stable-uid"
	kube.secrets["ns/gateway-tls"] = secret

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err == nil || result.Result != "finalizer_failed" {
		t.Fatalf("unexpected finalizer failure: result=%#v err=%v", result, err)
	}
	if kube.writeCount != 0 || kube.clearOwnerReferencesCount != 0 || len(backend.calls) != 0 {
		t.Fatalf("work continued without durable finalizer: operations=%#v backend=%#v", kube.operations, backend.calls)
	}
	if len(secret.Metadata.OwnerReferences) != 0 || secret.Metadata.UID != "stable-uid" {
		t.Fatalf("ownerless Secret changed while finalizer patch was denied: %#v", secret.Metadata)
	}
}

func TestSecretWriteFailurePreservesFinalizer(t *testing.T) {
	kube := newFakeKube()
	kube.writeErr = stderrors.New("secret write denied")
	backend := &fakeBackend{materials: []materialResponse{{value: testMaterial("etag"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}}}}
	reconciler := testReconciler(kube, backend)
	cert := testCertificate()

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil || result.Result != "secret_write_failed" {
		t.Fatalf("unexpected Secret failure: result=%#v err=%v", result, err)
	}
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) || kube.secrets["ns/gateway-tls"] != nil {
		t.Fatalf("Secret failure lost protection: cert=%#v secrets=%#v", cert.Metadata, kube.secrets)
	}
}

func TestDeletionPolicyTransitionsReconcileFinalizer(t *testing.T) {
	t.Run("Retain to Delete adds finalizer", func(t *testing.T) {
		kube := newFakeKube()
		cert := testCertificate()
		cert.Spec.SecretDeletionPolicy = PolicyDelete
		kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")
		reconciler := testReconciler(kube, &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}})

		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
			t.Fatalf("Delete policy finalizer not added: %#v", cert.Metadata.Finalizers)
		}
	})

	t.Run("Delete to Retain preserves cleanup finalizer and ownership", func(t *testing.T) {
		kube := newFakeKube()
		cert := testCertificate()
		cert.Metadata.Finalizers = []string{Finalizer}
		secret := ownedSecret(cert, "old")
		secret.Metadata.OwnerReferences = []OwnerReference{certhubOwnerReference(cert)}
		kube.secrets["ns/gateway-tls"] = secret
		reconciler := testReconciler(kube, &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}})

		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
			t.Fatalf("Retain policy cleanup finalizer missing: %#v", cert.Metadata.Finalizers)
		}
		if kube.clearOwnerReferencesCount != 0 || !reflect.DeepEqual(secret.Metadata.OwnerReferences, []OwnerReference{certhubOwnerReference(cert)}) {
			t.Fatalf("live Retain Secret ownership changed: %#v", secret.Metadata.OwnerReferences)
		}
	})
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

func TestStableReconcileSkipsStatusWritesAndEvents(t *testing.T) {
	t.Run("ready current", func(t *testing.T) {
		kube := newFakeKube()
		cert := testCertificate()
		kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")
		backend := &fakeBackend{materials: []materialResponse{
			{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}},
			{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}},
		}}
		reconciler := testReconciler(kube, backend)

		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		firstConditions := append([]Condition(nil), cert.Status.Conditions...)
		reconciler.Now = func() time.Time { return time.Date(2026, 6, 26, 13, 0, 0, 0, time.UTC) }
		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		if kube.statusUpdates != 1 {
			t.Fatalf("status updates = %d; want one transition write", kube.statusUpdates)
		}
		if len(kube.events) != 1 || kube.events[0].Reason != "CertificateReady" {
			t.Fatalf("events repeated for stable Ready status: %#v", kube.events)
		}
		if !reflect.DeepEqual(cert.Status.Conditions, firstConditions) {
			t.Fatalf("stable Ready conditions changed: before=%#v after=%#v", firstConditions, cert.Status.Conditions)
		}
	})

	t.Run("authorization failed", func(t *testing.T) {
		kube := newFakeKube()
		cert := testCertificate()
		backend := &fakeBackend{materials: []materialResponse{
			{err: apiError(http.StatusForbidden, certerrors.CodeDomainNotAuthorized, false, nil)},
			{err: apiError(http.StatusForbidden, certerrors.CodeDomainNotAuthorized, false, nil)},
		}}
		reconciler := testReconciler(kube, backend)

		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		firstConditions := append([]Condition(nil), cert.Status.Conditions...)
		reconciler.Now = func() time.Time { return time.Date(2026, 6, 26, 13, 0, 0, 0, time.UTC) }
		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		if kube.statusUpdates != 1 || len(kube.events) != 1 {
			t.Fatalf("stable authorization failure wrote status/events: updates=%d events=%#v", kube.statusUpdates, kube.events)
		}
		if !reflect.DeepEqual(cert.Status.Conditions, firstConditions) {
			t.Fatalf("stable authorization conditions changed: before=%#v after=%#v", firstConditions, cert.Status.Conditions)
		}
	})

	t.Run("ownership conflict", func(t *testing.T) {
		kube := newFakeKube()
		cert := testCertificate()
		unowned := ownedSecret(cert, "old")
		unowned.Metadata.Annotations[AnnotationOwnerUID] = "other-owner"
		kube.secrets["ns/gateway-tls"] = unowned
		reconciler := testReconciler(kube, &fakeBackend{})

		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		firstConditions := append([]Condition(nil), cert.Status.Conditions...)
		reconciler.Now = func() time.Time { return time.Date(2026, 6, 26, 13, 0, 0, 0, time.UTC) }
		if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
		if kube.statusUpdates != 1 || len(kube.events) != 1 {
			t.Fatalf("stable ownership conflict wrote status/events: updates=%d events=%#v", kube.statusUpdates, kube.events)
		}
		if !reflect.DeepEqual(cert.Status.Conditions, firstConditions) {
			t.Fatalf("stable ownership conditions changed: before=%#v after=%#v", firstConditions, cert.Status.Conditions)
		}
	})
}

func TestConditionTransitionTimeChangesOnlyWithConditionStatus(t *testing.T) {
	first := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	third := second.Add(time.Hour)
	status := CerthubCertificateStatus{Conditions: []Condition{
		condition(ConditionReady, ConditionFalse, "Pending", "waiting", first),
	}}

	upsertCondition(&status, condition(ConditionReady, ConditionFalse, "StillPending", "still waiting", second))
	if got := status.Conditions[0].LastTransitionTime; !got.Equal(first) {
		t.Fatalf("same-status update moved transition time to %s", got)
	}
	upsertCondition(&status, condition(ConditionReady, ConditionTrue, "Ready", "ready", third))
	if got := status.Conditions[0].LastTransitionTime; !got.Equal(third) {
		t.Fatalf("status transition time = %s; want %s", got, third)
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

func TestRetainPolicyClearsLegacyOwnerBeforeCRDeletion(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	secret := ownedSecret(cert, "old")
	secret.Metadata.OwnerReferences = []OwnerReference{certhubOwnerReference(cert)}
	kube.secrets["ns/gateway-tls"] = secret
	reconciler := testReconciler(kube, &fakeBackend{})

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if kube.deleteCount != 0 || kube.secrets["ns/gateway-tls"] == nil {
		t.Fatalf("Retain policy removed the target Secret")
	}
	if kube.clearOwnerReferencesCount != 1 || len(secret.Metadata.OwnerReferences) != 0 {
		t.Fatalf("owner reference was not cleared")
	}
	if slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("finalizer not removed after Secret retention: %#v", cert.Metadata.Finalizers)
	}
	if !reflect.DeepEqual(kube.operations, []string{"owner:clear", "finalizer:remove"}) {
		t.Fatalf("Retain finalizer released before owner cleanup: %#v", kube.operations)
	}
}

func TestRetainFinalizerRemovalFailureLeavesDetachedSecretAndTerminatingCertificate(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	secret := ownedSecret(cert, "old")
	kube.secrets["ns/gateway-tls"] = secret
	kube.finalizerErr = stderrors.New("finalizer patch denied")
	reconciler := testReconciler(kube, &fakeBackend{})

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err == nil || result.Result != "finalizer_failed" {
		t.Fatalf("unexpected finalizer removal failure: result=%#v err=%v", result, err)
	}
	if len(secret.Metadata.OwnerReferences) != 0 || !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("retention cleanup did not safely stop: secret=%#v cert=%#v", secret.Metadata, cert.Metadata)
	}
	if _, ok := kube.secrets["ns/gateway-tls"]; !ok {
		t.Fatal("retained Secret disappeared")
	}

	kube.finalizerErr = nil
	result, err = reconciler.Reconcile(context.Background(), cert)
	if err != nil || result.Result != "deleted" || slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("cleanup did not finish after permission restore: result=%#v err=%v finalizers=%#v", result, err, cert.Metadata.Finalizers)
	}
	if kube.clearOwnerReferencesCount != 1 {
		t.Fatalf("detached Secret was patched repeatedly: %d", kube.clearOwnerReferencesCount)
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
	if !reflect.DeepEqual(kube.operations, []string{"secret:delete", "finalizer:remove"}) {
		t.Fatalf("finalizer released before preconditioned deletion: %#v", kube.operations)
	}
}

func TestDeleteFailurePreservesFinalizer(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	cert.Spec.SecretDeletionPolicy = PolicyDelete
	kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")
	kube.deleteErr = stderrors.New("delete denied")
	reconciler := testReconciler(kube, &fakeBackend{})

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil || result.Result != "delete_failed" || !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("delete failure released finalizer: result=%#v err=%v finalizers=%#v", result, err, cert.Metadata.Finalizers)
	}
}

func TestDeletePendingPreservesFinalizerUntilSecretIsAbsent(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	cert.Spec.SecretDeletionPolicy = PolicyDelete
	kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")
	kube.deleteErr = ErrDeletionPending
	reconciler := testReconciler(kube, &fakeBackend{})

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil || result.Result != "delete_pending" || result.RequeueAfter != reconciler.Backoff {
		t.Fatalf("pending deletion result=%#v err=%v", result, err)
	}
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) || kube.secrets["ns/gateway-tls"] == nil {
		t.Fatalf("pending deletion released protection: cert=%#v secret=%#v", cert.Metadata, kube.secrets["ns/gateway-tls"])
	}
	if slices.Contains(kube.operations, "finalizer:remove") {
		t.Fatalf("pending deletion removed finalizer: %#v", kube.operations)
	}

	kube.deleteErr = nil
	result, err = reconciler.Reconcile(context.Background(), cert)
	if err != nil || result.Result != "deleted" || slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("completed deletion did not release finalizer: result=%#v err=%v cert=%#v", result, err, cert.Metadata)
	}
}

func TestStatusAlwaysObservesReconciledGeneration(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	cert.Metadata.Generation = 7
	kube.secrets["ns/gateway-tls"] = ownedSecret(cert, "old")
	reconciler := testReconciler(kube, &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}})

	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if cert.Status.ObservedGeneration != 7 || kube.statusUpdates != 1 {
		t.Fatalf("status generation = %d, writes=%d", cert.Status.ObservedGeneration, kube.statusUpdates)
	}

	cert.Metadata.Generation = 8
	reconciler.Backend = &fakeBackend{materials: []materialResponse{{meta: certhubclient.ResponseMeta{StatusCode: http.StatusNoContent}}}}
	if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if cert.Status.ObservedGeneration != 8 || kube.statusUpdates != 2 {
		t.Fatalf("new generation was not persisted: status=%#v writes=%d", cert.Status, kube.statusUpdates)
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
	if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		t.Fatalf("finalizer released without verified cleanup: %#v", cert.Metadata.Finalizers)
	}
}

func TestBackendTransportOutagePreservesSecretThenRecovers(t *testing.T) {
	kube := newFakeKube()
	cert := testCertificate()
	old := ownedSecret(cert, "old-etag")
	old.Data["tls.crt"] = []byte("OLD-CERT")
	kube.secrets["ns/gateway-tls"] = old
	backend := &fakeBackend{
		materials: []materialResponse{
			{err: stderrors.New("dial tcp 127.0.0.1:443: connect: connection refused")},
			{value: testMaterial("new-etag"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}},
		},
	}
	reconciler := testReconciler(kube, backend)

	result, err := reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.Backoff || result.Result != "backend_unavailable" || result.BackendCode != "transport" {
		t.Fatalf("unexpected outage result: %#v", result)
	}
	if string(kube.secrets["ns/gateway-tls"].Data["tls.crt"]) != "OLD-CERT" {
		t.Fatalf("existing secret changed during backend outage")
	}
	if cert.Status.Phase != PhasePending || !hasCondition(cert.Status, ConditionReady, ConditionFalse) {
		t.Fatalf("unexpected transient status: %#v", cert.Status)
	}

	result, err = reconciler.Reconcile(context.Background(), cert)
	if err != nil {
		t.Fatalf("recovery reconcile failed: %v", err)
	}
	if result.RequeueAfter != reconciler.ResyncInterval || result.Result != "synced" {
		t.Fatalf("unexpected recovery result: %#v", result)
	}
	if string(kube.secrets["ns/gateway-tls"].Data["tls.crt"]) != "FULLCHAIN" {
		t.Fatalf("secret was not updated after backend recovery")
	}
	if kube.secrets["ns/gateway-tls"].Metadata.Annotations[AnnotationMaterialETag] != "new-etag" {
		t.Fatalf("new etag not stored: %#v", kube.secrets["ns/gateway-tls"].Metadata.Annotations)
	}
	if cert.Status.Phase != PhaseReady || !hasCondition(cert.Status, ConditionReady, ConditionTrue) {
		t.Fatalf("unexpected recovered status: %#v", cert.Status)
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
		Config:  Config{WatchNamespaces: []string{"ns"}, ResyncInterval: time.Hour, ReconcileBackoff: 5 * time.Second},
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
		Config:  Config{WatchNamespaces: []string{"ns"}, ResyncInterval: time.Hour, ReconcileBackoff: 5 * time.Second},
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

func TestRuntimeReconcileAllCoversNamespacesDespiteListFailure(t *testing.T) {
	kube := newFakeKube()
	first := testCertificate()
	first.Metadata.Namespace = "first"
	second := testCertificate()
	second.Metadata.Namespace = "third"
	second.Metadata.Name = "second"
	second.Metadata.UID = "uid-2"
	kube.certificatesByNamespace = map[string][]*CerthubCertificate{
		"first": {first},
		"third": {second},
	}
	kube.listErrors = map[string]error{"second": stderrors.New("list denied")}
	backend := &fakeBackend{materials: []materialResponse{
		{value: testMaterial("first-etag"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}},
		{value: testMaterial("third-etag"), meta: certhubclient.ResponseMeta{StatusCode: http.StatusOK}},
	}}
	runtime := &Runtime{
		Config: Config{
			WatchNamespaces:  []string{"first", "second", "third"},
			ResyncInterval:   time.Hour,
			ReconcileBackoff: 5 * time.Second,
		},
		Kube:    kube,
		Backend: backend,
		Metrics: NewMetrics(),
	}
	reconciler := testReconciler(kube, backend)

	delay, err := runtime.reconcileAll(context.Background(), reconciler, testLogger(t))
	if err == nil || !strings.Contains(err.Error(), "second") {
		t.Fatalf("reconcileAll error = %v", err)
	}
	if delay != 5*time.Second {
		t.Fatalf("delay = %s; want list failure backoff", delay)
	}
	if !reflect.DeepEqual(kube.listedNamespaces, []string{"first", "second", "third"}) {
		t.Fatalf("listed namespaces = %#v", kube.listedNamespaces)
	}
	if kube.writeCount != 2 {
		t.Fatalf("writes = %d; want successful namespaces to reconcile", kube.writeCount)
	}
}

func TestRuntimeEmptyNamespaceListUsesClusterScope(t *testing.T) {
	kube := newFakeKube()
	backend := &fakeBackend{}
	runtime := &Runtime{
		Config:  Config{ResyncInterval: time.Hour, ReconcileBackoff: 5 * time.Second},
		Kube:    kube,
		Backend: backend,
		Metrics: NewMetrics(),
	}
	reconciler := testReconciler(kube, backend)

	if _, err := runtime.reconcileAll(context.Background(), reconciler, testLogger(t)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(kube.listedNamespaces, []string{""}) {
		t.Fatalf("listed namespaces = %#v; want cluster-wide empty namespace", kube.listedNamespaces)
	}
}

func TestRuntimeMultiplexesNamespaceWatches(t *testing.T) {
	kube := newFakeKube()
	kube.watchChannels = map[string]chan CertificateWatchEvent{
		"first":  make(chan CertificateWatchEvent, 1),
		"second": make(chan CertificateWatchEvent, 1),
	}
	runtime := &Runtime{
		Config: Config{WatchNamespaces: []string{"first", "second"}},
		Kube:   kube,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := runtime.watchCertificateChanges(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kube.watchChannels["second"] <- CertificateWatchEvent{Type: "ADDED", Certificate: testCertificate()}
	select {
	case change := <-events:
		if change.namespace != "second" || change.event.Type != "ADDED" {
			t.Fatalf("unexpected watch change: %#v", change)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for namespace watch event")
	}
	if !reflect.DeepEqual(kube.watchedNamespaces, []string{"first", "second"}) {
		t.Fatalf("watched namespaces = %#v", kube.watchedNamespaces)
	}
}

func TestRuntimeFiltersStatusOnlyWatchChanges(t *testing.T) {
	runtime := &Runtime{}
	base := testCertificate()
	base.Metadata.ResourceVersion = "1"
	runtime.rememberCertificateInput(base)

	statusOnly := cloneTestCertificate(base)
	statusOnly.Metadata.ResourceVersion = "2"
	statusOnly.Status.Phase = PhaseReady
	if runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "MODIFIED", Certificate: statusOnly}) {
		t.Fatal("status-only watch change triggered reconciliation")
	}

	generation := cloneTestCertificate(statusOnly)
	generation.Metadata.Generation++
	if !runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "MODIFIED", Certificate: generation}) {
		t.Fatal("generation change was ignored")
	}

	retry := cloneTestCertificate(generation)
	retry.Metadata.Annotations[AnnotationRetryID] = "retry-2"
	if !runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "MODIFIED", Certificate: retry}) {
		t.Fatal("retry annotation change was ignored")
	}

	spec := cloneTestCertificate(retry)
	spec.Spec.Domains = []string{"new.example.com"}
	if !runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "MODIFIED", Certificate: spec}) {
		t.Fatal("spec change was ignored")
	}

	finalizer := cloneTestCertificate(spec)
	finalizer.Metadata.Finalizers = []string{Finalizer}
	if !runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "MODIFIED", Certificate: finalizer}) {
		t.Fatal("finalizer change was ignored")
	}

	deleting := cloneTestCertificate(finalizer)
	now := time.Now().UTC()
	deleting.Metadata.DeletionTimestamp = &now
	if !runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "MODIFIED", Certificate: deleting}) {
		t.Fatal("deletion timestamp change was ignored")
	}
	if runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "DELETED", Certificate: deleting}) {
		t.Fatal("deleted watch event triggered reconciliation")
	}
	if !runtime.shouldReconcileWatchEvent("ns", CertificateWatchEvent{Type: "ADDED", Certificate: base}) {
		t.Fatal("re-created certificate was ignored after deletion")
	}
}

func TestRuntimeContinuesAfterInitialNamespaceListFailure(t *testing.T) {
	kube := newFakeKube()
	kube.listErrors = map[string]error{"second": stderrors.New("list denied")}
	backend := &fakeBackend{}
	runtime := &Runtime{
		Config: Config{
			WatchNamespaces:  []string{"first", "second"},
			MetricsBindAddr:  "127.0.0.1:0",
			ResyncInterval:   time.Hour,
			ReconcileBackoff: 5 * time.Second,
		},
		Kube:    kube,
		Backend: backend,
		Metrics: NewMetrics(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)

	if err := runtime.Run(ctx, io.Discard); err != nil {
		t.Fatalf("runtime stopped on partial initial list failure: %v", err)
	}
	if !reflect.DeepEqual(kube.watchedNamespaces, []string{"first", "second"}) {
		t.Fatalf("watched namespaces = %#v", kube.watchedNamespaces)
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

func TestConfigAndBackendConstruction(t *testing.T) {
	_, err := LoadConfig(func(key string) string {
		values := map[string]string{
			"CERTHUB_URL":   "http://certhub.example",
			"CERTHUB_TOKEN": validOperatorToken,
		}
		return values[key]
	})
	if err == nil {
		t.Fatalf("plain HTTP URL accepted")
	}
	for _, tt := range []struct {
		name  string
		token string
	}{
		{name: "missing token"},
		{name: "malformed token", token: "not-an-application-token"},
		{name: "user token", token: "cth_uat_v1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(func(key string) string {
				values := map[string]string{
					"CERTHUB_URL":   "https://certhub.example",
					"CERTHUB_TOKEN": tt.token,
				}
				return values[key]
			})
			if err == nil {
				t.Fatal("invalid token configuration accepted")
			}
		})
	}
	cfg, err := LoadConfig(func(key string) string {
		values := map[string]string{
			"CERTHUB_URL":                        "https://certhub.example",
			"CERTHUB_TOKEN":                      "  " + validOperatorToken + "\n",
			"WATCH_NAMESPACES":                   "apps, staging",
			"CERTHUB_HTTP_RETRY_MAX_ATTEMPTS":    "3",
			"CERTHUB_HTTP_RETRY_INITIAL_BACKOFF": "2s",
			"CERTHUB_HTTP_RETRY_MAX_BACKOFF":     "6s",
		}
		return values[key]
	})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.RetryPolicy.MaxAttempts != 3 || cfg.RetryPolicy.InitialBackoff != 2*time.Second || cfg.RetryPolicy.MaxBackoff != 6*time.Second {
		t.Fatalf("retry policy = %#v", cfg.RetryPolicy)
	}
	if !reflect.DeepEqual(cfg.WatchNamespaces, []string{"apps", "staging"}) {
		t.Fatalf("watch namespaces = %#v", cfg.WatchNamespaces)
	}
	if cfg.Token != validOperatorToken {
		t.Fatalf("token was not trimmed")
	}
	if backend, err := NewHTTPBackendFromConfig(cfg); err != nil || backend == nil {
		t.Fatalf("backend construction failed: %v", err)
	}
}

func TestOperatorResyncIntervalBounds(t *testing.T) {
	base := map[string]string{
		"CERTHUB_URL":   "https://certhub.example",
		"CERTHUB_TOKEN": validOperatorToken,
	}
	load := func(value string) (Config, error) {
		return LoadConfig(func(key string) string {
			if key == "CERTHUB_RESYNC_INTERVAL" {
				return value
			}
			return base[key]
		})
	}

	cfg, err := load("30s")
	if err != nil || cfg.ResyncInterval != 30*time.Second {
		t.Fatalf("30s resync rejected: cfg=%#v err=%v", cfg, err)
	}
	for _, value := range []string{"29.999s", "soon"} {
		if _, err := load(value); err == nil || !strings.Contains(err.Error(), "at least 30s") {
			t.Fatalf("invalid resync %q returned %v", value, err)
		}
	}
	cfg, err = load("")
	if err != nil || cfg.ResyncInterval != 6*time.Hour {
		t.Fatalf("default resync changed: cfg=%#v err=%v", cfg, err)
	}
}

func TestWatchNamespaceAndLegacyConfigValidation(t *testing.T) {
	base := map[string]string{
		"CERTHUB_URL":   "https://certhub.example",
		"CERTHUB_TOKEN": validOperatorToken,
	}
	load := func(overrides map[string]string) (Config, error) {
		return LoadConfig(func(key string) string {
			if value, ok := overrides[key]; ok {
				return value
			}
			return base[key]
		})
	}
	cfg, err := load(map[string]string{"WATCH_NAMESPACES": " apps "})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.WatchNamespaces, []string{"apps"}) {
		t.Fatalf("single namespace config = %#v", cfg)
	}
	cfg, err = load(map[string]string{"WATCH_NAMESPACES": "apps,staging"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.WatchNamespaces, []string{"apps", "staging"}) {
		t.Fatalf("multi-namespace config = %#v", cfg)
	}
	tests := []struct {
		name      string
		overrides map[string]string
	}{
		{name: "empty item", overrides: map[string]string{"WATCH_NAMESPACES": "apps,,staging"}},
		{name: "invalid namespace", overrides: map[string]string{"WATCH_NAMESPACES": "UPPER"}},
		{name: "duplicate namespace", overrides: map[string]string{"WATCH_NAMESPACES": "apps,apps"}},
		{name: "legacy singular", overrides: map[string]string{"WATCH_NAMESPACE": "apps"}},
		{name: "legacy allowlist", overrides: map[string]string{"CERTHUB_ALLOWED_SECRET_NAMES": "gateway-tls"}},
		{name: "legacy token Secret name", overrides: map[string]string{"CERTHUB_TOKEN_SECRET_NAME": "app-token"}},
		{name: "legacy token Secret key", overrides: map[string]string{"CERTHUB_TOKEN_SECRET_KEY": "token"}},
		{name: "legacy token Secret namespace", overrides: map[string]string{"CERTHUB_TOKEN_SECRET_NAMESPACE": "ops"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := load(tt.overrides); err == nil {
				t.Fatal("invalid namespace configuration accepted")
			}
		})
	}
}

func TestOperatorRetryConfigDefaultsAndValidation(t *testing.T) {
	base := map[string]string{
		"CERTHUB_URL":   "https://certhub.example",
		"CERTHUB_TOKEN": validOperatorToken,
	}
	load := func(overrides map[string]string) (Config, error) {
		return LoadConfig(func(key string) string {
			if value, ok := overrides[key]; ok {
				return value
			}
			return base[key]
		})
	}
	cfg, err := load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RetryPolicy.MaxAttempts != 5 || cfg.RetryPolicy.InitialBackoff != time.Second || cfg.RetryPolicy.MaxBackoff != 8*time.Second {
		t.Fatalf("default retry policy = %#v", cfg.RetryPolicy)
	}
	tests := []struct {
		name      string
		overrides map[string]string
	}{
		{name: "attempts not integer", overrides: map[string]string{"CERTHUB_HTTP_RETRY_MAX_ATTEMPTS": "many"}},
		{name: "zero attempts", overrides: map[string]string{"CERTHUB_HTTP_RETRY_MAX_ATTEMPTS": "0"}},
		{name: "too many attempts", overrides: map[string]string{"CERTHUB_HTTP_RETRY_MAX_ATTEMPTS": "11"}},
		{name: "initial malformed", overrides: map[string]string{"CERTHUB_HTTP_RETRY_INITIAL_BACKOFF": "soon"}},
		{name: "initial nonpositive", overrides: map[string]string{"CERTHUB_HTTP_RETRY_INITIAL_BACKOFF": "0s"}},
		{name: "maximum malformed", overrides: map[string]string{"CERTHUB_HTTP_RETRY_MAX_BACKOFF": "later"}},
		{name: "maximum below initial", overrides: map[string]string{"CERTHUB_HTTP_RETRY_INITIAL_BACKOFF": "5s", "CERTHUB_HTTP_RETRY_MAX_BACKOFF": "4s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := load(tt.overrides); err == nil {
				t.Fatal("invalid retry configuration accepted")
			}
		})
	}
	cfg, err = load(map[string]string{
		"CERTHUB_HTTP_RETRY_MAX_ATTEMPTS":    "1",
		"CERTHUB_HTTP_RETRY_INITIAL_BACKOFF": "1ns",
		"CERTHUB_HTTP_RETRY_MAX_BACKOFF":     "1ns",
	})
	if err != nil || cfg.RetryPolicy.MaxAttempts != 1 {
		t.Fatalf("single-attempt policy = %#v, err=%v", cfg.RetryPolicy, err)
	}
}

func TestOperatorExampleRetryConfigurationLoads(t *testing.T) {
	data, err := os.ReadFile("../../config/examples/operator.env")
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[key] = value
		}
	}
	cfg, err := LoadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RetryPolicy.MaxAttempts != 5 || cfg.RetryPolicy.InitialBackoff != time.Second || cfg.RetryPolicy.MaxBackoff != 8*time.Second {
		t.Fatalf("example retry policy = %#v", cfg.RetryPolicy)
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

func cloneTestCertificate(cert *CerthubCertificate) *CerthubCertificate {
	clone := *cert
	clone.Metadata = cert.Metadata
	clone.Metadata.Labels = cloneStringMap(cert.Metadata.Labels)
	clone.Metadata.Annotations = cloneStringMap(cert.Metadata.Annotations)
	clone.Metadata.OwnerReferences = append([]OwnerReference(nil), cert.Metadata.OwnerReferences...)
	clone.Metadata.Finalizers = append([]string(nil), cert.Metadata.Finalizers...)
	clone.Spec = cert.Spec
	clone.Spec.Domains = append([]string(nil), cert.Spec.Domains...)
	clone.Status = cloneCertificateStatus(cert.Status)
	return &clone
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	clone := make(map[string]string, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
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
			OwnerReferences: []OwnerReference{certhubOwnerReference(cert)},
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
	secrets                   map[string]*Secret
	certificates              []*CerthubCertificate
	certificatesByNamespace   map[string][]*CerthubCertificate
	listErrors                map[string]error
	listedNamespaces          []string
	watchChannels             map[string]chan CertificateWatchEvent
	watchedNamespaces         []string
	statusUpdates             int
	writeCount                int
	clearOwnerReferencesCount int
	deleteCount               int
	events                    []Event
	statusErr                 error
	beforeDelete              func()
	finalizerErr              error
	clearOwnerReferencesErr   error
	writeErr                  error
	deleteErr                 error
	operations                []string
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
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writeCount++
	f.operations = append(f.operations, "secret:write")
	f.secrets[secret.Metadata.Namespace+"/"+secret.Metadata.Name] = secret
	return nil
}

func (f *fakeKube) SetSecretOwnerReferences(_ context.Context, secret *Secret, ownerReferences []OwnerReference) error {
	if f.clearOwnerReferencesErr != nil {
		return f.clearOwnerReferencesErr
	}
	f.clearOwnerReferencesCount++
	if len(ownerReferences) == 0 {
		f.operations = append(f.operations, "owner:clear")
	} else {
		f.operations = append(f.operations, "owner:set")
	}
	secret.Metadata.OwnerReferences = append([]OwnerReference(nil), ownerReferences...)
	return nil
}

func (f *fakeKube) DeleteSecret(_ context.Context, namespace, name string, expected *Secret) error {
	if _, ok := f.secrets[namespace+"/"+name]; !ok {
		return ErrNotFound
	}
	if f.beforeDelete != nil {
		f.beforeDelete()
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if err := checkWritableExistingSecret(f.secrets[namespace+"/"+name], expected); err != nil {
		return err
	}
	f.deleteCount++
	f.operations = append(f.operations, "secret:delete")
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
	if slices.Contains(finalizers, Finalizer) {
		f.operations = append(f.operations, "finalizer:add")
	} else {
		f.operations = append(f.operations, "finalizer:remove")
	}
	return nil
}

func (f *fakeKube) EmitEvent(_ context.Context, event Event) error {
	f.events = append(f.events, event)
	return nil
}

func (f *fakeKube) ListCertificates(_ context.Context, namespace string) ([]*CerthubCertificate, error) {
	f.listedNamespaces = append(f.listedNamespaces, namespace)
	if err := f.listErrors[namespace]; err != nil {
		return nil, err
	}
	if f.certificatesByNamespace != nil {
		return f.certificatesByNamespace[namespace], nil
	}
	return f.certificates, nil
}

func (f *fakeKube) WatchCertificateChanges(ctx context.Context, namespace string) (<-chan CertificateWatchEvent, error) {
	f.watchedNamespaces = append(f.watchedNamespaces, namespace)
	if ch := f.watchChannels[namespace]; ch != nil {
		return ch, nil
	}
	ch := make(chan CertificateWatchEvent)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (f *fakeKube) DefaultNamespace() string {
	return "ns"
}
