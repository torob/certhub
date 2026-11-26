package operator

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
)

const (
	fakeAPISecretPath      = "/api/v1/namespaces/ns/secrets/gateway-tls"
	fakeAPISecretsPath     = "/api/v1/namespaces/ns/secrets"
	fakeAPICertificatePath = "/apis/certs.torob.dev/v1alpha1/namespaces/ns/certhubcertificates/gateway"
	fakeAPIEventsPath      = "/api/v1/namespaces/ns/events"
)

// fakeSecretAPI is a small Kubernetes API server for the gateway-tls Secret
// and its CerthubCertificate. It keeps the Secret as raw JSON and applies
// PUT (full replacement) and JSON merge patch (RFC 7386) with resourceVersion
// preconditions, like the API server does.
type fakeSecretAPI struct {
	t            *testing.T
	mu           sync.Mutex
	secret       map[string]any
	version      int
	secretWrites []string
	events       []string
	// afterGet, when set, runs with the lock held after each Secret GET.
	afterGet func()
}

func newFakeSecretAPI(t *testing.T, secret *Secret) (*fakeSecretAPI, *httptest.Server) {
	t.Helper()
	api := &fakeSecretAPI{t: t}
	if secret != nil {
		api.secret = rawKubeObject(t, secret)
		api.bumpVersion()
	}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	return api, server
}

func rawKubeObject(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fakeSecretAPI) bumpVersion() {
	f.version++
	metadata, _ := f.secret["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		f.secret["metadata"] = metadata
	}
	metadata["resourceVersion"] = strconv.Itoa(f.version)
}

// storedSecret returns the Secret as the API server stores it now.
func (f *fakeSecretAPI) storedSecret() *Secret {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secret == nil {
		return nil
	}
	encoded, err := json.Marshal(f.secret)
	if err != nil {
		f.t.Fatal(err)
	}
	var secret Secret
	if err := json.Unmarshal(encoded, &secret); err != nil {
		f.t.Fatal(err)
	}
	return &secret
}

func (f *fakeSecretAPI) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.secretWrites...)
}

func (f *fakeSecretAPI) eventReasons() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeSecretAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == fakeAPISecretPath && r.Method == http.MethodGet:
		if f.secret == nil {
			http.NotFound(w, r)
			return
		}
		writeKubeJSON(f.t, w, f.secret)
		if f.afterGet != nil {
			f.afterGet()
		}
	case r.URL.Path == fakeAPISecretsPath && r.Method == http.MethodPost:
		var created map[string]any
		decodeKubeJSON(f.t, r, &created)
		f.secretWrites = append(f.secretWrites, "POST")
		f.secret = created
		f.secret["metadata"].(map[string]any)["uid"] = "secret-uid"
		f.bumpVersion()
		w.WriteHeader(http.StatusCreated)
		writeKubeJSON(f.t, w, f.secret)
	case r.URL.Path == fakeAPISecretPath && r.Method == http.MethodPut:
		var replacement map[string]any
		decodeKubeJSON(f.t, r, &replacement)
		if !f.resourceVersionMatches(w, replacement) {
			return
		}
		live := f.secret["metadata"].(map[string]any)
		metadata, _ := replacement["metadata"].(map[string]any)
		if metadata == nil {
			metadata = map[string]any{}
			replacement["metadata"] = metadata
		}
		metadata["uid"] = live["uid"]
		f.secretWrites = append(f.secretWrites, "PUT")
		f.secret = replacement
		f.bumpVersion()
		writeKubeJSON(f.t, w, f.secret)
	case r.URL.Path == fakeAPISecretPath && r.Method == http.MethodPatch:
		if ct := r.Header.Get("Content-Type"); ct != "application/merge-patch+json" {
			f.t.Errorf("Secret patch content type = %q", ct)
			http.Error(w, "unsupported patch type", http.StatusUnsupportedMediaType)
			return
		}
		var patch map[string]any
		decodeKubeJSON(f.t, r, &patch)
		if !f.resourceVersionMatches(w, patch) {
			return
		}
		f.secretWrites = append(f.secretWrites, "PATCH")
		f.secret = applyJSONMergePatch(f.secret, patch).(map[string]any)
		f.bumpVersion()
		writeKubeJSON(f.t, w, f.secret)
	case r.URL.Path == fakeAPICertificatePath && r.Method == http.MethodPatch:
		var body struct {
			Metadata Metadata `json:"metadata"`
		}
		decodeKubeJSON(f.t, r, &body)
		writeKubeJSON(f.t, w, CerthubCertificate{Metadata: Metadata{
			Name:            "gateway",
			Namespace:       "ns",
			ResourceVersion: "rv-cert-finalized",
			Finalizers:      body.Metadata.Finalizers,
		}})
	case r.URL.Path == fakeAPICertificatePath+"/status" && r.Method == http.MethodPut:
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == fakeAPIEventsPath && r.Method == http.MethodPost:
		var event struct {
			Reason string `json:"reason"`
		}
		decodeKubeJSON(f.t, r, &event)
		f.events = append(f.events, event.Reason)
		w.WriteHeader(http.StatusCreated)
	default:
		f.t.Errorf("unexpected Kubernetes request: %s %s", r.Method, r.URL.String())
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}
}

// resourceVersionMatches answers 409 Conflict when the request carries a
// resourceVersion that is not the stored one.
func (f *fakeSecretAPI) resourceVersionMatches(w http.ResponseWriter, body map[string]any) bool {
	metadata, _ := body["metadata"].(map[string]any)
	requested, ok := metadata["resourceVersion"].(string)
	if !ok || requested == "" {
		return true
	}
	if requested == strconv.Itoa(f.version) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write([]byte(`{"kind":"Status","code":409,"reason":"Conflict"}`))
	return false
}

// applyJSONMergePatch applies an RFC 7386 JSON merge patch to target.
func applyJSONMergePatch(target, patch any) any {
	patchObject, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	targetObject, ok := target.(map[string]any)
	if !ok {
		targetObject = map[string]any{}
	}
	for key, value := range patchObject {
		if value == nil {
			delete(targetObject, key)
			continue
		}
		targetObject[key] = applyJSONMergePatch(targetObject[key], value)
	}
	return targetObject
}

var (
	foreignSecretLabels = map[string]string{
		"app.kubernetes.io/instance":   "gateway",
		"reflector.example/reflect-to": "edge",
	}
	foreignSecretAnnotations = map[string]string{
		"argocd.argoproj.io/tracking-id":                     "gateway:/Secret:ns/gateway-tls",
		"reflector.v1.k8s.emberstack.com/reflection-allowed": "true",
	}
	foreignSecretFinalizers = []string{"backup.example/protect"}
)

// liveSecretWithForeignMetadata returns a managed Secret on which other tools
// (Argo CD, reflector, a backup controller) added labels, annotations, a
// finalizer, and an extra data key.
func liveSecretWithForeignMetadata(cert *CerthubCertificate, ownerReferences []OwnerReference) *Secret {
	secret := ownedSecret(cert, "etag-1")
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	secret.Metadata.UID = "secret-uid"
	secret.Metadata.OwnerReferences = ownerReferences
	maps.Copy(secret.Metadata.Labels, foreignSecretLabels)
	maps.Copy(secret.Metadata.Annotations, foreignSecretAnnotations)
	secret.Metadata.Annotations[AnnotationCertificateID] = "cert-1"
	secret.Metadata.Finalizers = append([]string(nil), foreignSecretFinalizers...)
	secret.Data["ca.crt"] = []byte("FOREIGN-CA")
	return secret
}

func certificateWithPolicy(policy string) *CerthubCertificate {
	cert := testCertificate()
	cert.Spec.SecretDeletionPolicy = policy
	cert.Metadata.ResourceVersion = "rv-cert"
	cert.Metadata.Finalizers = []string{Finalizer}
	return cert
}

// A material rotation must keep the Secret labels, annotations, and
// finalizers that other tools added. Only the operator-managed fields change.
func TestReconcileSecretRotationKeepsForeignSecretMetadata(t *testing.T) {
	tests := []struct {
		name        string
		policy      string
		liveOwners  func(*CerthubCertificate) []OwnerReference
		wantOwners  func(*CerthubCertificate) []OwnerReference
		wantEventIn string
	}{
		{
			name:       "Retain",
			policy:     PolicyRetain,
			liveOwners: func(*CerthubCertificate) []OwnerReference { return nil },
			wantOwners: func(*CerthubCertificate) []OwnerReference { return nil },
		},
		{
			name:   "Delete",
			policy: PolicyDelete,
			liveOwners: func(cert *CerthubCertificate) []OwnerReference {
				return []OwnerReference{certhubOwnerReference(cert)}
			},
			wantOwners: func(cert *CerthubCertificate) []OwnerReference {
				return []OwnerReference{certhubOwnerReference(cert)}
			},
		},
		{
			name:   "Delete to Retain removes the operator owner reference",
			policy: PolicyRetain,
			liveOwners: func(cert *CerthubCertificate) []OwnerReference {
				return []OwnerReference{certhubOwnerReference(cert)}
			},
			wantOwners:  func(*CerthubCertificate) []OwnerReference { return nil },
			wantEventIn: "SecretOwnerReferenceRemoved",
		},
		{
			name:       "Retain to Delete adds the operator owner reference",
			policy:     PolicyDelete,
			liveOwners: func(*CerthubCertificate) []OwnerReference { return nil },
			wantOwners: func(cert *CerthubCertificate) []OwnerReference {
				return []OwnerReference{certhubOwnerReference(cert)}
			},
			wantEventIn: "SecretOwnerReferenceAdded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := certificateWithPolicy(tt.policy)
			live := liveSecretWithForeignMetadata(cert, tt.liveOwners(cert))
			api, server := newFakeSecretAPI(t, live)
			client := testRESTKubeClient(server.URL)
			backend := &fakeBackend{materials: []materialResponse{{
				value: testMaterial("etag-2"),
				meta:  certhubclient.ResponseMeta{StatusCode: http.StatusOK},
			}}}

			result, err := NewReconciler(client, backend).Reconcile(context.Background(), cert)
			if err != nil || result.Result != "synced" {
				t.Fatalf("Reconcile = %#v, %v; want synced", result, err)
			}
			if backend.ifNoneMatch != "etag-1" {
				t.Fatalf("If-None-Match = %q; want the live etag-1", backend.ifNoneMatch)
			}
			got := api.storedSecret()
			for key, value := range foreignSecretLabels {
				if got.Metadata.Labels[key] != value {
					t.Errorf("foreign label %s = %q after sync; want %q (labels=%v)", key, got.Metadata.Labels[key], value, got.Metadata.Labels)
				}
			}
			for key, value := range foreignSecretAnnotations {
				if got.Metadata.Annotations[key] != value {
					t.Errorf("foreign annotation %s = %q after sync; want %q (annotations=%v)", key, got.Metadata.Annotations[key], value, got.Metadata.Annotations)
				}
			}
			if !slices.Equal(got.Metadata.Finalizers, foreignSecretFinalizers) {
				t.Errorf("finalizers after sync = %q; want foreign %q", got.Metadata.Finalizers, foreignSecretFinalizers)
			}
			if !equalOwnerReferenceMultiset(got.Metadata.OwnerReferences, tt.wantOwners(cert)) {
				t.Errorf("owner references after sync = %#v; want %#v", got.Metadata.OwnerReferences, tt.wantOwners(cert))
			}
			wantManagedLabels := map[string]string{LabelManagedBy: ManagedByValue, LabelCertificateName: "gateway"}
			for key, value := range wantManagedLabels {
				if got.Metadata.Labels[key] != value {
					t.Errorf("managed label %s = %q; want %q", key, got.Metadata.Labels[key], value)
				}
			}
			wantManagedAnnotations := map[string]string{
				AnnotationCertificateID:     "cert-1",
				AnnotationFingerprintSHA256: "abc123",
				AnnotationMaterialETag:      "etag-2",
				AnnotationNotAfter:          "2026-09-24T00:00:00Z",
				AnnotationOwnerUID:          "uid-1",
			}
			for key, value := range wantManagedAnnotations {
				if got.Metadata.Annotations[key] != value {
					t.Errorf("managed annotation %s = %q; want %q", key, got.Metadata.Annotations[key], value)
				}
			}
			if len(got.Metadata.Labels) != len(foreignSecretLabels)+len(wantManagedLabels) ||
				len(got.Metadata.Annotations) != len(foreignSecretAnnotations)+len(wantManagedAnnotations) {
				t.Errorf("unexpected metadata keys: labels=%v annotations=%v", got.Metadata.Labels, got.Metadata.Annotations)
			}
			if got.Metadata.UID != "secret-uid" || got.Type != SecretTypeTLS {
				t.Errorf("Secret identity changed: uid=%q type=%q", got.Metadata.UID, got.Type)
			}
			// The spec requires that the managed Secret contains only the
			// expected TLS data keys, so the data stays operator-owned.
			if len(got.Data) != 2 || string(got.Data["tls.crt"]) != "FULLCHAIN" || string(got.Data["tls.key"]) != "PRIVATEKEY" {
				t.Errorf("Secret data keys = %v; want only the new tls.crt and tls.key", slices.Sorted(maps.Keys(got.Data)))
			}
			if events := api.eventReasons(); tt.wantEventIn != "" && !slices.Contains(events, tt.wantEventIn) {
				t.Errorf("events = %q; want %s", events, tt.wantEventIn)
			}
		})
	}
}

func requireForeignSecretMetadata(t *testing.T, got *Secret) {
	t.Helper()
	for key, value := range foreignSecretLabels {
		if got.Metadata.Labels[key] != value {
			t.Errorf("foreign label %s = %q; want %q", key, got.Metadata.Labels[key], value)
		}
	}
	for key, value := range foreignSecretAnnotations {
		if got.Metadata.Annotations[key] != value {
			t.Errorf("foreign annotation %s = %q; want %q", key, got.Metadata.Annotations[key], value)
		}
	}
	if !slices.Equal(got.Metadata.Finalizers, foreignSecretFinalizers) {
		t.Errorf("finalizers = %q; want foreign %q", got.Metadata.Finalizers, foreignSecretFinalizers)
	}
}

// A Secret that fails the ownership checks is never written, also when other
// tools added metadata to it.
func TestReconcileDoesNotWriteForeignSecret(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Secret)
	}{
		{
			name: "foreign owner reference",
			alter: func(secret *Secret) {
				secret.Metadata.OwnerReferences = []OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "reflector", UID: "deployment-uid", Controller: true}}
			},
		},
		{
			name: "foreign and own owner references",
			alter: func(secret *Secret) {
				secret.Metadata.OwnerReferences = append(secret.Metadata.OwnerReferences, OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "reflector", UID: "deployment-uid"})
			},
		},
		{
			name:  "owner UID of another Certificate",
			alter: func(secret *Secret) { secret.Metadata.Annotations[AnnotationOwnerUID] = "other-uid" },
		},
		{
			name:  "missing management label",
			alter: func(secret *Secret) { delete(secret.Metadata.Labels, LabelManagedBy) },
		},
	}
	for _, policy := range []string{PolicyRetain, PolicyDelete} {
		for _, tt := range tests {
			t.Run(policy+"/"+tt.name, func(t *testing.T) {
				cert := certificateWithPolicy(policy)
				live := liveSecretWithForeignMetadata(cert, []OwnerReference{certhubOwnerReference(cert)})
				tt.alter(live)
				api, server := newFakeSecretAPI(t, live)
				before := api.storedSecret()
				backend := &fakeBackend{materials: []materialResponse{{
					value: testMaterial("etag-2"),
					meta:  certhubclient.ResponseMeta{StatusCode: http.StatusOK},
				}}}

				result, err := NewReconciler(testRESTKubeClient(server.URL), backend).Reconcile(context.Background(), cert)
				if err != nil || result.Result != "ownership_conflict" {
					t.Fatalf("Reconcile = %#v, %v; want ownership_conflict", result, err)
				}
				if writes := api.writes(); len(writes) != 0 {
					t.Fatalf("foreign Secret writes = %q; want none", writes)
				}
				if after := api.storedSecret(); !reflect.DeepEqual(before, after) {
					t.Fatalf("foreign Secret changed:\nbefore %#v\nafter  %#v", before, after)
				}
			})
		}
	}
}

// Deleting a Retain Certificate removes only the operator's own owner
// reference. Data and foreign metadata stay.
func TestReconcileRetainDeletionKeepsForeignSecretMetadata(t *testing.T) {
	cert := certificateWithPolicy(PolicyRetain)
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	api, server := newFakeSecretAPI(t, liveSecretWithForeignMetadata(cert, []OwnerReference{certhubOwnerReference(cert)}))
	before := api.storedSecret()

	result, err := NewReconciler(testRESTKubeClient(server.URL), &fakeBackend{}).Reconcile(context.Background(), cert)
	if err != nil || result.Result != "deleted" {
		t.Fatalf("Reconcile = %#v, %v; want deleted", result, err)
	}
	got := api.storedSecret()
	if len(got.Metadata.OwnerReferences) != 0 {
		t.Fatalf("owner references after Retain deletion = %#v; want none", got.Metadata.OwnerReferences)
	}
	requireForeignSecretMetadata(t, got)
	if !reflect.DeepEqual(got.Data, before.Data) || !reflect.DeepEqual(got.Metadata.Annotations, before.Metadata.Annotations) || got.Metadata.UID != before.Metadata.UID {
		t.Fatalf("retained Secret data, annotations, or UID changed")
	}
	if writes := api.writes(); !slices.Equal(writes, []string{"PATCH"}) {
		t.Fatalf("Secret writes = %q; want one owner-reference PATCH", writes)
	}
}

// The update carries the resourceVersion that passed the ownership check, so
// the API server refuses it when the Secret changed in between.
func TestRESTKubeClientSecretUpdateRefusesSecretChangedAfterOwnershipCheck(t *testing.T) {
	cert := certificateWithPolicy(PolicyRetain)
	api, server := newFakeSecretAPI(t, liveSecretWithForeignMetadata(cert, nil))
	api.afterGet = func() {
		api.secret["metadata"].(map[string]any)["labels"].(map[string]any)["late.example/writer"] = "true"
		api.bumpVersion()
	}
	desired := ownedSecret(cert, "etag-2")

	err := testRESTKubeClient(server.URL).CreateOrUpdateSecret(context.Background(), desired)
	if err == nil || !strings.Contains(err.Error(), "status=409") {
		t.Fatalf("update error = %v; want 409 Conflict", err)
	}
	if writes := api.writes(); len(writes) != 0 {
		t.Fatalf("Secret writes = %q; want none", writes)
	}
	if got := api.storedSecret(); got.Metadata.Annotations[AnnotationMaterialETag] != "etag-1" {
		t.Fatalf("Secret was updated after a concurrent change: %#v", got.Metadata.Annotations)
	}
}

// When no other tool touched the Secret, a material rotation stores the same
// Secret as before: only the operator's labels, annotations, owner
// reference, type, and TLS data.
func TestReconcileSecretRotationWithoutForeignMetadataStoresOnlyManagedFields(t *testing.T) {
	for _, policy := range []string{PolicyRetain, PolicyDelete} {
		t.Run(policy, func(t *testing.T) {
			cert := certificateWithPolicy(policy)
			live := ownedSecret(cert, "etag-1")
			live.APIVersion = "v1"
			live.Kind = "Secret"
			live.Metadata.UID = "secret-uid"
			api, server := newFakeSecretAPI(t, live)
			backend := &fakeBackend{materials: []materialResponse{{
				value: testMaterial("etag-2"),
				meta:  certhubclient.ResponseMeta{StatusCode: http.StatusOK},
			}}}

			result, err := NewReconciler(testRESTKubeClient(server.URL), backend).Reconcile(context.Background(), cert)
			if err != nil || result.Result != "synced" {
				t.Fatalf("Reconcile = %#v, %v; want synced", result, err)
			}
			got := api.storedSecret()
			want := Secret{
				APIVersion: "v1",
				Kind:       "Secret",
				Metadata: Metadata{
					Name:            "gateway-tls",
					Namespace:       "ns",
					UID:             "secret-uid",
					ResourceVersion: got.Metadata.ResourceVersion,
					Labels:          map[string]string{LabelManagedBy: ManagedByValue, LabelCertificateName: "gateway"},
					Annotations: map[string]string{
						AnnotationCertificateID:     "cert-1",
						AnnotationFingerprintSHA256: "abc123",
						AnnotationMaterialETag:      "etag-2",
						AnnotationNotAfter:          "2026-09-24T00:00:00Z",
						AnnotationOwnerUID:          "uid-1",
					},
					OwnerReferences: managedSecretOwnerReferences(cert),
				},
				Type: SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": []byte("FULLCHAIN"), "tls.key": []byte("PRIVATEKEY")},
			}
			if len(want.Metadata.OwnerReferences) == 0 {
				want.Metadata.OwnerReferences = nil
			}
			if len(got.Metadata.OwnerReferences) == 0 {
				got.Metadata.OwnerReferences = nil
			}
			if !reflect.DeepEqual(*got, want) {
				t.Fatalf("stored Secret:\n got %#v\nwant %#v", *got, want)
			}
		})
	}
}
