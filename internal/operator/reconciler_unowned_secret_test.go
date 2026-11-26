package operator

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"
)

// cloneTestSecret returns a deep copy, so a test can prove that the operator
// did not change a Secret.
func cloneTestSecret(secret *Secret) *Secret {
	clone := *secret
	clone.Metadata.Labels = cloneStringMap(secret.Metadata.Labels)
	clone.Metadata.Annotations = cloneStringMap(secret.Metadata.Annotations)
	clone.Metadata.OwnerReferences = append([]OwnerReference(nil), secret.Metadata.OwnerReferences...)
	clone.Metadata.Finalizers = append([]string(nil), secret.Metadata.Finalizers...)
	clone.Data = make(map[string][]byte, len(secret.Data))
	for key, value := range secret.Data {
		clone.Data[key] = append([]byte(nil), value...)
	}
	return &clone
}

func deletingTestCertificate(policy string) *CerthubCertificate {
	cert := testCertificate()
	now := time.Now().UTC()
	cert.Metadata.DeletionTimestamp = &now
	cert.Metadata.Finalizers = []string{Finalizer}
	cert.Spec.SecretDeletionPolicy = policy
	return cert
}

func eventReasons(events []Event) []string {
	reasons := make([]string, 0, len(events))
	for _, event := range events {
		reasons = append(reasons, event.Reason)
	}
	return reasons
}

// A CR whose target Secret name is taken by a Secret that this CR never wrote
// has nothing to clean up. Before the fix the finalizer stayed until someone
// removed that Secret, so the CR stayed in Terminating.
func TestDeleteReleasesFinalizerWhenThisCertificateNeverOwnedTheSecret(t *testing.T) {
	foreignSecrets := map[string]func(cert *CerthubCertificate) *Secret{
		"foreign opaque Secret": func(cert *CerthubCertificate) *Secret {
			return &Secret{
				Metadata: Metadata{Name: cert.Spec.SecretName, Namespace: cert.Metadata.Namespace, Labels: map[string]string{"app": "other"}},
				Type:     "Opaque",
				Data:     map[string][]byte{"password": []byte("x")},
			}
		},
		"foreign TLS Secret with a foreign owner reference": func(cert *CerthubCertificate) *Secret {
			return &Secret{
				Metadata: Metadata{
					Name:            cert.Spec.SecretName,
					Namespace:       cert.Metadata.Namespace,
					OwnerReferences: []OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "cm-uid"}},
				},
				Type: SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": []byte("OTHER-CERT"), "tls.key": []byte("OTHER-KEY")},
			}
		},
		"Secret retained by an older CR with the same name": func(cert *CerthubCertificate) *Secret {
			older := testCertificate()
			older.Metadata.UID = "uid-older"
			return ownedSecret(older, "older-etag")
		},
		"Secret of another CR": func(cert *CerthubCertificate) *Secret {
			other := testCertificate()
			other.Metadata.Name = "other"
			other.Metadata.UID = "uid-other"
			other.Spec.SecretDeletionPolicy = PolicyDelete
			return ownedSecret(other, "other-etag")
		},
	}
	for _, policy := range []string{PolicyDelete, PolicyRetain} {
		for name, build := range foreignSecrets {
			t.Run(policy+"/"+name, func(t *testing.T) {
				kube := newFakeKube()
				cert := deletingTestCertificate(policy)
				secret := build(cert)
				before := cloneTestSecret(secret)
				kube.secrets["ns/gateway-tls"] = secret
				reconciler := testReconciler(kube, &fakeBackend{})

				if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
					t.Fatalf("reconcile failed: %v", err)
				}
				if slices.Contains(cert.Metadata.Finalizers, Finalizer) {
					t.Fatalf("finalizer kept for a Secret this CR never owned; events=%v", eventReasons(kube.events))
				}
				if kube.deleteCount != 0 || kube.writeCount != 0 || kube.clearOwnerReferencesCount != 0 {
					t.Fatalf("foreign Secret changed: delete=%d write=%d ownerRefs=%d", kube.deleteCount, kube.writeCount, kube.clearOwnerReferencesCount)
				}
				if got := kube.secrets["ns/gateway-tls"]; !reflect.DeepEqual(got, before) {
					t.Fatalf("foreign Secret changed:\n got %#v\nwant %#v", got, before)
				}
				if !slices.Contains(eventReasons(kube.events), "SecretNotOwned") {
					t.Fatalf("events = %v, want SecretNotOwned", eventReasons(kube.events))
				}
			})
		}
	}
}

// A Secret that carries this CR's UID but fails another ownership check may
// still hold material that this CR wrote. The finalizer must stay until a
// human resolves the conflict.
func TestDeleteKeepsFinalizerWhenSecretCarriesThisCertificateUID(t *testing.T) {
	conflicts := map[string]func(secret *Secret){
		"owner-uid annotation without the management label": func(secret *Secret) {
			delete(secret.Metadata.Labels, LabelManagedBy)
		},
		"owner-uid annotation on an Opaque Secret": func(secret *Secret) {
			secret.Type = "Opaque"
		},
		"owner reference to this CR without the owner-uid annotation": func(secret *Secret) {
			delete(secret.Metadata.Annotations, AnnotationOwnerUID)
			secret.Metadata.OwnerReferences = []OwnerReference{{APIVersion: APIVersion, Kind: Kind, Name: "gateway", UID: "uid-1"}}
		},
		"owner-uid annotation with an extra owner reference": func(secret *Secret) {
			secret.Metadata.OwnerReferences = append(secret.Metadata.OwnerReferences, OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "cm-uid"})
		},
	}
	for _, policy := range []string{PolicyDelete, PolicyRetain} {
		for name, mutate := range conflicts {
			t.Run(policy+"/"+name, func(t *testing.T) {
				kube := newFakeKube()
				cert := deletingTestCertificate(policy)
				secret := ownedSecret(cert, "etag")
				mutate(secret)
				before := cloneTestSecret(secret)
				kube.secrets["ns/gateway-tls"] = secret
				reconciler := testReconciler(kube, &fakeBackend{})

				if _, err := reconciler.Reconcile(context.Background(), cert); err != nil {
					t.Fatalf("reconcile failed: %v", err)
				}
				if !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
					t.Fatalf("finalizer released for a Secret that carries this CR's UID")
				}
				if kube.deleteCount != 0 || kube.writeCount != 0 || kube.clearOwnerReferencesCount != 0 {
					t.Fatalf("conflicting Secret changed: delete=%d write=%d ownerRefs=%d", kube.deleteCount, kube.writeCount, kube.clearOwnerReferencesCount)
				}
				if got := kube.secrets["ns/gateway-tls"]; !reflect.DeepEqual(got, before) {
					t.Fatalf("conflicting Secret changed:\n got %#v\nwant %#v", got, before)
				}
				if !slices.Contains(eventReasons(kube.events), "SecretOwnershipConflict") {
					t.Fatalf("events = %v, want SecretOwnershipConflict", eventReasons(kube.events))
				}
			})
		}
	}
}
