package operator

import "time"

const (
	APIGroup   = "certs.torob.dev"
	APIVersion = "certs.torob.dev/v1alpha1"
	Kind       = "CerthubCertificate"

	SecretTypeTLS = "kubernetes.io/tls"

	LabelManagedBy       = "app.kubernetes.io/managed-by"
	LabelCertificateName = "certhub.torob.dev/certhub-certificate-name"

	AnnotationCertificateID     = "certhub.torob.dev/certificate-id"
	AnnotationFingerprintSHA256 = "certhub.torob.dev/fingerprint-sha256"
	AnnotationMaterialETag      = "certhub.torob.dev/material-etag"
	AnnotationNotAfter          = "certhub.torob.dev/not-after"
	AnnotationOwnerUID          = "certhub.torob.dev/owner-uid"
	AnnotationRetryID           = "certhub.torob.dev/retry-id"

	ManagedByValue = "certhub-operator"

	Finalizer = "certhub.torob.dev/secret-cleanup"
)

type Metadata struct {
	Name              string            `json:"name,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp *time.Time        `json:"creationTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
	Finalizers        []string          `json:"finalizers,omitempty"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
}

type OwnerReference struct {
	APIVersion         string `json:"apiVersion,omitempty"`
	Kind               string `json:"kind,omitempty"`
	Name               string `json:"name,omitempty"`
	UID                string `json:"uid,omitempty"`
	Controller         bool   `json:"controller,omitempty"`
	BlockOwnerDeletion bool   `json:"blockOwnerDeletion,omitempty"`
}

type CerthubCertificate struct {
	APIVersion string                   `json:"apiVersion,omitempty"`
	Kind       string                   `json:"kind,omitempty"`
	Metadata   Metadata                 `json:"metadata"`
	Spec       CerthubCertificateSpec   `json:"spec"`
	Status     CerthubCertificateStatus `json:"status,omitempty"`
}

type CerthubCertificateSpec struct {
	Domains              []string `json:"domains"`
	SecretName           string   `json:"secretName"`
	KeyType              string   `json:"keyType,omitempty"`
	Issuer               string   `json:"issuer,omitempty"`
	SecretDeletionPolicy string   `json:"secretDeletionPolicy,omitempty"`
}

type CerthubCertificateStatus struct {
	ObservedGeneration int64       `json:"observedGeneration,omitempty"`
	Phase              string      `json:"phase,omitempty"`
	CertificateID      string      `json:"certificateId,omitempty"`
	ObservedDomains    []string    `json:"observedDomains,omitempty"`
	NotBefore          string      `json:"notBefore,omitempty"`
	NotAfter           string      `json:"notAfter,omitempty"`
	RenewalTime        string      `json:"renewalTime,omitempty"`
	Message            string      `json:"message,omitempty"`
	ObservedRetryID    string      `json:"observedRetryId,omitempty"`
	Conditions         []Condition `json:"conditions,omitempty"`
}

type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

type Secret struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   Metadata          `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
}

type Event struct {
	Namespace string `json:"-"`
	Name      string `json:"-"`
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
}

const (
	PolicyRetain = "Retain"
	PolicyDelete = "Delete"

	PhasePending       = "Pending"
	PhaseValidatingDNS = "ValidatingDNS"
	PhaseIssuing       = "Issuing"
	PhaseReady         = "Ready"
	PhaseFailed        = "Failed"

	ConditionAccepted            = "Accepted"
	ConditionReady               = "Ready"
	ConditionSecretSynced        = "SecretSynced"
	ConditionAuthorizationFailed = "AuthorizationFailed"
	ConditionIssuanceFailed      = "IssuanceFailed"
	ConditionCertificateRevoked  = "CertificateRevoked"

	ConditionTrue  = "True"
	ConditionFalse = "False"
)
