package certificates

import (
	"encoding/json"
	"time"
)

type KeyType string

const (
	KeyTypeRSA2048   KeyType = "rsa-2048"
	KeyTypeRSA3072   KeyType = "rsa-3072"
	KeyTypeRSA4096   KeyType = "rsa-4096"
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
)

type Status string

const (
	StatusPending       Status = "pending"
	StatusValidatingDNS Status = "validating_dns"
	StatusIssuing       Status = "issuing"
	StatusReady         Status = "ready"
	StatusRenewing      Status = "renewing"
	StatusRotatingKey   Status = "rotating_key"
	StatusExpired       Status = "expired"
	StatusRevoked       Status = "revoked"
	StatusFailed        Status = "failed"
	StatusDeleted       Status = "deleted"
)

type VersionStatus string

const (
	VersionStatusIssuing VersionStatus = "issuing"
	VersionStatusValid   VersionStatus = "valid"
	VersionStatusFailed  VersionStatus = "failed"
	VersionStatusRevoked VersionStatus = "revoked"
)

type IssuanceReason string

const (
	IssuanceReasonInitialIssue IssuanceReason = "initial_issue"
	IssuanceReasonRenewal      IssuanceReason = "renewal"
	IssuanceReasonKeyRotation  IssuanceReason = "key_rotation"
)

type JobReason string

const (
	JobReasonInitialIssue    JobReason = "initial_issue"
	JobReasonRenewal         JobReason = "renewal"
	JobReasonKeyRotation     JobReason = "key_rotation"
	JobReasonRevocationRetry JobReason = "revocation_retry"
	JobReasonDNSCleanup      JobReason = "dns_cleanup"
)

type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusSucceeded JobStatus = "succeeded"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCanceled  JobStatus = "canceled"
)

type RevocationReason string

const (
	RevocationReasonKeyCompromise        RevocationReason = "key_compromise"
	RevocationReasonSuperseded           RevocationReason = "superseded"
	RevocationReasonCessationOfOperation RevocationReason = "cessation_of_operation"
	RevocationReasonUnspecified          RevocationReason = "unspecified"
)

type ACMERemoteRevocationStatus string

const (
	ACMERemoteRevocationPending     ACMERemoteRevocationStatus = "pending"
	ACMERemoteRevocationSucceeded   ACMERemoteRevocationStatus = "succeeded"
	ACMERemoteRevocationFailed      ACMERemoteRevocationStatus = "failed"
	ACMERemoteRevocationNotRequired ACMERemoteRevocationStatus = "not_required"
)

type DNSChallengeStatus string

const (
	DNSChallengeStatusPending        DNSChallengeStatus = "pending"
	DNSChallengeStatusPresented      DNSChallengeStatus = "presented"
	DNSChallengeStatusValidated      DNSChallengeStatus = "validated"
	DNSChallengeStatusCleanupPending DNSChallengeStatus = "cleanup_pending"
	DNSChallengeStatusCleanupFailed  DNSChallengeStatus = "cleanup_failed"
	DNSChallengeStatusCleaned        DNSChallengeStatus = "cleaned"
)

type EventResult string

const (
	EventResultSuccess EventResult = "success"
	EventResultFailure EventResult = "failure"
)

type Certificate struct {
	ID               string
	NormalizedSANs   []string
	KeyType          KeyType
	IssuerID         string
	ApplicationID    string
	Status           Status
	FailureCode      *string
	FailureMessage   *string
	RevocationReason *RevocationReason
	RevokedAt        *time.Time
	RevokedByUserID  *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
	VersionCount     int64
}

type CertificateVersion struct {
	ID                           string
	CertificateID                string
	Version                      int
	Status                       VersionStatus
	Reason                       IssuanceReason
	CertPEM                      *string
	ChainPEM                     *string
	FullchainPEM                 *string
	PrivateKeyPEMEncrypted       *string
	NotBefore                    *time.Time
	NotAfter                     *time.Time
	SerialNumber                 *string
	FingerprintSHA256            *string
	KeyFingerprintSHA256         *string
	MaterialETag                 *string
	ACMEOrderURL                 *string
	CertificateURL               *string
	ACMERevocationStatus         *ACMERemoteRevocationStatus
	ACMERevocationAttempts       int
	ACMERevokedAt                *time.Time
	ACMERevocationFailureCode    *string
	ACMERevocationFailureMessage *string
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
	StartedAt                    *time.Time
	CompletedAt                  *time.Time
	IssuedAt                     *time.Time
	FailureCode                  *string
	FailureMessage               *string
}

type IssuanceJob struct {
	ID                   string
	CertificateID        string
	CertificateVersionID *string
	Reason               JobReason
	Status               JobStatus
	Attempt              int
	LockedBy             *string
	LockedUntil          *time.Time
	NextRunAt            time.Time
	StartedAt            *time.Time
	CompletedAt          *time.Time
	FailureCode          *string
	FailureMessage       *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type DNSChallengeRecord struct {
	ID                      string
	IssuanceJobID           string
	CertificateID           string
	CertificateVersionID    string
	DNSProviderID           string
	DNSProviderZoneID       string
	AuthorizationIdentifier string
	RecordName              string
	TXTValueEncrypted       string
	Status                  DNSChallengeStatus
	PresentedAt             *time.Time
	ValidatedAt             *time.Time
	CleanedAt               *time.Time
	FailureCode             *string
	FailureMessage          *string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type Event struct {
	ID                   string
	CertificateID        string
	CertificateVersionID *string
	IssuanceJobID        *string
	EventType            string
	Result               EventResult
	CorrelationID        *string
	Message              *string
	Metadata             json.RawMessage
	CreatedAt            time.Time
}
