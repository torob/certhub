package certificates

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/torob/certhub/internal/storage"
)

var (
	failureCodeRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
	sha256HexRE    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	materialETagRE = regexp.MustCompile(`^"cth-mat-v1\.[A-Za-z0-9_-]{43}"$`)
	eventTypeRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
)

func NormalizeSANs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("normalized_sans is required")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := storage.NormalizeCertificateIdentifier(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	slices.Sort(out)
	if len(out) == 0 || len(out) > 100 {
		return nil, errors.New("normalized_sans must contain between 1 and 100 identifiers")
	}
	return out, nil
}

func validateCreateOrReuse(params *CreateOrReuseCertificateParams) error {
	if err := storage.ValidateUUID(params.ID, "certificate_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.ApplicationID, "application_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.IssuerID, "issuer_id"); err != nil {
		return err
	}
	sans, err := NormalizeSANs(params.NormalizedSANs)
	if err != nil {
		return err
	}
	params.NormalizedSANs = sans
	if params.KeyType == "" {
		params.KeyType = KeyTypeECDSAP256
	}
	if err := validateKeyType(params.KeyType); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = StatusPending
	}
	return validateCertificateStatus(params.Status)
}

func validateList(params *ListCertificatesParams) error {
	if params.ApplicationID != nil {
		if err := storage.ValidateUUID(*params.ApplicationID, "application_id"); err != nil {
			return err
		}
	}
	for _, id := range params.ApplicationIDs {
		if err := storage.ValidateUUID(id, "application_id"); err != nil {
			return err
		}
	}
	if params.IssuerID != nil {
		if err := storage.ValidateUUID(*params.IssuerID, "issuer_id"); err != nil {
			return err
		}
	}
	if params.Status != nil {
		if err := validateCertificateStatus(*params.Status); err != nil {
			return err
		}
	}
	if params.KeyType != nil {
		if err := validateKeyType(*params.KeyType); err != nil {
			return err
		}
	}
	if len(params.NormalizedSANs) > 0 {
		sans, err := NormalizeSANs(params.NormalizedSANs)
		if err != nil {
			return err
		}
		params.NormalizedSANs = sans
	}
	return nil
}

func validateCreateIssuingVersion(params *CreateIssuingVersionParams) error {
	if err := storage.ValidateUUID(params.ID, "certificate_version_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return err
	}
	if params.Reason == "" {
		params.Reason = IssuanceReasonInitialIssue
	}
	return validateIssuanceReason(params.Reason)
}

func validatePrepareIssuingVersion(params *PrepareIssuingVersionParams) error {
	if err := storage.ValidateUUID(params.CertificateVersionID, "certificate_version_id"); err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(&params.PrivateKeyPEMEncrypted, "private_key_pem"); err != nil {
		return err
	}
	params.KeyFingerprintSHA256 = strings.ToLower(params.KeyFingerprintSHA256)
	if !sha256HexRE.MatchString(params.KeyFingerprintSHA256) {
		return errors.New("key_fingerprint_sha256 must be a lowercase SHA-256 hex digest")
	}
	return storage.ValidateHTTPSURL(&params.ACMEOrderURL, "acme_order_url")
}

func validateUpdateCertificateIssuanceStatus(params UpdateCertificateIssuanceStatusParams) error {
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return err
	}
	switch params.Status {
	case StatusValidatingDNS, StatusIssuing, StatusRenewing, StatusRotatingKey:
		return nil
	default:
		return errors.New("certificate issuance status is invalid")
	}
}

func validateEnsureJob(params *EnsureIssuanceJobParams) error {
	if err := storage.ValidateUUID(params.ID, "issuance_job_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return err
	}
	if params.CertificateVersionID != nil {
		if err := storage.ValidateUUID(*params.CertificateVersionID, "certificate_version_id"); err != nil {
			return err
		}
	}
	if params.Reason == "" {
		params.Reason = JobReasonInitialIssue
	}
	if err := validateJobReason(params.Reason); err != nil {
		return err
	}
	if params.NextRunAt.IsZero() {
		params.NextRunAt = time.Unix(0, 0).UTC()
	}
	return nil
}

func validateAttachIssuingVersionToJob(params AttachIssuingVersionToJobParams) error {
	if err := storage.ValidateUUID(params.JobID, "issuance_job_id"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
		return err
	}
	return storage.ValidateUUID(params.CertificateVersionID, "certificate_version_id")
}

func validateRevokeCertificateVersion(params RevokeCertificateVersionParams) error {
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.CertificateVersionID, "certificate_version_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.RevokedByUserID, "revoked_by_user_id"); err != nil {
		return err
	}
	switch params.Reason {
	case RevocationReasonKeyCompromise, RevocationReasonSuperseded, RevocationReasonCessationOfOperation, RevocationReasonUnspecified:
		return nil
	default:
		return errors.New("revocation reason is invalid")
	}
}

func validateClaimJob(params ClaimIssuanceJobParams) error {
	if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
		return err
	}
	if params.LockedUntil.IsZero() || !params.LockedUntil.After(time.Now()) {
		return errors.New("locked_until must be in the future")
	}
	return nil
}

func validateSucceedJob(params SucceedIssuanceJobParams) error {
	if err := storage.ValidateUUID(params.JobID, "issuance_job_id"); err != nil {
		return err
	}
	return storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255)
}

func validateFailJob(params *FailIssuanceJobParams) error {
	if err := storage.ValidateUUID(params.JobID, "issuance_job_id"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
		return err
	}
	if err := validateFailureCode(params.FailureCode); err != nil {
		return err
	}
	if params.MaxAttempts < 0 {
		return errors.New("max_attempts is invalid")
	}
	if params.RetryAfter < 0 {
		return errors.New("retry_after is invalid")
	}
	return storage.ValidateOptionalHumanString(params.FailureMessage, "failure_message", 2048)
}

func validateStoreMaterial(params *StoreMaterialParams) error {
	if params.JobID != "" {
		if err := storage.ValidateUUID(params.JobID, "issuance_job_id"); err != nil {
			return err
		}
		if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
			return err
		}
	}
	if err := storage.ValidateUUID(params.CertificateVersionID, "certificate_version_id"); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"cert_pem":               params.CertPEM,
		"chain_pem":              params.ChainPEM,
		"fullchain_pem":          params.FullchainPEM,
		"serial_number":          params.SerialNumber,
		"fingerprint_sha256":     params.FingerprintSHA256,
		"key_fingerprint_sha256": params.KeyFingerprintSHA256,
		"material_etag":          params.MaterialETag,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if err := storage.ValidateEncryptedEnvelope(&params.PrivateKeyPEMEncrypted, "private_key_pem"); err != nil {
		return err
	}
	if params.NotBefore.IsZero() || params.NotAfter.IsZero() || !params.NotAfter.After(params.NotBefore) {
		return errors.New("validity window is invalid")
	}
	params.FingerprintSHA256 = strings.ToLower(params.FingerprintSHA256)
	params.KeyFingerprintSHA256 = strings.ToLower(params.KeyFingerprintSHA256)
	if !sha256HexRE.MatchString(params.FingerprintSHA256) {
		return errors.New("fingerprint_sha256 must be a lowercase SHA-256 hex digest")
	}
	if !sha256HexRE.MatchString(params.KeyFingerprintSHA256) {
		return errors.New("key_fingerprint_sha256 must be a lowercase SHA-256 hex digest")
	}
	if len(params.MaterialETag) < 18 || len(params.MaterialETag) > 258 || !materialETagRE.MatchString(params.MaterialETag) {
		return errors.New("material_etag must be a strong ETag")
	}
	if err := storage.ValidateHTTPSURL(params.ACMEOrderURL, "acme_order_url"); err != nil {
		return err
	}
	return storage.ValidateHTTPSURL(params.CertificateURL, "certificate_url")
}

func validateRecordDNSChallenge(params *RecordDNSChallengeParams) error {
	if err := storage.ValidateUUID(params.ID, "dns_challenge_record_id"); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"issuance_job_id":        params.IssuanceJobID,
		"certificate_id":         params.CertificateID,
		"certificate_version_id": params.CertificateVersionID,
		"dns_provider_id":        params.DNSProviderID,
		"dns_provider_zone_id":   params.DNSProviderZoneID,
	} {
		if err := storage.ValidateUUID(value, field); err != nil {
			return err
		}
	}
	identifier, err := storage.NormalizeCertificateIdentifier(params.AuthorizationIdentifier)
	if err != nil {
		return err
	}
	params.AuthorizationIdentifier = identifier
	recordName, err := normalizeDNSTXTRecordName(params.RecordName)
	if err != nil {
		return err
	}
	params.RecordName = recordName
	if err := storage.ValidateEncryptedEnvelope(&params.TXTValueEncrypted, "txt_value_encrypted"); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = DNSChallengeStatusPending
	}
	return validateDNSChallengeStatus(params.Status)
}

func validateMarkDNSChallengeCleanup(params *MarkDNSChallengeCleanupParams) error {
	if err := storage.ValidateUUID(params.ID, "dns_challenge_record_id"); err != nil {
		return err
	}
	switch params.Status {
	case DNSChallengeStatusCleanupPending, DNSChallengeStatusCleanupFailed, DNSChallengeStatusCleaned:
	default:
		return errors.New("dns challenge cleanup status is invalid")
	}
	if params.Status == DNSChallengeStatusCleanupFailed {
		if err := validateFailureCode(params.FailureCode); err != nil {
			return err
		}
		return storage.ValidateOptionalHumanString(params.FailureMessage, "failure_message", 2048)
	}
	if params.FailureCode != "" || params.FailureMessage != nil {
		return errors.New("cleanup failure metadata requires cleanup_failed status")
	}
	return nil
}

func validateRecordEvent(params *RecordEventParams) error {
	if err := storage.ValidateUUID(params.ID, "certificate_event_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return err
	}
	if params.CertificateVersionID != nil {
		if err := storage.ValidateUUID(*params.CertificateVersionID, "certificate_version_id"); err != nil {
			return err
		}
	}
	if params.IssuanceJobID != nil {
		if err := storage.ValidateUUID(*params.IssuanceJobID, "issuance_job_id"); err != nil {
			return err
		}
	}
	if !eventTypeRE.MatchString(params.EventType) {
		return errors.New("event_type is invalid")
	}
	if params.Result == "" {
		params.Result = EventResultSuccess
	}
	if params.Result != EventResultSuccess && params.Result != EventResultFailure {
		return errors.New("event result is invalid")
	}
	if err := storage.ValidateCorrelationID(params.CorrelationID); err != nil {
		return err
	}
	if err := storage.ValidateOptionalHumanString(params.Message, "message", 2048); err != nil {
		return err
	}
	if len(params.Metadata) == 0 {
		params.Metadata = json.RawMessage(`{}`)
	}
	if !json.Valid(params.Metadata) {
		return errors.New("metadata must be valid JSON")
	}
	var value any
	if err := json.Unmarshal(params.Metadata, &value); err != nil {
		return errors.New("metadata must be valid JSON")
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("metadata must be a JSON object")
	}
	return nil
}

func normalizeDNSTXTRecordName(value string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(value), "_acme-challenge.") {
		return "", errors.New("record_name must be an _acme-challenge TXT owner name")
	}
	name, err := storage.NormalizeDNSName(value[len("_acme-challenge."):])
	if err != nil {
		return "", err
	}
	return "_acme-challenge." + name, nil
}

func validateKeyType(value KeyType) error {
	switch value {
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096, KeyTypeECDSAP256, KeyTypeECDSAP384:
		return nil
	default:
		return errors.New("key_type is invalid")
	}
}

func validateCertificateStatus(value Status) error {
	switch value {
	case StatusPending, StatusValidatingDNS, StatusIssuing, StatusReady, StatusRenewing, StatusRotatingKey, StatusExpired, StatusRevoked, StatusFailed, StatusDeleted:
		return nil
	default:
		return errors.New("certificate status is invalid")
	}
}

func validateIssuanceReason(value IssuanceReason) error {
	switch value {
	case IssuanceReasonInitialIssue, IssuanceReasonRenewal, IssuanceReasonKeyRotation, IssuanceReasonReissue:
		return nil
	default:
		return errors.New("issuance reason is invalid")
	}
}

func validateJobReason(value JobReason) error {
	switch value {
	case JobReasonInitialIssue, JobReasonRenewal, JobReasonKeyRotation, JobReasonReissue, JobReasonRevocationRetry, JobReasonDNSCleanup:
		return nil
	default:
		return errors.New("job reason is invalid")
	}
}

func validateDNSChallengeStatus(value DNSChallengeStatus) error {
	switch value {
	case DNSChallengeStatusPending, DNSChallengeStatusPresented, DNSChallengeStatusValidated, DNSChallengeStatusCleanupPending, DNSChallengeStatusCleanupFailed, DNSChallengeStatusCleaned:
		return nil
	default:
		return errors.New("dns challenge status is invalid")
	}
}

func validateFailureCode(value string) error {
	if !failureCodeRE.MatchString(value) {
		return errors.New("failure_code is invalid")
	}
	return nil
}
