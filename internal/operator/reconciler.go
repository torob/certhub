package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
	certerrors "github.com/torob/certhub/pkg/errors"
	"github.com/torob/certhub/pkg/material"
)

var ErrNotFound = stderrors.New("not found")

type KubernetesClient interface {
	GetSecret(ctx context.Context, namespace, name string) (*Secret, error)
	CreateOrUpdateSecret(ctx context.Context, secret *Secret) error
	ClearSecretOwnerReferences(ctx context.Context, secret *Secret) error
	DeleteSecret(ctx context.Context, namespace, name string, expected *Secret) error
	UpdateStatus(ctx context.Context, cert *CerthubCertificate) error
	UpdateFinalizers(ctx context.Context, cert *CerthubCertificate, finalizers []string) error
	EmitEvent(ctx context.Context, event Event) error
}

type BackendClient interface {
	GetTLSMaterial(ctx context.Context, criteria certhubclient.CertificateCriteria, opts certhubclient.RequestOptions) (*material.TLSMaterial, certhubclient.ResponseMeta, error)
	EnsureCertificate(ctx context.Context, criteria certhubclient.CertificateCriteria, opts certhubclient.RequestOptions) (*certhubclient.CertificateResponse, certhubclient.ResponseMeta, error)
}

type Reconciler struct {
	Kube           KubernetesClient
	Backend        BackendClient
	Metrics        *Metrics
	ResyncInterval time.Duration
	Backoff        time.Duration
	Now            func() time.Time
	NewRequestID   func(*CerthubCertificate) string
}

type Result struct {
	RequeueAfter time.Duration
	Result       string
	BackendCode  string
}

func reconcileResult(result string, requeueAfter time.Duration) Result {
	return Result{Result: result, RequeueAfter: requeueAfter}
}

func backendResult(result, code string, requeueAfter time.Duration) Result {
	return Result{Result: result, BackendCode: code, RequeueAfter: requeueAfter}
}

func NewReconciler(kube KubernetesClient, backend BackendClient) *Reconciler {
	return &Reconciler{
		Kube:           kube,
		Backend:        backend,
		Metrics:        NewMetrics(),
		ResyncInterval: 6 * time.Hour,
		Backoff:        time.Minute,
		Now:            func() time.Time { return time.Now().UTC() },
		NewRequestID: func(cert *CerthubCertificate) string {
			return fmt.Sprintf("operator-%s-%d", cert.Metadata.UID, time.Now().UnixNano())
		},
	}
}

func NewHTTPBackendFromConfig(cfg Config) (*certhubclient.Client, error) {
	return certhubclient.New(cfg.CerthubURL, cfg.Token, certhubclient.WithUserAgent("certhub-operator"), certhubclient.WithHTTPClient(BackendHTTPClient(cfg)), certhubclient.WithRetryPolicy(cfg.RetryPolicy))
}

func (r *Reconciler) Reconcile(ctx context.Context, cert *CerthubCertificate) (Result, error) {
	if r == nil || r.Kube == nil || r.Backend == nil {
		return Result{}, stderrors.New("operator reconciler is not configured")
	}
	if cert == nil {
		return Result{}, stderrors.New("CerthubCertificate is required")
	}
	if r.Now == nil {
		r.Now = func() time.Time { return time.Now().UTC() }
	}
	if r.NewRequestID == nil {
		r.NewRequestID = func(cert *CerthubCertificate) string {
			return fmt.Sprintf("operator-%s-%d", cert.Metadata.UID, r.Now().UnixNano())
		}
	}
	if r.ResyncInterval == 0 {
		r.ResyncInterval = 6 * time.Hour
	}
	if r.Backoff == 0 {
		r.Backoff = time.Minute
	}
	if cert.Metadata.DeletionTimestamp != nil {
		return r.reconcileDelete(ctx, cert)
	}

	normalized, err := ValidateCertificateSpec(cert.Spec)
	if err != nil {
		r.setStatus(cert, PhaseFailed, Sanitize(err.Error()),
			condition(ConditionAccepted, ConditionFalse, "InvalidSpec", err.Error(), r.Now()),
			condition(ConditionReady, ConditionFalse, "InvalidSpec", err.Error(), r.Now()),
		)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.Metrics.IncReconcile("invalid")
		return reconcileResult("invalid", 0), nil
	}
	if SecretDeletionPolicy(cert.Spec) == PolicyDelete && !slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		next := append([]string(nil), cert.Metadata.Finalizers...)
		next = append(next, Finalizer)
		if err := r.Kube.UpdateFinalizers(ctx, cert, next); err != nil {
			r.Metrics.IncReconcile("finalizer_failed")
			return reconcileResult("finalizer_failed", r.Backoff), err
		}
		cert.Metadata.Finalizers = next
	}

	secret, err := r.Kube.GetSecret(ctx, cert.Metadata.Namespace, cert.Spec.SecretName)
	if err != nil && !stderrors.Is(err, ErrNotFound) {
		r.failTransient(ctx, cert, "SecretReadFailed", err.Error())
		r.Metrics.IncReconcile("secret_read_failed")
		return reconcileResult("secret_read_failed", r.Backoff), nil
	}
	var ifNoneMatch string
	if err == nil && secret != nil {
		if ownershipErr := checkOwnedSecret(cert, secret); ownershipErr != nil {
			r.setStatus(cert, PhaseFailed, ownershipErr.Error(),
				condition(ConditionAccepted, ConditionTrue, "Accepted", "spec accepted", r.Now()),
				condition(ConditionSecretSynced, ConditionFalse, "SecretOwnershipConflict", ownershipErr.Error(), r.Now()),
				condition(ConditionReady, ConditionFalse, "SecretOwnershipConflict", ownershipErr.Error(), r.Now()),
			)
			if result, ok := r.updateStatus(ctx, cert); !ok {
				return result, nil
			}
			r.emit(ctx, cert, "Warning", "SecretOwnershipConflict", ownershipErr.Error())
			r.Metrics.IncReconcile("ownership_conflict")
			r.Metrics.IncSecretSync("ownership_conflict")
			return reconcileResult("ownership_conflict", 0), nil
		}
		if len(secret.Metadata.OwnerReferences) > 0 {
			if cleanupErr := r.Kube.ClearSecretOwnerReferences(ctx, secret); cleanupErr != nil {
				r.failTransient(ctx, cert, "SecretOwnerReferenceCleanupFailed", cleanupErr.Error())
				r.Metrics.IncReconcile("owner_reference_cleanup_failed")
				r.Metrics.IncSecretSync("metadata_migration_failed")
				return reconcileResult("owner_reference_cleanup_failed", r.Backoff), nil
			}
			secret.Metadata.OwnerReferences = nil
			r.emit(ctx, cert, "Normal", "SecretOwnerReferenceRemoved", "legacy Secret owner reference removed")
			r.Metrics.IncSecretSync("metadata_migrated")
		}
		ifNoneMatch = secret.Metadata.Annotations[AnnotationMaterialETag]
	}
	if SecretDeletionPolicy(cert.Spec) == PolicyRetain && slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		next := removeFinalizer(cert.Metadata.Finalizers, Finalizer)
		if err := r.Kube.UpdateFinalizers(ctx, cert, next); err != nil {
			r.Metrics.IncReconcile("finalizer_failed")
			return reconcileResult("finalizer_failed", r.Backoff), err
		}
		cert.Metadata.Finalizers = next
	}

	criteria := certhubclient.CertificateCriteria{
		Domains: normalized.Domains,
		KeyType: normalized.KeyType,
		Issuer:  normalized.Issuer,
	}
	materialValue, meta, err := r.Backend.GetTLSMaterial(ctx, criteria, certhubclient.RequestOptions{
		IfNoneMatch: ifNoneMatch,
		RequestID:   r.NewRequestID(cert),
	})
	if err == nil {
		r.Metrics.IncBackend("ok")
		if materialValue == nil && meta.StatusCode == http.StatusNoContent {
			r.markReady(cert, normalized.Domains, "", "Secret current")
			if result, ok := r.updateStatus(ctx, cert); !ok {
				return result, nil
			}
			r.emit(ctx, cert, "Normal", "CertificateReady", "Certificate material is ready")
			r.Metrics.IncReconcile("current")
			r.Metrics.IncSecretSync("current")
			return backendResult("current", "ok", r.ResyncInterval), nil
		}
		if materialValue == nil {
			r.failTransient(ctx, cert, "BackendUnavailable", "Certhub returned empty TLS material")
			r.Metrics.IncReconcile("empty_material")
			return backendResult("empty_material", "ok", r.Backoff), nil
		}
		if err := r.writeTLSSecret(ctx, cert, materialValue); err != nil {
			r.failTransient(ctx, cert, "SecretWriteFailed", err.Error())
			r.Metrics.IncReconcile("secret_write_failed")
			r.Metrics.IncSecretSync("write_failed")
			return reconcileResult("secret_write_failed", r.Backoff), nil
		}
		r.markReady(cert, normalized.Domains, materialValue.CertificateID, "Secret synced")
		cert.Status.NotBefore = materialValue.NotBefore.Format(time.RFC3339)
		cert.Status.NotAfter = materialValue.NotAfter.Format(time.RFC3339)
		cert.Status.RenewalTime = materialValue.NotAfter.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.emit(ctx, cert, "Normal", "CertificateReady", "Certificate material is ready")
		r.emit(ctx, cert, "Normal", "SecretSynced", "TLS Secret synced")
		r.Metrics.IncReconcile("synced")
		r.Metrics.IncSecretSync("synced")
		return backendResult("synced", "ok", r.ResyncInterval), nil
	}

	return r.handleBackendError(ctx, cert, criteria, normalized.Domains, err)
}

func (r *Reconciler) reconcileDelete(ctx context.Context, cert *CerthubCertificate) (Result, error) {
	if SecretDeletionPolicy(cert.Spec) == PolicyDelete {
		secret, err := r.Kube.GetSecret(ctx, cert.Metadata.Namespace, cert.Spec.SecretName)
		if err == nil && secret != nil {
			if ownershipErr := checkOwnedSecret(cert, secret); ownershipErr == nil {
				if deleteErr := r.Kube.DeleteSecret(ctx, cert.Metadata.Namespace, cert.Spec.SecretName, secret); deleteErr != nil && !stderrors.Is(deleteErr, ErrNotFound) {
					r.failTransient(ctx, cert, "SecretDeleteFailed", deleteErr.Error())
					r.Metrics.IncReconcile("delete_failed")
					return reconcileResult("delete_failed", r.Backoff), nil
				}
				r.emit(ctx, cert, "Normal", "SecretDeleted", "owned TLS Secret deleted")
			} else {
				r.emit(ctx, cert, "Warning", "SecretOwnershipConflict", ownershipErr.Error())
			}
		} else if err != nil && !stderrors.Is(err, ErrNotFound) {
			r.failTransient(ctx, cert, "SecretReadFailed", err.Error())
			return reconcileResult("secret_read_failed", r.Backoff), nil
		}
	} else {
		secret, err := r.Kube.GetSecret(ctx, cert.Metadata.Namespace, cert.Spec.SecretName)
		if err == nil && secret != nil && len(secret.Metadata.OwnerReferences) > 0 {
			if ownershipErr := checkOwnedSecret(cert, secret); ownershipErr == nil {
				if cleanupErr := r.Kube.ClearSecretOwnerReferences(ctx, secret); cleanupErr != nil {
					r.failTransient(ctx, cert, "SecretOwnerReferenceCleanupFailed", cleanupErr.Error())
					r.Metrics.IncReconcile("owner_reference_cleanup_failed")
					return reconcileResult("owner_reference_cleanup_failed", r.Backoff), nil
				}
				secret.Metadata.OwnerReferences = nil
				r.emit(ctx, cert, "Normal", "SecretRetained", "legacy Secret owner reference removed before deletion")
			} else {
				r.emit(ctx, cert, "Warning", "SecretOwnershipConflict", ownershipErr.Error())
			}
		} else if err != nil && !stderrors.Is(err, ErrNotFound) {
			r.failTransient(ctx, cert, "SecretReadFailed", err.Error())
			return reconcileResult("secret_read_failed", r.Backoff), nil
		}
	}
	if slices.Contains(cert.Metadata.Finalizers, Finalizer) {
		next := removeFinalizer(cert.Metadata.Finalizers, Finalizer)
		if err := r.Kube.UpdateFinalizers(ctx, cert, next); err != nil {
			r.Metrics.IncReconcile("finalizer_failed")
			return reconcileResult("finalizer_failed", r.Backoff), err
		}
		cert.Metadata.Finalizers = next
	}
	r.Metrics.IncReconcile("deleted")
	r.Metrics.ClearCertificateConditions(cert.Metadata.Namespace, cert.Metadata.Name)
	return reconcileResult("deleted", 0), nil
}

func removeFinalizer(finalizers []string, remove string) []string {
	next := make([]string, 0, len(finalizers))
	for _, finalizer := range finalizers {
		if finalizer != remove {
			next = append(next, finalizer)
		}
	}
	return next
}

func (r *Reconciler) handleBackendError(ctx context.Context, cert *CerthubCertificate, criteria certhubclient.CertificateCriteria, domains []string, err error) (Result, error) {
	var apiErr *certerrors.APIError
	if !stderrors.As(err, &apiErr) {
		r.failTransient(ctx, cert, "BackendUnavailable", err.Error())
		r.emit(ctx, cert, "Warning", "BackendUnavailable", "Certhub request failed")
		r.Metrics.IncReconcile("backend_unavailable")
		r.Metrics.IncBackend("transport")
		return backendResult("backend_unavailable", "transport", r.Backoff), nil
	}
	code := apiErr.Envelope.Code
	r.Metrics.IncBackend(code)
	switch code {
	case certerrors.CodeCertificateNotFound:
		response, meta, ensureErr := r.Backend.EnsureCertificate(ctx, criteria, certhubclient.RequestOptions{RequestID: r.NewRequestID(cert)})
		if ensureErr != nil {
			var ensureAPIErr *certerrors.APIError
			if stderrors.As(ensureErr, &ensureAPIErr) && ensureAPIErr.Envelope.Code == certerrors.CodeCertificateNotFound {
				r.failTransient(ctx, cert, "BackendUnavailable", "Certhub did not accept certificate creation")
				return backendResult("backend_unavailable", code, r.Backoff), nil
			}
			return r.handleBackendError(ctx, cert, criteria, domains, ensureErr)
		}
		certificateID := ""
		if response != nil {
			certificateID = response.Certificate.ID
		}
		cert.Status.CertificateID = certificateID
		r.setStatus(cert, PhaseIssuing, "Certificate creation requested",
			condition(ConditionAccepted, ConditionTrue, "Accepted", "spec accepted", r.Now()),
			condition(ConditionReady, ConditionFalse, "Issuing", "Certificate creation requested", r.Now()),
			condition(ConditionSecretSynced, ConditionFalse, "PendingMaterial", "TLS material is not ready", r.Now()),
		)
		cert.Status.ObservedDomains = append([]string(nil), domains...)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.emit(ctx, cert, "Normal", "CertificateCreated", "Certhub certificate creation requested")
		if delay, ok := meta.RetryAfterSeconds(); ok {
			return backendResult("certificate_created", code, time.Duration(delay)*time.Second), nil
		}
		return backendResult("certificate_created", code, r.Backoff), nil
	case certerrors.CodeCertificateNotReady, certerrors.CodeCertificateExpired:
		r.setStatus(cert, PhaseIssuing, "Certificate material is not ready",
			condition(ConditionAccepted, ConditionTrue, "Accepted", "spec accepted", r.Now()),
			condition(ConditionReady, ConditionFalse, "PendingMaterial", "Certificate material is not ready", r.Now()),
			condition(ConditionSecretSynced, ConditionFalse, "PendingMaterial", "TLS material is not ready", r.Now()),
		)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.emit(ctx, cert, "Normal", "CertificatePending", "Certificate material is not ready")
		return backendResult("pending_material", code, retryDelay(apiErr, r.Backoff)), nil
	case certerrors.CodeCertificateIssuanceFailed:
		r.setStatus(cert, PhaseFailed, Sanitize(apiErr.Envelope.Message),
			condition(ConditionIssuanceFailed, ConditionTrue, "IssuanceFailed", apiErr.Envelope.Message, r.Now()),
			condition(ConditionReady, ConditionFalse, "IssuanceFailed", apiErr.Envelope.Message, r.Now()),
		)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.emit(ctx, cert, "Warning", "IssuanceFailed", apiErr.Envelope.Message)
		return backendResult("issuance_failed", code, 0), nil
	case certerrors.CodeCertificateRevoked, certerrors.CodeCertificateNoActiveVersion:
		resultReason := "certificate_revoked"
		if code == certerrors.CodeCertificateNoActiveVersion {
			resultReason = "certificate_no_active_version"
		}
		r.setStatus(cert, PhaseFailed, Sanitize(apiErr.Envelope.Message),
			condition(ConditionCertificateRevoked, ConditionTrue, "CertificateRevoked", apiErr.Envelope.Message, r.Now()),
			condition(ConditionReady, ConditionFalse, "CertificateRevoked", apiErr.Envelope.Message, r.Now()),
		)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.emit(ctx, cert, "Warning", "CertificateRevoked", apiErr.Envelope.Message)
		return backendResult(resultReason, code, 0), nil
	case certerrors.CodeDomainNotAuthorized, certerrors.CodeApplicationSourceIPDenied, certerrors.CodeApplicationTokenRequired, certerrors.CodeInvalidToken:
		message := "Certhub Application is not authorized for this certificate"
		if code == certerrors.CodeApplicationSourceIPDenied {
			message = "operator source IP is outside the Certhub Application trusted source CIDRs"
		}
		r.setStatus(cert, PhaseFailed, message,
			condition(ConditionAuthorizationFailed, ConditionTrue, "AuthorizationFailed", message, r.Now()),
			condition(ConditionReady, ConditionFalse, "AuthorizationFailed", message, r.Now()),
		)
		if result, ok := r.updateStatus(ctx, cert); !ok {
			return result, nil
		}
		r.emit(ctx, cert, "Warning", "AuthorizationFailed", message)
		return backendResult("authorization_failed", code, 0), nil
	default:
		requeue := r.Backoff
		if apiErr.Envelope.Retryable {
			requeue = retryDelay(apiErr, r.Backoff)
		}
		r.failTransient(ctx, cert, backendReason(code), apiErr.Envelope.Message)
		r.emit(ctx, cert, "Warning", "BackendUnavailable", apiErr.Envelope.Message)
		return backendResult("backend_error", code, requeue), nil
	}
}

func retryDelay(apiErr *certerrors.APIError, fallback time.Duration) time.Duration {
	if seconds, ok := apiErr.RetryAfterSeconds(); ok {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func backendReason(code string) string {
	if code == "" {
		return "BackendUnavailable"
	}
	return code
}

func (r *Reconciler) writeTLSSecret(ctx context.Context, cert *CerthubCertificate, value *material.TLSMaterial) error {
	secret := &Secret{
		Metadata: Metadata{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Metadata.Namespace,
			UID:       "",
			Labels: map[string]string{
				LabelManagedBy:       ManagedByValue,
				LabelCertificateName: cert.Metadata.Name,
			},
			Annotations: map[string]string{
				AnnotationCertificateID:     value.CertificateID,
				AnnotationFingerprintSHA256: value.FingerprintSHA256,
				AnnotationMaterialETag:      value.MaterialETag,
				AnnotationNotAfter:          value.NotAfter.Format(time.RFC3339),
				AnnotationOwnerUID:          cert.Metadata.UID,
			},
		},
		Type: SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte(value.FullchainPEM),
			"tls.key": []byte(value.PrivateKeyPEM),
		},
	}
	return r.Kube.CreateOrUpdateSecret(ctx, secret)
}

func checkOwnedSecret(cert *CerthubCertificate, secret *Secret) error {
	return checkSecretOwnership(secret, cert.Metadata.Namespace, cert.Spec.SecretName, cert.Metadata.Name, cert.Metadata.UID)
}

func checkWritableExistingSecret(existing, desired *Secret) error {
	if existing == nil || desired == nil {
		return stderrors.New("target Secret ownership cannot be verified")
	}
	ownerUID := desired.Metadata.Annotations[AnnotationOwnerUID]
	certName := desired.Metadata.Labels[LabelCertificateName]
	return checkSecretOwnership(existing, desired.Metadata.Namespace, desired.Metadata.Name, certName, ownerUID)
}

func checkSecretOwnership(secret *Secret, namespace, secretName, certName, certUID string) error {
	if secret.Metadata.Namespace != namespace {
		return stderrors.New("target Secret is outside the CerthubCertificate namespace")
	}
	if secret.Metadata.Name != secretName {
		return stderrors.New("target Secret name does not match spec.secretName")
	}
	if secret.Type != SecretTypeTLS {
		return stderrors.New("target Secret is not a Kubernetes TLS Secret")
	}
	if secret.Metadata.Annotations[AnnotationOwnerUID] != certUID {
		return stderrors.New("target Secret is not owned by this CerthubCertificate")
	}
	if secret.Metadata.Labels[LabelManagedBy] != ManagedByValue {
		return stderrors.New("target Secret is missing Certhub operator management label")
	}
	if secret.Metadata.Labels[LabelCertificateName] != certName {
		return stderrors.New("target Secret belongs to another CerthubCertificate")
	}
	for _, ref := range secret.Metadata.OwnerReferences {
		if ref.APIVersion != APIVersion || ref.Kind != Kind || ref.UID != certUID || ref.Name != certName {
			return stderrors.New("target Secret owner reference does not match this CerthubCertificate")
		}
	}
	return nil
}

func (r *Reconciler) markReady(cert *CerthubCertificate, domains []string, certificateID, message string) {
	if certificateID != "" {
		cert.Status.CertificateID = certificateID
	}
	r.setStatus(cert, PhaseReady, message,
		condition(ConditionAccepted, ConditionTrue, "Accepted", "spec accepted", r.Now()),
		condition(ConditionReady, ConditionTrue, "Ready", "Certificate material is ready", r.Now()),
		condition(ConditionSecretSynced, ConditionTrue, "SecretSynced", "TLS Secret is synced", r.Now()),
	)
	cert.Status.ObservedDomains = append([]string(nil), domains...)
}

func (r *Reconciler) failTransient(ctx context.Context, cert *CerthubCertificate, reason, message string) {
	r.setStatus(cert, PhasePending, Sanitize(message),
		condition(ConditionReady, ConditionFalse, reason, message, r.Now()),
		condition(ConditionSecretSynced, ConditionFalse, reason, message, r.Now()),
	)
	_, _ = r.updateStatus(ctx, cert)
}

func (r *Reconciler) setStatus(cert *CerthubCertificate, phase, message string, conditions ...Condition) {
	cert.Status.Phase = phase
	cert.Status.Message = Sanitize(message)
	for _, next := range conditions {
		upsertCondition(&cert.Status, next)
	}
	if retryID := cert.Metadata.Annotations[AnnotationRetryID]; retryID != "" {
		marker := retryIDMarker(retryID)
		if marker != cert.Status.ObservedRetryID {
			cert.Status.ObservedRetryID = marker
		}
	}
}

func (r *Reconciler) updateStatus(ctx context.Context, cert *CerthubCertificate) (Result, bool) {
	if err := r.Kube.UpdateStatus(ctx, cert); err != nil {
		r.Metrics.IncReconcile("status_update_failed")
		return reconcileResult("status_update_failed", r.Backoff), false
	}
	r.Metrics.SetCertificateConditions(cert)
	return Result{}, true
}

func retryIDMarker(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func condition(conditionType, status, reason, message string, now time.Time) Condition {
	return Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            Sanitize(message),
		LastTransitionTime: now,
	}
}

func upsertCondition(status *CerthubCertificateStatus, next Condition) {
	for i := range status.Conditions {
		if status.Conditions[i].Type == next.Type {
			status.Conditions[i] = next
			return
		}
	}
	status.Conditions = append(status.Conditions, next)
}

func (r *Reconciler) emit(ctx context.Context, cert *CerthubCertificate, eventType, reason, message string) {
	_ = r.Kube.EmitEvent(ctx, Event{
		Namespace: cert.Metadata.Namespace,
		Name:      cert.Metadata.Name,
		Type:      eventType,
		Reason:    reason,
		Message:   Sanitize(message),
	})
}
