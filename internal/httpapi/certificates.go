package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	auditdomain "github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	certdomain "github.com/torob/certhub/internal/certificates"
	tlsmaterial "github.com/torob/certhub/pkg/material"
)

type certificateCriteriaRequest struct {
	Domains       []string `json:"domains"`
	KeyType       string   `json:"key_type"`
	Issuer        string   `json:"issuer"`
	ApplicationID *string  `json:"application_id,omitempty"`
}

type certificateRevokeRequest struct {
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

type apiCertificate struct {
	ID                    string                 `json:"id"`
	ApplicationID         string                 `json:"application_id"`
	NormalizedSANs        []string               `json:"normalized_sans"`
	KeyType               string                 `json:"key_type"`
	IssuerID              string                 `json:"issuer_id"`
	IssuerName            *string                `json:"issuer_name,omitempty"`
	Status                string                 `json:"status"`
	LatestVersion         *apiCertificateVersion `json:"latest_version,omitempty"`
	FailureCode           *string                `json:"failure_code,omitempty"`
	FailureMessage        *string                `json:"failure_message,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	DeletedAt             *time.Time             `json:"deleted_at,omitempty"`
	HasActiveValidVersion bool                   `json:"has_active_valid_version"`
	HasIssuingVersion     bool                   `json:"has_issuing_version"`
}

type apiCertificateVersion struct {
	ID                           string     `json:"id"`
	CertificateID                string     `json:"certificate_id"`
	Version                      int        `json:"version"`
	Status                       string     `json:"status"`
	Reason                       string     `json:"reason"`
	NotBefore                    *time.Time `json:"not_before,omitempty"`
	NotAfter                     *time.Time `json:"not_after,omitempty"`
	SerialNumber                 *string    `json:"serial_number,omitempty"`
	FingerprintSHA256            *string    `json:"fingerprint_sha256,omitempty"`
	KeyFingerprintSHA256         *string    `json:"key_fingerprint_sha256,omitempty"`
	MaterialETag                 *string    `json:"material_etag,omitempty"`
	RevocationReason             *string    `json:"revocation_reason,omitempty"`
	RevokedAt                    *time.Time `json:"revoked_at,omitempty"`
	RevokedByUserID              *string    `json:"revoked_by_user_id,omitempty"`
	ACMERevocationStatus         *string    `json:"acme_revocation_status,omitempty"`
	ACMERevocationAttempts       int        `json:"acme_revocation_attempts"`
	ACMERevokedAt                *time.Time `json:"acme_revoked_at,omitempty"`
	ACMERevocationFailureCode    *string    `json:"acme_revocation_failure_code,omitempty"`
	ACMERevocationFailureMessage *string    `json:"acme_revocation_failure_message,omitempty"`
	CreatedAt                    time.Time  `json:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at"`
	StartedAt                    *time.Time `json:"started_at,omitempty"`
	CompletedAt                  *time.Time `json:"completed_at,omitempty"`
	IssuedAt                     *time.Time `json:"issued_at,omitempty"`
	FailureCode                  *string    `json:"failure_code,omitempty"`
	FailureMessage               *string    `json:"failure_message,omitempty"`
}

func isCertificateEndpoint(p string) bool {
	if p == "/v1/sync/certificates" || p == "/v1/sync/certificates/tls-material" || p == "/v1/sync/certificates/tls-archive" {
		return true
	}
	if p == "/v1/certificates" || strings.HasPrefix(p, "/v1/certificates/") {
		return true
	}
	parts, ok := applicationPathParts(p)
	return ok && len(parts) == 2 && parts[1] == "certificates"
}

func (s *Server) serveCertificates(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	if s.certs == nil {
		return writeCertificateError(w, certdomain.ErrCertificateServiceUnavailable)
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sync/certificates":
		return s.handleSyncCertificate(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sync/certificates/tls-material":
		return s.handleSyncMaterial(w, r, reqctx, false)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sync/certificates/tls-archive":
		return s.handleSyncMaterial(w, r, reqctx, true)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/certificates":
		return s.handleListCertificates(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/applications/"):
		return s.handleCreateApplicationCertificate(w, r)
	default:
		return s.handleCertificateByID(w, r, reqctx)
	}
}

func (s *Server) handleSyncCertificate(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateCertificateApplication(w, r, reqctx)
	if !ok {
		return status, code
	}
	criteria, err := decodeCertificateCriteria(r)
	if err != nil {
		return writeCertificateError(w, certdomain.ErrInvalidRequest)
	}
	result, err := s.certs.EnsureForApplicationToken(r.Context(), certdomain.ApplicationActor{ApplicationID: current.Application.ID, TokenID: current.Token.ID}, criteria)
	if err != nil {
		return writeCertificateError(w, err)
	}
	noStoreHeaders(w.Header())
	if result.Accepted {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusAccepted, map[string]any{"certificate": serializeCertificate(result.Certificate)})
		return http.StatusAccepted, ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificate": serializeCertificate(result.Certificate)})
	return http.StatusOK, ""
}

func (s *Server) handleCreateApplicationCertificate(w http.ResponseWriter, r *http.Request) (int, string) {
	current, status, code, ok := s.authenticateCertificateUser(w, r)
	if !ok {
		return status, code
	}
	parts, ok := applicationPathParts(r.URL.Path)
	if !ok || len(parts) != 2 || parts[1] != "certificates" {
		return writeCertificateError(w, certdomain.ErrNotFound)
	}
	criteria, err := decodeCertificateCriteria(r)
	if err != nil {
		return writeCertificateError(w, certdomain.ErrInvalidRequest)
	}
	result, err := s.certs.EnsureForUser(r.Context(), certificateActor(current), parts[0], criteria)
	if err != nil {
		return writeCertificateError(w, err)
	}
	noStoreHeaders(w.Header())
	if result.Accepted {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusAccepted, map[string]any{"certificate": serializeCertificate(result.Certificate)})
		return http.StatusAccepted, ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificate": serializeCertificate(result.Certificate)})
	return http.StatusOK, ""
}

func (s *Server) handleSyncMaterial(w http.ResponseWriter, r *http.Request, reqctx RequestContext, archive bool) (int, string) {
	current, status, code, ok := s.authenticateCertificateApplication(w, r, reqctx)
	if !ok {
		return status, code
	}
	if archive && !acceptsGzip(r.Header.Get("Accept")) {
		return writeError(w, http.StatusNotAcceptable, Error{Code: "not_acceptable", Message: "Requested response media type is not supported.", Details: map[string]any{}})
	}
	criteria, err := decodeCertificateCriteria(r)
	if err != nil {
		return writeCertificateError(w, certdomain.ErrInvalidRequest)
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		meta, err := s.certs.MaterialMetadataForCriteria(r.Context(), certdomain.ApplicationActor{ApplicationID: current.Application.ID, TokenID: current.Token.ID}, criteria)
		if err != nil {
			return writeCertificateError(w, err)
		}
		if etagMatches(inm, meta.MaterialETag) {
			materialHeaders(w.Header(), meta.MaterialETag)
			w.WriteHeader(http.StatusNoContent)
			return http.StatusNoContent, ""
		}
	}
	auditCtx := certificateAuditContext(reqctx)
	result, err := s.certs.MaterialForCriteria(r.Context(), certdomain.ApplicationActor{ApplicationID: current.Application.ID, TokenID: current.Token.ID}, criteria, auditCtx)
	if err != nil {
		return writeCertificateError(w, err)
	}
	if etagMatches(r.Header.Get("If-None-Match"), result.Material.MaterialETag) {
		materialHeaders(w.Header(), result.Material.MaterialETag)
		w.WriteHeader(http.StatusNoContent)
		return http.StatusNoContent, ""
	}
	if err := s.certs.AuditPrivateKeyRead(r.Context(), auditdomain.IdentityTypeApplication, current.Application.ID, result.Certificate, result.Version, auditCtx); err != nil {
		return writeCertificateError(w, err)
	}
	return writeMaterialResponse(w, result.Material, archive)
}

func (s *Server) handleListCertificates(w http.ResponseWriter, r *http.Request) (int, string) {
	current, status, code, ok := s.authenticateCertificateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseCertificateListParams(r)
	if err != nil {
		return writeCertificateError(w, certdomain.ErrInvalidRequest)
	}
	result, err := s.certs.ListCertificates(r.Context(), certificateActor(current), params)
	if err != nil {
		return writeCertificateError(w, err)
	}
	certs := make([]apiCertificate, 0, len(result.Certificates))
	for _, cert := range result.Certificates {
		certs = append(certs, serializeCertificate(cert))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"certificates": certs, "pagination": pageMeta(result.Limit, result.Offset, result.Total)})
	return http.StatusOK, ""
}

func (s *Server) handleCertificateByID(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateCertificateUser(w, r)
	if !ok {
		return status, code
	}
	actor := certificateActor(current)
	if certID, versionID, tail, ok := certificateVersionPath(r.URL.Path); ok {
		switch {
		case r.Method == http.MethodGet && tail == "tls-archive":
			return s.handleIDVersionArchive(w, r, reqctx, actor, certID, versionID)
		case r.Method == http.MethodPost && tail == "revoke":
			var body certificateRevokeRequest
			if err := decodeJSONBody(r, &body); err != nil || body.Reason == "" {
				return writeCertificateError(w, certdomain.ErrInvalidRequest)
			}
			version, err := s.certs.RevokeCertificateVersion(r.Context(), actor, certID, versionID, certdomain.RevocationReason(body.Reason))
			if err != nil {
				return writeCertificateError(w, err)
			}
			noStoreHeaders(w.Header())
			writeJSON(w, http.StatusAccepted, map[string]any{"version": serializeCertificateVersion(version)})
			return http.StatusAccepted, ""
		default:
			return writeCertificateError(w, certdomain.ErrNotFound)
		}
	}
	id, tail, ok := certificatePathID(r.URL.Path)
	if !ok {
		return writeCertificateError(w, certdomain.ErrNotFound)
	}
	switch {
	case r.Method == http.MethodGet && tail == "":
		cert, err := s.certs.GetCertificate(r.Context(), actor, id)
		if err != nil {
			return writeCertificateError(w, err)
		}
		noStoreHeaders(w.Header())
		writeJSON(w, http.StatusOK, map[string]any{"certificate": serializeCertificate(cert)})
		return http.StatusOK, ""
	case r.Method == http.MethodGet && tail == "versions":
		opts, err := parseListOptions(r)
		if err != nil {
			return writeCertificateError(w, certdomain.ErrInvalidRequest)
		}
		result, err := s.certs.ListVersions(r.Context(), actor, id, opts)
		if err != nil {
			return writeCertificateError(w, err)
		}
		versions := make([]apiCertificateVersion, 0, len(result.Versions))
		for _, version := range result.Versions {
			versions = append(versions, serializeCertificateVersion(version))
		}
		noStoreHeaders(w.Header())
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions, "pagination": pageMeta(result.Limit, result.Offset, result.Total)})
		return http.StatusOK, ""
	case r.Method == http.MethodGet && tail == "tls-archive":
		return s.handleIDArchive(w, r, reqctx, actor, id)
	case r.Method == http.MethodPost && (tail == "renew" || tail == "rotate-key" || tail == "reissue"):
		reason := certdomain.IssuanceReasonRenewal
		if tail == "rotate-key" {
			reason = certdomain.IssuanceReasonKeyRotation
		} else if tail == "reissue" {
			reason = certdomain.IssuanceReasonReissue
		}
		version, err := s.certs.StartLifecycle(r.Context(), actor, id, reason)
		if err != nil {
			return writeCertificateError(w, err)
		}
		noStoreHeaders(w.Header())
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusAccepted, map[string]any{"version": serializeCertificateVersion(version)})
		return http.StatusAccepted, ""
	case r.Method == http.MethodGet && tail == "events":
		return s.handleCertificateEvents(w, r, actor, id)
	default:
		return writeCertificateError(w, certdomain.ErrNotFound)
	}
}

func (s *Server) handleIDArchive(w http.ResponseWriter, r *http.Request, reqctx RequestContext, actor certdomain.Actor, certificateID string) (int, string) {
	if !acceptsGzip(r.Header.Get("Accept")) {
		return writeError(w, http.StatusNotAcceptable, Error{Code: "not_acceptable", Message: "Requested response media type is not supported.", Details: map[string]any{}})
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		meta, err := s.certs.MaterialMetadataForID(r.Context(), actor, certificateID)
		if err != nil {
			return writeCertificateError(w, err)
		}
		if etagMatches(inm, meta.MaterialETag) {
			materialHeaders(w.Header(), meta.MaterialETag)
			w.WriteHeader(http.StatusNotModified)
			return http.StatusNotModified, ""
		}
	}
	auditCtx := certificateAuditContext(reqctx)
	result, err := s.certs.MaterialForID(r.Context(), actor, certificateID, auditCtx)
	if err != nil {
		return writeCertificateError(w, err)
	}
	if etagMatches(r.Header.Get("If-None-Match"), result.Material.MaterialETag) {
		materialHeaders(w.Header(), result.Material.MaterialETag)
		w.WriteHeader(http.StatusNotModified)
		return http.StatusNotModified, ""
	}
	if err := s.certs.AuditPrivateKeyRead(r.Context(), auditdomain.IdentityTypeUser, actor.ID, result.Certificate, result.Version, auditCtx); err != nil {
		return writeCertificateError(w, err)
	}
	return writeMaterialResponse(w, result.Material, true)
}

func (s *Server) handleIDVersionArchive(w http.ResponseWriter, r *http.Request, reqctx RequestContext, actor certdomain.Actor, certificateID, versionID string) (int, string) {
	if !acceptsGzip(r.Header.Get("Accept")) {
		return writeError(w, http.StatusNotAcceptable, Error{Code: "not_acceptable", Message: "Requested response media type is not supported.", Details: map[string]any{}})
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		meta, err := s.certs.MaterialMetadataForVersionID(r.Context(), actor, certificateID, versionID)
		if err != nil {
			return writeCertificateError(w, err)
		}
		if etagMatches(inm, meta.MaterialETag) {
			materialHeaders(w.Header(), meta.MaterialETag)
			w.WriteHeader(http.StatusNotModified)
			return http.StatusNotModified, ""
		}
	}
	auditCtx := certificateAuditContext(reqctx)
	result, err := s.certs.MaterialForVersionID(r.Context(), actor, certificateID, versionID, auditCtx)
	if err != nil {
		return writeCertificateError(w, err)
	}
	if etagMatches(r.Header.Get("If-None-Match"), result.Material.MaterialETag) {
		materialHeaders(w.Header(), result.Material.MaterialETag)
		w.WriteHeader(http.StatusNotModified)
		return http.StatusNotModified, ""
	}
	if err := s.certs.AuditPrivateKeyRead(r.Context(), auditdomain.IdentityTypeUser, actor.ID, result.Certificate, result.Version, auditCtx); err != nil {
		return writeCertificateError(w, err)
	}
	return writeMaterialResponse(w, result.Material, true)
}

func (s *Server) handleCertificateEvents(w http.ResponseWriter, r *http.Request, actor certdomain.Actor, certificateID string) (int, string) {
	if s.audit == nil {
		return writeCertificateError(w, certdomain.ErrCertificateServiceUnavailable)
	}
	cert, err := s.certs.GetCertificateForEvents(r.Context(), actor, certificateID)
	if err != nil {
		return writeCertificateError(w, err)
	}
	params, err := parseAuditEventsParams(r)
	if err != nil {
		return writeCertificateError(w, certdomain.ErrInvalidRequest)
	}
	params.ScopeCertificateID = &cert.ID
	params.ScopeApplicationID = &cert.ApplicationID
	result, err := s.audit.ListEvents(r.Context(), auditdomain.Actor{ID: actor.ID, GlobalRole: string(actor.GlobalRole)}, params)
	if err != nil {
		return writeAuditError(w, err)
	}
	events := make([]apiAuditEvent, 0, len(result.Events))
	for _, event := range result.Events {
		events = append(events, serializeAuditEvent(event))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"audit_events": events, "pagination": pageMeta(result.Limit, result.Offset, result.Total)})
	return http.StatusOK, ""
}

func writeMaterialResponse(w http.ResponseWriter, material tlsmaterial.TLSMaterial, archive bool) (int, string) {
	materialHeaders(w.Header(), material.MaterialETag)
	if archive {
		data, err := tlsmaterial.BuildTLSArchive(material)
		if err != nil {
			return writeCertificateError(w, certdomain.ErrCertificateServiceUnavailable)
		}
		filename := tlsmaterial.SafeArchiveBasename(material.Domains, material.CertificateID) + ".tar.gz"
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return http.StatusOK, ""
	}
	writeJSON(w, http.StatusOK, material)
	return http.StatusOK, ""
}

func materialHeaders(h http.Header, etag string) {
	noStoreHeaders(h)
	h.Set("Vary", "Authorization")
	h.Set("ETag", etag)
}

func decodeCertificateCriteria(r *http.Request) (certdomain.Criteria, error) {
	var body certificateCriteriaRequest
	if err := decodeJSONBody(r, &body); err != nil {
		return certdomain.Criteria{}, err
	}
	if body.ApplicationID != nil {
		return certdomain.Criteria{}, errors.New("application_id is not allowed")
	}
	return certdomain.Criteria{Domains: body.Domains, KeyType: body.KeyType, Issuer: body.Issuer}, nil
}

func parseCertificateListParams(r *http.Request) (certdomain.ListParams, error) {
	opts, err := parseListOptions(r)
	if err != nil {
		return certdomain.ListParams{}, err
	}
	query := r.URL.Query()
	params := certdomain.ListParams{ListOptions: opts, Application: query.Get("application"), Domain: query.Get("domain"), Issuer: query.Get("issuer")}
	if raw := query.Get("application_id"); raw != "" {
		params.ApplicationID = &raw
	}
	if raw := query.Get("status"); raw != "" {
		status := certdomain.Status(raw)
		params.Status = &status
	}
	if raw := query.Get("key_type"); raw != "" {
		keyType := certdomain.KeyType(raw)
		params.KeyType = &keyType
	}
	if raw := query.Get("expires_before"); raw != "" {
		expiresBefore, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return certdomain.ListParams{}, err
		}
		params.ExpiresBefore = &expiresBefore
	}
	return params, nil
}

func (s *Server) authenticateCertificateApplication(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (appdomain.AuthenticatedApplication, int, string, bool) {
	token, err := requiredBearerToken(r)
	if err != nil {
		status, code := writeApplicationError(w, err)
		return appdomain.AuthenticatedApplication{}, status, code, false
	}
	if !strings.HasPrefix(token, appdomain.ApplicationTokenPrefix) {
		status, code := writeApplicationError(w, appdomain.ErrApplicationTokenRequired)
		return appdomain.AuthenticatedApplication{}, status, code, false
	}
	return s.authenticateApplication(w, r, reqctx)
}

func (s *Server) authenticateCertificateUser(w http.ResponseWriter, r *http.Request) (auth.AuthenticatedUser, int, string, bool) {
	if token, ok := authorizationBearer(r); ok && strings.HasPrefix(token, appdomain.ApplicationTokenPrefix) {
		status, code := writeIdentityError(w, auth.ErrUserTokenRequired)
		return auth.AuthenticatedUser{}, status, code, false
	}
	return s.authenticateUser(w, r)
}

func writeCertificateError(w http.ResponseWriter, err error) (int, string) {
	var state certdomain.StateError
	var renewalNotDue certdomain.RenewalNotDueError
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "Internal server error."
	retryAfter := 0
	details := map[string]any{}
	switch {
	case errors.Is(err, certdomain.ErrCertificateServiceUnavailable):
		status, code, message = http.StatusServiceUnavailable, "service_unavailable", "Backend is not ready."
	case errors.Is(err, certdomain.ErrInvalidRequest):
		status, code, message = http.StatusBadRequest, "invalid_request", "Request body or query parameters are invalid."
	case errors.Is(err, certdomain.ErrForbidden):
		status, code, message = http.StatusForbidden, "application_access_denied", "The authenticated identity is not allowed to access this resource."
	case errors.Is(err, certdomain.ErrDomainNotAuthorized):
		status, code, message = http.StatusForbidden, "domain_not_authorized", "Requested domains are not authorized for this Application."
	case errors.Is(err, certdomain.ErrNotFound):
		status, code, message = http.StatusNotFound, "certificate_not_found", "Resource does not exist or is not visible."
	case errors.Is(err, certdomain.ErrIssuerNotConfigured):
		status, code, message = http.StatusConflict, "issuer_not_configured", "No active default issuer is configured."
	case errors.Is(err, certdomain.ErrSystemManagedResource):
		status, code, message = http.StatusConflict, "system_managed_resource", "Resource is managed by Certhub configuration."
	case errors.As(err, &renewalNotDue):
		status, code, message = http.StatusConflict, "renewal_not_due", "Certificate is not inside its renewal window."
		details = renewalNotDueDetails(renewalNotDue)
	case errors.Is(err, certdomain.ErrConflict):
		status, code, message = http.StatusConflict, "conflict", "Resource state conflicts with this request."
	case errors.As(err, &state):
		status = http.StatusConflict
		details = certificateStateDetails(state)
		switch {
		case errors.Is(state.Err, certdomain.ErrCertificateNotReady):
			code, message, retryAfter = "certificate_not_ready", "Certificate material is not ready.", 5
		case errors.Is(state.Err, certdomain.ErrCertificateExpired):
			code, message, retryAfter = "certificate_expired", "Certificate material is expired.", 5
		case errors.Is(state.Err, certdomain.ErrCertificateIssuanceFailed):
			code, message = "certificate_issuance_failed", "Certificate issuance failed."
		case errors.Is(state.Err, certdomain.ErrCertificateRevoked):
			code, message = "certificate_revoked", "Certificate is revoked."
		case errors.Is(state.Err, certdomain.ErrCertificateNoActiveVersion):
			code, message = "certificate_no_active_version", "Certificate has no active valid version."
		}
	case errors.Is(err, certdomain.ErrCertificateNotReady):
		status, code, message, retryAfter = http.StatusConflict, "certificate_not_ready", "Certificate material is not ready.", 5
	case errors.Is(err, certdomain.ErrCertificateExpired):
		status, code, message, retryAfter = http.StatusConflict, "certificate_expired", "Certificate material is expired.", 5
	case errors.Is(err, certdomain.ErrCertificateIssuanceFailed):
		status, code, message = http.StatusConflict, "certificate_issuance_failed", "Certificate issuance failed."
	case errors.Is(err, certdomain.ErrCertificateRevoked):
		status, code, message = http.StatusConflict, "certificate_revoked", "Certificate is revoked."
	case errors.Is(err, certdomain.ErrCertificateNoActiveVersion):
		status, code, message = http.StatusConflict, "certificate_no_active_version", "Certificate has no active valid version."
	}
	return writeError(w, status, Error{Code: code, Message: message, Retryable: retryAfter > 0 || status == http.StatusServiceUnavailable, RetryAfterSeconds: retryAfter, Details: details})
}

func renewalNotDueDetails(err certdomain.RenewalNotDueError) map[string]any {
	details := map[string]any{
		"certificate_id":     err.Certificate.ID,
		"version":            err.Version.Version,
		"renewal_not_before": err.RenewalNotBefore,
	}
	if err.Version.NotAfter != nil {
		details["not_after"] = err.Version.NotAfter
	}
	return details
}

func certificateStateDetails(state certdomain.StateError) map[string]any {
	details := map[string]any{
		"certificate_id": state.Certificate.ID,
		"status":         string(state.Certificate.Status),
	}
	if state.Certificate.FailureCode != nil {
		details["failure_code"] = *state.Certificate.FailureCode
	}
	if state.Certificate.FailureMessage != nil {
		details["failure_message"] = *state.Certificate.FailureMessage
	}
	if state.Certificate.RevocationReason != nil {
		details["revocation_reason"] = string(*state.Certificate.RevocationReason)
	}
	if state.Certificate.RevokedAt != nil {
		details["revoked_at"] = state.Certificate.RevokedAt
	}
	if state.Version != nil {
		details["version_id"] = state.Version.ID
		details["version"] = state.Version.Version
		details["version_status"] = string(state.Version.Status)
		if state.Version.FailureCode != nil {
			details["failure_code"] = *state.Version.FailureCode
		}
		if state.Version.FailureMessage != nil {
			details["failure_message"] = *state.Version.FailureMessage
		}
		if state.Version.NotAfter != nil {
			details["not_after"] = state.Version.NotAfter
		}
		if state.Version.RevocationReason != nil {
			details["revocation_reason"] = string(*state.Version.RevocationReason)
		}
		if state.Version.RevokedAt != nil {
			details["revoked_at"] = state.Version.RevokedAt
		}
	}
	return details
}

func certificatePathID(p string) (string, string, bool) {
	rest := strings.TrimPrefix(p, "/v1/certificates/")
	if rest == p || rest == "" {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 1 {
		return parts[0], "", parts[0] != ""
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func certificateVersionPath(p string) (string, string, string, bool) {
	rest := strings.TrimPrefix(p, "/v1/certificates/")
	if rest == p || rest == "" {
		return "", "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 4 || parts[0] == "" || parts[1] != "versions" || parts[2] == "" || parts[3] == "" {
		return "", "", "", false
	}
	return parts[0], parts[2], parts[3], true
}

func certificateActor(current auth.AuthenticatedUser) certdomain.Actor {
	return certdomain.Actor{ID: current.User.ID, GlobalRole: current.User.GlobalRole}
}

func certificateAuditContext(reqctx RequestContext) certdomain.AuditContext {
	return certdomain.AuditContext{CorrelationID: reqctx.RequestID, SourceIP: sourceIPString(reqctx)}
}

func serializeCertificate(cert certdomain.Certificate) apiCertificate {
	out := apiCertificate{
		ID:                    cert.ID,
		ApplicationID:         cert.ApplicationID,
		NormalizedSANs:        cert.NormalizedSANs,
		KeyType:               string(cert.KeyType),
		IssuerID:              cert.IssuerID,
		Status:                string(cert.Status),
		FailureCode:           cert.FailureCode,
		FailureMessage:        cert.FailureMessage,
		CreatedAt:             cert.CreatedAt,
		UpdatedAt:             cert.UpdatedAt,
		DeletedAt:             cert.DeletedAt,
		HasActiveValidVersion: cert.HasActiveValidVersion,
		HasIssuingVersion:     cert.HasIssuingVersion,
	}
	if cert.IssuerName != "" {
		out.IssuerName = &cert.IssuerName
	}
	if cert.LatestVersion != nil {
		latest := serializeCertificateVersion(*cert.LatestVersion)
		out.LatestVersion = &latest
	}
	return out
}

func serializeCertificateVersion(version certdomain.CertificateVersion) apiCertificateVersion {
	out := apiCertificateVersion{
		ID:                           version.ID,
		CertificateID:                version.CertificateID,
		Version:                      version.Version,
		Status:                       string(version.Status),
		Reason:                       string(version.Reason),
		NotBefore:                    version.NotBefore,
		NotAfter:                     version.NotAfter,
		SerialNumber:                 version.SerialNumber,
		FingerprintSHA256:            version.FingerprintSHA256,
		KeyFingerprintSHA256:         version.KeyFingerprintSHA256,
		MaterialETag:                 version.MaterialETag,
		RevokedAt:                    version.RevokedAt,
		RevokedByUserID:              version.RevokedByUserID,
		ACMERevocationAttempts:       version.ACMERevocationAttempts,
		ACMERevokedAt:                version.ACMERevokedAt,
		ACMERevocationFailureCode:    version.ACMERevocationFailureCode,
		ACMERevocationFailureMessage: version.ACMERevocationFailureMessage,
		CreatedAt:                    version.CreatedAt,
		UpdatedAt:                    version.UpdatedAt,
		StartedAt:                    version.StartedAt,
		CompletedAt:                  version.CompletedAt,
		IssuedAt:                     version.IssuedAt,
		FailureCode:                  version.FailureCode,
		FailureMessage:               version.FailureMessage,
	}
	if version.ACMERevocationStatus != nil {
		raw := string(*version.ACMERevocationStatus)
		out.ACMERevocationStatus = &raw
	}
	if version.RevocationReason != nil {
		raw := string(*version.RevocationReason)
		out.RevocationReason = &raw
	}
	return out
}

func acceptsGzip(header string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		media := strings.TrimSpace(strings.Split(part, ";")[0])
		if media == "*/*" || media == "application/*" || media == "application/gzip" {
			return true
		}
	}
	return false
}

func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.TrimSpace(part) == etag {
			return true
		}
	}
	return false
}
