package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	auditdomain "github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/storage"
)

type applicationCreateRequest struct {
	Name               string   `json:"name"`
	DisplayName        string   `json:"display_name"`
	Description        *string  `json:"description"`
	Status             string   `json:"status"`
	TrustedSourceCIDRs []string `json:"trusted_source_cidrs"`
}

type domainScopeCreateRequest struct {
	Value string `json:"value"`
}

type grantPutRequest struct {
	Role string `json:"role"`
}

type apiApplication struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	DisplayName            string     `json:"display_name"`
	Status                 string     `json:"status"`
	SystemKind             *string    `json:"system_kind"`
	Description            *string    `json:"description,omitempty"`
	TrustedSourceCIDRs     []string   `json:"trusted_source_cidrs"`
	CurrentUserRole        string     `json:"current_user_role"`
	DomainScopeCount       int64      `json:"domain_scope_count"`
	TokenCount             int64      `json:"token_count"`
	TrustedSourceCIDRCount int64      `json:"trusted_source_cidr_count"`
	CertificateCount       int64      `json:"certificate_count"`
	LastUsedAt             *time.Time `json:"last_used_at,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type apiApplicationToken struct {
	ID            string     `json:"id"`
	ApplicationID string     `json:"application_id"`
	Name          string     `json:"name"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

type apiDomainScope struct {
	ID              string    `json:"id"`
	ApplicationID   string    `json:"application_id"`
	Value           string    `json:"value"`
	Kind            string    `json:"kind"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedByUserID *string   `json:"created_by_user_id,omitempty"`
}

type apiGrant struct {
	ID              string         `json:"id"`
	ApplicationID   string         `json:"application_id"`
	UserID          string         `json:"user_id"`
	Role            string         `json:"role"`
	User            map[string]any `json:"user"`
	CreatedAt       time.Time      `json:"created_at"`
	CreatedByUserID *string        `json:"created_by_user_id,omitempty"`
}

type apiAuditEvent struct {
	ID                 string          `json:"id"`
	IdentityType       string          `json:"identity_type"`
	IdentityID         *string         `json:"identity_id,omitempty"`
	Action             string          `json:"action"`
	TargetType         string          `json:"target_type"`
	TargetID           *string         `json:"target_id,omitempty"`
	ScopeApplicationID *string         `json:"scope_application_id,omitempty"`
	ScopeCertificateID *string         `json:"scope_certificate_id,omitempty"`
	ScopeUserID        *string         `json:"scope_user_id,omitempty"`
	ScopeDNSProviderID *string         `json:"scope_dns_provider_id,omitempty"`
	Result             string          `json:"result"`
	CorrelationID      *string         `json:"correlation_id,omitempty"`
	SourceIP           *string         `json:"source_ip,omitempty"`
	Metadata           json.RawMessage `json:"metadata"`
	CreatedAt          time.Time       `json:"created_at"`
}

func isApplicationEndpoint(p string) bool {
	return p == "/v1/applications" || strings.HasPrefix(p, "/v1/applications/")
}

func (s *Server) serveApplications(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	if s.apps == nil {
		return writeApplicationError(w, appdomain.ErrApplicationServiceUnavailable)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/applications":
		return s.handleListApplications(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/applications":
		return s.handleCreateApplication(w, r, reqctx)
	}
	parts, ok := applicationPathParts(r.URL.Path)
	if !ok {
		return s.authenticatedApplicationNotFound(w, r)
	}
	applicationID := parts[0]
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		return s.handleGetApplication(w, r, reqctx, applicationID)
	case len(parts) == 1 && r.Method == http.MethodPatch:
		return s.handlePatchApplication(w, r, reqctx, applicationID)
	case len(parts) == 2 && parts[1] == "tokens" && r.Method == http.MethodGet:
		return s.handleListApplicationTokens(w, r, reqctx, applicationID)
	case len(parts) == 2 && parts[1] == "tokens" && r.Method == http.MethodPost:
		return s.handleCreateApplicationToken(w, r, reqctx, applicationID)
	case len(parts) == 3 && parts[1] == "tokens" && r.Method == http.MethodDelete:
		return s.handleRevokeApplicationToken(w, r, reqctx, applicationID, parts[2])
	case len(parts) == 2 && parts[1] == "domain-scopes" && r.Method == http.MethodGet:
		return s.handleListDomainScopes(w, r, reqctx, applicationID)
	case len(parts) == 2 && parts[1] == "domain-scopes" && r.Method == http.MethodPost:
		return s.handleCreateDomainScope(w, r, reqctx, applicationID)
	case len(parts) == 3 && parts[1] == "domain-scopes" && r.Method == http.MethodDelete:
		return s.handleDeleteDomainScope(w, r, reqctx, applicationID, parts[2])
	case len(parts) == 2 && parts[1] == "users" && r.Method == http.MethodGet:
		return s.handleListApplicationGrants(w, r, reqctx, applicationID)
	case len(parts) == 3 && parts[1] == "users" && r.Method == http.MethodPut:
		return s.handlePutApplicationGrant(w, r, reqctx, applicationID, parts[2])
	case len(parts) == 3 && parts[1] == "users" && r.Method == http.MethodDelete:
		return s.handleDeleteApplicationGrant(w, r, reqctx, applicationID, parts[2])
	default:
		return s.authenticatedApplicationNotFound(w, r)
	}
}

func (s *Server) authenticatedApplicationNotFound(w http.ResponseWriter, r *http.Request) (int, string) {
	if _, status, code, ok := s.authenticateUser(w, r); !ok {
		return status, code
	}
	return writeApplicationError(w, appdomain.ErrNotFound)
}

func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request, _ RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseListApplicationsParams(r)
	if err != nil {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	result, err := s.apps.ListApplications(r.Context(), applicationActor(current), params)
	if err != nil {
		return writeApplicationError(w, err)
	}
	apps := make([]apiApplication, 0, len(result.Applications))
	for _, app := range result.Applications {
		apps = append(apps, serializeApplication(app))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"applications": apps,
		"pagination":   pageMeta(result.Limit, result.Offset, result.Total),
	})
	return http.StatusOK, ""
}

func (s *Server) handleCreateApplication(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body applicationCreateRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Name == "" || body.DisplayName == "" {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	app, err := s.apps.CreateApplication(r.Context(), applicationActor(current), appdomain.CreateApplicationParams{
		Name:               body.Name,
		DisplayName:        body.DisplayName,
		Description:        body.Description,
		Status:             appdomain.Status(body.Status),
		TrustedSourceCIDRs: body.TrustedSourceCIDRs,
	}, applicationAuditContext(reqctx))
	if err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, map[string]any{"application": serializeApplication(app)})
	return http.StatusCreated, ""
}

func (s *Server) handleGetApplication(w http.ResponseWriter, r *http.Request, _ RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	app, err := s.apps.GetApplication(r.Context(), applicationActor(current), applicationID)
	if err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"application": serializeApplication(app)})
	return http.StatusOK, ""
}

func (s *Server) handlePatchApplication(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := decodeApplicationPatch(r)
	if err != nil {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	app, err := s.apps.UpdateApplication(r.Context(), applicationActor(current), applicationID, params, applicationAuditContext(reqctx))
	if err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"application": serializeApplication(app)})
	return http.StatusOK, ""
}

func (s *Server) handleListApplicationTokens(w http.ResponseWriter, r *http.Request, _ RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseListTokensParams(r)
	if err != nil {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	result, err := s.apps.ListTokens(r.Context(), applicationActor(current), applicationID, params)
	if err != nil {
		return writeApplicationError(w, err)
	}
	tokens := make([]apiApplicationToken, 0, len(result.Tokens))
	for _, token := range result.Tokens {
		tokens = append(tokens, serializeApplicationToken(token))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens":     tokens,
		"pagination": pageMeta(result.Limit, result.Offset, result.Total),
	})
	return http.StatusOK, ""
}

func (s *Server) handleCreateApplicationToken(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := decodeApplicationTokenCreate(r)
	if err != nil {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	result, err := s.apps.CreateToken(r.Context(), applicationActor(current), applicationID, params, applicationAuditContext(reqctx))
	if err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":       serializeApplicationToken(result.Token),
		"token_value": result.TokenValue,
	})
	return http.StatusCreated, ""
}

func (s *Server) handleRevokeApplicationToken(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID, tokenID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	if err := s.apps.RevokeToken(r.Context(), applicationActor(current), applicationID, tokenID, applicationAuditContext(reqctx)); err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, ""
}

func (s *Server) handleListDomainScopes(w http.ResponseWriter, r *http.Request, _ RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	opts, err := parseListOptions(r)
	if err != nil {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	result, err := s.apps.ListDomainScopes(r.Context(), applicationActor(current), applicationID, opts)
	if err != nil {
		return writeApplicationError(w, err)
	}
	scopes := make([]apiDomainScope, 0, len(result.DomainScopes))
	for _, scope := range result.DomainScopes {
		scopes = append(scopes, serializeDomainScope(scope))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"domain_scopes": scopes,
		"pagination":    pageMeta(result.Limit, result.Offset, result.Total),
	})
	return http.StatusOK, ""
}

func (s *Server) handleCreateDomainScope(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body domainScopeCreateRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Value == "" {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	scope, err := s.apps.CreateDomainScope(r.Context(), applicationActor(current), applicationID, body.Value, applicationAuditContext(reqctx))
	if err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, map[string]any{"domain_scope": serializeDomainScope(scope)})
	return http.StatusCreated, ""
}

func (s *Server) handleDeleteDomainScope(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID, scopeID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	if err := s.apps.DeleteDomainScope(r.Context(), applicationActor(current), applicationID, scopeID, applicationAuditContext(reqctx)); err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, ""
}

func (s *Server) handleListApplicationGrants(w http.ResponseWriter, r *http.Request, _ RequestContext, applicationID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	opts, err := parseListOptions(r)
	if err != nil {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	result, err := s.apps.ListGrants(r.Context(), applicationActor(current), applicationID, opts)
	if err != nil {
		return writeApplicationError(w, err)
	}
	grants := make([]apiGrant, 0, len(result.Grants))
	for _, grant := range result.Grants {
		grants = append(grants, serializeGrant(grant))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"grants":     grants,
		"pagination": pageMeta(result.Limit, result.Offset, result.Total),
	})
	return http.StatusOK, ""
}

func (s *Server) handlePutApplicationGrant(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID, userID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body grantPutRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Role == "" {
		return writeApplicationError(w, appdomain.ErrInvalidRequest)
	}
	result, err := s.apps.UpsertGrant(r.Context(), applicationActor(current), applicationID, userID, appdomain.GrantRole(body.Role), applicationAuditContext(reqctx))
	if err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	statusCode := http.StatusOK
	if result.Created {
		statusCode = http.StatusCreated
	}
	writeJSON(w, statusCode, map[string]any{"grant": serializeGrant(result.Grant)})
	return statusCode, ""
}

func (s *Server) handleDeleteApplicationGrant(w http.ResponseWriter, r *http.Request, reqctx RequestContext, applicationID, userID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	if err := s.apps.DeleteGrant(r.Context(), applicationActor(current), applicationID, userID, applicationAuditContext(reqctx)); err != nil {
		return writeApplicationError(w, err)
	}
	noStoreHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, ""
}

func (s *Server) serveAuditEvents(w http.ResponseWriter, r *http.Request, _ RequestContext) (int, string) {
	if s.audit == nil {
		return writeAuditError(w, auditdomain.ErrAuditServiceUnavailable)
	}
	if r.Method != http.MethodGet {
		if _, status, code, ok := s.authenticateUser(w, r); !ok {
			return status, code
		}
		return writeAuditError(w, appdomain.ErrNotFound)
	}
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseAuditEventsParams(r)
	if err != nil {
		return writeAuditError(w, auditdomain.ErrInvalidRequest)
	}
	result, err := s.audit.ListEvents(r.Context(), auditdomain.Actor{ID: current.User.ID, GlobalRole: string(current.User.GlobalRole)}, params)
	if err != nil {
		return writeAuditError(w, err)
	}
	events := make([]apiAuditEvent, 0, len(result.Events))
	for _, event := range result.Events {
		events = append(events, serializeAuditEvent(event))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"audit_events": events,
		"pagination":   pageMeta(result.Limit, result.Offset, result.Total),
	})
	return http.StatusOK, ""
}

func (s *Server) authenticateApplication(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (appdomain.AuthenticatedApplication, int, string, bool) {
	if s.apps == nil {
		status, code := writeApplicationError(w, appdomain.ErrApplicationServiceUnavailable)
		return appdomain.AuthenticatedApplication{}, status, code, false
	}
	token, err := requiredBearerToken(r)
	if err != nil {
		status, code := writeApplicationError(w, appdomain.ErrInvalidToken)
		return appdomain.AuthenticatedApplication{}, status, code, false
	}
	current, err := s.apps.ValidateApplicationToken(r.Context(), token, reqctx.SourceIP)
	if err != nil {
		status, code := writeApplicationError(w, err)
		return appdomain.AuthenticatedApplication{}, status, code, false
	}
	return current, http.StatusOK, "", true
}

func writeApplicationError(w http.ResponseWriter, err error) (int, string) {
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "Internal server error."
	retryAfter := 0
	switch {
	case errors.Is(err, appdomain.ErrApplicationServiceUnavailable):
		status, code, message = http.StatusServiceUnavailable, "service_unavailable", "Backend is not ready."
	case errors.Is(err, appdomain.ErrInvalidToken), errors.Is(err, auth.ErrInvalidToken):
		status, code, message = http.StatusUnauthorized, "invalid_token", "Authentication token is missing, invalid, or expired."
	case errors.Is(err, auth.ErrRefreshTokenNotAllowed):
		status, code, message = http.StatusForbidden, "refresh_token_not_allowed", "Refresh tokens are accepted only by the refresh endpoint."
	case errors.Is(err, appdomain.ErrApplicationTokenRequired):
		status, code, message = http.StatusForbidden, "application_token_required", "An Application token is required."
	case errors.Is(err, appdomain.ErrSourceIPDenied):
		status, code, message = http.StatusForbidden, "application_source_ip_denied", "Application token source IP is not trusted."
	case errors.Is(err, appdomain.ErrForbidden):
		status, code, message = http.StatusForbidden, "application_access_denied", "The authenticated identity is not allowed to access this resource."
	case errors.Is(err, appdomain.ErrNotFound):
		status, code, message = http.StatusNotFound, "certificate_not_found", "Resource does not exist or is not visible."
	case errors.Is(err, appdomain.ErrConflict):
		status, code, message = http.StatusConflict, "conflict", "Resource state conflicts with this request."
		retryAfter = 1
	case errors.Is(err, appdomain.ErrSystemManagedResource):
		status, code, message = http.StatusConflict, "system_managed_resource", "Resource is owned by backend process configuration."
		retryAfter = 1
	case errors.Is(err, appdomain.ErrInvalidRequest):
		status, code, message = http.StatusBadRequest, "invalid_request", "Request body or query parameters are invalid."
	}
	return writeError(w, status, Error{Code: code, Message: message, Retryable: status == http.StatusServiceUnavailable, RetryAfterSeconds: retryAfter, Details: map[string]any{}})
}

func writeAuditError(w http.ResponseWriter, err error) (int, string) {
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "Internal server error."
	switch {
	case errors.Is(err, auditdomain.ErrAuditServiceUnavailable), errors.Is(err, appdomain.ErrApplicationServiceUnavailable):
		status, code, message = http.StatusServiceUnavailable, "service_unavailable", "Backend is not ready."
	case errors.Is(err, auditdomain.ErrInvalidRequest), errors.Is(err, appdomain.ErrInvalidRequest):
		status, code, message = http.StatusBadRequest, "invalid_request", "Request body or query parameters are invalid."
	case errors.Is(err, auditdomain.ErrForbidden), errors.Is(err, appdomain.ErrForbidden):
		status, code, message = http.StatusForbidden, "application_access_denied", "The authenticated identity is not allowed to access this resource."
	case errors.Is(err, appdomain.ErrNotFound):
		status, code, message = http.StatusNotFound, "certificate_not_found", "Resource does not exist or is not visible."
	}
	return writeError(w, status, Error{Code: code, Message: message, Retryable: status == http.StatusServiceUnavailable, Details: map[string]any{}})
}

func parseListApplicationsParams(r *http.Request) (appdomain.ListApplicationsParams, error) {
	opts, err := parseListOptions(r)
	if err != nil {
		return appdomain.ListApplicationsParams{}, err
	}
	params := appdomain.ListApplicationsParams{ListOptions: opts, Search: r.URL.Query().Get("search")}
	if raw := r.URL.Query().Get("status"); raw != "" {
		status := appdomain.Status(raw)
		params.Status = &status
	}
	return params, nil
}

func parseListTokensParams(r *http.Request) (appdomain.ListTokensParams, error) {
	opts, err := parseListOptions(r)
	if err != nil {
		return appdomain.ListTokensParams{}, err
	}
	params := appdomain.ListTokensParams{ListOptions: opts}
	if raw := r.URL.Query().Get("status"); raw != "" {
		status := appdomain.TokenStatus(raw)
		params.Status = &status
	}
	return params, nil
}

func parseListOptions(r *http.Request) (storage.ListOptions, error) {
	limit, err := parseIntQuery(r.URL.Query().Get("limit"))
	if err != nil {
		return storage.ListOptions{}, err
	}
	offset, err := parseIntQuery(r.URL.Query().Get("offset"))
	if err != nil {
		return storage.ListOptions{}, err
	}
	return storage.ListOptions{Limit: limit, Offset: offset}, nil
}

func parseAuditEventsParams(r *http.Request) (auditdomain.ListEventsParams, error) {
	opts, err := parseListOptions(r)
	if err != nil {
		return auditdomain.ListEventsParams{}, err
	}
	query := r.URL.Query()
	params := auditdomain.ListEventsParams{ListOptions: opts}
	if raw := query.Get("identity_type"); raw != "" {
		v := auditdomain.IdentityType(raw)
		params.IdentityType = &v
	}
	params.IdentityID = optionalQueryString(query.Get("identity_id"))
	params.Action = optionalQueryString(query.Get("action"))
	params.TargetType = optionalQueryString(query.Get("target_type"))
	params.TargetID = optionalQueryString(query.Get("target_id"))
	params.ScopeCertificateID = optionalQueryString(query.Get("certificate_id"))
	params.ScopeApplicationID = optionalQueryString(query.Get("application_id"))
	params.CorrelationID = optionalQueryString(query.Get("correlation_id"))
	if raw := query.Get("result"); raw != "" {
		v := auditdomain.Result(raw)
		params.Result = &v
	}
	if raw := query.Get("created_at_from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return auditdomain.ListEventsParams{}, err
		}
		params.CreatedAfter = &t
	}
	if raw := query.Get("created_at_to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return auditdomain.ListEventsParams{}, err
		}
		params.CreatedBefore = &t
	}
	return params, nil
}

func decodeApplicationPatch(r *http.Request) (appdomain.UpdateApplicationParams, error) {
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil {
		return appdomain.UpdateApplicationParams{}, err
	}
	if len(raw) == 0 {
		return appdomain.UpdateApplicationParams{}, errors.New("empty patch")
	}
	allowed := map[string]bool{
		"display_name":         true,
		"description":          true,
		"status":               true,
		"trusted_source_cidrs": true,
	}
	var out appdomain.UpdateApplicationParams
	for key, value := range raw {
		if !allowed[key] {
			return out, errors.New("unknown field")
		}
		switch key {
		case "display_name":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.DisplayName = storage.SetString(v)
		case "description":
			out.Description.Set = true
			if string(value) != "null" {
				var v string
				if err := json.Unmarshal(value, &v); err != nil {
					return out, err
				}
				out.Description.Value = &v
			}
		case "status":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.Status = storage.SetString(v)
		case "trusted_source_cidrs":
			if string(value) == "null" {
				return out, errors.New("trusted_source_cidrs cannot be null")
			}
			var v []string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.TrustedSourceCIDRs = &v
		}
	}
	return out, nil
}

func decodeApplicationTokenCreate(r *http.Request) (appdomain.CreateTokenServiceParams, error) {
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil {
		return appdomain.CreateTokenServiceParams{}, err
	}
	nameRaw, ok := raw["name"]
	if !ok {
		return appdomain.CreateTokenServiceParams{}, errors.New("name is required")
	}
	var out appdomain.CreateTokenServiceParams
	if err := json.Unmarshal(nameRaw, &out.Name); err != nil {
		return out, err
	}
	if expiresRaw, ok := raw["expires_at"]; ok {
		out.ExpiresAtSet = true
		if string(expiresRaw) != "null" {
			var rawTime string
			if err := json.Unmarshal(expiresRaw, &rawTime); err != nil {
				return out, err
			}
			expiresAt, err := time.Parse(time.RFC3339, rawTime)
			if err != nil {
				return out, err
			}
			out.ExpiresAt = &expiresAt
		}
	}
	for key := range raw {
		if key != "name" && key != "expires_at" {
			return out, errors.New("unknown field")
		}
	}
	return out, nil
}

func applicationPathParts(p string) ([]string, bool) {
	rest := strings.TrimPrefix(p, "/v1/applications/")
	if rest == p || rest == "" {
		return nil, false
	}
	parts := strings.Split(rest, "/")
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
	}
	return parts, true
}

func applicationActor(current auth.AuthenticatedUser) appdomain.Actor {
	return appdomain.Actor{ID: current.User.ID, GlobalRole: current.User.GlobalRole}
}

func applicationAuditContext(reqctx RequestContext) appdomain.AuditContext {
	return appdomain.AuditContext{CorrelationID: reqctx.RequestID, SourceIP: sourceIPString(reqctx)}
}

func serializeApplication(value appdomain.ApplicationWithRole) apiApplication {
	systemKind := (*string)(nil)
	if value.Application.SystemKind != nil {
		raw := string(*value.Application.SystemKind)
		systemKind = &raw
	}
	return apiApplication{
		ID:                     value.Application.ID,
		Name:                   value.Application.Name,
		DisplayName:            value.Application.DisplayName,
		Status:                 string(value.Application.Status),
		SystemKind:             systemKind,
		Description:            value.Application.Description,
		TrustedSourceCIDRs:     value.Application.TrustedSourceCIDRs,
		CurrentUserRole:        value.CurrentRole,
		DomainScopeCount:       value.Application.DomainScopeCount,
		TokenCount:             value.Application.TokenCount,
		TrustedSourceCIDRCount: value.Application.TrustedSourceCIDRCount,
		CertificateCount:       0,
		CreatedAt:              value.Application.CreatedAt,
		UpdatedAt:              value.Application.UpdatedAt,
	}
}

func serializeApplicationToken(token appdomain.ApplicationToken) apiApplicationToken {
	return apiApplicationToken{
		ID:            token.ID,
		ApplicationID: token.ApplicationID,
		Name:          token.Name,
		Status:        string(token.Status),
		CreatedAt:     token.CreatedAt,
		ExpiresAt:     token.ExpiresAt,
		LastUsedAt:    token.LastUsedAt,
		RevokedAt:     token.RevokedAt,
	}
}

func serializeDomainScope(scope appdomain.DomainScope) apiDomainScope {
	return apiDomainScope{
		ID:              scope.ID,
		ApplicationID:   scope.ApplicationID,
		Value:           scope.Value,
		Kind:            string(scope.Kind),
		CreatedAt:       scope.CreatedAt,
		CreatedByUserID: scope.CreatedByUserID,
	}
}

func serializeGrant(value appdomain.GrantWithUser) apiGrant {
	user := map[string]any{
		"id":              value.User.ID,
		"email":           value.User.Email,
		"display_name":    value.User.DisplayName,
		"status":          string(value.User.Status),
		"already_granted": true,
		"grant_role":      string(value.Grant.Role),
	}
	return apiGrant{
		ID:              value.Grant.ID,
		ApplicationID:   value.Grant.ApplicationID,
		UserID:          value.Grant.UserID,
		Role:            string(value.Grant.Role),
		User:            user,
		CreatedAt:       value.Grant.CreatedAt,
		CreatedByUserID: value.Grant.CreatedByUserID,
	}
}

func serializeAuditEvent(event auditdomain.Event) apiAuditEvent {
	metadata := event.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	return apiAuditEvent{
		ID:                 event.ID,
		IdentityType:       string(event.IdentityType),
		IdentityID:         event.IdentityID,
		Action:             event.Action,
		TargetType:         event.TargetType,
		TargetID:           event.TargetID,
		ScopeApplicationID: event.ScopeApplicationID,
		ScopeCertificateID: event.ScopeCertificateID,
		ScopeUserID:        event.ScopeUserID,
		ScopeDNSProviderID: event.ScopeDNSProviderID,
		Result:             string(event.Result),
		CorrelationID:      event.CorrelationID,
		SourceIP:           event.SourceIP,
		Metadata:           metadata,
		CreatedAt:          event.CreatedAt,
	}
}

func pageMeta(limit, offset int, total int64) map[string]any {
	return map[string]any{"limit": limit, "offset": offset, "total": total}
}

func optionalQueryString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
