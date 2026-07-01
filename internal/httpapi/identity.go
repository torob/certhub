package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	appdomain "github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type totpCodeRequest struct {
	TOTPCode string `json:"totp_code"`
}

type disable2FARequest struct {
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type handoffRequest struct {
	HandoffID string `json:"handoff_id"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type userCreateRequest struct {
	Email                string  `json:"email"`
	DisplayName          string  `json:"display_name"`
	GlobalRole           string  `json:"global_role"`
	Status               string  `json:"status"`
	Password             *string `json:"password"`
	ProvisionPassword2FA bool    `json:"provision_password_2fa"`
}

type apiUser struct {
	ID                    string     `json:"id"`
	Email                 string     `json:"email"`
	DisplayName           string     `json:"display_name"`
	PasswordLoginEnabled  bool       `json:"password_login_enabled"`
	Password2FAEnabled    bool       `json:"password_2fa_enabled"`
	OIDCLinked            bool       `json:"oidc_linked"`
	GlobalRole            string     `json:"global_role"`
	Status                string     `json:"status"`
	ApplicationGrantCount int64      `json:"application_grant_count"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	LastLoginAt           *time.Time `json:"last_login_at,omitempty"`
}

type apiTOTPProvisioning struct {
	Issuer          string `json:"issuer"`
	AccountLabel    string `json:"account_label"`
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

type apiTokens struct {
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func isIdentityEndpoint(p string) bool {
	return p == "/v1/auth/login" ||
		p == "/v1/auth/password-2fa/setup" ||
		p == "/v1/auth/password-2fa/confirm" ||
		p == "/v1/auth/password-2fa" ||
		p == "/v1/auth/oidc/login" ||
		p == "/v1/auth/oidc/callback" ||
		p == "/v1/auth/oidc/handoff" ||
		p == "/v1/auth/refresh" ||
		p == "/v1/auth/logout" ||
		p == "/v1/auth/me" ||
		p == "/v1/users" ||
		p == "/v1/users/lookup" ||
		(strings.HasPrefix(p, "/v1/users/") && strings.Count(strings.TrimPrefix(p, "/v1/users/"), "/") == 0)
}

func (s *Server) serveIdentity(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	if r.URL.Path == "/v1/auth/me" {
		if s.auth == nil && s.apps == nil {
			return writeIdentityError(w, auth.ErrIdentityServiceUnavailable)
		}
	} else if s.auth == nil || (strings.HasPrefix(r.URL.Path, "/v1/users") && s.users == nil) {
		return writeIdentityError(w, auth.ErrIdentityServiceUnavailable)
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login":
		return s.handlePasswordLogin(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/password-2fa/setup":
		return s.handleSetupPassword2FA(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/password-2fa/confirm":
		return s.handleConfirmPassword2FA(w, r, reqctx)
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/auth/password-2fa":
		return s.handleDisablePassword2FA(w, r, reqctx)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/oidc/login":
		return s.handleStartOIDCLogin(w, r, reqctx)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/oidc/callback":
		return s.handleCompleteOIDCCallback(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/oidc/handoff":
		return s.handleOIDCHandoff(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/refresh":
		return s.handleRefresh(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/logout":
		return s.handleLogout(w, r, reqctx)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/me":
		return s.handleAuthMe(w, r, reqctx)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/users":
		return s.handleListUsers(w, r, reqctx)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/users":
		return s.handleCreateUser(w, r, reqctx)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/users/lookup":
		return s.handleLookupUser(w, r, reqctx)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/users/"):
		return s.handleGetUser(w, r, reqctx)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/users/"):
		return s.handlePatchUser(w, r, reqctx)
	default:
		return writeError(w, http.StatusNotFound, Error{
			Code: "certificate_not_found", Message: "Resource does not exist or is not visible.", Retryable: false, Details: map[string]any{},
		})
	}
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	var body loginRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Email == "" || body.Password == "" {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	if _, err := storage.NormalizeEmail(body.Email); err != nil {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	result, err := s.auth.PasswordLogin(r.Context(), auth.PasswordLoginParams{
		Email:    body.Email,
		Password: body.Password,
		TOTPCode: body.TOTPCode,
		Audit:    s.authAuditContext(r, reqctx),
	})
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"user":               serializeUser(result.User),
		"access_token":       result.Tokens.AccessToken,
		"access_expires_at":  result.Tokens.AccessExpiresAt,
		"refresh_token":      result.Tokens.RefreshToken,
		"refresh_expires_at": result.Tokens.RefreshExpiresAt,
	})
	return http.StatusOK, ""
}

func (s *Server) handleSetupPassword2FA(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	provisioning, err := s.auth.SetupPassword2FA(r.Context(), current, s.authAuditContext(r, reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, serializeAuthTOTP(provisioning))
	return http.StatusOK, ""
}

func (s *Server) handleConfirmPassword2FA(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body totpCodeRequest
	if err := decodeJSONBody(r, &body); err != nil || body.TOTPCode == "" {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	if err := s.auth.ConfirmPassword2FA(r.Context(), current, body.TOTPCode, s.authAuditContext(r, reqctx)); err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"password_2fa_enabled": true})
	return http.StatusOK, ""
}

func (s *Server) handleDisablePassword2FA(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body disable2FARequest
	if err := decodeJSONBody(r, &body); err != nil || (body.Password == "" && body.TOTPCode == "") {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	if err := s.auth.DisablePassword2FA(r.Context(), current, body.Password, body.TOTPCode, s.authAuditContext(r, reqctx)); err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, ""
}

func (s *Server) handleStartOIDCLogin(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	result, err := s.auth.StartOIDCLogin(r.Context(), r.URL.Query().Get("return_url"), s.authAuditContext(r, reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	w.Header().Set("Location", result.AuthorizationURL)
	w.WriteHeader(http.StatusFound)
	return http.StatusFound, ""
}

func (s *Server) handleCompleteOIDCCallback(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	result, err := s.auth.CompleteOIDCCallback(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state"), s.authAuditContext(r, reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	w.Header().Set("Location", result.RedirectURL)
	w.WriteHeader(http.StatusFound)
	return http.StatusFound, ""
}

func (s *Server) handleOIDCHandoff(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	var body handoffRequest
	if err := decodeJSONBody(r, &body); err != nil || body.HandoffID == "" {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	result, err := s.auth.ExchangeOIDCHandoff(r.Context(), body.HandoffID, s.authAuditContext(r, reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"user":               serializeUser(result.User),
		"access_token":       result.Tokens.AccessToken,
		"access_expires_at":  result.Tokens.AccessExpiresAt,
		"refresh_token":      result.Tokens.RefreshToken,
		"refresh_expires_at": result.Tokens.RefreshExpiresAt,
	})
	return http.StatusOK, ""
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	if token, ok := authorizationBearer(r); ok && strings.HasPrefix(token, auth.UserRefreshTokenPrefix) {
		return writeIdentityError(w, auth.ErrRefreshTokenNotAllowed)
	}
	var body refreshRequest
	if err := decodeJSONBody(r, &body); err != nil || body.RefreshToken == "" {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	result, err := s.auth.Refresh(r.Context(), body.RefreshToken, s.authAuditContext(r, reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, apiTokens{
		AccessToken:      result.Tokens.AccessToken,
		AccessExpiresAt:  result.Tokens.AccessExpiresAt,
		RefreshToken:     result.Tokens.RefreshToken,
		RefreshExpiresAt: result.Tokens.RefreshExpiresAt,
	})
	return http.StatusOK, ""
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	if err := s.auth.Logout(r.Context(), current, s.authAuditContext(r, reqctx)); err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, ""
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	token, err := requiredBearerToken(r)
	if err != nil {
		return writeIdentityError(w, err)
	}
	if strings.HasPrefix(token, appdomain.ApplicationTokenPrefix) {
		current, status, code, ok := s.authenticateApplication(w, r, reqctx)
		if !ok {
			return status, code
		}
		noStoreHeaders(w.Header())
		writeJSON(w, http.StatusOK, map[string]any{
			"identity_type": "application",
			"identity": map[string]any{
				"id":           current.Application.ID,
				"name":         current.Application.Name,
				"display_name": current.Application.DisplayName,
				"status":       string(current.Application.Status),
			},
		})
		return http.StatusOK, ""
	}
	if s.auth == nil {
		return writeIdentityError(w, auth.ErrIdentityServiceUnavailable)
	}
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"identity_type": "user",
		"identity": map[string]any{
			"id":                           current.User.ID,
			"email":                        current.User.Email,
			"display_name":                 current.User.DisplayName,
			"password_login_enabled":       current.User.PasswordHash != nil,
			"password_2fa_enabled":         current.User.Password2FAEnabled,
			"password_2fa_disable_allowed": current.User.PasswordHash == nil || !s.cfg.Auth.Password.TwoFARequired,
			"global_role":                  string(current.User.GlobalRole),
			"status":                       string(current.User.Status),
		},
	})
	return http.StatusOK, ""
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, _ RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseListUsersParams(r)
	if err != nil {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	result, err := s.users.ListUsers(r.Context(), userActor(current), params)
	if err != nil {
		return writeIdentityError(w, err)
	}
	out := make([]apiUser, 0, len(result.Users))
	for _, user := range result.Users {
		out = append(out, serializeUser(user))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{
		"users": out,
		"pagination": map[string]any{
			"limit":  result.Limit,
			"offset": result.Offset,
			"total":  result.Total,
		},
	})
	return http.StatusOK, ""
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body userCreateRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Email == "" || body.DisplayName == "" {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	params := userdomain.CreateUserServiceParams{
		Email:                body.Email,
		DisplayName:          body.DisplayName,
		GlobalRole:           userdomain.GlobalRole(body.GlobalRole),
		Status:               userdomain.Status(body.Status),
		Password:             body.Password,
		ProvisionPassword2FA: body.ProvisionPassword2FA,
	}
	result, err := s.users.CreateUser(r.Context(), userActor(current), params, s.userAuditContext(reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	response := map[string]any{"user": serializeUser(result.User)}
	if result.Password2FA != nil {
		response["password_2fa"] = serializeUserTOTP(*result.Password2FA)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, response)
	return http.StatusCreated, ""
}

func (s *Server) handleLookupUser(w http.ResponseWriter, r *http.Request, _ RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	email := r.URL.Query().Get("email")
	if _, err := storage.NormalizeEmail(email); err != nil {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	var appID *string
	if raw := r.URL.Query().Get("application_id"); raw != "" {
		appID = &raw
	}
	result, err := s.users.LookupUser(r.Context(), userActor(current), email, appID)
	if err != nil {
		return writeIdentityError(w, err)
	}
	user := map[string]any{
		"id":              result.User.ID,
		"email":           result.User.Email,
		"display_name":    result.User.DisplayName,
		"status":          string(result.User.Status),
		"already_granted": result.AlreadyGranted,
	}
	if result.GrantRole != nil {
		user["grant_role"] = *result.GrantRole
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
	return http.StatusOK, ""
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, _ RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	id, ok := userIDFromPath(r.URL.Path)
	if !ok {
		return writeIdentityError(w, userdomain.ErrNotFound)
	}
	user, err := s.users.GetUser(r.Context(), userActor(current), id)
	if err != nil {
		return writeIdentityError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"user": serializeUser(user)})
	return http.StatusOK, ""
}

func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	id, ok := userIDFromPath(r.URL.Path)
	if !ok {
		return writeIdentityError(w, userdomain.ErrNotFound)
	}
	params, err := decodeUserPatch(r)
	if err != nil {
		return writeIdentityError(w, userdomain.ErrInvalidRequest)
	}
	result, err := s.users.UpdateUser(r.Context(), userActor(current), id, params, s.userAuditContext(reqctx))
	if err != nil {
		return writeIdentityError(w, err)
	}
	response := map[string]any{"user": serializeUser(result.User)}
	if result.Password2FA != nil {
		response["password_2fa"] = serializeUserTOTP(*result.Password2FA)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, response)
	return http.StatusOK, ""
}

func (s *Server) authenticateUser(w http.ResponseWriter, r *http.Request) (auth.AuthenticatedUser, int, string, bool) {
	if s.auth == nil {
		status, code := writeIdentityError(w, auth.ErrIdentityServiceUnavailable)
		return auth.AuthenticatedUser{}, status, code, false
	}
	token, err := requiredBearerToken(r)
	if err != nil {
		status, code := writeIdentityError(w, err)
		return auth.AuthenticatedUser{}, status, code, false
	}
	current, err := s.auth.ValidateUserAccessToken(r.Context(), token)
	if err != nil {
		status, code := writeIdentityError(w, err)
		return auth.AuthenticatedUser{}, status, code, false
	}
	return current, http.StatusOK, "", true
}

func writeIdentityError(w http.ResponseWriter, err error) (int, string) {
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "Internal server error."
	retryAfter := 0
	switch {
	case errors.Is(err, auth.ErrIdentityServiceUnavailable), errors.Is(err, userdomain.ErrUserServiceUnavailable):
		status, code, message = http.StatusServiceUnavailable, "service_unavailable", "Backend is not ready."
	case errors.Is(err, auth.ErrInvalidToken):
		status, code, message = http.StatusUnauthorized, "invalid_token", "Authentication token is missing, invalid, or expired."
	case errors.Is(err, auth.ErrRefreshTokenNotAllowed):
		status, code, message = http.StatusForbidden, "refresh_token_not_allowed", "Refresh tokens are accepted only by the refresh endpoint."
	case errors.Is(err, auth.ErrUserTokenRequired):
		status, code, message = http.StatusForbidden, "user_token_required", "A User access token is required."
	case errors.Is(err, auth.ErrInvalidCredentials):
		status, code, message = http.StatusUnauthorized, "invalid_credentials", "Credentials are invalid."
	case errors.Is(err, auth.ErrInvalid2FACode):
		status, code, message = http.StatusUnauthorized, "invalid_2fa_code", "Authentication code is invalid."
	case errors.Is(err, auth.ErrPasswordAuthDisabled):
		status, code, message = http.StatusForbidden, "password_auth_disabled", "Password authentication is disabled."
	case errors.Is(err, auth.ErrPassword2FARequired), errors.Is(err, userdomain.ErrPassword2FARequired):
		status, code, message = http.StatusForbidden, "password_2fa_required", "Password 2FA is required."
	case errors.Is(err, auth.ErrInvalidRefreshToken):
		status, code, message = http.StatusUnauthorized, "invalid_refresh_token", "Refresh token is invalid."
	case errors.Is(err, auth.ErrSessionExpired):
		status, code, message = http.StatusUnauthorized, "session_expired", "Session expired."
	case errors.Is(err, auth.ErrUserDisabled):
		status, code, message = http.StatusForbidden, "user_disabled", "User is disabled."
	case errors.Is(err, auth.ErrOIDCDisabled):
		status, code, message = http.StatusForbidden, "oidc_auth_failed", "OIDC authentication is disabled."
	case errors.Is(err, auth.ErrOIDCValidationFailed):
		status, code, message = http.StatusUnauthorized, "oidc_auth_failed", "OIDC callback validation failed."
	case errors.Is(err, auth.ErrOIDCUserNotProvisioned):
		status, code, message = http.StatusForbidden, "user_not_provisioned", "User is not provisioned."
	case errors.Is(err, auth.ErrConflict), errors.Is(err, userdomain.ErrConflict):
		status, code, message = http.StatusConflict, "conflict", "Resource state conflicts with this request."
		retryAfter = 1
	case errors.Is(err, auth.ErrNotFound), errors.Is(err, userdomain.ErrNotFound):
		status, code, message = http.StatusNotFound, "certificate_not_found", "Resource does not exist or is not visible."
	case errors.Is(err, auth.ErrForbidden), errors.Is(err, userdomain.ErrForbidden):
		status, code, message = http.StatusForbidden, "application_access_denied", "The authenticated identity is not allowed to access this resource."
	case errors.Is(err, userdomain.ErrInvalidRequest):
		status, code, message = http.StatusBadRequest, "invalid_request", "Request body or query parameters are invalid."
	}
	return writeError(w, status, Error{Code: code, Message: message, Retryable: status == http.StatusServiceUnavailable, RetryAfterSeconds: retryAfter, Details: map[string]any{}})
}

func decodeJSONBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return io.EOF
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("body must contain one JSON value")
	}
	return nil
}

func decodeUserPatch(r *http.Request) (userdomain.UpdateUserServiceParams, error) {
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil {
		return userdomain.UpdateUserServiceParams{}, err
	}
	if len(raw) == 0 {
		return userdomain.UpdateUserServiceParams{}, errors.New("empty patch")
	}
	allowed := map[string]bool{
		"display_name":           true,
		"global_role":            true,
		"status":                 true,
		"password":               true,
		"provision_password_2fa": true,
		"reset_password_2fa":     true,
	}
	var out userdomain.UpdateUserServiceParams
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
			out.DisplayName = &v
		case "global_role":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			role := userdomain.GlobalRole(v)
			out.GlobalRole = &role
		case "status":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			status := userdomain.Status(v)
			out.Status = &status
		case "password":
			out.PasswordSet = true
			if string(value) != "null" {
				var v string
				if err := json.Unmarshal(value, &v); err != nil {
					return out, err
				}
				out.Password = &v
			}
		case "provision_password_2fa":
			if err := json.Unmarshal(value, &out.ProvisionPassword2FA); err != nil {
				return out, err
			}
		case "reset_password_2fa":
			if err := json.Unmarshal(value, &out.ResetPassword2FA); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func parseListUsersParams(r *http.Request) (userdomain.ListUsersParams, error) {
	query := r.URL.Query()
	limit, err := parseIntQuery(query.Get("limit"))
	if err != nil {
		return userdomain.ListUsersParams{}, err
	}
	offset, err := parseIntQuery(query.Get("offset"))
	if err != nil {
		return userdomain.ListUsersParams{}, err
	}
	params := userdomain.ListUsersParams{
		ListOptions: storage.ListOptions{Limit: limit, Offset: offset},
		Search:      query.Get("search"),
	}
	if raw := query.Get("status"); raw != "" {
		status := userdomain.Status(raw)
		params.Status = &status
	}
	if raw := query.Get("global_role"); raw != "" {
		role := userdomain.GlobalRole(raw)
		params.GlobalRole = &role
	}
	return params, nil
}

func parseIntQuery(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func requiredBearerToken(r *http.Request) (string, error) {
	token, ok := authorizationBearer(r)
	if !ok {
		return "", auth.ErrInvalidToken
	}
	return token, nil
}

func authorizationBearer(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return "", false
	}
	parts := strings.Fields(raw)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

func (s *Server) authAuditContext(r *http.Request, reqctx RequestContext) auth.AuditContext {
	return auth.AuditContext{
		CorrelationID: reqctx.RequestID,
		SourceIP:      sourceIPString(reqctx),
		UserAgent:     safeUserAgent(r.UserAgent()),
	}
}

func (s *Server) userAuditContext(reqctx RequestContext) userdomain.AuditContext {
	return userdomain.AuditContext{CorrelationID: reqctx.RequestID, SourceIP: sourceIPString(reqctx)}
}

func safeUserAgent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			continue
		}
		if b.Len() >= 1024 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func userActor(current auth.AuthenticatedUser) userdomain.Actor {
	return userdomain.Actor{ID: current.User.ID, GlobalRole: current.User.GlobalRole}
}

func userIDFromPath(p string) (string, bool) {
	id := strings.TrimPrefix(p, "/v1/users/")
	if id == "" || strings.Contains(id, "/") || id == "lookup" {
		return "", false
	}
	return id, true
}

func serializeUser(user userdomain.User) apiUser {
	return apiUser{
		ID:                    user.ID,
		Email:                 user.Email,
		DisplayName:           user.DisplayName,
		PasswordLoginEnabled:  user.PasswordHash != nil,
		Password2FAEnabled:    user.Password2FAEnabled,
		OIDCLinked:            user.OIDCIssuer != nil && user.OIDCSubject != nil,
		GlobalRole:            string(user.GlobalRole),
		Status:                string(user.Status),
		ApplicationGrantCount: user.ApplicationGrantCount,
		CreatedAt:             user.CreatedAt,
		UpdatedAt:             user.UpdatedAt,
		LastLoginAt:           user.LastLoginAt,
	}
}

func serializeAuthTOTP(value auth.TOTPProvisioning) apiTOTPProvisioning {
	return apiTOTPProvisioning{
		Issuer:          value.Issuer,
		AccountLabel:    value.AccountLabel,
		Secret:          value.Secret,
		ProvisioningURI: value.ProvisioningURI,
	}
}

func serializeUserTOTP(value userdomain.TOTPProvisioning) apiTOTPProvisioning {
	return apiTOTPProvisioning{
		Issuer:          value.Issuer,
		AccountLabel:    value.AccountLabel,
		Secret:          value.Secret,
		ProvisioningURI: value.ProvisioningURI,
	}
}
