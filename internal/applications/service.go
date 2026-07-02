package applications

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

const (
	ApplicationTokenPrefix = "cth_app_v1_"
	tokenSecretBytes       = 32
)

var (
	ErrApplicationServiceUnavailable = errors.New("application service unavailable")
	ErrInvalidToken                  = errors.New("invalid token")
	ErrApplicationTokenRequired      = errors.New("application token required")
	ErrSourceIPDenied                = errors.New("application source ip denied")
	ErrForbidden                     = errors.New("forbidden")
	ErrNotFound                      = errors.New("not found")
	ErrConflict                      = errors.New("conflict")
	ErrInvalidRequest                = errors.New("invalid request")
	ErrSystemManagedResource         = errors.New("system managed resource")
)

type Store interface {
	Create(context.Context, CreateApplicationParams) (Application, error)
	Get(context.Context, string) (Application, error)
	List(context.Context, ListApplicationsParams) ([]Application, error)
	Count(context.Context, ListApplicationsParams) (int64, error)
	ListVisible(context.Context, string, ListApplicationsParams) ([]Application, error)
	CountVisible(context.Context, string, ListApplicationsParams) (int64, error)
	ListAccessibleApplicationIDs(context.Context, string) ([]string, error)
	Update(context.Context, string, UpdateApplicationParams) (Application, error)
	CreateToken(context.Context, CreateTokenParams) (ApplicationToken, error)
	LookupTokenByHash(context.Context, string) (TokenIdentity, error)
	MarkTokenUsed(context.Context, string) error
	ListTokens(context.Context, string, ListTokensParams) ([]ApplicationToken, error)
	CountTokens(context.Context, string, ListTokensParams) (int64, error)
	RevokeToken(context.Context, string, string) (bool, error)
	AddDomainScope(context.Context, AddDomainScopeParams) (DomainScope, error)
	ListDomainScopes(context.Context, string, storage.ListOptions) ([]DomainScope, error)
	CountDomainScopes(context.Context, string, storage.ListOptions) (int64, error)
	DeleteDomainScope(context.Context, string, string) (bool, error)
	UpsertGrant(context.Context, UpsertGrantParams) (UserGrant, error)
	ListGrants(context.Context, string, storage.ListOptions) ([]UserGrant, error)
	CountGrants(context.Context, string, storage.ListOptions) (int64, error)
	GetGrant(context.Context, string, string) (UserGrant, error)
	DeleteGrant(context.Context, string, string) (bool, error)
}

type UserReader interface {
	Get(context.Context, string) (users.User, error)
}

type AuditRepository interface {
	Append(context.Context, audit.AppendEventParams) (audit.Event, error)
}

type Service struct {
	repo      Store
	userRepo  UserReader
	auditRepo AuditRepository
	keys      *security.KeySet
	cfg       config.ApplicationTokenConfig
	tx        storage.Beginner
}

type ServiceConfig struct {
	Repository      Store
	UserRepository  UserReader
	AuditRepository AuditRepository
	KeySet          *security.KeySet
	Config          config.ApplicationTokenConfig
	Storage         storage.Beginner
}

type Actor struct {
	ID         string
	GlobalRole users.GlobalRole
}

type AuditContext struct {
	CorrelationID string
	SourceIP      string
}

type AuthenticatedApplication struct {
	Application Application
	Token       ApplicationToken
}

type ApplicationWithRole struct {
	Application Application
	CurrentRole string
}

type ListApplicationsResult struct {
	Applications []ApplicationWithRole
	Limit        int
	Offset       int
	Total        int64
}

type CreateTokenServiceParams struct {
	Name         string
	ExpiresAtSet bool
	ExpiresAt    *time.Time
}

type CreateTokenResult struct {
	Token      ApplicationToken
	TokenValue string
}

type ListTokensResult struct {
	Tokens []ApplicationToken
	Limit  int
	Offset int
	Total  int64
}

type ListDomainScopesResult struct {
	DomainScopes []DomainScope
	Limit        int
	Offset       int
	Total        int64
}

type GrantWithUser struct {
	Grant UserGrant
	User  users.User
}

type UpsertGrantResult struct {
	Grant   GrantWithUser
	Created bool
}

type ListGrantsResult struct {
	Grants []GrantWithUser
	Limit  int
	Offset int
	Total  int64
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{
		repo:      cfg.Repository,
		userRepo:  cfg.UserRepository,
		auditRepo: cfg.AuditRepository,
		keys:      cfg.KeySet,
		cfg:       cfg.Config,
		tx:        cfg.Storage,
	}
}

func (s *Service) ValidateApplicationToken(ctx context.Context, token string, sourceIP netip.Addr) (AuthenticatedApplication, error) {
	if err := s.ready(); err != nil {
		return AuthenticatedApplication{}, err
	}
	if err := validatePresentedApplicationToken(token); err != nil {
		return AuthenticatedApplication{}, err
	}
	identity, err := s.repo.LookupTokenByHash(ctx, s.keys.HashToken(token))
	if err != nil {
		return AuthenticatedApplication{}, ErrInvalidToken
	}
	now := time.Now().UTC()
	if identity.Token.Status != TokenStatusActive || (identity.Token.ExpiresAt != nil && !identity.Token.ExpiresAt.After(now)) {
		return AuthenticatedApplication{}, ErrInvalidToken
	}
	if identity.Application.Status != StatusActive {
		return AuthenticatedApplication{}, ErrInvalidToken
	}
	if !trustedSourceAllowed(identity.Application.TrustedSourceCIDRs, sourceIP) {
		return AuthenticatedApplication{}, ErrSourceIPDenied
	}
	if err := s.repo.MarkTokenUsed(ctx, identity.Token.ID); err != nil {
		return AuthenticatedApplication{}, err
	}
	return AuthenticatedApplication{Application: identity.Application, Token: identity.Token}, nil
}

func (s *Service) ListApplications(ctx context.Context, actor Actor, params ListApplicationsParams) (ListApplicationsResult, error) {
	if err := s.ready(); err != nil {
		return ListApplicationsResult{}, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListApplicationsResult{}, ErrInvalidRequest
	}
	params.ListOptions = opts
	var apps []Application
	var total int64
	if actor.admin() {
		apps, err = s.repo.List(ctx, params)
		if err == nil {
			total, err = s.repo.Count(ctx, params)
		}
	} else {
		apps, err = s.repo.ListVisible(ctx, actor.ID, params)
		if err == nil {
			total, err = s.repo.CountVisible(ctx, actor.ID, params)
		}
	}
	if err != nil {
		return ListApplicationsResult{}, classifyReadError(err)
	}
	out := make([]ApplicationWithRole, 0, len(apps))
	for _, app := range apps {
		role := string(users.GlobalRoleAdmin)
		if !actor.admin() {
			grant, err := s.repo.GetGrant(ctx, app.ID, actor.ID)
			if err != nil {
				return ListApplicationsResult{}, classifyReadError(err)
			}
			role = string(grant.Role)
		}
		out = append(out, ApplicationWithRole{Application: app, CurrentRole: role})
	}
	return ListApplicationsResult{Applications: out, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) CreateApplication(ctx context.Context, actor Actor, params CreateApplicationParams, auditCtx AuditContext) (ApplicationWithRole, error) {
	var result ApplicationWithRole
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.createApplication(ctx, actor, params, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) createApplication(ctx context.Context, actor Actor, params CreateApplicationParams, auditCtx AuditContext) (ApplicationWithRole, error) {
	if err := s.ready(); err != nil {
		return ApplicationWithRole{}, err
	}
	if !actor.admin() {
		return ApplicationWithRole{}, ErrForbidden
	}
	app, err := s.repo.Create(ctx, params)
	if err != nil {
		return ApplicationWithRole{}, classifyWriteError(err)
	}
	if err := s.auditApplicationEvent(ctx, actor.ID, "application_created", "application", &app.ID, app.ID, auditCtx, map[string]any{
		"name":   app.Name,
		"status": string(app.Status),
	}); err != nil {
		return ApplicationWithRole{}, err
	}
	return ApplicationWithRole{Application: app, CurrentRole: string(users.GlobalRoleAdmin)}, nil
}

func (s *Service) GetApplication(ctx context.Context, actor Actor, applicationID string) (ApplicationWithRole, error) {
	if err := s.ready(); err != nil {
		return ApplicationWithRole{}, err
	}
	app, err := s.repo.Get(ctx, applicationID)
	if err != nil {
		return ApplicationWithRole{}, ErrNotFound
	}
	role, err := s.roleForApplication(ctx, actor, app.ID)
	if err != nil {
		return ApplicationWithRole{}, err
	}
	return ApplicationWithRole{Application: app, CurrentRole: role}, nil
}

func (s *Service) UpdateApplication(ctx context.Context, actor Actor, applicationID string, params UpdateApplicationParams, auditCtx AuditContext) (ApplicationWithRole, error) {
	var result ApplicationWithRole
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.updateApplication(ctx, actor, applicationID, params, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) updateApplication(ctx context.Context, actor Actor, applicationID string, params UpdateApplicationParams, auditCtx AuditContext) (ApplicationWithRole, error) {
	if err := s.ready(); err != nil {
		return ApplicationWithRole{}, err
	}
	if !actor.admin() {
		return ApplicationWithRole{}, ErrForbidden
	}
	app, err := s.repo.Get(ctx, applicationID)
	if err != nil {
		return ApplicationWithRole{}, ErrNotFound
	}
	if app.systemManaged() {
		return ApplicationWithRole{}, ErrSystemManagedResource
	}
	updated, err := s.repo.Update(ctx, applicationID, params)
	if err != nil {
		return ApplicationWithRole{}, classifyWriteError(err)
	}
	if err := s.auditApplicationEvent(ctx, actor.ID, "application_updated", "application", &updated.ID, updated.ID, auditCtx, map[string]any{
		"name":   updated.Name,
		"status": string(updated.Status),
	}); err != nil {
		return ApplicationWithRole{}, err
	}
	return ApplicationWithRole{Application: updated, CurrentRole: string(users.GlobalRoleAdmin)}, nil
}

func (s *Service) ListTokens(ctx context.Context, actor Actor, applicationID string, params ListTokensParams) (ListTokensResult, error) {
	if err := s.ready(); err != nil {
		return ListTokensResult{}, err
	}
	if err := s.requireManager(ctx, actor, applicationID); err != nil {
		return ListTokensResult{}, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListTokensResult{}, ErrInvalidRequest
	}
	params.ListOptions = opts
	tokens, err := s.repo.ListTokens(ctx, applicationID, params)
	if err != nil {
		return ListTokensResult{}, classifyReadError(err)
	}
	total, err := s.repo.CountTokens(ctx, applicationID, params)
	if err != nil {
		return ListTokensResult{}, classifyReadError(err)
	}
	return ListTokensResult{Tokens: tokens, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) CreateToken(ctx context.Context, actor Actor, applicationID string, params CreateTokenServiceParams, auditCtx AuditContext) (CreateTokenResult, error) {
	var result CreateTokenResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.createToken(ctx, actor, applicationID, params, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) createToken(ctx context.Context, actor Actor, applicationID string, params CreateTokenServiceParams, auditCtx AuditContext) (CreateTokenResult, error) {
	if err := s.ready(); err != nil {
		return CreateTokenResult{}, err
	}
	app, err := s.requireMutableManager(ctx, actor, applicationID)
	if err != nil {
		return CreateTokenResult{}, err
	}
	expiresAt, err := s.resolveTokenExpiry(params)
	if err != nil {
		return CreateTokenResult{}, err
	}
	tokenValue, err := randomApplicationToken()
	if err != nil {
		return CreateTokenResult{}, err
	}
	token, err := s.repo.CreateToken(ctx, CreateTokenParams{
		ApplicationID: applicationID,
		Name:          params.Name,
		TokenHash:     s.keys.HashToken(tokenValue),
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		return CreateTokenResult{}, classifyWriteError(err)
	}
	if err := s.auditApplicationEvent(ctx, actor.ID, "application_token_created", "application_token", &token.ID, app.ID, auditCtx, map[string]any{
		"application_id": app.ID,
		"name":           token.Name,
		"expires_at":     token.ExpiresAt,
	}); err != nil {
		return CreateTokenResult{}, err
	}
	return CreateTokenResult{Token: token, TokenValue: tokenValue}, nil
}

func (s *Service) RevokeToken(ctx context.Context, actor Actor, applicationID, tokenID string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.revokeToken(ctx, actor, applicationID, tokenID, auditCtx)
	})
}

func (s *Service) revokeToken(ctx context.Context, actor Actor, applicationID, tokenID string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	app, err := s.requireMutableManager(ctx, actor, applicationID)
	if err != nil {
		return err
	}
	revoked, err := s.repo.RevokeToken(ctx, applicationID, tokenID)
	if err != nil {
		return classifyWriteError(err)
	}
	if !revoked {
		return ErrNotFound
	}
	return s.auditApplicationEvent(ctx, actor.ID, "application_token_revoked", "application_token", &tokenID, app.ID, auditCtx, map[string]any{
		"application_id": app.ID,
	})
}

func (s *Service) ListDomainScopes(ctx context.Context, actor Actor, applicationID string, opts storage.ListOptions) (ListDomainScopesResult, error) {
	if err := s.ready(); err != nil {
		return ListDomainScopesResult{}, err
	}
	if err := s.requireManager(ctx, actor, applicationID); err != nil {
		return ListDomainScopesResult{}, err
	}
	normalized, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return ListDomainScopesResult{}, ErrInvalidRequest
	}
	scopes, err := s.repo.ListDomainScopes(ctx, applicationID, normalized)
	if err != nil {
		return ListDomainScopesResult{}, classifyReadError(err)
	}
	total, err := s.repo.CountDomainScopes(ctx, applicationID, normalized)
	if err != nil {
		return ListDomainScopesResult{}, classifyReadError(err)
	}
	return ListDomainScopesResult{DomainScopes: scopes, Limit: normalized.Limit, Offset: normalized.Offset, Total: total}, nil
}

func (s *Service) CreateDomainScope(ctx context.Context, actor Actor, applicationID, value string, auditCtx AuditContext) (DomainScope, error) {
	var result DomainScope
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.createDomainScope(ctx, actor, applicationID, value, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) createDomainScope(ctx context.Context, actor Actor, applicationID, value string, auditCtx AuditContext) (DomainScope, error) {
	if err := s.ready(); err != nil {
		return DomainScope{}, err
	}
	app, err := s.requireMutableManager(ctx, actor, applicationID)
	if err != nil {
		return DomainScope{}, err
	}
	scope, err := s.repo.AddDomainScope(ctx, AddDomainScopeParams{
		ApplicationID:   applicationID,
		Value:           value,
		CreatedByUserID: &actor.ID,
	})
	if err != nil {
		return DomainScope{}, classifyWriteError(err)
	}
	if err := s.auditApplicationEvent(ctx, actor.ID, "domain_scope_created", "domain_scope", &scope.ID, app.ID, auditCtx, map[string]any{
		"application_id": app.ID,
		"value":          scope.Value,
		"kind":           string(scope.Kind),
	}); err != nil {
		return DomainScope{}, err
	}
	return scope, nil
}

func (s *Service) DeleteDomainScope(ctx context.Context, actor Actor, applicationID, scopeID string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.deleteDomainScope(ctx, actor, applicationID, scopeID, auditCtx)
	})
}

func (s *Service) deleteDomainScope(ctx context.Context, actor Actor, applicationID, scopeID string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	app, err := s.requireMutableManager(ctx, actor, applicationID)
	if err != nil {
		return err
	}
	deleted, err := s.repo.DeleteDomainScope(ctx, applicationID, scopeID)
	if err != nil {
		return classifyWriteError(err)
	}
	if !deleted {
		return ErrNotFound
	}
	return s.auditApplicationEvent(ctx, actor.ID, "domain_scope_deleted", "domain_scope", &scopeID, app.ID, auditCtx, map[string]any{
		"application_id": app.ID,
	})
}

func (s *Service) ListGrants(ctx context.Context, actor Actor, applicationID string, opts storage.ListOptions) (ListGrantsResult, error) {
	if err := s.ready(); err != nil {
		return ListGrantsResult{}, err
	}
	if err := s.requireManager(ctx, actor, applicationID); err != nil {
		return ListGrantsResult{}, err
	}
	normalized, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return ListGrantsResult{}, ErrInvalidRequest
	}
	grants, err := s.repo.ListGrants(ctx, applicationID, normalized)
	if err != nil {
		return ListGrantsResult{}, classifyReadError(err)
	}
	total, err := s.repo.CountGrants(ctx, applicationID, normalized)
	if err != nil {
		return ListGrantsResult{}, classifyReadError(err)
	}
	withUsers, err := s.attachUsers(ctx, grants)
	if err != nil {
		return ListGrantsResult{}, err
	}
	return ListGrantsResult{Grants: withUsers, Limit: normalized.Limit, Offset: normalized.Offset, Total: total}, nil
}

func (s *Service) UpsertGrant(ctx context.Context, actor Actor, applicationID, userID string, role GrantRole, auditCtx AuditContext) (UpsertGrantResult, error) {
	var result UpsertGrantResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.upsertGrant(ctx, actor, applicationID, userID, role, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) upsertGrant(ctx context.Context, actor Actor, applicationID, userID string, role GrantRole, auditCtx AuditContext) (UpsertGrantResult, error) {
	if err := s.ready(); err != nil {
		return UpsertGrantResult{}, err
	}
	app, err := s.requireMutableManager(ctx, actor, applicationID)
	if err != nil {
		return UpsertGrantResult{}, err
	}
	user, err := s.userByID(ctx, userID)
	if err != nil {
		return UpsertGrantResult{}, err
	}
	created := false
	if _, err := s.repo.GetGrant(ctx, applicationID, userID); err != nil {
		if !errors.Is(err, storage.ErrNoRows) {
			classified := classifyReadError(err)
			if !errors.Is(classified, ErrNotFound) {
				return UpsertGrantResult{}, classified
			}
		}
		created = true
	}
	grant, err := s.repo.UpsertGrant(ctx, UpsertGrantParams{
		ApplicationID:   applicationID,
		UserID:          userID,
		Role:            role,
		CreatedByUserID: &actor.ID,
	})
	if err != nil {
		return UpsertGrantResult{}, classifyWriteError(err)
	}
	if err := s.auditApplicationEvent(ctx, actor.ID, "application_access_granted", "application_access", &grant.ID, app.ID, auditCtx, map[string]any{
		"application_id": app.ID,
		"user_id":        userID,
		"role":           string(grant.Role),
	}); err != nil {
		return UpsertGrantResult{}, err
	}
	return UpsertGrantResult{Grant: GrantWithUser{Grant: grant, User: user}, Created: created}, nil
}

func (s *Service) DeleteGrant(ctx context.Context, actor Actor, applicationID, userID string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.deleteGrant(ctx, actor, applicationID, userID, auditCtx)
	})
}

func (s *Service) deleteGrant(ctx context.Context, actor Actor, applicationID, userID string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	app, err := s.requireMutableManager(ctx, actor, applicationID)
	if err != nil {
		return err
	}
	grant, err := s.repo.GetGrant(ctx, applicationID, userID)
	if err != nil {
		classified := classifyReadError(err)
		if errors.Is(classified, ErrNotFound) {
			return nil
		}
		return classified
	}
	deleted, err := s.repo.DeleteGrant(ctx, applicationID, userID)
	if err != nil {
		return classifyWriteError(err)
	}
	if !deleted {
		return ErrNotFound
	}
	return s.auditApplicationEvent(ctx, actor.ID, "application_access_revoked", "application_access", &grant.ID, app.ID, auditCtx, map[string]any{
		"application_id": app.ID,
		"user_id":        userID,
		"role":           string(grant.Role),
	})
}

func (s *Service) withWriteTx(ctx context.Context, fn func(*Service) error) error {
	if s.tx == nil {
		return fn(s)
	}
	return storage.WithTx(ctx, s.tx, func(ctx context.Context, tx storage.Tx) error {
		txsvc := *s
		txsvc.repo = NewRepository(tx)
		txsvc.userRepo = users.NewRepository(tx)
		txsvc.auditRepo = audit.NewRepository(tx)
		txsvc.tx = nil
		return fn(&txsvc)
	})
}

func (s *Service) CanManageApplication(ctx context.Context, applicationID, userID string) error {
	if err := s.ready(); err != nil {
		return err
	}
	grant, err := s.repo.GetGrant(ctx, applicationID, userID)
	if err != nil {
		return ErrForbidden
	}
	if grant.Role != GrantRoleManager {
		return ErrForbidden
	}
	return nil
}

func (s *Service) LookupUserGrant(ctx context.Context, applicationID, userID string) (users.LookupGrant, error) {
	if err := s.ready(); err != nil {
		return users.LookupGrant{}, err
	}
	grant, err := s.repo.GetGrant(ctx, applicationID, userID)
	if err != nil {
		return users.LookupGrant{AlreadyGranted: false}, users.ErrNotFound
	}
	role := string(grant.Role)
	return users.LookupGrant{AlreadyGranted: true, Role: &role}, nil
}

func (s *Service) ListAccessibleApplicationIDs(ctx context.Context, userID string) ([]string, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.repo.ListAccessibleApplicationIDs(ctx, userID)
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil || s.auditRepo == nil || s.keys == nil {
		return ErrApplicationServiceUnavailable
	}
	return nil
}

func (s *Service) requireMutableManager(ctx context.Context, actor Actor, applicationID string) (Application, error) {
	app, err := s.repo.Get(ctx, applicationID)
	if err != nil {
		return Application{}, ErrNotFound
	}
	if app.systemManaged() {
		return Application{}, ErrSystemManagedResource
	}
	if actor.admin() {
		return app, nil
	}
	grant, err := s.repo.GetGrant(ctx, applicationID, actor.ID)
	if err != nil {
		return Application{}, ErrForbidden
	}
	if grant.Role != GrantRoleManager {
		return Application{}, ErrForbidden
	}
	return app, nil
}

func (s *Service) requireManager(ctx context.Context, actor Actor, applicationID string) error {
	if _, err := s.repo.Get(ctx, applicationID); err != nil {
		return ErrNotFound
	}
	if actor.admin() {
		return nil
	}
	grant, err := s.repo.GetGrant(ctx, applicationID, actor.ID)
	if err != nil {
		return ErrForbidden
	}
	if grant.Role != GrantRoleManager {
		return ErrForbidden
	}
	return nil
}

func (s *Service) roleForApplication(ctx context.Context, actor Actor, applicationID string) (string, error) {
	if actor.admin() {
		return string(users.GlobalRoleAdmin), nil
	}
	grant, err := s.repo.GetGrant(ctx, applicationID, actor.ID)
	if err != nil {
		return "", ErrForbidden
	}
	return string(grant.Role), nil
}

func (s *Service) resolveTokenExpiry(params CreateTokenServiceParams) (*time.Time, error) {
	now := time.Now().UTC()
	if !params.ExpiresAtSet {
		expires := now.Add(time.Duration(s.cfg.DefaultTTLSeconds) * time.Second)
		return &expires, nil
	}
	if params.ExpiresAt == nil {
		return nil, nil
	}
	if !params.ExpiresAt.After(now) {
		return nil, ErrInvalidRequest
	}
	maxExpires := now.Add(time.Duration(s.cfg.MaxTTLSeconds) * time.Second)
	if params.ExpiresAt.After(maxExpires) {
		return nil, ErrInvalidRequest
	}
	return params.ExpiresAt, nil
}

func (s *Service) attachUsers(ctx context.Context, grants []UserGrant) ([]GrantWithUser, error) {
	out := make([]GrantWithUser, 0, len(grants))
	for _, grant := range grants {
		user, err := s.userByID(ctx, grant.UserID)
		if err != nil {
			return nil, err
		}
		out = append(out, GrantWithUser{Grant: grant, User: user})
	}
	return out, nil
}

func (s *Service) userByID(ctx context.Context, id string) (users.User, error) {
	if s.userRepo == nil {
		return users.User{}, ErrApplicationServiceUnavailable
	}
	user, err := s.userRepo.Get(ctx, id)
	if err != nil {
		return users.User{}, ErrNotFound
	}
	return user, nil
}

func (s *Service) auditApplicationEvent(ctx context.Context, actorID, action, targetType string, targetID *string, applicationID string, auditCtx AuditContext, metadata map[string]any) error {
	_, err := s.auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:       audit.IdentityTypeUser,
		IdentityID:         &actorID,
		Action:             action,
		TargetType:         targetType,
		TargetID:           targetID,
		ScopeApplicationID: &applicationID,
		Result:             audit.ResultSuccess,
		CorrelationID:      optionalString(auditCtx.CorrelationID),
		SourceIP:           optionalString(auditCtx.SourceIP),
		Metadata:           metadataJSON(metadata),
	})
	return err
}

func (a Actor) admin() bool {
	return a.GlobalRole == users.GlobalRoleAdmin
}

func (a Application) systemManaged() bool {
	return a.SystemKind != nil && *a.SystemKind == SystemKindCerthubServer
}

func validatePresentedApplicationToken(token string) error {
	switch {
	case strings.HasPrefix(token, ApplicationTokenPrefix):
		if len(token) != len(ApplicationTokenPrefix)+43 {
			return ErrInvalidToken
		}
		return nil
	case strings.HasPrefix(token, auth.UserAccessTokenPrefix):
		return ErrApplicationTokenRequired
	default:
		return ErrInvalidToken
	}
}

func trustedSourceAllowed(cidrs []string, sourceIP netip.Addr) bool {
	if len(cidrs) == 0 {
		return true
	}
	if !sourceIP.IsValid() {
		return false
	}
	for _, value := range cidrs {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(sourceIP) {
			return true
		}
	}
	return false
}

func randomApplicationToken() (string, error) {
	buf := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return ApplicationTokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func classifyReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNoRows) {
		return ErrNotFound
	}
	if !strings.Contains(err.Error(), "postgresql") {
		return ErrInvalidRequest
	}
	return err
}

func classifyWriteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNoRows) {
		return ErrNotFound
	}
	if strings.Contains(err.Error(), "SQLSTATE 23505") || strings.Contains(err.Error(), "constraint violation") {
		return ErrConflict
	}
	if strings.Contains(err.Error(), "SQLSTATE 23503") {
		return ErrNotFound
	}
	if !strings.Contains(err.Error(), "postgresql") {
		return ErrInvalidRequest
	}
	return err
}

func metadataJSON(metadata map[string]any) json.RawMessage {
	if metadata == nil {
		return json.RawMessage(`{}`)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
