package issuers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/torob/certhub/internal/acme"
	"github.com/torob/certhub/internal/audit"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

var (
	ErrIssuerServiceUnavailable = errors.New("issuer service unavailable")
	ErrForbidden                = errors.New("forbidden")
	ErrNotFound                 = errors.New("not found")
	ErrConflict                 = errors.New("conflict")
	ErrInvalidRequest           = errors.New("invalid request")
	ErrUpstreamDependency       = errors.New("upstream dependency failed")
)

type Store interface {
	Create(context.Context, CreateIssuerParams) (Issuer, error)
	Get(context.Context, string) (Issuer, error)
	List(context.Context, ListIssuersParams) ([]Issuer, error)
	Count(context.Context, ListIssuersParams) (int64, error)
	Update(context.Context, string, UpdateIssuerParams) (Issuer, error)
	EnsureACMEAccount(context.Context, CreateACMEAccountParams) (ACMEAccount, error)
}

type AuditRepository interface {
	Append(context.Context, audit.AppendEventParams) (audit.Event, error)
}

type Actor struct {
	ID         string
	GlobalRole users.GlobalRole
	System     bool
}

type AuditContext struct {
	CorrelationID string
	SourceIP      string
	Command       string
}

type ServiceConfig struct {
	Repository       Store
	AuditRepository  AuditRepository
	AccountRegistrar acme.AccountRegistrar
	KeySet           *security.KeySet
	Storage          storage.Beginner
}

type Service struct {
	repo      Store
	auditRepo AuditRepository
	accounts  acme.AccountRegistrar
	keys      *security.KeySet
	tx        storage.Beginner
}

type ListIssuersResult struct {
	Issuers []Issuer
	Limit   int
	Offset  int
	Total   int64
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{repo: cfg.Repository, auditRepo: cfg.AuditRepository, accounts: cfg.AccountRegistrar, keys: cfg.KeySet, tx: cfg.Storage}
}

func (s *Service) ListIssuers(ctx context.Context, actor Actor, params ListIssuersParams) (ListIssuersResult, error) {
	if err := s.ready(); err != nil {
		return ListIssuersResult{}, err
	}
	if !actor.admin() {
		return ListIssuersResult{}, ErrForbidden
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListIssuersResult{}, ErrInvalidRequest
	}
	params.ListOptions = opts
	items, err := s.repo.List(ctx, params)
	if err != nil {
		return ListIssuersResult{}, classifyReadError(err)
	}
	total, err := s.repo.Count(ctx, params)
	if err != nil {
		return ListIssuersResult{}, classifyReadError(err)
	}
	return ListIssuersResult{Issuers: items, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) GetIssuer(ctx context.Context, actor Actor, id string) (Issuer, error) {
	if err := s.ready(); err != nil {
		return Issuer{}, err
	}
	if !actor.admin() {
		return Issuer{}, ErrForbidden
	}
	issuer, err := s.repo.Get(ctx, id)
	if err != nil {
		return Issuer{}, classifyReadError(err)
	}
	return issuer, nil
}

func (s *Service) CreateIssuer(ctx context.Context, actor Actor, params CreateIssuerParams, auditCtx AuditContext) (Issuer, error) {
	var result Issuer
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		issuer, err := txsvc.createIssuer(ctx, actor, params, auditCtx)
		if err == nil {
			result = issuer
		}
		return err
	})
	return result, err
}

func (s *Service) createIssuer(ctx context.Context, actor Actor, params CreateIssuerParams, auditCtx AuditContext) (Issuer, error) {
	if err := s.ready(); err != nil {
		return Issuer{}, err
	}
	if s.accounts == nil || s.keys == nil {
		return Issuer{}, ErrIssuerServiceUnavailable
	}
	if !actor.admin() {
		return Issuer{}, ErrForbidden
	}
	requestedStatus := params.Status
	requestedDefault := params.IsDefault
	if requestedStatus != "" {
		if err := validateStatus(requestedStatus); err != nil {
			return Issuer{}, ErrInvalidRequest
		}
	}
	params.Status = StatusDisabled
	params.IsDefault = false
	issuer, err := s.repo.Create(ctx, params)
	if err != nil {
		return Issuer{}, classifyWriteError(err)
	}
	reg, err := s.accounts.RegisterOrReuseAccount(ctx, acme.AccountRegistrationParams{
		DirectoryURL: issuer.DirectoryURL,
		Email:        issuer.ContactEmail,
	})
	if err != nil {
		return Issuer{}, ErrUpstreamDependency
	}
	accountID, err := storage.NewUUID()
	if err != nil {
		return Issuer{}, err
	}
	encrypted, err := s.keys.SealDatabaseValue(reg.PrivateKeyPEM, acmeAccountPrivateKeyAAD(accountID))
	if err != nil {
		return Issuer{}, err
	}
	if _, err := s.repo.EnsureACMEAccount(ctx, CreateACMEAccountParams{
		ID:                     accountID,
		IssuerID:               issuer.ID,
		Email:                  issuer.ContactEmail,
		AccountURL:             reg.AccountURL,
		PrivateKeyPEMEncrypted: encrypted,
		Status:                 ACMEAccountStatusActive,
	}); err != nil {
		return Issuer{}, classifyWriteError(err)
	}
	update := UpdateIssuerParams{IsDefault: storage.SetBool(requestedDefault)}
	if requestedStatus != "" {
		update.Status = storage.SetString(string(requestedStatus))
	}
	if requestedStatus == "" {
		update.Status = storage.SetString(string(StatusActive))
	}
	issuer, err = s.repo.Update(ctx, issuer.ID, update)
	if err != nil {
		return Issuer{}, classifyWriteError(err)
	}
	if err := s.auditIssuerEvent(ctx, actor, "issuer_created", &issuer.ID, auditCtx, map[string]any{
		"name":        issuer.Name,
		"type":        string(issuer.Type),
		"environment": string(issuer.Environment),
		"default":     issuer.IsDefault,
		"status":      string(issuer.Status),
	}); err != nil {
		return Issuer{}, err
	}
	return issuer, nil
}

func (s *Service) UpdateIssuer(ctx context.Context, actor Actor, id string, params UpdateIssuerParams, auditCtx AuditContext) (Issuer, error) {
	var result Issuer
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		issuer, err := txsvc.updateIssuer(ctx, actor, id, params, auditCtx)
		if err == nil {
			result = issuer
		}
		return err
	})
	return result, err
}

func (s *Service) updateIssuer(ctx context.Context, actor Actor, id string, params UpdateIssuerParams, auditCtx AuditContext) (Issuer, error) {
	if err := s.ready(); err != nil {
		return Issuer{}, err
	}
	if !actor.admin() {
		return Issuer{}, ErrForbidden
	}
	issuer, err := s.repo.Update(ctx, id, params)
	if err != nil {
		return Issuer{}, classifyWriteError(err)
	}
	if err := s.auditIssuerEvent(ctx, actor, "issuer_updated", &issuer.ID, auditCtx, map[string]any{
		"name":    issuer.Name,
		"default": issuer.IsDefault,
		"status":  string(issuer.Status),
	}); err != nil {
		return Issuer{}, err
	}
	return issuer, nil
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil {
		return ErrIssuerServiceUnavailable
	}
	return nil
}

func (s *Service) withWriteTx(ctx context.Context, fn func(*Service) error) error {
	if s.tx == nil {
		return fn(s)
	}
	return storage.WithTx(ctx, s.tx, func(ctx context.Context, tx storage.Tx) error {
		txsvc := *s
		txsvc.repo = NewRepository(tx)
		if s.auditRepo != nil {
			txsvc.auditRepo = audit.NewRepository(tx)
		}
		return fn(&txsvc)
	})
}

func (s *Service) auditIssuerEvent(ctx context.Context, actor Actor, action string, targetID *string, auditCtx AuditContext, metadata map[string]any) error {
	if s.auditRepo == nil {
		return nil
	}
	metadata = auditMetadataWithCommand(metadata, auditCtx.Command)
	identityType := audit.IdentityTypeUser
	var identityID *string
	if actor.System {
		identityType = audit.IdentityTypeSystem
	} else {
		identityID = &actor.ID
	}
	_, err := s.auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:  identityType,
		IdentityID:    identityID,
		Action:        action,
		TargetType:    "issuer",
		TargetID:      targetID,
		Result:        audit.ResultSuccess,
		CorrelationID: optionalString(auditCtx.CorrelationID),
		SourceIP:      optionalString(auditCtx.SourceIP),
		Metadata:      metadataJSON(metadata),
	})
	return err
}

func auditMetadataWithCommand(metadata map[string]any, command string) map[string]any {
	if command == "" {
		return metadata
	}
	out := map[string]any{}
	for key, value := range metadata {
		out[key] = value
	}
	out["command"] = command
	return out
}

func (a Actor) admin() bool {
	return a.System || a.GlobalRole == users.GlobalRoleAdmin
}

func acmeAccountPrivateKeyAAD(accountID string) string {
	return "v1:table=acme_accounts:column=private_key_pem:row_id=" + accountID
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
	if strings.Contains(err.Error(), "active ACME account") {
		return ErrConflict
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
