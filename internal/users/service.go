package users

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
)

const (
	userTOTPSecretBytes  = 20
	userTOTPIssuer       = "Certhub"
	userTOTPDigits       = 6
	userTOTPPeriodSecond = 30
)

var (
	ErrForbidden              = errors.New("forbidden")
	ErrNotFound               = errors.New("not found")
	ErrConflict               = errors.New("conflict")
	ErrInvalidRequest         = errors.New("invalid request")
	ErrPassword2FARequired    = errors.New("password 2fa required")
	ErrUserServiceUnavailable = errors.New("user service unavailable")
)

type AuditRepository interface {
	Append(context.Context, audit.AppendEventParams) (audit.Event, error)
}

type Store interface {
	Create(context.Context, CreateUserParams) (User, error)
	List(context.Context, ListUsersParams) ([]User, error)
	Count(context.Context, ListUsersParams) (int64, error)
	Get(context.Context, string) (User, error)
	Update(context.Context, string, UpdateUserParams) (User, error)
	LookupActiveByNormalizedEmail(context.Context, string) (User, error)
}

type GrantLookupReader interface {
	CanManageApplication(context.Context, string, string) error
	LookupUserGrant(context.Context, string, string) (LookupGrant, error)
}

type LookupGrant struct {
	AlreadyGranted bool
	Role           *string
}

type Service struct {
	repo        Store
	auditRepo   AuditRepository
	grantReader GrantLookupReader
	keys        *security.KeySet
	cfg         config.AuthConfig
	tx          storage.Beginner
}

type ServiceConfig struct {
	Repository      Store
	AuditRepository AuditRepository
	GrantReader     GrantLookupReader
	KeySet          *security.KeySet
	Config          config.AuthConfig
	Storage         storage.Beginner
}

type Actor struct {
	ID         string
	GlobalRole GlobalRole
}

type AuditContext struct {
	CorrelationID string
	SourceIP      string
	Command       string
}

type TOTPProvisioning struct {
	Issuer          string
	AccountLabel    string
	Secret          string
	ProvisioningURI string
}

type CreateUserServiceParams struct {
	Email                string
	DisplayName          string
	GlobalRole           GlobalRole
	Status               Status
	Password             *string
	ProvisionPassword2FA bool
	OIDCIssuer           *string
	OIDCSubject          *string
}

type CreateUserResult struct {
	User        User
	Password2FA *TOTPProvisioning
}

type BootstrapCreateAdminParams struct {
	Email              string
	DisplayName        string
	Password           *string
	OIDCIssuer         *string
	OIDCSubject        *string
	AllowExistingAdmin bool
	ConfirmPassword2FA func(TOTPProvisioning) (string, error)
}

type UpdateUserServiceParams struct {
	DisplayName          *string
	GlobalRole           *GlobalRole
	Status               *Status
	PasswordSet          bool
	Password             *string
	ProvisionPassword2FA bool
	ResetPassword2FA     bool
	OIDCSet              bool
	OIDCIssuer           *string
	OIDCSubject          *string
}

type UpdateUserResult struct {
	User        User
	Password2FA *TOTPProvisioning
}

type ListUsersResult struct {
	Users  []User
	Limit  int
	Offset int
	Total  int64
}

type LookupUserResult struct {
	User           User
	AlreadyGranted bool
	GrantRole      *string
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{
		repo:        cfg.Repository,
		auditRepo:   cfg.AuditRepository,
		grantReader: cfg.GrantReader,
		keys:        cfg.KeySet,
		cfg:         cfg.Config,
		tx:          cfg.Storage,
	}
}

func (s *Service) CreateUser(ctx context.Context, actor Actor, params CreateUserServiceParams, auditCtx AuditContext) (CreateUserResult, error) {
	var result CreateUserResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.createUser(ctx, actor, params, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) createUser(ctx context.Context, actor Actor, params CreateUserServiceParams, auditCtx AuditContext) (CreateUserResult, error) {
	if err := s.ready(); err != nil {
		return CreateUserResult{}, err
	}
	if !actor.admin() {
		return CreateUserResult{}, ErrForbidden
	}
	normalizedEmail, err := storage.NormalizeEmail(params.Email)
	if err != nil {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if err := storage.ValidateHumanString(params.DisplayName, "display_name", 1, 255); err != nil {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if params.GlobalRole != "" && params.GlobalRole != GlobalRoleUser && params.GlobalRole != GlobalRoleAdmin {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if params.Status != "" && params.Status != StatusActive && params.Status != StatusDisabled {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if (params.OIDCIssuer == nil) != (params.OIDCSubject == nil) {
		return CreateUserResult{}, ErrInvalidRequest
	}
	create := CreateUserParams{
		Email:       params.Email,
		DisplayName: params.DisplayName,
		GlobalRole:  params.GlobalRole,
		Status:      params.Status,
		OIDCIssuer:  params.OIDCIssuer,
		OIDCSubject: params.OIDCSubject,
	}
	var provisioning *TOTPProvisioning
	if params.Password != nil {
		if err := security.ValidatePasswordPolicy(*params.Password, normalizedEmail); err != nil {
			return CreateUserResult{}, ErrInvalidRequest
		}
		if s.cfg.Password.TwoFARequired && !params.ProvisionPassword2FA {
			return CreateUserResult{}, ErrPassword2FARequired
		}
		hash, err := security.HashPassword(*params.Password)
		if err != nil {
			return CreateUserResult{}, err
		}
		create.PasswordHash = &hash
		if params.ProvisionPassword2FA {
			id, err := storage.NewUUID()
			if err != nil {
				return CreateUserResult{}, err
			}
			create.ID = id
			p, encrypted, err := s.newTOTPProvisioning(create.ID, normalizedEmail)
			if err != nil {
				return CreateUserResult{}, err
			}
			create.Password2FAEnabled = true
			create.TOTPSecretEncrypted = &encrypted
			provisioning = &p
		}
	}
	user, err := s.repo.Create(ctx, create)
	if err != nil {
		return CreateUserResult{}, classifyWriteError(err)
	}
	if err := s.auditUserEvent(ctx, actor.ID, "user_created", &user.ID, auditCtx, map[string]any{"global_role": string(user.GlobalRole), "status": string(user.Status)}); err != nil {
		return CreateUserResult{}, err
	}
	if provisioning != nil {
		if err := s.auditUserEvent(ctx, actor.ID, "password_2fa_enabled", &user.ID, auditCtx, map[string]any{"provisioned_by_admin": true}); err != nil {
			return CreateUserResult{}, err
		}
	}
	return CreateUserResult{User: user, Password2FA: provisioning}, nil
}

func (s *Service) BootstrapCreateAdmin(ctx context.Context, params BootstrapCreateAdminParams, auditCtx AuditContext) (CreateUserResult, error) {
	var result CreateUserResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.bootstrapCreateAdmin(ctx, params, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) bootstrapCreateAdmin(ctx context.Context, params BootstrapCreateAdminParams, auditCtx AuditContext) (CreateUserResult, error) {
	if err := s.ready(); err != nil {
		return CreateUserResult{}, err
	}
	if params.Password == nil && params.OIDCIssuer == nil {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if !params.AllowExistingAdmin {
		status := StatusActive
		role := GlobalRoleAdmin
		count, err := s.repo.Count(ctx, ListUsersParams{Status: &status, GlobalRole: &role})
		if err != nil {
			return CreateUserResult{}, classifyWriteError(err)
		}
		if count > 0 {
			return CreateUserResult{}, ErrConflict
		}
	}
	normalizedEmail, err := storage.NormalizeEmail(params.Email)
	if err != nil {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if err := storage.ValidateHumanString(params.DisplayName, "display_name", 1, 255); err != nil {
		return CreateUserResult{}, ErrInvalidRequest
	}
	if (params.OIDCIssuer == nil) != (params.OIDCSubject == nil) {
		return CreateUserResult{}, ErrInvalidRequest
	}
	create := CreateUserParams{
		Email:       params.Email,
		DisplayName: params.DisplayName,
		GlobalRole:  GlobalRoleAdmin,
		Status:      StatusActive,
		OIDCIssuer:  params.OIDCIssuer,
		OIDCSubject: params.OIDCSubject,
	}
	var provisioning *TOTPProvisioning
	if params.Password != nil {
		if err := security.ValidatePasswordPolicy(*params.Password, normalizedEmail); err != nil {
			return CreateUserResult{}, ErrInvalidRequest
		}
		hash, err := security.HashPassword(*params.Password)
		if err != nil {
			return CreateUserResult{}, err
		}
		create.PasswordHash = &hash
		if s.cfg.Password.TwoFARequired {
			id, err := storage.NewUUID()
			if err != nil {
				return CreateUserResult{}, err
			}
			create.ID = id
			p, encrypted, err := s.newTOTPProvisioning(create.ID, normalizedEmail)
			if err != nil {
				return CreateUserResult{}, err
			}
			if params.ConfirmPassword2FA != nil {
				code, err := params.ConfirmPassword2FA(p)
				if err != nil {
					return CreateUserResult{}, ErrInvalidRequest
				}
				if !verifyUserTOTP(p.Secret, code, time.Now().UTC()) {
					return CreateUserResult{}, ErrInvalidRequest
				}
			}
			create.Password2FAEnabled = true
			create.TOTPSecretEncrypted = &encrypted
			provisioning = &p
		}
	}
	user, err := s.repo.Create(ctx, create)
	if err != nil {
		return CreateUserResult{}, classifyWriteError(err)
	}
	metadata := map[string]any{
		"email":         user.Email,
		"global_role":   string(user.GlobalRole),
		"status":        string(user.Status),
		"password_auth": params.Password != nil,
		"oidc_link":     params.OIDCIssuer != nil,
		"password_2fa":  provisioning != nil,
	}
	if auditCtx.Command != "" {
		metadata["command"] = auditCtx.Command
	}
	_, err = s.auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:  audit.IdentityTypeSystem,
		Action:        "bootstrap_admin_created",
		TargetType:    "user",
		TargetID:      &user.ID,
		ScopeUserID:   &user.ID,
		Result:        audit.ResultSuccess,
		CorrelationID: optionalString(auditCtx.CorrelationID),
		SourceIP:      optionalString(auditCtx.SourceIP),
		Metadata:      metadataJSON(metadata),
	})
	if err != nil {
		return CreateUserResult{}, err
	}
	return CreateUserResult{User: user, Password2FA: provisioning}, nil
}

func (s *Service) ListUsers(ctx context.Context, actor Actor, params ListUsersParams) (ListUsersResult, error) {
	if err := s.ready(); err != nil {
		return ListUsersResult{}, err
	}
	if !actor.admin() {
		return ListUsersResult{}, ErrForbidden
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListUsersResult{}, err
	}
	params.ListOptions = opts
	users, err := s.repo.List(ctx, params)
	if err != nil {
		return ListUsersResult{}, err
	}
	total, err := s.repo.Count(ctx, params)
	if err != nil {
		return ListUsersResult{}, err
	}
	return ListUsersResult{Users: users, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) GetUser(ctx context.Context, actor Actor, id string) (User, error) {
	if err := s.ready(); err != nil {
		return User{}, err
	}
	if !actor.admin() {
		return User{}, ErrForbidden
	}
	user, err := s.repo.Get(ctx, id)
	if err != nil {
		return User{}, ErrNotFound
	}
	return user, nil
}

func (s *Service) UpdateUser(ctx context.Context, actor Actor, id string, params UpdateUserServiceParams, auditCtx AuditContext) (UpdateUserResult, error) {
	var result UpdateUserResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.updateUser(ctx, actor, id, params, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) updateUser(ctx context.Context, actor Actor, id string, params UpdateUserServiceParams, auditCtx AuditContext) (UpdateUserResult, error) {
	if err := s.ready(); err != nil {
		return UpdateUserResult{}, err
	}
	if !actor.admin() {
		return UpdateUserResult{}, ErrForbidden
	}
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return UpdateUserResult{}, ErrNotFound
	}
	update := UpdateUserParams{}
	if params.DisplayName != nil {
		update.DisplayName = storage.SetString(*params.DisplayName)
	}
	if params.GlobalRole != nil {
		update.GlobalRole = storage.SetString(string(*params.GlobalRole))
	}
	if params.Status != nil {
		update.Status = storage.SetString(string(*params.Status))
	}
	var provisioning *TOTPProvisioning
	passwordWillExist := current.PasswordHash != nil
	if params.PasswordSet {
		if params.Password == nil {
			update.PasswordHash = storage.ClearString()
			passwordWillExist = false
		} else {
			if err := security.ValidatePasswordPolicy(*params.Password, current.Email); err != nil {
				return UpdateUserResult{}, ErrInvalidRequest
			}
			if s.cfg.Password.TwoFARequired && !params.ProvisionPassword2FA {
				return UpdateUserResult{}, ErrPassword2FARequired
			}
			hash, err := security.HashPassword(*params.Password)
			if err != nil {
				return UpdateUserResult{}, err
			}
			update.PasswordHash = storage.SetString(hash)
			passwordWillExist = true
		}
	}
	if params.ResetPassword2FA {
		if s.cfg.Password.TwoFARequired && passwordWillExist {
			return UpdateUserResult{}, ErrPassword2FARequired
		}
		update.Password2FAEnabled = storage.SetBool(false)
		update.TOTPSecretEncrypted = storage.ClearString()
		update.PendingTOTPSecretEncrypted = storage.ClearString()
	}
	if params.ProvisionPassword2FA {
		if !passwordWillExist {
			return UpdateUserResult{}, ErrInvalidRequest
		}
		p, encrypted, err := s.newTOTPProvisioning(id, current.Email)
		if err != nil {
			return UpdateUserResult{}, err
		}
		update.Password2FAEnabled = storage.SetBool(true)
		update.TOTPSecretEncrypted = storage.SetString(encrypted)
		update.PendingTOTPSecretEncrypted = storage.ClearString()
		provisioning = &p
	}
	if params.OIDCSet {
		if (params.OIDCIssuer == nil) != (params.OIDCSubject == nil) {
			return UpdateUserResult{}, ErrInvalidRequest
		}
		if params.OIDCIssuer == nil {
			update.OIDCIssuer = storage.ClearString()
			update.OIDCSubject = storage.ClearString()
		} else {
			update.OIDCIssuer = storage.SetString(*params.OIDCIssuer)
			update.OIDCSubject = storage.SetString(*params.OIDCSubject)
		}
	}
	user, err := s.repo.Update(ctx, id, update)
	if err != nil {
		return UpdateUserResult{}, classifyWriteError(err)
	}
	if err := s.auditUserEvent(ctx, actor.ID, "user_updated", &user.ID, auditCtx, map[string]any{"status": string(user.Status), "global_role": string(user.GlobalRole)}); err != nil {
		return UpdateUserResult{}, err
	}
	if params.ResetPassword2FA || provisioning != nil {
		action := "password_2fa_disabled"
		if provisioning != nil {
			action = "password_2fa_enabled"
		}
		if err := s.auditUserEvent(ctx, actor.ID, action, &user.ID, auditCtx, map[string]any{"provisioned_by_admin": provisioning != nil}); err != nil {
			return UpdateUserResult{}, err
		}
	}
	return UpdateUserResult{User: user, Password2FA: provisioning}, nil
}

func (s *Service) LookupUser(ctx context.Context, actor Actor, email string, applicationID *string) (LookupUserResult, error) {
	if err := s.ready(); err != nil {
		return LookupUserResult{}, err
	}
	if !actor.admin() {
		if applicationID == nil || *applicationID == "" || s.grantReader == nil {
			return LookupUserResult{}, ErrForbidden
		}
		if err := s.grantReader.CanManageApplication(ctx, *applicationID, actor.ID); err != nil {
			return LookupUserResult{}, ErrForbidden
		}
	}
	user, err := s.repo.LookupActiveByNormalizedEmail(ctx, email)
	if err != nil {
		return LookupUserResult{}, ErrNotFound
	}
	result := LookupUserResult{User: user}
	if applicationID != nil && *applicationID != "" && s.grantReader != nil {
		grant, err := s.grantReader.LookupUserGrant(ctx, *applicationID, user.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return LookupUserResult{}, err
		}
		result.AlreadyGranted = grant.AlreadyGranted
		result.GrantRole = grant.Role
	}
	return result, nil
}

func (s *Service) withWriteTx(ctx context.Context, fn func(*Service) error) error {
	if s.tx == nil {
		return fn(s)
	}
	return storage.WithTx(ctx, s.tx, func(ctx context.Context, tx storage.Tx) error {
		txsvc := *s
		txsvc.repo = NewRepository(tx)
		txsvc.auditRepo = audit.NewRepository(tx)
		txsvc.tx = nil
		return fn(&txsvc)
	})
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil || s.auditRepo == nil || s.keys == nil {
		return ErrUserServiceUnavailable
	}
	return nil
}

func (s *Service) newTOTPProvisioning(userID, email string) (TOTPProvisioning, string, error) {
	secret, err := newTOTPSecret()
	if err != nil {
		return TOTPProvisioning{}, "", err
	}
	aad := totpAAD(userID)
	if userID == "" {
		aad = "user:pending-create:totp_secret"
	}
	encrypted, err := s.keys.EncryptTOTPSecret(secret, aad)
	if err != nil {
		return TOTPProvisioning{}, "", err
	}
	provisioning := TOTPProvisioning{
		Issuer:          userTOTPIssuer,
		AccountLabel:    email,
		Secret:          secret,
		ProvisioningURI: userProvisioningURI(userTOTPIssuer, email, secret),
	}
	return provisioning, encrypted, nil
}

func (s *Service) auditUserEvent(ctx context.Context, actorID, action string, targetID *string, auditCtx AuditContext, metadata map[string]any) error {
	_, err := s.auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:  audit.IdentityTypeUser,
		IdentityID:    &actorID,
		Action:        action,
		TargetType:    "user",
		TargetID:      targetID,
		Result:        audit.ResultSuccess,
		CorrelationID: optionalString(auditCtx.CorrelationID),
		SourceIP:      optionalString(auditCtx.SourceIP),
		Metadata:      metadataJSON(metadata),
	})
	return err
}

func (a Actor) admin() bool {
	return a.GlobalRole == GlobalRoleAdmin
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

func newTOTPSecret() (string, error) {
	buf := make([]byte, userTOTPSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func userProvisioningURI(issuer, accountLabel, secret string) string {
	label := url.PathEscape(issuer + ":" + accountLabel)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(userTOTPDigits))
	q.Set("period", strconv.Itoa(userTOTPPeriodSecond))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func totpAAD(userID string) string {
	return "user:" + userID + ":totp_secret"
}

func verifyUserTOTP(secret, code string, now time.Time) bool {
	if len(code) != userTOTPDigits {
		return false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	counter := now.Unix() / userTOTPPeriodSecond
	for skew := -1; skew <= 1; skew++ {
		if generateUserTOTP(secret, counter+int64(skew), userTOTPDigits) == code {
			return true
		}
	}
	return false
}

func generateUserTOTP(secret string, counter int64, digits int) string {
	if counter < 0 || digits <= 0 || digits > 8 {
		return ""
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	modulo := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, binCode%modulo)
}
