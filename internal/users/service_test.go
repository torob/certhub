package users

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
)

func TestCreateUserRequiresProvisioningWhenPassword2FARequired(t *testing.T) {
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}, UserAccessTokenTTLSeconds: 300, UserSessionTTLSeconds: 3600},
	})
	password := "correct horse battery staple"
	_, err := service.CreateUser(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: GlobalRoleAdmin}, CreateUserServiceParams{
		Email:       "user@example.com",
		DisplayName: "User Name",
		Password:    &password,
	}, AuditContext{})
	if !errors.Is(err, ErrPassword2FARequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateUserRequiresPasswordUnlessOIDCEnabled(t *testing.T) {
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}},
	})
	_, err := service.CreateUser(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: GlobalRoleAdmin}, CreateUserServiceParams{
		Email:       "user@example.com",
		DisplayName: "User Name",
	}, AuditContext{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateUserAllowsPasswordlessUserWhenOIDCEnabled(t *testing.T) {
	store := &serviceFakeStore{}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{OIDC: config.OIDCConfig{Enabled: true}},
	})
	result, err := service.CreateUser(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: GlobalRoleAdmin}, CreateUserServiceParams{
		Email:       "user@example.com",
		DisplayName: "User Name",
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.Email != "user@example.com" || store.created.PasswordHash != nil || store.created.OIDCIssuer != nil || store.created.OIDCSubject != nil {
		t.Fatalf("passwordless OIDC-provisioned user = result %#v created %#v", result.User, store.created)
	}
}

func TestCreateUserInviteReturnsOneTimeLinkAndStoresHash(t *testing.T) {
	store := &serviceFakeStore{}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true}, UserInviteTTLSeconds: 3600},
	})
	result, err := service.CreateUserInvite(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: GlobalRoleAdmin}, CreateUserInviteServiceParams{
		Email:      "Invitee@Example.COM",
		GlobalRole: GlobalRoleAdmin,
		InviteURL:  func(token string) string { return "https://certhub.example/signup?invite=" + token },
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Invite.Email != "invitee@example.com" || result.Invite.GlobalRole != GlobalRoleAdmin {
		t.Fatalf("invite = %#v", result.Invite)
	}
	if !strings.Contains(result.InviteURL, "cth_inv_v1_") {
		t.Fatalf("invite url = %q", result.InviteURL)
	}
	if store.createdInvite.TokenHash == "" || strings.Contains(result.InviteURL, store.createdInvite.TokenHash) {
		t.Fatalf("token hash leaked or missing: url=%q hash=%q", result.InviteURL, store.createdInvite.TokenHash)
	}
}

func TestSignupUserInviteWithoutForced2FAConsumesInvite(t *testing.T) {
	token := "cth_inv_v1_" + strings.Repeat("A", 43)
	keys := serviceTestKeySet(t)
	store := &serviceFakeStore{invite: UserInvite{
		ID:              "22345678-1234-4234-9234-123456789abc",
		Email:           "invitee@example.com",
		GlobalRole:      GlobalRoleUser,
		Status:          "active",
		TokenHash:       keys.HashToken(token),
		CreatedByUserID: "12345678-1234-4234-9234-123456789abc",
	}}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: &serviceFakeAudit{},
		KeySet:          keys,
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: false}},
	})
	result, err := service.SignupUserInvite(context.Background(), token, SignupUserInviteParams{
		DisplayName: "Invitee User",
		Password:    "correct horse battery staple",
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.User == nil {
		t.Fatalf("result = %#v", result)
	}
	if store.created.Email != "invitee@example.com" || store.created.PasswordHash == nil || *store.created.PasswordHash == "correct horse battery staple" {
		t.Fatalf("created = %#v", store.created)
	}
	if store.consumedTokenHash != keys.HashToken(token) {
		t.Fatalf("consumed token hash = %q", store.consumedTokenHash)
	}
}

func TestSignupUserInviteForced2FARequiresVerifiedCode(t *testing.T) {
	token := "cth_inv_v1_" + strings.Repeat("B", 43)
	keys := serviceTestKeySet(t)
	store := &serviceFakeStore{invite: UserInvite{
		ID:              "22345678-1234-4234-9234-123456789abc",
		Email:           "invitee@example.com",
		GlobalRole:      GlobalRoleUser,
		Status:          "active",
		TokenHash:       keys.HashToken(token),
		CreatedByUserID: "12345678-1234-4234-9234-123456789abc",
	}}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: &serviceFakeAudit{},
		KeySet:          keys,
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}},
	})
	start, err := service.SignupUserInvite(context.Background(), token, SignupUserInviteParams{
		DisplayName: "Invitee User",
		Password:    "correct horse battery staple",
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if start.Status != "password_2fa_required" || start.Password2FA == nil || !strings.HasPrefix(start.Password2FA.ProvisioningURI, "otpauth://totp/") {
		t.Fatalf("start = %#v", start)
	}
	if _, err := service.ConfirmUserInvite2FA(context.Background(), token, "000000", AuditContext{}); !errors.Is(err, ErrInvalid2FACode) {
		t.Fatalf("wrong code err = %v", err)
	}
	code := generateUserTOTP(start.Password2FA.Secret, time.Now().UTC().Unix()/userTOTPPeriodSecond, userTOTPDigits)
	done, err := service.ConfirmUserInvite2FA(context.Background(), token, code, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "completed" || store.created.TOTPSecretEncrypted == nil || !store.created.Password2FAEnabled {
		t.Fatalf("done = %#v created = %#v", done, store.created)
	}
}

func TestLookupUserNonAdminRequiresApplicationManagerGrant(t *testing.T) {
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}, UserAccessTokenTTLSeconds: 300, UserSessionTTLSeconds: 3600},
	})
	appID := "22345678-1234-4234-9234-123456789abc"
	_, err := service.LookupUser(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: GlobalRoleUser}, "user@example.com", &appID)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupUserNonAdminManagerCanLookupActiveUserForApplication(t *testing.T) {
	user := User{
		ID:          "32345678-1234-4234-9234-123456789abc",
		Email:       "user@example.com",
		DisplayName: "User Name",
		Status:      StatusActive,
	}
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{lookupUser: user},
		AuditRepository: &serviceFakeAudit{},
		GrantReader:     serviceFakeGrantReader{canManage: true, role: "manager"},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}, UserAccessTokenTTLSeconds: 300, UserSessionTTLSeconds: 3600},
	})
	appID := "22345678-1234-4234-9234-123456789abc"
	result, err := service.LookupUser(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: GlobalRoleUser}, "user@example.com", &appID)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.ID != user.ID || !result.AlreadyGranted || result.GrantRole == nil || *result.GrantRole != "manager" {
		t.Fatalf("result = %#v", result)
	}
}

func TestBootstrapCreateAdminRejectsExistingActiveAdminUnlessAllowed(t *testing.T) {
	password := "correct horse battery staple"
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{count: 1},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}},
	})
	_, err := service.BootstrapCreateAdmin(context.Background(), BootstrapCreateAdminParams{
		Email:       "admin@example.com",
		DisplayName: "Admin User",
		Password:    &password,
	}, AuditContext{})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapCreateAdminRequiresPasswordUnlessOIDCEnabled(t *testing.T) {
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}},
	})
	_, err := service.BootstrapCreateAdmin(context.Background(), BootstrapCreateAdminParams{
		Email:       "admin@example.com",
		DisplayName: "Admin User",
	}, AuditContext{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapCreateAdminAllowsPasswordlessAdminWhenOIDCEnabled(t *testing.T) {
	store := &serviceFakeStore{}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{OIDC: config.OIDCConfig{Enabled: true}},
	})
	result, err := service.BootstrapCreateAdmin(context.Background(), BootstrapCreateAdminParams{
		Email:       "admin@example.com",
		DisplayName: "Admin User",
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.GlobalRole != GlobalRoleAdmin || result.User.Status != StatusActive || store.created.PasswordHash != nil || store.created.OIDCIssuer != nil || store.created.OIDCSubject != nil {
		t.Fatalf("passwordless OIDC-provisioned admin = result %#v created %#v", result.User, store.created)
	}
}

func TestBootstrapCreateAdminCreatesSystemAuditAndTOTPProvisioning(t *testing.T) {
	password := "correct horse battery staple"
	store := &serviceFakeStore{}
	auditRepo := &serviceFakeAudit{}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: auditRepo,
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}},
	})
	result, err := service.BootstrapCreateAdmin(context.Background(), BootstrapCreateAdminParams{
		Email:       "Admin@Example.COM",
		DisplayName: "Admin User",
		Password:    &password,
	}, AuditContext{CorrelationID: "bootstrap-test", Command: "certhub-server bootstrap create-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.GlobalRole != GlobalRoleAdmin || result.User.Status != StatusActive || result.User.Email != "admin@example.com" {
		t.Fatalf("user = %#v", result.User)
	}
	if result.Password2FA == nil || !strings.HasPrefix(result.Password2FA.ProvisioningURI, "otpauth://totp/") {
		t.Fatalf("provisioning = %#v", result.Password2FA)
	}
	if store.created.PasswordHash == nil || *store.created.PasswordHash == password {
		t.Fatalf("password was not hashed: %#v", store.created.PasswordHash)
	}
	if !store.created.Password2FAEnabled || store.created.TOTPSecretEncrypted == nil {
		t.Fatalf("2fa fields not stored: %#v", store.created)
	}
	if auditRepo.event.IdentityType != audit.IdentityTypeSystem || auditRepo.event.Action != "bootstrap_admin_created" || auditRepo.event.TargetID == nil || *auditRepo.event.TargetID != result.User.ID {
		t.Fatalf("audit event = %#v", auditRepo.event)
	}
	var metadata map[string]any
	if err := json.Unmarshal(auditRepo.event.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["command"] != "certhub-server bootstrap create-admin" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if strings.Contains(string(auditRepo.event.Metadata), result.Password2FA.Secret) || strings.Contains(string(auditRepo.event.Metadata), password) {
		t.Fatalf("audit metadata leaked bootstrap secret: %s", auditRepo.event.Metadata)
	}
}

func TestBootstrapCreateAdminConfirmationRunsBeforeCreate(t *testing.T) {
	password := "correct horse battery staple"
	store := &serviceFakeStore{}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}},
	})
	var sawProvisioning bool
	_, err := service.BootstrapCreateAdmin(context.Background(), BootstrapCreateAdminParams{
		Email:       "admin@example.com",
		DisplayName: "Admin User",
		Password:    &password,
		ConfirmPassword2FA: func(p TOTPProvisioning) (string, error) {
			sawProvisioning = strings.HasPrefix(p.ProvisioningURI, "otpauth://totp/")
			return "000000", nil
		},
	}, AuditContext{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err = %v", err)
	}
	if !sawProvisioning {
		t.Fatalf("confirmation hook did not receive provisioning")
	}
	if store.created.Email != "" {
		t.Fatalf("user was created before successful TOTP confirmation: %#v", store.created)
	}
}

type serviceFakeStore struct {
	lookupUser        User
	invite            UserInvite
	count             int64
	created           CreateUserParams
	createdInvite     CreateUserInviteParams
	pendingInvite     SetInvitePendingSignupParams
	consumedTokenHash string
}

func (s *serviceFakeStore) Create(_ context.Context, params CreateUserParams) (User, error) {
	s.created = params
	return User{
		ID:                  params.ID,
		Email:               strings.ToLower(params.Email),
		DisplayName:         params.DisplayName,
		PasswordHash:        params.PasswordHash,
		Password2FAEnabled:  params.Password2FAEnabled,
		TOTPSecretEncrypted: params.TOTPSecretEncrypted,
		OIDCIssuer:          params.OIDCIssuer,
		OIDCSubject:         params.OIDCSubject,
		GlobalRole:          params.GlobalRole,
		Status:              params.Status,
	}, nil
}

func (s *serviceFakeStore) List(context.Context, ListUsersParams) ([]User, error) {
	return nil, errors.New("not implemented")
}

func (s *serviceFakeStore) Count(context.Context, ListUsersParams) (int64, error) {
	return s.count, nil
}

func (s *serviceFakeStore) Get(context.Context, string) (User, error) {
	return User{}, errors.New("not implemented")
}

func (s *serviceFakeStore) Update(context.Context, string, UpdateUserParams) (User, error) {
	return User{}, errors.New("not implemented")
}

func (s *serviceFakeStore) LookupActiveByNormalizedEmail(context.Context, string) (User, error) {
	if s.lookupUser.ID != "" {
		return s.lookupUser, nil
	}
	return User{}, errors.New("not implemented")
}

func (s *serviceFakeStore) CreateInvite(_ context.Context, params CreateUserInviteParams) (UserInvite, error) {
	s.createdInvite = params
	return UserInvite{
		ID:              params.ID,
		Email:           strings.ToLower(params.Email),
		GlobalRole:      params.GlobalRole,
		TokenHash:       params.TokenHash,
		Status:          "active",
		CreatedByUserID: params.CreatedByUserID,
		ExpiresAt:       params.ExpiresAt,
	}, nil
}

func (s *serviceFakeStore) LookupActiveInviteByEmail(context.Context, string) (UserInvite, error) {
	return UserInvite{}, errors.New("not implemented")
}

func (s *serviceFakeStore) GetActiveInviteByTokenHash(context.Context, string) (UserInvite, error) {
	if s.invite.ID != "" {
		return s.invite, nil
	}
	return UserInvite{}, errors.New("not implemented")
}

func (s *serviceFakeStore) SetInvitePendingSignup(_ context.Context, params SetInvitePendingSignupParams) (UserInvite, error) {
	s.pendingInvite = params
	s.invite.PendingUserID = &params.PendingUserID
	s.invite.PendingDisplayName = &params.PendingDisplayName
	s.invite.PendingPasswordHash = &params.PendingPasswordHash
	s.invite.PendingTOTPSecretEncrypted = &params.PendingTOTPSecretEncrypted
	return s.invite, nil
}

func (s *serviceFakeStore) ConsumeInvite(_ context.Context, tokenHash, createdUserID string) (UserInvite, error) {
	s.consumedTokenHash = tokenHash
	s.invite.Status = "consumed"
	s.invite.CreatedUserID = &createdUserID
	return s.invite, nil
}

type serviceFakeAudit struct {
	event audit.AppendEventParams
}

func (s *serviceFakeAudit) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	s.event = params
	return audit.Event{}, nil
}

type serviceFakeGrantReader struct {
	canManage bool
	role      string
}

func (f serviceFakeGrantReader) CanManageApplication(context.Context, string, string) error {
	if !f.canManage {
		return ErrForbidden
	}
	return nil
}

func (f serviceFakeGrantReader) LookupUserGrant(context.Context, string, string) (LookupGrant, error) {
	if f.role == "" {
		return LookupGrant{}, ErrNotFound
	}
	role := f.role
	return LookupGrant{AlreadyGranted: true, Role: &role}, nil
}

func serviceTestKeySet(t *testing.T) *security.KeySet {
	t.Helper()
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
