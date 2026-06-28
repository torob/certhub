package users

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
)

func TestCreateUserRequiresProvisioningWhenPassword2FARequired(t *testing.T) {
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}, UserAccessTokenTTLSeconds: 300, UserRefreshTokenTTLSeconds: 3600},
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

func TestLookupUserNonAdminRequiresApplicationManagerGrant(t *testing.T) {
	service := NewService(ServiceConfig{
		Repository:      &serviceFakeStore{},
		AuditRepository: &serviceFakeAudit{},
		KeySet:          serviceTestKeySet(t),
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}, UserAccessTokenTTLSeconds: 300, UserRefreshTokenTTLSeconds: 3600},
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
		Config:          config.AuthConfig{Password: config.PasswordConfig{Enabled: true, TwoFARequired: true}, UserAccessTokenTTLSeconds: 300, UserRefreshTokenTTLSeconds: 3600},
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
	lookupUser User
	count      int64
	created    CreateUserParams
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
