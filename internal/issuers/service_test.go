package issuers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"certhub/internal/acme"
	"certhub/internal/audit"
	security "certhub/internal/crypto"
	"certhub/internal/users"
)

func TestCreateIssuerCreatesEncryptedACMEAccountAndAuditsNoSecret(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &issuerServiceStore{now: time.Now().UTC()}
	auditRepo := &issuerAuditStore{}
	service := NewService(ServiceConfig{
		Repository:      store,
		AuditRepository: auditRepo,
		AccountRegistrar: staticRegistrar{
			registration: acme.AccountRegistration{
				AccountURL:    "https://acme.example/acct/123",
				PrivateKeyPEM: []byte("SECRET-PRIVATE-KEY-CANARY"),
			},
		},
		KeySet: keys,
	})
	issuer, err := service.CreateIssuer(context.Background(), Actor{
		ID:         "12345678-1234-4234-9234-123456789abc",
		GlobalRole: users.GlobalRoleAdmin,
	}, CreateIssuerParams{
		Name:         "letsencrypt_staging",
		Type:         TypeACME,
		DirectoryURL: "https://acme.example/directory",
		Environment:  EnvironmentStaging,
		IsDefault:    true,
		Status:       StatusActive,
		ContactEmail: "Platform@Example.COM",
	}, AuditContext{CorrelationID: "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	if issuer.Status != StatusActive || !issuer.IsDefault || !issuer.ActiveACMEAccount {
		t.Fatalf("issuer = %#v", issuer)
	}
	if store.created.Status != StatusDisabled || store.created.IsDefault {
		t.Fatalf("issuer was not staged disabled before account creation: %#v", store.created)
	}
	if store.account.PrivateKeyPEMEncrypted == "" || strings.Contains(store.account.PrivateKeyPEMEncrypted, "SECRET-PRIVATE-KEY-CANARY") {
		t.Fatalf("private key was not encrypted: %s", store.account.PrivateKeyPEMEncrypted)
	}
	auditJSON, _ := json.Marshal(auditRepo.events)
	if strings.Contains(string(auditJSON), "SECRET-PRIVATE-KEY-CANARY") || strings.Contains(string(auditJSON), store.account.PrivateKeyPEMEncrypted) {
		t.Fatalf("audit leaked secret material: %s", auditJSON)
	}
}

func TestCreateIssuerWithSystemActorAuditsSystemIdentity(t *testing.T) {
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	auditRepo := &issuerAuditStore{}
	service := NewService(ServiceConfig{
		Repository:      &issuerServiceStore{now: time.Now().UTC()},
		AuditRepository: auditRepo,
		AccountRegistrar: staticRegistrar{
			registration: acme.AccountRegistration{
				AccountURL:    "https://acme.example/acct/123",
				PrivateKeyPEM: []byte("SECRET-PRIVATE-KEY-CANARY"),
			},
		},
		KeySet: keys,
	})
	_, err = service.CreateIssuer(context.Background(), Actor{
		ID:         "12345678-1234-4234-9234-123456789abc",
		GlobalRole: users.GlobalRoleAdmin,
		System:     true,
	}, CreateIssuerParams{
		Name:         "letsencrypt_staging",
		Type:         TypeACME,
		DirectoryURL: "https://acme.example/directory",
		Environment:  EnvironmentStaging,
		Status:       StatusActive,
		ContactEmail: "platform@example.com",
	}, AuditContext{CorrelationID: "bootstrap-create-issuer", Command: "certhub-server bootstrap create-issuer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(auditRepo.events) == 0 {
		t.Fatalf("no audit events recorded")
	}
	event := auditRepo.events[len(auditRepo.events)-1]
	if event.IdentityType != audit.IdentityTypeSystem || event.IdentityID != nil {
		t.Fatalf("audit identity = %s %#v", event.IdentityType, event.IdentityID)
	}
	var metadata map[string]any
	if err := json.Unmarshal(event.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["command"] != "certhub-server bootstrap create-issuer" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

type staticRegistrar struct {
	registration acme.AccountRegistration
	err          error
}

func (s staticRegistrar) RegisterOrReuseAccount(context.Context, acme.AccountRegistrationParams) (acme.AccountRegistration, error) {
	return s.registration, s.err
}

type issuerServiceStore struct {
	now     time.Time
	issuer  Issuer
	created CreateIssuerParams
	account CreateACMEAccountParams
}

func (s *issuerServiceStore) Create(_ context.Context, params CreateIssuerParams) (Issuer, error) {
	s.created = params
	s.issuer = Issuer{
		ID:                   "22345678-1234-4234-9234-123456789abc",
		Name:                 params.Name,
		Type:                 params.Type,
		DirectoryURL:         params.DirectoryURL,
		Environment:          params.Environment,
		IsDefault:            params.IsDefault,
		Status:               params.Status,
		RenewalWindowSeconds: 2592000,
		ContactEmail:         strings.ToLower(params.ContactEmail),
		CreatedAt:            s.now,
		UpdatedAt:            s.now,
	}
	return s.issuer, nil
}

func (s *issuerServiceStore) Get(context.Context, string) (Issuer, error) { return s.issuer, nil }

func (s *issuerServiceStore) List(context.Context, ListIssuersParams) ([]Issuer, error) {
	return []Issuer{s.issuer}, nil
}

func (s *issuerServiceStore) Count(context.Context, ListIssuersParams) (int64, error) { return 1, nil }

func (s *issuerServiceStore) Update(_ context.Context, _ string, params UpdateIssuerParams) (Issuer, error) {
	if params.IsDefault.Set {
		s.issuer.IsDefault = params.IsDefault.Value
	}
	if params.Status.Set {
		s.issuer.Status = Status(*params.Status.Value)
	}
	s.issuer.ActiveACMEAccount = s.account.ID != ""
	return s.issuer, nil
}

func (s *issuerServiceStore) EnsureACMEAccount(_ context.Context, params CreateACMEAccountParams) (ACMEAccount, error) {
	s.account = params
	return ACMEAccount{
		ID:                     params.ID,
		IssuerID:               params.IssuerID,
		Email:                  params.Email,
		AccountURL:             params.AccountURL,
		PrivateKeyPEMEncrypted: params.PrivateKeyPEMEncrypted,
		Status:                 params.Status,
		CreatedAt:              s.now,
		UpdatedAt:              s.now,
	}, nil
}

type issuerAuditStore struct {
	events []audit.AppendEventParams
}

func (s *issuerAuditStore) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	s.events = append(s.events, params)
	return audit.Event{}, nil
}
