package applications

import (
	"context"
	"errors"
	"testing"

	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestOnlyAdministratorsCanChangeDomainAuthorization(t *testing.T) {
	for _, role := range []GrantRole{GrantRoleViewer, GrantRoleCertificateReader, GrantRoleManager} {
		t.Run(string(role), func(t *testing.T) {
			store := &scopeSecurityStore{serviceFakeStore: &serviceFakeStore{application: Application{ID: "22345678-1234-4234-9234-123456789abc", Status: StatusActive}}, role: role}
			auditRepo := &serviceFakeAudit{}
			svc := NewService(ServiceConfig{Repository: store, AuditRepository: auditRepo, KeySet: serviceTestKeySet(t)})
			actor := Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: users.GlobalRoleUser}
			if _, err := svc.CreateDomainScope(context.Background(), actor, store.application.ID, "*.other-tenant.example", AuditContext{}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("application role %s authorized another tenant's domain: %v", role, err)
			}
			if err := svc.DeleteDomainScope(context.Background(), actor, store.application.ID, "32345678-1234-4234-9234-123456789abc", AuditContext{}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("application role %s changed administrator-defined scopes: %v", role, err)
			}
			if store.writes != 0 || len(auditRepo.events) != 0 {
				t.Fatal("rejected request changed domain authorization")
			}
			if role == GrantRoleManager {
				result, err := svc.ListDomainScopes(context.Background(), actor, store.application.ID, storage.ListOptions{})
				if err != nil || len(result.DomainScopes) != 1 {
					t.Fatalf("manager cannot inspect authorized domains: %v", err)
				}
			}
			actor.GlobalRole = users.GlobalRoleAdmin
			scope, err := svc.CreateDomainScope(context.Background(), actor, store.application.ID, "api.example.com", AuditContext{})
			if err != nil {
				t.Fatalf("administrator could not authorize domain: %v", err)
			}
			if err := svc.DeleteDomainScope(context.Background(), actor, store.application.ID, scope.ID, AuditContext{}); err != nil || store.writes != 2 {
				t.Fatalf("administrator could not remove authorization: %v", err)
			}
		})
	}
}

type scopeSecurityStore struct {
	*serviceFakeStore
	role   GrantRole
	writes int
}

func (s *scopeSecurityStore) GetGrant(context.Context, string, string) (UserGrant, error) {
	return UserGrant{Role: s.role}, nil
}

func (s *scopeSecurityStore) AddDomainScope(_ context.Context, params AddDomainScopeParams) (DomainScope, error) {
	s.writes++
	return DomainScope{ID: "32345678-1234-4234-9234-123456789abc", ApplicationID: params.ApplicationID, Value: params.Value}, nil
}

func (s *scopeSecurityStore) DeleteDomainScope(context.Context, string, string) (bool, error) {
	s.writes++
	return true, nil
}

func (s *scopeSecurityStore) ListDomainScopes(context.Context, string, storage.ListOptions) ([]DomainScope, error) {
	return []DomainScope{{Value: "api.example.com"}}, nil
}

func (s *scopeSecurityStore) CountDomainScopes(context.Context, string, storage.ListOptions) (int64, error) {
	return 1, nil
}
