package audit

import (
	"context"
	"testing"
	"time"
)

func TestListEventsNonAdminRequiresApplicationScope(t *testing.T) {
	repo := &serviceFakeEventStore{}
	visibility := serviceFakeVisibility{ids: []string{
		"22345678-1234-4234-9234-123456789abc",
		"32345678-1234-4234-9234-123456789abc",
	}}
	service := NewService(ServiceConfig{Repository: repo, ApplicationReader: visibility})

	result, err := service.ListEvents(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: "user"}, ListEventsParams{})
	if err != ErrForbidden {
		t.Fatalf("err = %v result = %#v", err, result)
	}
	if repo.listCalled {
		t.Fatalf("unscoped non-admin query reached repository")
	}
}

func TestListEventsNonAdminRestrictsToAccessibleApplicationScope(t *testing.T) {
	repo := &serviceFakeEventStore{}
	appID := "22345678-1234-4234-9234-123456789abc"
	visibility := serviceFakeVisibility{ids: []string{appID}}
	service := NewService(ServiceConfig{Repository: repo, ApplicationReader: visibility})

	result, err := service.ListEvents(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: "user"}, ListEventsParams{ScopeApplicationID: &appID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(repo.listParams.VisibleApplicationIDs) != 1 || repo.listParams.VisibleApplicationIDs[0] != appID {
		t.Fatalf("result = %#v params = %#v", result, repo.listParams)
	}
}

func TestListEventsNonAdminInaccessibleApplicationFilterReturnsEmpty(t *testing.T) {
	repo := &serviceFakeEventStore{}
	visibility := serviceFakeVisibility{ids: []string{"22345678-1234-4234-9234-123456789abc"}}
	service := NewService(ServiceConfig{Repository: repo, ApplicationReader: visibility})
	otherApp := "32345678-1234-4234-9234-123456789abc"

	_, err := service.ListEvents(context.Background(), Actor{ID: "12345678-1234-4234-9234-123456789abc", GlobalRole: "user"}, ListEventsParams{ScopeApplicationID: &otherApp})
	if err != ErrForbidden {
		t.Fatalf("err = %v", err)
	}
	if repo.listCalled {
		t.Fatalf("inaccessible application query reached repository")
	}
}

type serviceFakeEventStore struct {
	listCalled bool
	listParams ListEventsParams
}

func (f *serviceFakeEventStore) List(_ context.Context, params ListEventsParams) ([]Event, error) {
	f.listCalled = true
	f.listParams = params
	now := time.Now()
	appID := "22345678-1234-4234-9234-123456789abc"
	return []Event{{
		ID:                 "42345678-1234-4234-9234-123456789abc",
		IdentityType:       IdentityTypeUser,
		IdentityID:         &appID,
		Action:             "application_created",
		TargetType:         "application",
		TargetID:           &appID,
		ScopeApplicationID: &appID,
		Result:             ResultSuccess,
		Metadata:           []byte(`{}`),
		CreatedAt:          now,
	}}, nil
}

func (f *serviceFakeEventStore) Count(context.Context, ListEventsParams) (int64, error) {
	return 1, nil
}

type serviceFakeVisibility struct {
	ids []string
}

func (f serviceFakeVisibility) ListAccessibleApplicationIDs(context.Context, string) ([]string, error) {
	return append([]string(nil), f.ids...), nil
}
