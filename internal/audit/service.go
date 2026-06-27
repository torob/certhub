package audit

import (
	"context"
	"errors"
	"strings"

	"certhub/internal/storage"
)

var (
	ErrAuditServiceUnavailable = errors.New("audit service unavailable")
	ErrForbidden               = errors.New("forbidden")
	ErrInvalidRequest          = errors.New("invalid request")
)

type EventStore interface {
	List(context.Context, ListEventsParams) ([]Event, error)
	Count(context.Context, ListEventsParams) (int64, error)
}

type ApplicationVisibilityReader interface {
	ListAccessibleApplicationIDs(context.Context, string) ([]string, error)
}

type Actor struct {
	ID         string
	GlobalRole string
}

type ListEventsResult struct {
	Events []Event
	Limit  int
	Offset int
	Total  int64
}

type Service struct {
	repo       EventStore
	visibility ApplicationVisibilityReader
}

type ServiceConfig struct {
	Repository        EventStore
	ApplicationReader ApplicationVisibilityReader
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{repo: cfg.Repository, visibility: cfg.ApplicationReader}
}

func (s *Service) ListEvents(ctx context.Context, actor Actor, params ListEventsParams) (ListEventsResult, error) {
	if err := s.ready(); err != nil {
		return ListEventsResult{}, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListEventsResult{}, ErrInvalidRequest
	}
	params.ListOptions = opts
	if err := validateList(params); err != nil {
		return ListEventsResult{}, ErrInvalidRequest
	}
	if !actor.admin() {
		if s.visibility == nil {
			return ListEventsResult{}, ErrAuditServiceUnavailable
		}
		if params.ScopeApplicationID == nil {
			return ListEventsResult{}, ErrForbidden
		}
		ids, err := s.visibility.ListAccessibleApplicationIDs(ctx, actor.ID)
		if err != nil {
			return ListEventsResult{}, err
		}
		if !containsString(ids, *params.ScopeApplicationID) {
			return ListEventsResult{}, ErrForbidden
		}
		params.VisibleApplicationIDs = []string{*params.ScopeApplicationID}
	}
	events, err := s.repo.List(ctx, params)
	if err != nil {
		return ListEventsResult{}, classifyServiceReadError(err)
	}
	total, err := s.repo.Count(ctx, params)
	if err != nil {
		return ListEventsResult{}, classifyServiceReadError(err)
	}
	return ListEventsResult{Events: events, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil {
		return ErrAuditServiceUnavailable
	}
	return nil
}

func (a Actor) admin() bool {
	return a.GlobalRole == "admin"
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func classifyServiceReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNoRows) {
		return ErrInvalidRequest
	}
	if !strings.Contains(err.Error(), "postgresql") {
		return ErrInvalidRequest
	}
	return err
}
