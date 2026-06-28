package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/torob/certhub/internal/storage"
)

type IdentityType string

const (
	IdentityTypeUser        IdentityType = "user"
	IdentityTypeApplication IdentityType = "application"
	IdentityTypeSystem      IdentityType = "system"
)

type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

type Event struct {
	ID                 string
	IdentityType       IdentityType
	IdentityID         *string
	Action             string
	TargetType         string
	TargetID           *string
	ScopeApplicationID *string
	ScopeCertificateID *string
	ScopeUserID        *string
	ScopeDNSProviderID *string
	Result             Result
	CorrelationID      *string
	SourceIP           *string
	Metadata           json.RawMessage
	CreatedAt          time.Time
}

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type AppendEventParams struct {
	ID                 string
	IdentityType       IdentityType
	IdentityID         *string
	Action             string
	TargetType         string
	TargetID           *string
	ScopeApplicationID *string
	ScopeCertificateID *string
	ScopeUserID        *string
	ScopeDNSProviderID *string
	Result             Result
	CorrelationID      *string
	SourceIP           *string
	Metadata           json.RawMessage
}

type ListEventsParams struct {
	storage.ListOptions
	IdentityType          *IdentityType
	IdentityID            *string
	Action                *string
	TargetType            *string
	TargetID              *string
	Result                *Result
	ScopeApplicationID    *string
	ScopeCertificateID    *string
	ScopeUserID           *string
	ScopeDNSProviderID    *string
	CorrelationID         *string
	CreatedAfter          *time.Time
	CreatedBefore         *time.Time
	VisibleApplicationIDs []string
}

func (r Repository) Append(ctx context.Context, params AppendEventParams) (Event, error) {
	if r.db == nil {
		return Event{}, errors.New("audit repository storage is required")
	}
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Event{}, err
		}
		params.ID = id
	}
	if len(params.Metadata) == 0 {
		params.Metadata = json.RawMessage(`{}`)
	}
	if err := validateAppend(&params); err != nil {
		return Event{}, err
	}
	event, err := scanEvent(r.db.QueryRow(ctx, `
insert into audit_events (
    id, identity_type, identity_id, action, target_type, target_id,
    scope_application_id, scope_certificate_id, scope_user_id, scope_dns_provider_id,
    result, correlation_id, source_ip, metadata
) values (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14
)
returning `+eventColumnsSQL(),
		params.ID, string(params.IdentityType), params.IdentityID, params.Action, params.TargetType, params.TargetID,
		params.ScopeApplicationID, params.ScopeCertificateID, params.ScopeUserID, params.ScopeDNSProviderID,
		string(params.Result), params.CorrelationID, params.SourceIP, []byte(params.Metadata)))
	if err != nil {
		return Event{}, fmt.Errorf("append audit event: %w", err)
	}
	return event, nil
}

func (r Repository) List(ctx context.Context, params ListEventsParams) ([]Event, error) {
	query, args, err := r.listQuery(params)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("list audit events: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	return events, nil
}

func (r Repository) Count(ctx context.Context, params ListEventsParams) (int64, error) {
	query, args, err := r.countQuery(params)
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count audit events: %w", err)
	}
	return total, nil
}

func (r Repository) listQuery(params ListEventsParams) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	if err := validateList(params); err != nil {
		return "", nil, err
	}
	where, args := listWhere(params)
	args = append(args, opts.Limit, opts.Offset)
	query := `select ` + eventColumnsSQL() + ` from audit_events`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" order by created_at desc, id desc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func (r Repository) countQuery(params ListEventsParams) (string, []any, error) {
	if _, err := storage.NormalizeListOptions(params.ListOptions); err != nil {
		return "", nil, err
	}
	if err := validateList(params); err != nil {
		return "", nil, err
	}
	where, args := listWhere(params)
	query := `select count(*)::bigint from audit_events`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	return query, args, nil
}

func listWhere(params ListEventsParams) ([]string, []any) {
	var args []any
	var where []string
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if params.IdentityType != nil {
		add("identity_type = $%d", string(*params.IdentityType))
	}
	if params.IdentityID != nil {
		add("identity_id = $%d", *params.IdentityID)
	}
	if params.Action != nil {
		add("action = $%d", *params.Action)
	}
	if params.TargetType != nil {
		add("target_type = $%d", *params.TargetType)
	}
	if params.TargetID != nil {
		add("target_id = $%d", *params.TargetID)
	}
	if params.Result != nil {
		add("result = $%d", string(*params.Result))
	}
	if params.ScopeApplicationID != nil {
		add("scope_application_id = $%d", *params.ScopeApplicationID)
	}
	if params.ScopeCertificateID != nil {
		add("scope_certificate_id = $%d", *params.ScopeCertificateID)
	}
	if params.ScopeUserID != nil {
		add("scope_user_id = $%d", *params.ScopeUserID)
	}
	if params.ScopeDNSProviderID != nil {
		add("scope_dns_provider_id = $%d", *params.ScopeDNSProviderID)
	}
	if params.CorrelationID != nil {
		add("correlation_id = $%d", *params.CorrelationID)
	}
	if params.CreatedAfter != nil {
		add("created_at >= $%d", *params.CreatedAfter)
	}
	if params.CreatedBefore != nil {
		add("created_at < $%d", *params.CreatedBefore)
	}
	if len(params.VisibleApplicationIDs) > 0 {
		add("scope_application_id = any($%d::uuid[])", params.VisibleApplicationIDs)
	}
	return where, args
}

func eventColumnsSQL() string {
	return `id, identity_type, identity_id, action, target_type, target_id,
    scope_application_id, scope_certificate_id, scope_user_id, scope_dns_provider_id,
    result, correlation_id, source_ip, metadata, created_at`
}

type scanner interface {
	Scan(...any) error
}

func scanEvent(row scanner) (Event, error) {
	var event Event
	var identityType, result string
	var identityID, targetID, scopeApplicationID, scopeCertificateID, scopeUserID, scopeDNSProviderID sql.NullString
	var correlationID, sourceIP sql.NullString
	var metadata []byte
	if err := row.Scan(
		&event.ID,
		&identityType,
		&identityID,
		&event.Action,
		&event.TargetType,
		&targetID,
		&scopeApplicationID,
		&scopeCertificateID,
		&scopeUserID,
		&scopeDNSProviderID,
		&result,
		&correlationID,
		&sourceIP,
		&metadata,
		&event.CreatedAt,
	); err != nil {
		return Event{}, err
	}
	event.IdentityType = IdentityType(identityType)
	event.IdentityID = stringPtr(identityID)
	event.TargetID = stringPtr(targetID)
	event.ScopeApplicationID = stringPtr(scopeApplicationID)
	event.ScopeCertificateID = stringPtr(scopeCertificateID)
	event.ScopeUserID = stringPtr(scopeUserID)
	event.ScopeDNSProviderID = stringPtr(scopeDNSProviderID)
	event.Result = Result(result)
	event.CorrelationID = stringPtr(correlationID)
	event.SourceIP = stringPtr(sourceIP)
	event.Metadata = append(json.RawMessage(nil), metadata...)
	return event, nil
}

func validateAppend(params *AppendEventParams) error {
	if err := storage.ValidateUUID(params.ID, "audit_event_id"); err != nil {
		return err
	}
	if err := validateIdentity(params.IdentityType, params.IdentityID); err != nil {
		return err
	}
	if err := validateAction(params.Action); err != nil {
		return err
	}
	if err := validateTargetType(params.TargetType); err != nil {
		return err
	}
	for field, value := range map[string]*string{
		"target_id":             params.TargetID,
		"scope_application_id":  params.ScopeApplicationID,
		"scope_certificate_id":  params.ScopeCertificateID,
		"scope_user_id":         params.ScopeUserID,
		"scope_dns_provider_id": params.ScopeDNSProviderID,
	} {
		if value != nil {
			if err := storage.ValidateUUID(*value, field); err != nil {
				return err
			}
		}
	}
	if err := validateResult(params.Result); err != nil {
		return err
	}
	if err := storage.ValidateCorrelationID(params.CorrelationID); err != nil {
		return err
	}
	if err := storage.ValidateOptionalHumanString(params.SourceIP, "source_ip", 128); err != nil {
		return err
	}
	return validateMetadata(params.Metadata)
}

func validateList(params ListEventsParams) error {
	if params.IdentityType != nil {
		if err := validateIdentityType(*params.IdentityType); err != nil {
			return err
		}
	}
	for field, value := range map[string]*string{
		"identity_id":           params.IdentityID,
		"target_id":             params.TargetID,
		"scope_application_id":  params.ScopeApplicationID,
		"scope_certificate_id":  params.ScopeCertificateID,
		"scope_user_id":         params.ScopeUserID,
		"scope_dns_provider_id": params.ScopeDNSProviderID,
	} {
		if value != nil {
			if err := storage.ValidateUUID(*value, field); err != nil {
				return err
			}
		}
	}
	if params.Action != nil {
		if err := validateAction(*params.Action); err != nil {
			return err
		}
	}
	if params.TargetType != nil {
		if err := validateTargetType(*params.TargetType); err != nil {
			return err
		}
	}
	if params.Result != nil {
		if err := validateResult(*params.Result); err != nil {
			return err
		}
	}
	if err := storage.ValidateCorrelationID(params.CorrelationID); err != nil {
		return err
	}
	if params.CreatedAfter != nil && params.CreatedBefore != nil && !params.CreatedBefore.After(*params.CreatedAfter) {
		return errors.New("created_before must be after created_after")
	}
	for _, id := range params.VisibleApplicationIDs {
		if err := storage.ValidateUUID(id, "visible_application_id"); err != nil {
			return err
		}
	}
	return nil
}

func validateIdentity(identityType IdentityType, identityID *string) error {
	if err := validateIdentityType(identityType); err != nil {
		return err
	}
	if identityType == IdentityTypeSystem {
		if identityID != nil {
			return errors.New("system audit identity_id must be null")
		}
		return nil
	}
	if identityID == nil {
		return errors.New("audit identity_id is required")
	}
	return storage.ValidateUUID(*identityID, "identity_id")
}

func validateIdentityType(identityType IdentityType) error {
	switch identityType {
	case IdentityTypeUser, IdentityTypeApplication, IdentityTypeSystem:
		return nil
	default:
		return errors.New("identity_type is invalid")
	}
}

func validateResult(result Result) error {
	switch result {
	case ResultSuccess, ResultFailure:
		return nil
	default:
		return errors.New("audit result is invalid")
	}
}

func validateAction(action string) error {
	if len(action) < 1 || len(action) > 128 {
		return errors.New("audit action is invalid")
	}
	for i, r := range action {
		if i == 0 {
			if r < 'a' || r > 'z' {
				return errors.New("audit action is invalid")
			}
			continue
		}
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return errors.New("audit action is invalid")
		}
	}
	return nil
}

func validateTargetType(targetType string) error {
	if len(targetType) < 1 || len(targetType) > 64 {
		return errors.New("audit target_type is invalid")
	}
	for i, r := range targetType {
		if i == 0 {
			if r < 'a' || r > 'z' {
				return errors.New("audit target_type is invalid")
			}
			continue
		}
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return errors.New("audit target_type is invalid")
		}
	}
	return nil
}

func validateMetadata(metadata json.RawMessage) error {
	var decoded map[string]any
	if err := json.Unmarshal(metadata, &decoded); err != nil {
		return errors.New("audit metadata must be a JSON object")
	}
	if decoded == nil {
		return errors.New("audit metadata must be a JSON object")
	}
	return nil
}

func stringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}
