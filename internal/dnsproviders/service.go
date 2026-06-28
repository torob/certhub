package dnsproviders

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/torob/certhub/internal/audit"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

var (
	ErrDNSProviderServiceUnavailable = errors.New("dns provider service unavailable")
	ErrForbidden                     = errors.New("forbidden")
	ErrNotFound                      = errors.New("not found")
	ErrConflict                      = errors.New("conflict")
	ErrInvalidRequest                = errors.New("invalid request")
	ErrProviderDiscovery             = errors.New("dns provider zone discovery failed")
)

type Store interface {
	Create(context.Context, CreateProviderParams) (Provider, error)
	Get(context.Context, string) (Provider, error)
	List(context.Context, ListProvidersParams) ([]Provider, error)
	Count(context.Context, ListProvidersParams) (int64, error)
	Update(context.Context, string, UpdateProviderParams) (Provider, error)
	ReplaceCredentials(context.Context, string, string) (Provider, error)
	GetCredentialsEncrypted(context.Context, string) (string, error)
	AddZone(context.Context, AddZoneParams) (Zone, error)
	DeleteZone(context.Context, string, string) (bool, error)
	ListZones(context.Context, string, storage.ListOptions) ([]Zone, error)
	CountZones(context.Context, string) (int64, error)
	FindZoneForDNSName(context.Context, string) (ZoneMatch, error)
	EnsureRefreshJob(context.Context, EnsureRefreshJobParams) (RefreshJob, error)
	ClaimNextRefreshJob(context.Context, ClaimRefreshJobParams) (RefreshJob, error)
	CompleteRefreshJobSuccess(context.Context, CompleteRefreshJobParams) (RefreshJob, error)
	FailRefreshJob(context.Context, FailRefreshJobParams) (RefreshJob, error)
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
	Repository      Store
	AuditRepository AuditRepository
	KeySet          *security.KeySet
	ZoneListers     ZoneListerRegistry
	Storage         storage.Beginner
}

type Service struct {
	repo      Store
	auditRepo AuditRepository
	keys      *security.KeySet
	listers   ZoneListerRegistry
	tx        storage.Beginner
}

type CreateProviderServiceParams struct {
	Name        string
	Type        ProviderType
	Credentials json.RawMessage
	ZoneMode    ZoneMode
	Status      Status
}

type UpdateProviderServiceParams struct {
	ZoneMode    storage.OptionalString
	Status      storage.OptionalString
	Credentials json.RawMessage
}

type ListProvidersResult struct {
	Providers []Provider
	Limit     int
	Offset    int
	Total     int64
}

type ListZonesResult struct {
	Zones  []Zone
	Limit  int
	Offset int
	Total  int64
}

type DiscoveredZone struct {
	ZoneName              string
	AlreadyConfigured     bool
	ConflictDNSProviderID *string
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{repo: cfg.Repository, auditRepo: cfg.AuditRepository, keys: cfg.KeySet, listers: cfg.ZoneListers, tx: cfg.Storage}
}

func (s *Service) ListProviders(ctx context.Context, actor Actor, params ListProvidersParams) (ListProvidersResult, error) {
	if err := s.ready(); err != nil {
		return ListProvidersResult{}, err
	}
	if !actor.admin() {
		return ListProvidersResult{}, ErrForbidden
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return ListProvidersResult{}, ErrInvalidRequest
	}
	params.ListOptions = opts
	providers, err := s.repo.List(ctx, params)
	if err != nil {
		return ListProvidersResult{}, classifyReadError(err)
	}
	total, err := s.repo.Count(ctx, params)
	if err != nil {
		return ListProvidersResult{}, classifyReadError(err)
	}
	return ListProvidersResult{Providers: providers, Limit: opts.Limit, Offset: opts.Offset, Total: total}, nil
}

func (s *Service) GetProvider(ctx context.Context, actor Actor, id string) (Provider, error) {
	if err := s.ready(); err != nil {
		return Provider{}, err
	}
	if !actor.admin() {
		return Provider{}, ErrForbidden
	}
	provider, err := s.repo.Get(ctx, id)
	if err != nil {
		return Provider{}, classifyReadError(err)
	}
	return provider, nil
}

func (s *Service) CreateProvider(ctx context.Context, actor Actor, params CreateProviderServiceParams, auditCtx AuditContext) (Provider, error) {
	var result Provider
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		provider, err := txsvc.createProvider(ctx, actor, params, auditCtx)
		if err == nil {
			result = provider
		}
		return err
	})
	return result, err
}

func (s *Service) createProvider(ctx context.Context, actor Actor, params CreateProviderServiceParams, auditCtx AuditContext) (Provider, error) {
	if err := s.readyWithKeys(); err != nil {
		return Provider{}, err
	}
	if !actor.admin() {
		return Provider{}, ErrForbidden
	}
	id, err := storage.NewUUID()
	if err != nil {
		return Provider{}, err
	}
	plaintext, err := validatedCredentialJSON(params.Type, params.Credentials)
	if err != nil {
		return Provider{}, ErrInvalidRequest
	}
	encrypted, err := s.keys.SealDatabaseValue(plaintext, dnsProviderCredentialsAAD(id))
	if err != nil {
		return Provider{}, err
	}
	provider, err := s.repo.Create(ctx, CreateProviderParams{
		ID:                   id,
		Name:                 params.Name,
		Type:                 params.Type,
		CredentialsEncrypted: encrypted,
		ZoneMode:             params.ZoneMode,
		Status:               params.Status,
	})
	if err != nil {
		return Provider{}, classifyWriteError(err)
	}
	if err := s.auditProviderEvent(ctx, actor, "dns_provider_created", &provider.ID, auditCtx, map[string]any{
		"name":      provider.Name,
		"type":      string(provider.Type),
		"zone_mode": string(provider.ZoneMode),
		"status":    string(provider.Status),
	}); err != nil {
		return Provider{}, err
	}
	return provider, nil
}

func (s *Service) UpdateProvider(ctx context.Context, actor Actor, id string, params UpdateProviderServiceParams, auditCtx AuditContext) (Provider, error) {
	var result Provider
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		provider, err := txsvc.updateProvider(ctx, actor, id, params, auditCtx)
		if err == nil {
			result = provider
		}
		return err
	})
	return result, err
}

func (s *Service) updateProvider(ctx context.Context, actor Actor, id string, params UpdateProviderServiceParams, auditCtx AuditContext) (Provider, error) {
	if err := s.readyWithKeys(); err != nil {
		return Provider{}, err
	}
	if !actor.admin() {
		return Provider{}, ErrForbidden
	}
	provider, err := s.repo.Get(ctx, id)
	if err != nil {
		return Provider{}, classifyReadError(err)
	}
	updated, err := s.repo.Update(ctx, id, UpdateProviderParams{ZoneMode: params.ZoneMode, Status: params.Status})
	if err != nil {
		return Provider{}, classifyWriteError(err)
	}
	if len(params.Credentials) != 0 {
		plaintext, err := validatedCredentialJSON(provider.Type, params.Credentials)
		if err != nil {
			return Provider{}, ErrInvalidRequest
		}
		encrypted, err := s.keys.SealDatabaseValue(plaintext, dnsProviderCredentialsAAD(id))
		if err != nil {
			return Provider{}, err
		}
		updated, err = s.repo.ReplaceCredentials(ctx, id, encrypted)
		if err != nil {
			return Provider{}, classifyWriteError(err)
		}
	}
	if err := s.auditProviderEvent(ctx, actor, "dns_provider_updated", &updated.ID, auditCtx, map[string]any{
		"name":      updated.Name,
		"type":      string(updated.Type),
		"zone_mode": string(updated.ZoneMode),
		"status":    string(updated.Status),
	}); err != nil {
		return Provider{}, err
	}
	return updated, nil
}

func (s *Service) ListZones(ctx context.Context, actor Actor, providerID string, opts storage.ListOptions) (ListZonesResult, error) {
	if err := s.ready(); err != nil {
		return ListZonesResult{}, err
	}
	if !actor.admin() {
		return ListZonesResult{}, ErrForbidden
	}
	if _, err := s.repo.Get(ctx, providerID); err != nil {
		return ListZonesResult{}, classifyReadError(err)
	}
	normalized, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return ListZonesResult{}, ErrInvalidRequest
	}
	zones, err := s.repo.ListZones(ctx, providerID, normalized)
	if err != nil {
		return ListZonesResult{}, classifyReadError(err)
	}
	total, err := s.repo.CountZones(ctx, providerID)
	if err != nil {
		return ListZonesResult{}, classifyReadError(err)
	}
	return ListZonesResult{Zones: zones, Limit: normalized.Limit, Offset: normalized.Offset, Total: total}, nil
}

func (s *Service) AddZone(ctx context.Context, actor Actor, providerID, zoneName string, auditCtx AuditContext) (Zone, error) {
	var result Zone
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		zone, err := txsvc.addZone(ctx, actor, providerID, zoneName, auditCtx)
		if err == nil {
			result = zone
		}
		return err
	})
	return result, err
}

func (s *Service) addZone(ctx context.Context, actor Actor, providerID, zoneName string, auditCtx AuditContext) (Zone, error) {
	if err := s.ready(); err != nil {
		return Zone{}, err
	}
	if !actor.admin() {
		return Zone{}, ErrForbidden
	}
	provider, err := s.repo.Get(ctx, providerID)
	if err != nil {
		return Zone{}, classifyReadError(err)
	}
	if provider.ZoneMode != ZoneModeManual {
		return Zone{}, ErrForbidden
	}
	zone, err := s.repo.AddZone(ctx, AddZoneParams{DNSProviderID: providerID, ZoneName: zoneName})
	if err != nil {
		return Zone{}, classifyWriteError(err)
	}
	if err := s.auditProviderEvent(ctx, actor, "dns_provider_zone_created", &providerID, auditCtx, map[string]any{"zone_name": zone.ZoneName}); err != nil {
		return Zone{}, err
	}
	return zone, nil
}

func (s *Service) DeleteZone(ctx context.Context, actor Actor, providerID, zoneID string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.deleteZone(ctx, actor, providerID, zoneID, auditCtx)
	})
}

func (s *Service) deleteZone(ctx context.Context, actor Actor, providerID, zoneID string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	if !actor.admin() {
		return ErrForbidden
	}
	provider, err := s.repo.Get(ctx, providerID)
	if err != nil {
		return classifyReadError(err)
	}
	if provider.ZoneMode != ZoneModeManual {
		return ErrForbidden
	}
	deleted, err := s.repo.DeleteZone(ctx, providerID, zoneID)
	if err != nil {
		return classifyWriteError(err)
	}
	if !deleted {
		return ErrNotFound
	}
	return s.auditProviderEvent(ctx, actor, "dns_provider_zone_deleted", &providerID, auditCtx, map[string]any{"zone_id": zoneID})
}

func (s *Service) ListDiscoveredZones(ctx context.Context, actor Actor, providerID string) ([]DiscoveredZone, error) {
	if err := s.readyWithKeys(); err != nil {
		return nil, err
	}
	if !actor.admin() {
		return nil, ErrForbidden
	}
	provider, zones, err := s.discoverProviderZones(ctx, providerID)
	if err != nil {
		return nil, err
	}
	out := make([]DiscoveredZone, 0, len(zones))
	for _, zone := range zones {
		item := DiscoveredZone{ZoneName: zone}
		match, err := s.repo.FindZoneForDNSName(ctx, zone)
		if err == nil {
			if match.Provider.ID == provider.ID && match.Zone.ZoneName == zone {
				item.AlreadyConfigured = true
			} else if match.Zone.ZoneName == zone {
				item.ConflictDNSProviderID = &match.Provider.ID
			}
		} else if !errors.Is(classifyReadError(err), ErrNotFound) {
			return nil, classifyReadError(err)
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Service) RefreshZones(ctx context.Context, actor Actor, providerID string, auditCtx AuditContext) (RefreshJob, error) {
	var result RefreshJob
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		job, err := txsvc.refreshZones(ctx, actor, providerID, auditCtx)
		if err == nil {
			result = job
		}
		return err
	})
	return result, err
}

func (s *Service) refreshZones(ctx context.Context, actor Actor, providerID string, auditCtx AuditContext) (RefreshJob, error) {
	if err := s.ready(); err != nil {
		return RefreshJob{}, err
	}
	if !actor.admin() {
		return RefreshJob{}, ErrForbidden
	}
	provider, err := s.repo.Get(ctx, providerID)
	if err != nil {
		return RefreshJob{}, classifyReadError(err)
	}
	if provider.ZoneMode != ZoneModeAuto {
		return RefreshJob{}, ErrForbidden
	}
	if provider.ZoneRefreshFailureCode != nil && *provider.ZoneRefreshFailureCode == FailureCodeZoneConflict {
		return RefreshJob{}, ErrConflict
	}
	job, err := s.repo.EnsureRefreshJob(ctx, EnsureRefreshJobParams{DNSProviderID: providerID})
	if err != nil {
		return RefreshJob{}, classifyWriteError(err)
	}
	if err := s.auditProviderEvent(ctx, actor, "dns_provider_zone_refresh_requested", &providerID, auditCtx, map[string]any{"job_id": job.ID}); err != nil {
		return RefreshJob{}, err
	}
	return job, nil
}

func (s *Service) CompleteNextRefreshJob(ctx context.Context, workerID string) (RefreshJob, bool, error) {
	if err := s.readyWithKeys(); err != nil {
		return RefreshJob{}, false, err
	}
	job, err := s.repo.ClaimNextRefreshJob(ctx, ClaimRefreshJobParams{WorkerID: workerID, LockedUntil: time.Now().Add(5 * time.Minute)})
	if err != nil {
		if errors.Is(classifyReadError(err), ErrNotFound) {
			return RefreshJob{}, false, nil
		}
		return RefreshJob{}, false, classifyReadError(err)
	}
	_, zones, err := s.discoverProviderZones(ctx, job.DNSProviderID)
	if err != nil {
		msg := "zone discovery failed"
		failed, failErr := s.repo.FailRefreshJob(ctx, FailRefreshJobParams{JobID: job.ID, DNSProviderID: job.DNSProviderID, WorkerID: workerID, FailureCode: "dns_zone_discovery_failed", FailureMessage: &msg})
		if failErr != nil {
			return RefreshJob{}, true, classifyWriteError(failErr)
		}
		return failed, true, nil
	}
	completed, err := s.repo.CompleteRefreshJobSuccess(ctx, CompleteRefreshJobParams{JobID: job.ID, DNSProviderID: job.DNSProviderID, WorkerID: workerID, ZoneNames: zones})
	if err != nil {
		return RefreshJob{}, true, classifyWriteError(err)
	}
	return completed, true, nil
}

func (s *Service) discoverProviderZones(ctx context.Context, providerID string) (Provider, []string, error) {
	provider, err := s.repo.Get(ctx, providerID)
	if err != nil {
		return Provider{}, nil, classifyReadError(err)
	}
	lister := s.listers[provider.Type]
	if lister == nil {
		return Provider{}, nil, ErrConflict
	}
	encrypted, err := s.repo.GetCredentialsEncrypted(ctx, provider.ID)
	if err != nil {
		return Provider{}, nil, classifyReadError(err)
	}
	plaintext, err := s.keys.OpenDatabaseValue(encrypted, dnsProviderCredentialsAAD(provider.ID))
	if err != nil {
		return Provider{}, nil, ErrProviderDiscovery
	}
	zones, err := lister.ListZones(ctx, json.RawMessage(plaintext))
	if err != nil {
		return Provider{}, nil, ErrProviderDiscovery
	}
	return provider, zones, nil
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil {
		return ErrDNSProviderServiceUnavailable
	}
	return nil
}

func (s *Service) readyWithKeys() error {
	if err := s.ready(); err != nil {
		return err
	}
	if s.keys == nil {
		return ErrDNSProviderServiceUnavailable
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

func validatedCredentialJSON(providerType ProviderType, raw json.RawMessage) ([]byte, error) {
	switch providerType {
	case ProviderTypeCloudflare:
		if err := requireCredentialKeys(raw, "api_token"); err != nil {
			return nil, ErrInvalidRequest
		}
		var creds CloudflareCredentials
		if err := json.Unmarshal(raw, &creds); err != nil || !validSecretString(creds.APIToken) {
			return nil, ErrInvalidRequest
		}
		return json.Marshal(creds)
	case ProviderTypeArvanCloud:
		if err := requireCredentialKeys(raw, "api_key"); err != nil {
			return nil, ErrInvalidRequest
		}
		var creds ArvanCloudCredentials
		if err := json.Unmarshal(raw, &creds); err != nil || !validSecretString(creds.APIKey) {
			return nil, ErrInvalidRequest
		}
		return json.Marshal(creds)
	default:
		return nil, ErrInvalidRequest
	}
}

func requireCredentialKeys(raw json.RawMessage, allowedKeys ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if len(fields) != len(allowedKeys) {
		return ErrInvalidRequest
	}
	for _, key := range allowedKeys {
		if _, ok := fields[key]; !ok {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validSecretString(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n\t")
}

func dnsProviderCredentialsAAD(providerID string) string {
	return "v1:table=dns_providers:column=credentials_encrypted:row_id=" + providerID
}

func uniqueSortedZones(zones []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(zones))
	for _, zone := range zones {
		normalized, err := storage.NormalizeDNSName(zone)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	slices.Sort(out)
	return out, nil
}

func (s *Service) auditProviderEvent(ctx context.Context, actor Actor, action string, targetID *string, auditCtx AuditContext, metadata map[string]any) error {
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
		IdentityType:       identityType,
		IdentityID:         identityID,
		Action:             action,
		TargetType:         "dns_provider",
		TargetID:           targetID,
		ScopeDNSProviderID: targetID,
		Result:             audit.ResultSuccess,
		CorrelationID:      optionalString(auditCtx.CorrelationID),
		SourceIP:           optionalString(auditCtx.SourceIP),
		Metadata:           metadataJSON(metadata),
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
