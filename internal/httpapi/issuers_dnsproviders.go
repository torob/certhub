package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/torob/certhub/internal/auth"
	dnsdomain "github.com/torob/certhub/internal/dnsproviders"
	issuerdomain "github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
)

type issuerCreateRequest struct {
	Name                 string `json:"name"`
	Type                 string `json:"type"`
	DirectoryURL         string `json:"directory_url"`
	Environment          string `json:"environment"`
	Default              bool   `json:"default"`
	Status               string `json:"status"`
	RenewalWindowSeconds int    `json:"renewal_window_seconds"`
	ContactEmail         string `json:"contact_email"`
}

type apiIssuer struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Type                 string    `json:"type"`
	DirectoryURL         string    `json:"directory_url"`
	Environment          string    `json:"environment"`
	Default              bool      `json:"default"`
	Status               string    `json:"status"`
	RenewalWindowSeconds int       `json:"renewal_window_seconds"`
	ContactEmail         string    `json:"contact_email"`
	ACMEAccountStatus    string    `json:"acme_account_status,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type dnsProviderCreateRequest struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	ZoneMode    string          `json:"zone_mode"`
	Status      string          `json:"status"`
	Credentials json.RawMessage `json:"credentials"`
}

type dnsProviderZoneCreateRequest struct {
	ZoneName string `json:"zone_name"`
}

type apiDNSProvider struct {
	ID                        string     `json:"id"`
	Name                      string     `json:"name"`
	Type                      string     `json:"type"`
	ZoneMode                  string     `json:"zone_mode"`
	LastZoneRefreshAt         *time.Time `json:"last_zone_refresh_at,omitempty"`
	ZoneRefreshStatus         string     `json:"zone_refresh_status"`
	ZoneRefreshFailureCode    *string    `json:"zone_refresh_failure_code,omitempty"`
	ZoneRefreshFailureMessage *string    `json:"zone_refresh_failure_message,omitempty"`
	Status                    string     `json:"status"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

type apiDNSProviderZone struct {
	ID            string    `json:"id"`
	DNSProviderID string    `json:"dns_provider_id"`
	ZoneName      string    `json:"zone_name"`
	CreatedAt     time.Time `json:"created_at"`
}

type apiDiscoveredZone struct {
	ZoneName              string  `json:"zone_name"`
	AlreadyConfigured     bool    `json:"already_configured"`
	ConflictDNSProviderID *string `json:"conflict_dns_provider_id,omitempty"`
}

type apiRefreshJob struct {
	ID                    string     `json:"id"`
	DNSProviderID         string     `json:"dns_provider_id"`
	Status                string     `json:"status"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
	DiscoveredZoneCount   *int       `json:"discovered_zone_count,omitempty"`
	FailureCode           *string    `json:"failure_code,omitempty"`
	FailureMessage        *string    `json:"failure_message,omitempty"`
	ConflictZoneName      *string    `json:"conflict_zone_name,omitempty"`
	ConflictDNSProviderID *string    `json:"conflict_dns_provider_id,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func isIssuerEndpoint(p string) bool {
	return p == "/v1/issuers" || strings.HasPrefix(p, "/v1/issuers/")
}

func isDNSProviderEndpoint(p string) bool {
	return p == "/v1/dns-providers" || strings.HasPrefix(p, "/v1/dns-providers/")
}

func (s *Server) serveIssuers(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	if s.issuers == nil {
		return writeIssuerError(w, issuerdomain.ErrIssuerServiceUnavailable)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/issuers":
		return s.handleListIssuers(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/issuers":
		return s.handleCreateIssuer(w, r, reqctx)
	}
	parts, ok := singleResourcePathPart(r.URL.Path, "/v1/issuers/")
	if !ok {
		return s.authenticatedIssuerNotFound(w, r)
	}
	switch r.Method {
	case http.MethodGet:
		return s.handleGetIssuer(w, r, parts)
	case http.MethodPatch:
		return s.handlePatchIssuer(w, r, reqctx, parts)
	default:
		return s.authenticatedIssuerNotFound(w, r)
	}
}

func (s *Server) handleListIssuers(w http.ResponseWriter, r *http.Request) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseListIssuersParams(r)
	if err != nil {
		return writeIssuerError(w, issuerdomain.ErrInvalidRequest)
	}
	result, err := s.issuers.ListIssuers(r.Context(), issuerActor(current), params)
	if err != nil {
		return writeIssuerError(w, err)
	}
	items := make([]apiIssuer, 0, len(result.Issuers))
	for _, issuer := range result.Issuers {
		items = append(items, serializeIssuer(issuer))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"issuers": items, "pagination": pageMeta(result.Limit, result.Offset, result.Total)})
	return http.StatusOK, ""
}

func (s *Server) handleCreateIssuer(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body issuerCreateRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Name == "" || body.Type == "" || body.DirectoryURL == "" || body.Environment == "" || body.ContactEmail == "" {
		return writeIssuerError(w, issuerdomain.ErrInvalidRequest)
	}
	issuer, err := s.issuers.CreateIssuer(r.Context(), issuerActor(current), issuerdomain.CreateIssuerParams{
		Name:                 body.Name,
		Type:                 issuerdomain.Type(body.Type),
		DirectoryURL:         body.DirectoryURL,
		Environment:          issuerdomain.Environment(body.Environment),
		IsDefault:            body.Default,
		Status:               issuerdomain.Status(body.Status),
		RenewalWindowSeconds: body.RenewalWindowSeconds,
		ContactEmail:         body.ContactEmail,
	}, issuerAuditContext(reqctx))
	if err != nil {
		return writeIssuerError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, map[string]any{"issuer": serializeIssuer(issuer)})
	return http.StatusCreated, ""
}

func (s *Server) handleGetIssuer(w http.ResponseWriter, r *http.Request, id string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	issuer, err := s.issuers.GetIssuer(r.Context(), issuerActor(current), id)
	if err != nil {
		return writeIssuerError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"issuer": serializeIssuer(issuer)})
	return http.StatusOK, ""
}

func (s *Server) handlePatchIssuer(w http.ResponseWriter, r *http.Request, reqctx RequestContext, id string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := decodeIssuerPatch(r)
	if err != nil {
		return writeIssuerError(w, issuerdomain.ErrInvalidRequest)
	}
	issuer, err := s.issuers.UpdateIssuer(r.Context(), issuerActor(current), id, params, issuerAuditContext(reqctx))
	if err != nil {
		return writeIssuerError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"issuer": serializeIssuer(issuer)})
	return http.StatusOK, ""
}

func (s *Server) serveDNSProviders(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	if s.dns == nil {
		return writeDNSProviderError(w, dnsdomain.ErrDNSProviderServiceUnavailable)
	}
	if r.URL.Path == "/v1/dns-providers" {
		switch r.Method {
		case http.MethodGet:
			return s.handleListDNSProviders(w, r)
		case http.MethodPost:
			return s.handleCreateDNSProvider(w, r, reqctx)
		}
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/dns-providers/"), "/")
	if len(parts) == 0 || parts[0] == "" || strings.TrimPrefix(r.URL.Path, "/v1/dns-providers/") == r.URL.Path {
		return s.authenticatedDNSProviderNotFound(w, r)
	}
	providerID := parts[0]
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		return s.handleGetDNSProvider(w, r, providerID)
	case len(parts) == 1 && r.Method == http.MethodPatch:
		return s.handlePatchDNSProvider(w, r, reqctx, providerID)
	case len(parts) == 2 && parts[1] == "zones" && r.Method == http.MethodGet:
		return s.handleListDNSProviderZones(w, r, providerID)
	case len(parts) == 2 && parts[1] == "zones" && r.Method == http.MethodPost:
		return s.handleCreateDNSProviderZone(w, r, reqctx, providerID)
	case len(parts) == 3 && parts[1] == "zones" && parts[2] == "discovered" && r.Method == http.MethodGet:
		return s.handleListDiscoveredDNSProviderZones(w, r, providerID)
	case len(parts) == 3 && parts[1] == "zones" && parts[2] == "refresh" && r.Method == http.MethodPost:
		return s.handleRefreshDNSProviderZones(w, r, reqctx, providerID)
	case len(parts) == 3 && parts[1] == "zones" && r.Method == http.MethodDelete:
		return s.handleDeleteDNSProviderZone(w, r, reqctx, providerID, parts[2])
	default:
		return s.authenticatedDNSProviderNotFound(w, r)
	}
}

func (s *Server) handleListDNSProviders(w http.ResponseWriter, r *http.Request) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := parseListDNSProvidersParams(r)
	if err != nil {
		return writeDNSProviderError(w, dnsdomain.ErrInvalidRequest)
	}
	result, err := s.dns.ListProviders(r.Context(), dnsActor(current), params)
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	items := make([]apiDNSProvider, 0, len(result.Providers))
	for _, provider := range result.Providers {
		items = append(items, serializeDNSProvider(provider))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"dns_providers": items, "pagination": pageMeta(result.Limit, result.Offset, result.Total)})
	return http.StatusOK, ""
}

func (s *Server) handleCreateDNSProvider(w http.ResponseWriter, r *http.Request, reqctx RequestContext) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body dnsProviderCreateRequest
	if err := decodeJSONBody(r, &body); err != nil || body.Name == "" || body.Type == "" || len(body.Credentials) == 0 {
		return writeDNSProviderError(w, dnsdomain.ErrInvalidRequest)
	}
	provider, err := s.dns.CreateProvider(r.Context(), dnsActor(current), dnsdomain.CreateProviderServiceParams{
		Name:        body.Name,
		Type:        dnsdomain.ProviderType(body.Type),
		ZoneMode:    dnsdomain.ZoneMode(body.ZoneMode),
		Status:      dnsdomain.Status(body.Status),
		Credentials: body.Credentials,
	}, dnsAuditContext(reqctx))
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, map[string]any{"dns_provider": serializeDNSProvider(provider)})
	return http.StatusCreated, ""
}

func (s *Server) handleGetDNSProvider(w http.ResponseWriter, r *http.Request, providerID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	provider, err := s.dns.GetProvider(r.Context(), dnsActor(current), providerID)
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"dns_provider": serializeDNSProvider(provider)})
	return http.StatusOK, ""
}

func (s *Server) handlePatchDNSProvider(w http.ResponseWriter, r *http.Request, reqctx RequestContext, providerID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	params, err := decodeDNSProviderPatch(r)
	if err != nil {
		return writeDNSProviderError(w, dnsdomain.ErrInvalidRequest)
	}
	provider, err := s.dns.UpdateProvider(r.Context(), dnsActor(current), providerID, params, dnsAuditContext(reqctx))
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"dns_provider": serializeDNSProvider(provider)})
	return http.StatusOK, ""
}

func (s *Server) handleListDNSProviderZones(w http.ResponseWriter, r *http.Request, providerID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	opts, err := parseListOptions(r)
	if err != nil {
		return writeDNSProviderError(w, dnsdomain.ErrInvalidRequest)
	}
	result, err := s.dns.ListZones(r.Context(), dnsActor(current), providerID, opts)
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	zones := make([]apiDNSProviderZone, 0, len(result.Zones))
	for _, zone := range result.Zones {
		zones = append(zones, serializeDNSProviderZone(zone))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones, "pagination": pageMeta(result.Limit, result.Offset, result.Total)})
	return http.StatusOK, ""
}

func (s *Server) handleCreateDNSProviderZone(w http.ResponseWriter, r *http.Request, reqctx RequestContext, providerID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	var body dnsProviderZoneCreateRequest
	if err := decodeJSONBody(r, &body); err != nil || body.ZoneName == "" {
		return writeDNSProviderError(w, dnsdomain.ErrInvalidRequest)
	}
	zone, err := s.dns.AddZone(r.Context(), dnsActor(current), providerID, body.ZoneName, dnsAuditContext(reqctx))
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusCreated, map[string]any{"zone": serializeDNSProviderZone(zone)})
	return http.StatusCreated, ""
}

func (s *Server) handleDeleteDNSProviderZone(w http.ResponseWriter, r *http.Request, reqctx RequestContext, providerID, zoneID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	if err := s.dns.DeleteZone(r.Context(), dnsActor(current), providerID, zoneID, dnsAuditContext(reqctx)); err != nil {
		return writeDNSProviderError(w, err)
	}
	noStoreHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, ""
}

func (s *Server) handleListDiscoveredDNSProviderZones(w http.ResponseWriter, r *http.Request, providerID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	result, err := s.dns.ListDiscoveredZones(r.Context(), dnsActor(current), providerID)
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	zones := make([]apiDiscoveredZone, 0, len(result))
	for _, zone := range result {
		zones = append(zones, apiDiscoveredZone{ZoneName: zone.ZoneName, AlreadyConfigured: zone.AlreadyConfigured, ConflictDNSProviderID: zone.ConflictDNSProviderID})
	}
	noStoreHeaders(w.Header())
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones})
	return http.StatusOK, ""
}

func (s *Server) handleRefreshDNSProviderZones(w http.ResponseWriter, r *http.Request, reqctx RequestContext, providerID string) (int, string) {
	current, status, code, ok := s.authenticateUser(w, r)
	if !ok {
		return status, code
	}
	if err := decodeOptionalLifecycleNote(r); err != nil {
		return writeDNSProviderError(w, dnsdomain.ErrInvalidRequest)
	}
	job, err := s.dns.RefreshZones(r.Context(), dnsActor(current), providerID, dnsAuditContext(reqctx))
	if err != nil {
		return writeDNSProviderError(w, err)
	}
	noStoreHeaders(w.Header())
	w.Header().Set("Retry-After", strconv.Itoa(s.cfg.API.DefaultRetryAfterSeconds))
	writeJSON(w, http.StatusAccepted, map[string]any{"job": serializeRefreshJob(job)})
	return http.StatusAccepted, ""
}

func (s *Server) authenticatedIssuerNotFound(w http.ResponseWriter, r *http.Request) (int, string) {
	if _, status, code, ok := s.authenticateUser(w, r); !ok {
		return status, code
	}
	return writeIssuerError(w, issuerdomain.ErrNotFound)
}

func (s *Server) authenticatedDNSProviderNotFound(w http.ResponseWriter, r *http.Request) (int, string) {
	if _, status, code, ok := s.authenticateUser(w, r); !ok {
		return status, code
	}
	return writeDNSProviderError(w, dnsdomain.ErrNotFound)
}

func parseListIssuersParams(r *http.Request) (issuerdomain.ListIssuersParams, error) {
	opts, err := parseListOptions(r)
	if err != nil {
		return issuerdomain.ListIssuersParams{}, err
	}
	params := issuerdomain.ListIssuersParams{ListOptions: opts}
	if raw := r.URL.Query().Get("status"); raw != "" {
		status := issuerdomain.Status(raw)
		params.Status = &status
	}
	return params, nil
}

func parseListDNSProvidersParams(r *http.Request) (dnsdomain.ListProvidersParams, error) {
	opts, err := parseListOptions(r)
	if err != nil {
		return dnsdomain.ListProvidersParams{}, err
	}
	query := r.URL.Query()
	params := dnsdomain.ListProvidersParams{ListOptions: opts}
	if raw := query.Get("type"); raw != "" {
		v := dnsdomain.ProviderType(raw)
		params.Type = &v
	}
	if raw := query.Get("zone_mode"); raw != "" {
		v := dnsdomain.ZoneMode(raw)
		params.ZoneMode = &v
	}
	if raw := query.Get("status"); raw != "" {
		v := dnsdomain.Status(raw)
		params.Status = &v
	}
	return params, nil
}

func decodeIssuerPatch(r *http.Request) (issuerdomain.UpdateIssuerParams, error) {
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil || len(raw) == 0 {
		return issuerdomain.UpdateIssuerParams{}, errors.New("invalid patch")
	}
	allowed := map[string]bool{"default": true, "status": true, "renewal_window_seconds": true, "contact_email": true}
	var out issuerdomain.UpdateIssuerParams
	for key, value := range raw {
		if !allowed[key] {
			return out, errors.New("immutable or unknown field")
		}
		switch key {
		case "default":
			var v bool
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.IsDefault = storage.SetBool(v)
		case "status":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.Status = storage.SetString(v)
		case "renewal_window_seconds":
			var v int
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.RenewalWindowSeconds = storage.SetInt(v)
		case "contact_email":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.ContactEmail = storage.SetString(v)
		}
	}
	return out, nil
}

func decodeDNSProviderPatch(r *http.Request) (dnsdomain.UpdateProviderServiceParams, error) {
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil || len(raw) == 0 {
		return dnsdomain.UpdateProviderServiceParams{}, errors.New("invalid patch")
	}
	allowed := map[string]bool{"zone_mode": true, "status": true, "credentials": true}
	var out dnsdomain.UpdateProviderServiceParams
	for key, value := range raw {
		if !allowed[key] {
			return out, errors.New("immutable or unknown field")
		}
		switch key {
		case "zone_mode":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.ZoneMode = storage.SetString(v)
		case "status":
			var v string
			if err := json.Unmarshal(value, &v); err != nil {
				return out, err
			}
			out.Status = storage.SetString(v)
		case "credentials":
			if string(value) == "null" {
				return out, errors.New("credentials cannot be null")
			}
			out.Credentials = append(json.RawMessage(nil), value...)
		}
	}
	return out, nil
}

func decodeOptionalLifecycleNote(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil {
		return err
	}
	for key, value := range raw {
		if key != "note" || string(value) == "null" {
			return errors.New("invalid lifecycle note")
		}
		var note string
		if err := json.Unmarshal(value, &note); err != nil {
			return err
		}
		if err := storage.ValidateHumanString(note, "note", 0, 2048); err != nil {
			return err
		}
	}
	return nil
}

func singleResourcePathPart(p, prefix string) (string, bool) {
	rest := strings.TrimPrefix(p, prefix)
	if rest == p || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

func issuerActor(current auth.AuthenticatedUser) issuerdomain.Actor {
	return issuerdomain.Actor{ID: current.User.ID, GlobalRole: current.User.GlobalRole}
}

func dnsActor(current auth.AuthenticatedUser) dnsdomain.Actor {
	return dnsdomain.Actor{ID: current.User.ID, GlobalRole: current.User.GlobalRole}
}

func issuerAuditContext(reqctx RequestContext) issuerdomain.AuditContext {
	return issuerdomain.AuditContext{CorrelationID: reqctx.RequestID, SourceIP: sourceIPString(reqctx)}
}

func dnsAuditContext(reqctx RequestContext) dnsdomain.AuditContext {
	return dnsdomain.AuditContext{CorrelationID: reqctx.RequestID, SourceIP: sourceIPString(reqctx)}
}

func serializeIssuer(issuer issuerdomain.Issuer) apiIssuer {
	status := ""
	if issuer.ActiveACMEAccount {
		status = "active"
	}
	return apiIssuer{
		ID:                   issuer.ID,
		Name:                 issuer.Name,
		Type:                 string(issuer.Type),
		DirectoryURL:         issuer.DirectoryURL,
		Environment:          string(issuer.Environment),
		Default:              issuer.IsDefault,
		Status:               string(issuer.Status),
		RenewalWindowSeconds: issuer.RenewalWindowSeconds,
		ContactEmail:         issuer.ContactEmail,
		ACMEAccountStatus:    status,
		CreatedAt:            issuer.CreatedAt,
		UpdatedAt:            issuer.UpdatedAt,
	}
}

func serializeDNSProvider(provider dnsdomain.Provider) apiDNSProvider {
	return apiDNSProvider{
		ID:                        provider.ID,
		Name:                      provider.Name,
		Type:                      string(provider.Type),
		ZoneMode:                  string(provider.ZoneMode),
		LastZoneRefreshAt:         provider.LastZoneRefreshAt,
		ZoneRefreshStatus:         string(provider.ZoneRefreshStatus),
		ZoneRefreshFailureCode:    provider.ZoneRefreshFailureCode,
		ZoneRefreshFailureMessage: provider.ZoneRefreshFailureMessage,
		Status:                    string(provider.Status),
		CreatedAt:                 provider.CreatedAt,
		UpdatedAt:                 provider.UpdatedAt,
	}
}

func serializeDNSProviderZone(zone dnsdomain.Zone) apiDNSProviderZone {
	return apiDNSProviderZone{ID: zone.ID, DNSProviderID: zone.DNSProviderID, ZoneName: zone.ZoneName, CreatedAt: zone.CreatedAt}
}

func serializeRefreshJob(job dnsdomain.RefreshJob) apiRefreshJob {
	return apiRefreshJob{
		ID:                    job.ID,
		DNSProviderID:         job.DNSProviderID,
		Status:                string(job.Status),
		StartedAt:             job.StartedAt,
		CompletedAt:           job.CompletedAt,
		DiscoveredZoneCount:   job.DiscoveredZoneCount,
		FailureCode:           job.FailureCode,
		FailureMessage:        job.FailureMessage,
		ConflictZoneName:      job.ConflictZoneName,
		ConflictDNSProviderID: job.ConflictDNSProviderID,
		CreatedAt:             job.CreatedAt,
		UpdatedAt:             job.UpdatedAt,
	}
}

func writeIssuerError(w http.ResponseWriter, err error) (int, string) {
	status, code, message := domainError(err, "service_unavailable")
	return writeError(w, status, Error{Code: code, Message: message, Retryable: status == http.StatusServiceUnavailable, RetryAfterSeconds: retryAfter(status), Details: map[string]any{}})
}

func writeDNSProviderError(w http.ResponseWriter, err error) (int, string) {
	status, code, message := domainError(err, "service_unavailable")
	return writeError(w, status, Error{Code: code, Message: message, Retryable: status == http.StatusServiceUnavailable, RetryAfterSeconds: retryAfter(status), Details: map[string]any{}})
}

func domainError(err error, unavailableCode string) (int, string, string) {
	switch {
	case errors.Is(err, issuerdomain.ErrIssuerServiceUnavailable), errors.Is(err, dnsdomain.ErrDNSProviderServiceUnavailable):
		return http.StatusServiceUnavailable, unavailableCode, "Backend is not ready."
	case errors.Is(err, auth.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid_token", "Authentication token is missing, invalid, or expired."
	case errors.Is(err, auth.ErrRefreshTokenNotAllowed):
		return http.StatusForbidden, "refresh_token_not_allowed", "Refresh tokens are accepted only by the refresh endpoint."
	case errors.Is(err, auth.ErrUserTokenRequired):
		return http.StatusForbidden, "user_token_required", "A User access token is required."
	case errors.Is(err, issuerdomain.ErrForbidden), errors.Is(err, dnsdomain.ErrForbidden):
		return http.StatusForbidden, "application_access_denied", "The authenticated identity is not allowed to access this resource."
	case errors.Is(err, issuerdomain.ErrNotFound), errors.Is(err, dnsdomain.ErrNotFound):
		return http.StatusNotFound, "certificate_not_found", "Resource does not exist or is not visible."
	case errors.Is(err, issuerdomain.ErrConflict), errors.Is(err, dnsdomain.ErrConflict):
		return http.StatusConflict, "conflict", "Resource state conflicts with this request."
	case errors.Is(err, issuerdomain.ErrInvalidRequest), errors.Is(err, dnsdomain.ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request", "Request body or query parameters are invalid."
	case errors.Is(err, issuerdomain.ErrUpstreamDependency):
		return http.StatusServiceUnavailable, "issuer_unavailable", "Issuer dependency is unavailable."
	case errors.Is(err, dnsdomain.ErrProviderDiscovery):
		return http.StatusServiceUnavailable, "dns_zone_discovery_failed", "DNS provider zone discovery failed."
	default:
		return http.StatusInternalServerError, "internal_error", "Internal server error."
	}
}

func retryAfter(status int) int {
	if status == http.StatusConflict {
		return 1
	}
	if status == http.StatusServiceUnavailable {
		return 10
	}
	return 0
}
