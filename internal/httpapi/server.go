package httpapi

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	appdomain "certhub/internal/applications"
	auditdomain "certhub/internal/audit"
	"certhub/internal/auth"
	certdomain "certhub/internal/certificates"
	"certhub/internal/config"
	security "certhub/internal/crypto"
	dnsdomain "certhub/internal/dnsproviders"
	issuerdomain "certhub/internal/issuers"
	userdomain "certhub/internal/users"
	"certhub/internal/webui"
)

type ReadinessChecker interface {
	CheckReadiness() []ReadinessCheck
}

type ReadinessCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Server struct {
	cfg     *config.Config
	checker ReadinessChecker
	metrics *metrics
	logger  *jsonLogger
	static  fs.FS
	auth    *auth.Service
	users   *userdomain.Service
	apps    *appdomain.Service
	audit   *auditdomain.Service
	issuers *issuerdomain.Service
	dns     *dnsdomain.Service
	certs   *certdomain.Service
}

type Option func(*Server)

func WithReadinessChecker(checker ReadinessChecker) Option {
	return func(s *Server) {
		s.checker = checker
	}
}

func WithIdentityServices(authService *auth.Service, usersService *userdomain.Service) Option {
	return func(s *Server) {
		s.auth = authService
		s.users = usersService
	}
}

func WithApplicationAccessServices(applicationsService *appdomain.Service, auditService *auditdomain.Service) Option {
	return func(s *Server) {
		s.apps = applicationsService
		s.audit = auditService
	}
}

func WithIssuerService(service *issuerdomain.Service) Option {
	return func(s *Server) {
		s.issuers = service
	}
}

func WithDNSProviderService(service *dnsdomain.Service) Option {
	return func(s *Server) {
		s.dns = service
	}
}

func WithCertificateService(service *certdomain.Service) Option {
	return func(s *Server) {
		s.certs = service
	}
}

func WithStaticFS(static fs.FS) Option {
	return func(s *Server) {
		if static != nil {
			s.static = static
		}
	}
}

func New(cfg *config.Config, opts ...Option) *Server {
	s := &Server{cfg: cfg, checker: platformReadiness{}, metrics: newMetrics(), static: webui.FS()}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := requestID(r.Header.Get("X-Request-ID"))
	w.Header().Set("X-Request-ID", requestID)
	reqctx := s.deriveRequestContext(r, requestID)
	r = r.WithContext(context.WithValue(r.Context(), requestContextKey{}, reqctx))

	route := routeTemplate(r.URL.Path)
	status := http.StatusOK
	errorCode := ""
	defer func() {
		s.metrics.observe(r.Method, route, status, errorCode)
		s.logRequest(r, reqctx, route, status, errorCode, time.Since(start))
	}()

	if reqctx.ForwardedMalformed && !isOperationalEndpoint(r.URL.Path) {
		s.logForwardedHeaderSecurity(r, reqctx, route)
		status, errorCode = writeError(w, http.StatusBadRequest, Error{
			Code: "invalid_request", Message: "Forwarded headers are malformed or conflicting.", Retryable: false, Details: map[string]any{},
		})
		return
	}
	if !isOperationalEndpoint(r.URL.Path) && !s.acceptHost(reqctx) {
		status, errorCode = writeError(w, http.StatusForbidden, Error{
			Code: "invalid_request", Message: "Host is not allowed.", Retryable: false, Details: map[string]any{},
		})
		return
	}
	if s.cfg.HTTP.RequireHTTPS && !isOperationalEndpoint(r.URL.Path) && reqctx.EffectiveScheme != "https" {
		status, errorCode = writeError(w, http.StatusForbidden, Error{
			Code: "invalid_request", Message: "HTTPS is required for this endpoint.", Retryable: false, Details: map[string]any{},
		})
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		noStoreHeaders(w.Header())
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case r.Method == http.MethodGet && r.URL.Path == "/readyz":
		checks, ready := s.readinessSnapshot()
		body := map[string]any{"ready": ready, "checks": checks}
		noStoreHeaders(w.Header())
		if ready {
			writeJSON(w, http.StatusOK, body)
			return
		}
		status, errorCode = writeError(w, http.StatusServiceUnavailable, Error{
			Code: "service_unavailable", Message: "Backend is not ready.", Retryable: true, RetryAfterSeconds: 10,
			Details: map[string]any{"checks": checks},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		noStoreHeaders(w.Header())
		status = http.StatusOK
		_, ready := s.readinessSnapshot()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(s.metrics.render(ready)))
	case isIdentityEndpoint(r.URL.Path):
		status, errorCode = s.serveIdentity(w, r, reqctx)
	case isCertificateEndpoint(r.URL.Path):
		status, errorCode = s.serveCertificates(w, r, reqctx)
	case isApplicationEndpoint(r.URL.Path):
		status, errorCode = s.serveApplications(w, r, reqctx)
	case isIssuerEndpoint(r.URL.Path):
		status, errorCode = s.serveIssuers(w, r, reqctx)
	case isDNSProviderEndpoint(r.URL.Path):
		status, errorCode = s.serveDNSProviders(w, r, reqctx)
	case r.URL.Path == "/v1/audit-events":
		status, errorCode = s.serveAuditEvents(w, r, reqctx)
	case isReservedBackendPath(r.URL.Path):
		status, errorCode = writeError(w, http.StatusNotFound, Error{
			Code: "certificate_not_found", Message: "Resource does not exist or is not visible.", Retryable: false, Details: map[string]any{},
		})
	default:
		status = s.serveStatic(w, r)
	}
}

type RequestContext struct {
	RequestID          string
	SourceIP           netip.Addr
	EffectiveScheme    string
	EffectiveHost      string
	TrustedProxyPeer   bool
	ForwardedMalformed bool
}

type requestContextKey struct{}

func RequestContextFrom(ctx context.Context) (RequestContext, bool) {
	value, ok := ctx.Value(requestContextKey{}).(RequestContext)
	return value, ok
}

func (s *Server) acceptHost(ctx RequestContext) bool {
	if s.cfg.Server.PublicHostname == "" {
		return true
	}
	if ctx.EffectiveHost == "" {
		return false
	}
	return ctx.EffectiveHost == s.cfg.Server.PublicHostname
}

func (s *Server) deriveRequestContext(r *http.Request, requestID string) RequestContext {
	peer, peerOK := parseRemoteAddr(r.RemoteAddr)
	trusted := peerOK && s.peerTrustedAddr(peer)
	sourceIP := peer
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host, hostOK := normalizeHost(r.Host)
	if !hostOK {
		host = ""
	}

	malformed := false
	if trusted {
		var forwarded forwardedValues
		forwardedHeaders := r.Header.Values("Forwarded")
		hasForwarded := len(forwardedHeaders) > 0
		if hasForwarded {
			var ok bool
			forwarded, ok = parseForwardedHeader(forwardedHeaders)
			if !ok {
				malformed = true
			}
		}

		var xForwardedFor []netip.Addr
		xForwardedForHeaders := r.Header.Values("X-Forwarded-For")
		if len(xForwardedForHeaders) > 0 {
			chain, ok := parseXForwardedFor(xForwardedForHeaders)
			if !ok {
				malformed = true
			} else {
				xForwardedFor = chain
			}
		}

		xForwardedProto := ""
		xForwardedProtoHeaders := r.Header.Values("X-Forwarded-Proto")
		if len(xForwardedProtoHeaders) > 0 {
			proto, ok := parseForwardedProto(xForwardedProtoHeaders)
			if !ok {
				malformed = true
			} else {
				xForwardedProto = proto
			}
		}

		xForwardedHost := ""
		xForwardedHostHeaders := r.Header.Values("X-Forwarded-Host")
		if len(xForwardedHostHeaders) > 0 {
			forwardedHost, ok := parseForwardedHost(xForwardedHostHeaders)
			if !ok {
				malformed = true
			} else {
				xForwardedHost = forwardedHost
			}
		}

		if len(forwarded.For) > 0 {
			sourceIP = nearestUntrusted(forwarded.For, peer, s.peerTrustedAddr)
		}
		if len(xForwardedFor) > 0 {
			xSourceIP := nearestUntrusted(xForwardedFor, peer, s.peerTrustedAddr)
			if sourceIP != peer && sourceIP != xSourceIP {
				malformed = true
			} else if sourceIP == peer {
				sourceIP = xSourceIP
			}
		}

		if forwarded.Proto != "" && xForwardedProto != "" && forwarded.Proto != xForwardedProto {
			malformed = true
		}
		if forwarded.Proto != "" {
			scheme = forwarded.Proto
		} else if xForwardedProto != "" {
			scheme = xForwardedProto
		}

		if forwarded.Host != "" && xForwardedHost != "" && forwarded.Host != xForwardedHost {
			malformed = true
		}
		if forwarded.Host != "" {
			host = forwarded.Host
		} else if xForwardedHost != "" {
			host = xForwardedHost
		}
	}

	return RequestContext{
		RequestID:          requestID,
		SourceIP:           sourceIP,
		EffectiveScheme:    scheme,
		EffectiveHost:      host,
		TrustedProxyPeer:   trusted,
		ForwardedMalformed: malformed,
	}
}

func (s *Server) peerTrusted(remoteAddr string) bool {
	addr, err := netip.ParseAddr(remoteAddr)
	if err == nil {
		return s.peerTrustedAddr(addr)
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err = netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return s.peerTrustedAddr(addr)
}

func (s *Server) peerTrustedAddr(addr netip.Addr) bool {
	for _, prefix := range s.cfg.HTTP.TrustedProxyCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type forwardedValues struct {
	For   []netip.Addr
	Proto string
	Host  string
}

func parseRemoteAddr(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return addr, err == nil
}

func parseForwardedHeader(values []string) (forwardedValues, bool) {
	var out forwardedValues
	seenElement := false
	lastProto := ""
	lastHost := ""
	for _, header := range values {
		for _, rawElement := range strings.Split(header, ",") {
			element := strings.TrimSpace(rawElement)
			if element == "" {
				return forwardedValues{}, false
			}
			params := strings.Split(element, ";")
			seenParams := map[string]bool{}
			elementProto := ""
			elementHost := ""
			for _, param := range params {
				key, raw, ok := strings.Cut(strings.TrimSpace(param), "=")
				if !ok {
					return forwardedValues{}, false
				}
				key = strings.ToLower(strings.TrimSpace(key))
				if key == "" {
					return forwardedValues{}, false
				}
				value, ok := unquoteForwardedValue(strings.TrimSpace(raw))
				if !ok {
					return forwardedValues{}, false
				}
				switch key {
				case "for":
					if seenParams[key] {
						return forwardedValues{}, false
					}
					seenParams[key] = true
					addr, ok := parseForwardedForValue(value)
					if !ok {
						return forwardedValues{}, false
					}
					out.For = append(out.For, addr)
				case "proto":
					if seenParams[key] {
						return forwardedValues{}, false
					}
					seenParams[key] = true
					proto, ok := normalizeForwardedProto(value)
					if !ok {
						return forwardedValues{}, false
					}
					elementProto = proto
				case "host":
					if seenParams[key] {
						return forwardedValues{}, false
					}
					seenParams[key] = true
					host, ok := normalizeHost(value)
					if !ok {
						return forwardedValues{}, false
					}
					elementHost = host
				}
			}
			seenElement = true
			lastProto = elementProto
			lastHost = elementHost
		}
	}
	if !seenElement {
		return forwardedValues{}, false
	}
	out.Proto = lastProto
	out.Host = lastHost
	return out, true
}

func unquoteForwardedValue(value string) (string, bool) {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		unquoted := strings.Builder{}
		escaped := false
		for _, r := range value[1 : len(value)-1] {
			if escaped {
				unquoted.WriteRune(r)
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			unquoted.WriteRune(r)
		}
		if escaped {
			return "", false
		}
		return unquoted.String(), true
	}
	if strings.ContainsAny(value, `" `) {
		return "", false
	}
	return value, value != ""
}

func parseForwardedForValue(value string) (netip.Addr, bool) {
	if strings.EqualFold(value, "unknown") || strings.HasPrefix(value, "_") {
		return netip.Addr{}, false
	}
	if strings.HasPrefix(value, "[") {
		host, _, err := net.SplitHostPort(value)
		if err != nil {
			host = strings.Trim(value, "[]")
		}
		addr, err := netip.ParseAddr(host)
		return addr, err == nil
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		value = host
	}
	addr, err := netip.ParseAddr(value)
	return addr, err == nil
}

func parseXForwardedFor(values []string) ([]netip.Addr, bool) {
	var out []netip.Addr
	for _, header := range values {
		for _, part := range strings.Split(header, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				return nil, false
			}
			out = append(out, addr)
		}
	}
	return out, true
}

func parseForwardedProto(values []string) (string, bool) {
	out := ""
	for _, header := range values {
		for _, part := range strings.Split(header, ",") {
			proto, ok := normalizeForwardedProto(strings.TrimSpace(part))
			if !ok {
				return "", false
			}
			out = proto
		}
	}
	return out, true
}

func normalizeForwardedProto(value string) (string, bool) {
	switch strings.ToLower(value) {
	case "http":
		return "http", true
	case "https":
		return "https", true
	default:
		return "", false
	}
}

func parseForwardedHost(values []string) (string, bool) {
	out := ""
	for _, header := range values {
		for _, part := range strings.Split(header, ",") {
			host, ok := normalizeHost(strings.TrimSpace(part))
			if !ok {
				return "", false
			}
			out = host
		}
	}
	return out, true
}

func normalizeHost(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "/?#") {
		return "", false
	}
	host := value
	if strings.HasPrefix(value, "[") {
		parsedHost, _, err := net.SplitHostPort(value)
		if err != nil {
			return "", false
		}
		host = parsedHost
	} else if strings.Contains(value, ":") {
		parsedHost, port, err := net.SplitHostPort(value)
		if err != nil || port == "" {
			return "", false
		}
		host = parsedHost
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.HasPrefix(host, "*.") {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return "", false
		}
	}
	return host, true
}

func nearestUntrusted(chain []netip.Addr, peer netip.Addr, trusted func(netip.Addr) bool) netip.Addr {
	full := append(append([]netip.Addr{}, chain...), peer)
	for i := len(full) - 1; i >= 0; i-- {
		if !trusted(full[i]) {
			return full[i]
		}
	}
	if len(chain) > 0 {
		return chain[0]
	}
	return peer
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) int {
	if badStaticPath(r.URL.EscapedPath()) {
		securityHeaders(w.Header())
		noStoreHeaders(w.Header())
		http.NotFound(w, r)
		return http.StatusNotFound
	}
	clean := path.Clean("/" + r.URL.Path)
	switch clean {
	case "/", "/index.html":
		return s.writeStaticFile(w, "index.html", true)
	default:
		if strings.Contains(path.Base(clean), ".") {
			return s.writeStaticFile(w, strings.TrimPrefix(clean, "/"), false)
		}
		return s.writeStaticFile(w, "index.html", true)
	}
}

func (s *Server) writeStaticFile(w http.ResponseWriter, name string, index bool) int {
	data, err := fs.ReadFile(s.static, name)
	if err != nil {
		securityHeaders(w.Header())
		noStoreHeaders(w.Header())
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found\n"))
		return http.StatusNotFound
	}
	securityHeaders(w.Header())
	if index {
		indexCacheHeaders(w.Header())
	} else {
		if isHashedStaticAsset(name) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			noStoreHeaders(w.Header())
		}
	}
	if ctype := mime.TypeByExtension(path.Ext(name)); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return http.StatusOK
}

func isHashedStaticAsset(name string) bool {
	base := path.Base(name)
	ext := path.Ext(base)
	if ext == "" || !strings.HasPrefix(name, "assets/") {
		return false
	}
	stem := strings.TrimSuffix(base, ext)
	parts := strings.Split(stem, "-")
	if len(parts) < 2 {
		return false
	}
	hash := parts[len(parts)-1]
	if len(hash) < 8 {
		return false
	}
	for _, r := range hash {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

type platformReadiness struct{}

func (platformReadiness) CheckReadiness() []ReadinessCheck {
	return []ReadinessCheck{
		{Name: "postgresql", Status: "failed"},
		{Name: "migrations", Status: "failed"},
		{Name: "encryption_key", Status: "ok"},
		{Name: "process_configuration", Status: "ok"},
	}
}

type Error struct {
	Code              string
	Message           string
	Retryable         bool
	RetryAfterSeconds int
	Details           map[string]any
}

func writeError(w http.ResponseWriter, status int, err Error) (int, string) {
	if err.Details == nil {
		err.Details = map[string]any{}
	}
	err.Message = security.RedactString(err.Message)
	err.Details = sanitizeMap(err.Details)
	if err.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(err.RetryAfterSeconds))
	}
	noStoreHeaders(w.Header())
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":                err.Code,
			"message":             err.Message,
			"retryable":           err.Retryable,
			"retry_after_seconds": nullableRetry(err.RetryAfterSeconds),
			"details":             err.Details,
		},
	})
	return status, err.Code
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func nullableRetry(seconds int) any {
	if seconds <= 0 {
		return nil
	}
	return seconds
}

func noStoreHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

func securityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

func indexCacheHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
}

func isOperationalEndpoint(p string) bool {
	return p == "/healthz" || p == "/readyz" || p == "/metrics"
}

func isReservedBackendPath(p string) bool {
	return p == "/healthz" || p == "/readyz" || p == "/metrics" ||
		strings.HasPrefix(p, "/healthz/") || strings.HasPrefix(p, "/readyz/") || strings.HasPrefix(p, "/metrics/") ||
		p == "/v1" || strings.HasPrefix(p, "/v1/")
}

func routeTemplate(p string) string {
	switch {
	case p == "/healthz":
		return "/healthz"
	case p == "/readyz":
		return "/readyz"
	case p == "/metrics":
		return "/metrics"
	case p == "/v1" || strings.HasPrefix(p, "/v1/"):
		return "/v1/*"
	default:
		return "/{frontend}"
	}
}

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func requestID(value string) string {
	if requestIDRE.MatchString(value) {
		return value
	}
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func sanitizedReadinessChecks(checks []ReadinessCheck) []ReadinessCheck {
	out := make([]ReadinessCheck, 0, len(checks))
	for _, check := range checks {
		out = append(out, ReadinessCheck{
			Name:   security.RedactString(check.Name),
			Status: security.RedactString(check.Status),
		})
	}
	return out
}

func (s *Server) readinessSnapshot() ([]ReadinessCheck, bool) {
	checks := sanitizedReadinessChecks(s.checker.CheckReadiness())
	ready := true
	for _, check := range checks {
		if check.Status != "ok" {
			ready = false
			break
		}
	}
	return checks, ready
}

func sanitizeMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[security.RedactString(k)] = sanitizeAny(v)
	}
	return out
}

func sanitizeAny(value any) any {
	switch v := value.(type) {
	case string:
		return security.RedactString(v)
	case []ReadinessCheck:
		return sanitizedReadinessChecks(v)
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeAny(item))
		}
		return out
	case map[string]any:
		return sanitizeMap(v)
	default:
		return value
	}
}

func badStaticPath(escaped string) bool {
	if escaped == "" {
		return false
	}
	if strings.Contains(escaped, "\\") || strings.Contains(escaped, "//") {
		return true
	}
	current := escaped
	for range 3 {
		unescaped, err := pathUnescape(current)
		if err != nil {
			return true
		}
		if strings.Contains(unescaped, "\\") || strings.Contains(unescaped, "//") {
			return true
		}
		parts := strings.Split(unescaped, "/")
		for _, part := range parts {
			if part == ".." {
				return true
			}
		}
		if unescaped == current {
			break
		}
		current = unescaped
	}
	return false
}

func pathUnescape(value string) (string, error) {
	out := strings.Builder{}
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			out.WriteByte(value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", fmt.Errorf("bad escape")
		}
		v, err := strconv.ParseUint(value[i+1:i+3], 16, 8)
		if err != nil {
			return "", err
		}
		out.WriteByte(byte(v))
		i += 2
	}
	return out.String(), nil
}

type metrics struct {
	mu       sync.Mutex
	requests map[string]int
}

func newMetrics() *metrics {
	return &metrics{requests: map[string]int{}}
}

func (m *metrics) observe(method, route string, status int, errorCode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := method + "\xff" + route + "\xff" + strconv.Itoa(status) + "\xff" + errorCode
	m.requests[key]++
}

func (m *metrics) render(ready bool) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	b.WriteString("# HELP certhub_http_requests_total HTTP requests handled by the Certhub platform router.\n")
	b.WriteString("# TYPE certhub_http_requests_total counter\n")
	for key, count := range m.requests {
		parts := strings.Split(key, "\xff")
		fmt.Fprintf(&b, "certhub_http_requests_total{method=%q,path=%q,status=%q,error_code=%q} %d\n", parts[0], parts[1], parts[2], parts[3], count)
	}
	b.WriteString("# HELP certhub_platform_ready Readiness status of the platform scaffold.\n")
	b.WriteString("# TYPE certhub_platform_ready gauge\n")
	if ready {
		b.WriteString("certhub_platform_ready 1\n")
	} else {
		b.WriteString("certhub_platform_ready 0\n")
	}
	return b.String()
}
