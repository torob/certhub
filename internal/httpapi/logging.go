package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	security "github.com/torob/certhub/internal/crypto"
)

type jsonLogger struct {
	mu  sync.Mutex
	out io.Writer
}

func WithLogWriter(out io.Writer) Option {
	return func(s *Server) {
		if out == nil {
			s.logger = nil
			return
		}
		s.logger = &jsonLogger{out: out}
	}
}

func (s *Server) logRequest(r *http.Request, ctx RequestContext, route string, status int, errorCode string, latency time.Duration) {
	if s.logger == nil {
		return
	}
	s.logger.write(map[string]any{
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"level":          requestLogLevel(status),
		"event":          "http_request",
		"method":         r.Method,
		"path_template":  route,
		"status":         status,
		"latency_ms":     float64(latency.Microseconds()) / 1000,
		"request_id":     ctx.RequestID,
		"correlation_id": ctx.RequestID,
		"source_ip":      sourceIPString(ctx),
		"identity_type":  "",
		"identity_id":    "",
		"error_code":     errorCode,
	})
}

func (s *Server) logForwardedHeaderSecurity(r *http.Request, ctx RequestContext, route string) {
	if s.logger == nil {
		return
	}
	s.logger.write(map[string]any{
		"timestamp":          time.Now().UTC().Format(time.RFC3339Nano),
		"level":              "warn",
		"event":              "security.forwarded_headers_rejected",
		"method":             r.Method,
		"path_template":      route,
		"request_id":         ctx.RequestID,
		"correlation_id":     ctx.RequestID,
		"source_ip":          sourceIPString(ctx),
		"trusted_proxy_peer": ctx.TrustedProxyPeer,
		"reason":             "malformed_or_conflicting_forwarded_headers",
	})
}

func sourceIPString(ctx RequestContext) string {
	if !ctx.SourceIP.IsValid() {
		return ""
	}
	return ctx.SourceIP.String()
}

func requestLogLevel(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status >= 400:
		return "warn"
	default:
		return "info"
	}
}

func (l *jsonLogger) write(fields map[string]any) {
	if l == nil || l.out == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.out).Encode(sanitizeLogMap(fields))
}

func sanitizeLogMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[security.RedactString(k)] = sanitizeLogValue(v)
	}
	return out
}

func sanitizeLogValue(value any) any {
	switch v := value.(type) {
	case string:
		return security.RedactString(v)
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, security.RedactString(item))
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeLogValue(item))
		}
		return out
	case map[string]any:
		return sanitizeLogMap(v)
	default:
		return value
	}
}
