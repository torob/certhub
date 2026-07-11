package certhubclient

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	certerrors "github.com/torob/certhub/pkg/errors"
	"github.com/torob/certhub/pkg/material"
)

const (
	ApplicationTokenPrefix = "cth_app_v1_"
	UserAccessTokenPrefix  = "cth_uat_v1_"
)

var tokenSecretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type TokenClass string

const (
	TokenClassUnknown     TokenClass = "unknown"
	TokenClassApplication TokenClass = "application"
	TokenClassUserAccess  TokenClass = "user_access"
)

type CertificateCriteria struct {
	Domains []string `json:"domains"`
	KeyType string   `json:"key_type,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
}

type RequestOptions struct {
	IfNoneMatch string
	RequestID   string
}

type ResponseMeta struct {
	StatusCode              int
	RequestID               string
	ETag                    string
	HeaderRetryAfterSeconds *int
}

func (m ResponseMeta) RetryAfterSeconds() (int, bool) {
	if m.HeaderRetryAfterSeconds == nil {
		return 0, false
	}
	return *m.HeaderRetryAfterSeconds, true
}

type CertificateResponse struct {
	Certificate Certificate `json:"certificate"`
}

type Certificate struct {
	ID               string     `json:"id"`
	Enabled          bool       `json:"enabled"`
	ApplicationID    string     `json:"application_id"`
	NormalizedSANs   []string   `json:"normalized_sans"`
	KeyType          string     `json:"key_type"`
	IssuerID         string     `json:"issuer_id"`
	IssuerName       string     `json:"issuer_name,omitempty"`
	Status           string     `json:"status"`
	LatestVersion    any        `json:"latest_version,omitempty"`
	FailureCode      *string    `json:"failure_code,omitempty"`
	FailureMessage   *string    `json:"failure_message,omitempty"`
	RevocationReason *string    `json:"revocation_reason,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
	userAgent  string
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

func WithUserAgent(userAgent string) Option {
	return func(c *Client) {
		c.userAgent = strings.TrimSpace(userAgent)
	}
}

func New(baseURL, token string, opts ...Option) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("parse Certhub URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, stderrors.New("Certhub URL must be absolute")
	}
	if err := ValidateApplicationToken(token); err != nil {
		return nil, err
	}
	c := &Client{
		baseURL:    parsed,
		token:      token,
		httpClient: http.DefaultClient,
		userAgent:  "certhub-go-client",
	}
	for _, opt := range opts {
		opt(c)
	}
	c.httpClient = clientWithSafeRedirects(c.httpClient)
	return c, nil
}

func ClassifyToken(token string) TokenClass {
	switch {
	case strings.HasPrefix(token, ApplicationTokenPrefix):
		return TokenClassApplication
	case strings.HasPrefix(token, UserAccessTokenPrefix):
		return TokenClassUserAccess
	default:
		return TokenClassUnknown
	}
}

func ValidateApplicationToken(token string) error {
	token = strings.TrimSpace(token)
	switch ClassifyToken(token) {
	case TokenClassApplication:
		secret := strings.TrimPrefix(token, ApplicationTokenPrefix)
		if !tokenSecretPattern.MatchString(secret) {
			return certerrors.NewLocal(certerrors.CodeInvalidToken, "Application token has an invalid format.")
		}
		return nil
	case TokenClassUserAccess:
		return certerrors.NewLocal(certerrors.CodeApplicationTokenRequired, "User access tokens are not accepted by sync clients.")
	default:
		if token == "" {
			return certerrors.NewLocal(certerrors.CodeApplicationTokenRequired, "Application token is required.")
		}
		return certerrors.NewLocal(certerrors.CodeInvalidToken, "Application token has an invalid format.")
	}
}

func (c *Client) EnsureCertificate(ctx context.Context, criteria CertificateCriteria, opts RequestOptions) (*CertificateResponse, ResponseMeta, error) {
	var out CertificateResponse
	meta, err := c.doJSON(ctx, http.MethodPost, "/v1/sync/certificates", criteria, opts, &out, http.StatusOK, http.StatusAccepted)
	if err != nil {
		return nil, meta, err
	}
	return &out, meta, nil
}

func (c *Client) GetTLSMaterial(ctx context.Context, criteria CertificateCriteria, opts RequestOptions) (*material.TLSMaterial, ResponseMeta, error) {
	var out material.TLSMaterial
	meta, err := c.doJSON(ctx, http.MethodPost, "/v1/sync/certificates/tls-material", criteria, opts, &out, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return nil, meta, err
	}
	if meta.StatusCode == http.StatusNoContent {
		return nil, meta, nil
	}
	return &out, meta, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, opts RequestOptions, out any, okStatuses ...int) (ResponseMeta, error) {
	var payload bytes.Buffer
	enc := json.NewEncoder(&payload)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return ResponseMeta{}, fmt.Errorf("encode request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), &payload)
	if err != nil {
		return ResponseMeta{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if opts.RequestID != "" {
		req.Header.Set("X-Request-ID", opts.RequestID)
	}
	if opts.IfNoneMatch != "" {
		req.Header.Set("If-None-Match", opts.IfNoneMatch)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ResponseMeta{}, err
	}
	defer resp.Body.Close()

	meta := responseMeta(resp)
	if statusAllowed(resp.StatusCode, okStatuses) {
		if resp.StatusCode == http.StatusNoContent {
			_, _ = io.Copy(io.Discard, resp.Body)
			return meta, nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return meta, fmt.Errorf("decode response body: %w", err)
		}
		return meta, nil
	}

	var errorResponse certerrors.Response
	if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
		return meta, fmt.Errorf("decode error response: status=%d request_id=%s: %w", resp.StatusCode, meta.RequestID, err)
	}
	return meta, certerrors.NewAPIError(resp.StatusCode, meta.RequestID, meta.HeaderRetryAfterSeconds, errorResponse.Error)
}

func (c *Client) endpoint(path string) string {
	next := *c.baseURL
	next.Path = path
	next.RawPath = ""
	next.RawQuery = ""
	next.Fragment = ""
	return next.String()
}

func responseMeta(resp *http.Response) ResponseMeta {
	meta := ResponseMeta{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("X-Request-ID"),
		ETag:       resp.Header.Get("ETag"),
	}
	if seconds, ok := certerrors.ParseRetryAfterSeconds(resp.Header.Get("Retry-After"), time.Now().UTC()); ok {
		meta.HeaderRetryAfterSeconds = &seconds
	}
	return meta
}

func statusAllowed(status int, allowed []int) bool {
	for _, candidate := range allowed {
		if status == candidate {
			return true
		}
	}
	return false
}

func clientWithSafeRedirects(httpClient *http.Client) *http.Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	copyClient := *httpClient
	previous := copyClient.CheckRedirect
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return stderrors.New("stopped after 10 redirects")
		}
		if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
			req.Header.Del("Authorization")
		}
		if previous != nil {
			return previous(req, via)
		}
		return nil
	}
	return &copyClient
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
