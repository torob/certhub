package main

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"time"

	"github.com/torob/certhub/pkg/certhubclient"
	certerrors "github.com/torob/certhub/pkg/errors"
)

const (
	ExitSuccess          = 0
	ExitGeneral          = 1
	ExitInvalidArguments = 2
	ExitAuthFailed       = 3
	ExitForbidden        = 4
	ExitNotFound         = 5
	ExitNotReady         = 6
	ExitIssuanceFailed   = 7
	ExitTimeout          = 8
	ExitFilesystem       = 9
)

type SyncRunner struct {
	cfg    Config
	plan   []PlanItem
	client *certhubclient.Client
}

type Summary struct {
	Changed    bool         `json:"changed"`
	Configured int          `json:"configured"`
	Succeeded  int          `json:"succeeded"`
	Failed     int          `json:"failed"`
	Results    []ItemResult `json:"results"`
}

type ItemResult struct {
	Changed       bool     `json:"changed"`
	OutDir        string   `json:"out_dir"`
	Domains       []string `json:"domains"`
	CertificateID string   `json:"certificate_id,omitempty"`
	Version       int      `json:"version,omitempty"`
	MaterialETag  string   `json:"material_etag,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	RequestID     string   `json:"request_id,omitempty"`
	ErrorCode     string   `json:"error_code,omitempty"`
	ErrorMessage  string   `json:"error_message,omitempty"`
	ExitCode      int      `json:"exit_code,omitempty"`
}

func NewSyncRunner(cfg Config, plan []PlanItem) (*SyncRunner, error) {
	client, err := certhubclient.New(cfg.URL, cfg.Token, certhubclient.WithUserAgent("certhub-cli"))
	if err != nil {
		return nil, err
	}
	return &SyncRunner{cfg: cfg, plan: plan, client: client}, nil
}

func (r *SyncRunner) RunOnce(ctx context.Context) Summary {
	summary := Summary{Configured: len(r.plan), Results: make([]ItemResult, 0, len(r.plan))}
	for _, item := range r.plan {
		result := r.syncOne(ctx, item)
		if result.Changed {
			summary.Changed = true
		}
		if result.ExitCode == ExitSuccess {
			summary.Succeeded++
		} else {
			summary.Failed++
		}
		summary.Results = append(summary.Results, result)
		if result.ExitCode != ExitSuccess && r.cfg.Sync.FailFast {
			break
		}
	}
	return summary
}

func (r *SyncRunner) syncOne(ctx context.Context, item PlanItem) ItemResult {
	result := ItemResult{OutDir: item.OutDir, Domains: item.Criteria.Domains}
	deadline := time.Now().Add(item.Timeout)
	created := false
	for {
		metadata, _ := ReadMetadata(item.OutDir)
		ifNoneMatch := ""
		if !item.Force && metadata.MaterialETag != "" {
			ifNoneMatch = metadata.MaterialETag
		}
		material, meta, err := r.client.GetTLSMaterial(ctx, item.Criteria, certhubclient.RequestOptions{
			IfNoneMatch: ifNoneMatch,
			RequestID:   newRequestID(),
		})
		result.RequestID = meta.RequestID
		if err == nil {
			if material == nil && meta.StatusCode == http.StatusNoContent {
				result.Changed = false
				result.MaterialETag = metadata.MaterialETag
				return result
			}
			if err := PublishMaterial(item.OutDir, *material, time.Now().UTC()); err != nil {
				result.ExitCode = ExitFilesystem
				result.ErrorCode = "local_filesystem_write_failed"
				result.ErrorMessage = err.Error()
				return result
			}
			result.Changed = true
			result.CertificateID = material.CertificateID
			result.Version = material.Version
			result.MaterialETag = material.MaterialETag
			result.NotAfter = material.NotAfter.Format(time.RFC3339)
			return result
		}
		var apiErr *certerrors.APIError
		if !stderrors.As(err, &apiErr) {
			result.ExitCode = ExitGeneral
			result.ErrorCode = "request_failed"
			result.ErrorMessage = err.Error()
			return result
		}
		result.ErrorCode = apiErr.Envelope.Code
		result.ErrorMessage = apiErr.Envelope.Message
		result.RequestID = apiErr.RequestID
		switch apiErr.Envelope.Code {
		case certerrors.CodeCertificateNotFound:
			if created {
				result.ExitCode = ExitNotFound
				return result
			}
			if _, ensureMeta, ensureErr := r.client.EnsureCertificate(ctx, item.Criteria, certhubclient.RequestOptions{RequestID: newRequestID()}); ensureErr != nil {
				result.RequestID = ensureMeta.RequestID
				return resultFromError(item, ensureErr, ensureMeta.RequestID)
			} else if seconds, ok := ensureMeta.RetryAfterSeconds(); ok {
				if !sleepUntilRetry(ctx, item, time.Duration(seconds)*time.Second, deadline) {
					result.ExitCode = ExitTimeout
					result.ErrorCode = "timeout"
					result.ErrorMessage = "timed out waiting for certificate material"
					return result
				}
			}
			created = true
		case certerrors.CodeCertificateNotReady, certerrors.CodeCertificateExpired:
			if !item.Wait {
				result.ExitCode = ExitNotReady
				return result
			}
			if !sleepForRetry(ctx, item, apiErr, deadline) {
				result.ExitCode = ExitTimeout
				result.ErrorCode = "timeout"
				result.ErrorMessage = "timed out waiting for certificate material"
				return result
			}
		default:
			result.ExitCode = exitCodeForError(apiErr)
			return result
		}
	}
}

func resultFromError(item PlanItem, err error, requestID string) ItemResult {
	result := ItemResult{OutDir: item.OutDir, Domains: item.Criteria.Domains, RequestID: requestID, ExitCode: exitCodeForError(err)}
	var apiErr *certerrors.APIError
	if stderrors.As(err, &apiErr) {
		result.ErrorCode = apiErr.Envelope.Code
		result.ErrorMessage = apiErr.Envelope.Message
		if apiErr.RequestID != "" {
			result.RequestID = apiErr.RequestID
		}
	} else {
		result.ErrorCode = "request_failed"
		result.ErrorMessage = err.Error()
	}
	return result
}

func sleepForRetry(ctx context.Context, item PlanItem, apiErr *certerrors.APIError, deadline time.Time) bool {
	delay := item.PollInterval
	if seconds, ok := apiErr.RetryAfterSeconds(); ok {
		delay = time.Duration(seconds) * time.Second
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	if delay > remaining {
		delay = remaining
	}
	return sleepContext(ctx, delay)
}

func sleepUntilRetry(ctx context.Context, item PlanItem, delay time.Duration, deadline time.Time) bool {
	if delay <= 0 {
		delay = item.PollInterval
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	if delay > remaining {
		delay = remaining
	}
	return sleepContext(ctx, delay)
}

func exitCodeForError(err error) int {
	var apiErr *certerrors.APIError
	if !stderrors.As(err, &apiErr) {
		return ExitGeneral
	}
	switch apiErr.Envelope.Code {
	case certerrors.CodeInvalidRequest, "invalid_domain", "not_acceptable":
		return ExitInvalidArguments
	case certerrors.CodeInvalidToken, "invalid_credentials", "session_expired", certerrors.CodeRefreshTokenNotAllowed:
		return ExitAuthFailed
	case certerrors.CodeApplicationTokenRequired, certerrors.CodeUserTokenRequired, "application_access_denied", "application_source_ip_denied", "domain_not_authorized":
		return ExitForbidden
	case certerrors.CodeCertificateNotFound:
		return ExitNotFound
	case certerrors.CodeCertificateNotReady, certerrors.CodeCertificateExpired:
		return ExitNotReady
	case certerrors.CodeCertificateIssuanceFailed, certerrors.CodeCertificateRevoked, certerrors.CodeCertificateNoActiveVersion:
		return ExitIssuanceFailed
	case certerrors.CodeServiceUnavailable, certerrors.CodeIssuerUnavailable, certerrors.CodeDNSProviderUnavailable, certerrors.CodeDNSZoneDiscoveryFailed, certerrors.CodeRateLimited:
		return ExitTimeout
	case certerrors.CodeIssuerNotConfigured:
		return ExitGeneral
	default:
		return ExitGeneral
	}
}

func (s Summary) ExitCode() int {
	exit := ExitSuccess
	for _, result := range s.Results {
		if result.ExitCode > exit {
			exit = result.ExitCode
		}
	}
	return exit
}

func newRequestID() string {
	return fmt.Sprintf("cli-%d", time.Now().UnixNano())
}
