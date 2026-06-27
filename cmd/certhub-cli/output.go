package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

var outputRedactions = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`cth_(?:app|uat|urt)_v1_[A-Za-z0-9_-]{43}`), "[REDACTED_TOKEN]"},
	{regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`), "[REDACTED_PEM]"},
	{regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[^,\s;]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)(cookie:\s*)[^,\r\n{}]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)\b(token|password|client_secret|secret|api[_-]?key|key)\s*([:=])\s*([^,\s;&]+)`), "${1}${2}[REDACTED]"},
	{regexp.MustCompile(`(?i)(https?://)[^/\s:@]+:[^/\s@]+@`), "${1}[REDACTED]@"},
	{regexp.MustCompile(`(?i)("(?:cert|chain|fullchain|private_key)_pem"\s*:\s*")([^"\\]|\\.)*(")`), "${1}[REDACTED]${3}"},
	{regexp.MustCompile(`(?i)("(?:data|stringData|token|password|client_secret|secret|api_key)"\s*:\s*)("[^"]*"|\{[^}]*\})`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)(private[_-]?key(?:_pem)?\s*[:=]\s*)\S+`), "${1}[REDACTED]"},
}

func writeSummary(summary Summary, opts commandOptions, stdout, stderr io.Writer) {
	summary = redactSummary(summary)
	if opts.json {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(summary)
		return
	}
	for _, result := range summary.Results {
		if result.ExitCode == ExitSuccess {
			if opts.quiet {
				continue
			}
			if result.Changed {
				fmt.Fprintf(stdout, "updated %s certificate_id=%s version=%d not_after=%s\n", result.OutDir, result.CertificateID, result.Version, result.NotAfter)
			} else {
				fmt.Fprintf(stdout, "current %s material_etag=%s\n", result.OutDir, result.MaterialETag)
			}
			continue
		}
		fmt.Fprintf(stderr, "failed %s domains=%v code=%s request_id=%s: %s\n", result.OutDir, result.Domains, result.ErrorCode, result.RequestID, result.ErrorMessage)
	}
}

func redactSummary(summary Summary) Summary {
	summary.Results = append([]ItemResult(nil), summary.Results...)
	for i := range summary.Results {
		summary.Results[i].ErrorMessage = redactOutput(summary.Results[i].ErrorMessage)
	}
	return summary
}

func redactOutput(value string) string {
	for _, redaction := range outputRedactions {
		value = redaction.pattern.ReplaceAllString(value, redaction.replacement)
	}
	return value
}
