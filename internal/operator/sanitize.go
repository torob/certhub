package operator

import (
	"regexp"
	"strings"
)

var redactions = []struct {
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

func Sanitize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, redaction := range redactions {
		value = redaction.pattern.ReplaceAllString(value, redaction.replacement)
	}
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}
