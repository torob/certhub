package crypto

import (
	"net/url"
	"regexp"
	"strings"
)

const Redacted = "[redacted]"

var redactionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization\s*:\s*)(?:bearer\s+)?[^\s,;]+`),
	regexp.MustCompile(`(?i)(cookie\s*:\s*)[^\r\n]+`),
	regexp.MustCompile(`cth_(?:app|uat|urt)_v1_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`otpauth://[^\s"'<>]+`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)((?:password|totp_code|totp_secret|code_verifier|state|authorization_code|access_token|refresh_token|token|client_secret)\s*[=:]\s*)[^\s,;&]+`),
	regexp.MustCompile(`(?i)("?(?:password|totp_code|totp_secret|code_verifier|state|authorization_code|access_token|refresh_token|token|client_secret)"?\s*:\s*")[^"]*(")`),
	regexp.MustCompile(`(?i)("alg"\s*:\s*"AES-256-GCM"[^}]*"ciphertext"\s*:\s*")[^"]+(")`),
}

func RedactString(value string) string {
	out := redactURLUserinfo(value)
	for _, pattern := range redactionPatterns {
		out = pattern.ReplaceAllStringFunc(out, func(match string) string {
			sub := pattern.FindStringSubmatch(match)
			switch len(sub) {
			case 2:
				return sub[1] + Redacted
			case 3:
				return sub[1] + Redacted + sub[2]
			default:
				return Redacted
			}
		})
	}
	return out
}

func RedactValues(value string, canaries ...string) string {
	out := RedactString(value)
	for _, canary := range canaries {
		if canary == "" {
			continue
		}
		out = strings.ReplaceAll(out, canary, Redacted)
	}
	return out
}

func redactURLUserinfo(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value
	}
	changed := false
	for i, field := range fields {
		u, err := url.Parse(field)
		if err != nil || u.User == nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		u.User = url.User(Redacted)
		fields[i] = u.String()
		changed = true
	}
	if !changed {
		return value
	}
	return strings.Join(fields, " ")
}
