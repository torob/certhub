package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteSummaryRedactsSecrets(t *testing.T) {
	summary := Summary{Configured: 1, Failed: 1, Results: []ItemResult{{
		OutDir:       "/tmp/out",
		Domains:      []string{"api.example.com"},
		ErrorCode:    "request_failed",
		ErrorMessage: `https://user:secret@example.com Authorization: Bearer cth_app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Cookie: session=COOKIESECRET; csrftoken=CSRFSECRET {"data":{"tls.key":"BASE64KEY","tls.crt":"BASE64CRT"},"stringData":{"token":"STRINGTOKEN"},"private_key_pem":"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----","cert_pem":"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----"} token=value password: hunter2 client_secret=s3 api_key=k key=plain`,
		ExitCode:     ExitGeneral,
	}}}

	var stdout, stderr bytes.Buffer
	writeSummary(summary, commandOptions{}, &stdout, &stderr)
	if got := stderr.String(); leaksRedactionCanary(got) {
		t.Fatalf("human output leaked secret material: %q", got)
	}

	stdout.Reset()
	stderr.Reset()
	writeSummary(summary, commandOptions{json: true}, &stdout, &stderr)
	if got := stdout.String(); leaksRedactionCanary(got) {
		t.Fatalf("json output leaked secret material: %q", got)
	}
}

func leaksRedactionCanary(got string) bool {
	for _, leak := range []string{
		"cth_app_v1_", "PRIVATE KEY", "CERTIFICATE", "user:secret", "session=abc",
		"COOKIESECRET", "CSRFSECRET", "BASE64KEY", "BASE64CRT", "STRINGTOKEN",
		"token=value", "hunter2", "client_secret=s3", "api_key=k", "key=plain",
		`"tls.key"`, "public",
	} {
		if strings.Contains(got, leak) {
			return true
		}
	}
	return false
}
