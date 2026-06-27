package storage

import "testing"

func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("USER@Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got != "user@example.com" {
		t.Fatalf("normalized email = %q", got)
	}
	for _, value := range []string{" Name <user@example.com>", "user@example.com ", "not-an-email", "a\n@example.com"} {
		if _, err := NormalizeEmail(value); err == nil {
			t.Fatalf("NormalizeEmail(%q) succeeded", value)
		}
	}
}

func TestNormalizeTrustedSourceCIDRs(t *testing.T) {
	got, err := NormalizeTrustedSourceCIDRs([]string{"203.0.113.10", "2001:db8::10", "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::10/128", "203.0.113.0/24", "203.0.113.10/32"}
	if len(got) != len(want) {
		t.Fatalf("cidrs = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cidrs = %#v want %#v", got, want)
		}
	}
	if _, err := NormalizeTrustedSourceCIDRs([]string{"203.0.113.10", "203.0.113.10/32"}); err == nil {
		t.Fatalf("duplicate CIDRs were accepted")
	}
}

func TestNormalizeDomainScopeValue(t *testing.T) {
	for input, want := range map[string]string{
		"Torob.DEV.":        "torob.dev",
		"*.Api.Torob.DEV.":  "*.api.torob.dev",
		"bücher.example":    "xn--bcher-kva.example",
		"*.bücher.example.": "*.xn--bcher-kva.example",
	} {
		got, err := NormalizeDomainScopeValue(input)
		if err != nil {
			t.Fatalf("NormalizeDomainScopeValue(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeDomainScopeValue(%q) = %q want %q", input, got, want)
		}
	}
	for _, input := range []string{"com", "*.com", "co.uk", "*.co.uk", "*.*.torob.dev", "a.*.torob.dev", "localhost"} {
		if _, err := NormalizeDomainScopeValue(input); err == nil {
			t.Fatalf("NormalizeDomainScopeValue(%q) succeeded", input)
		}
	}
}

func TestValidatePublicHTTPSURL(t *testing.T) {
	for _, value := range []string{
		"https://acme-v02.api.letsencrypt.org/directory",
		"https://example.com:8443/path",
	} {
		if err := ValidatePublicHTTPSURL(&value, "url"); err != nil {
			t.Fatalf("ValidatePublicHTTPSURL(%q): %v", value, err)
		}
	}
	for _, value := range []string{
		"http://example.com",
		"https://user:pass@example.com/path",
		"https://example.com/#fragment",
		"https://localhost/directory",
		"https://127.0.0.1/directory",
		"https://10.0.0.1/directory",
		"https://[fe80::1]/directory",
	} {
		if err := ValidatePublicHTTPSURL(&value, "url"); err == nil {
			t.Fatalf("ValidatePublicHTTPSURL(%q) succeeded", value)
		}
	}
}
