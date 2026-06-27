package certcriteria

import "testing"

func TestNormalizeSortsSANsAndDefaultsKeyType(t *testing.T) {
	got, err := Normalize(Criteria{Domains: []string{"WWW.Example.COM.", "*.Example.COM"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyType != DefaultKeyType {
		t.Fatalf("key type = %q", got.KeyType)
	}
	want := []string{"*.example.com", "www.example.com"}
	if len(got.Domains) != len(want) {
		t.Fatalf("domains = %#v", got.Domains)
	}
	for i := range want {
		if got.Domains[i] != want[i] {
			t.Fatalf("domains = %#v want %#v", got.Domains, want)
		}
	}
}

func TestNormalizeRejectsDuplicateAndInvalidKeyType(t *testing.T) {
	if _, err := Normalize(Criteria{Domains: []string{"api.example.com", "API.example.com"}}); err == nil {
		t.Fatalf("duplicate SANs accepted")
	}
	if _, err := Normalize(Criteria{Domains: []string{"api.example.com"}, KeyType: "rsa-1024"}); err == nil {
		t.Fatalf("invalid key type accepted")
	}
}
