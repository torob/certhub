package certificates

import "testing"

func TestNormalizeSANsSortsDedupesAndNormalizes(t *testing.T) {
	got, err := NormalizeSANs([]string{"API.Example.COM.", "bücher.example", "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "xn--bcher-kva.example"}
	if len(got) != len(want) {
		t.Fatalf("sans = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sans = %#v want %#v", got, want)
		}
	}
}

func TestNormalizeSANsRejectsInvalidWildcard(t *testing.T) {
	for _, value := range []string{"*.*.example.com", "api.*.example.com", "localhost"} {
		if _, err := NormalizeSANs([]string{value}); err == nil {
			t.Fatalf("NormalizeSANs(%q) succeeded", value)
		}
	}
}

func TestNormalizeSANsAllowsExactAndCorrespondingWildcard(t *testing.T) {
	got, err := NormalizeSANs([]string{"Example.COM.", "*.Example.COM."})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.example.com", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("sans = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sans = %#v want %#v", got, want)
		}
	}
}

func TestStoreMaterialValidationRequiresStrongETagAndFingerprints(t *testing.T) {
	err := validateStoreMaterial(&StoreMaterialParams{
		CertificateVersionID:   "12345678-1234-4234-9234-123456789abc",
		CertPEM:                "cert",
		ChainPEM:               "chain",
		FullchainPEM:           "fullchain",
		PrivateKeyPEMEncrypted: `{"version":"1"}`,
		NotBefore:              testTime(),
		NotAfter:               testTime().AddDate(0, 0, 90),
		SerialNumber:           "01",
		FingerprintSHA256:      "abc",
		KeyFingerprintSHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
		MaterialETag:           "weak",
	})
	if err == nil {
		t.Fatalf("invalid material was accepted")
	}
}
