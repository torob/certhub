package material

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"slices"
	"testing"
	"time"
)

func TestBuildTLSArchiveUsesFixedSafeEntries(t *testing.T) {
	archive, err := BuildTLSArchive(TLSMaterial{
		CertificateID:        "cert-id",
		ApplicationID:        "app-id",
		Domains:              []string{"*.example.com"},
		KeyType:              "ecdsa-p256",
		IssuerID:             "issuer-id",
		IssuerName:           "letsencrypt",
		Version:              1,
		CertPEM:              "CERT",
		ChainPEM:             "CHAIN",
		FullchainPEM:         "FULLCHAIN",
		PrivateKeyPEM:        "PRIVATE",
		NotBefore:            time.Unix(1, 0).UTC(),
		NotAfter:             time.Unix(2, 0).UTC(),
		SerialNumber:         "01",
		FingerprintSHA256:    "fp",
		KeyFingerprintSHA256: "kfp",
		MaterialETag:         `"etag"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		if header.Name == "metadata.json" {
			data, _ := io.ReadAll(tr)
			if bytes.Contains(data, []byte("PRIVATE")) {
				t.Fatalf("metadata leaked private key: %s", data)
			}
		}
	}
	want := []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "metadata.json"}
	if !slices.Equal(names, want) {
		t.Fatalf("entries = %#v want %#v", names, want)
	}
}

func TestSafeArchiveBasename(t *testing.T) {
	if got := SafeArchiveBasename([]string{"*.Torob.Dev."}, "fallback"); got != "wildcard_torob_dev" {
		t.Fatalf("basename = %q", got)
	}
	if got := SafeArchiveBasename(nil, "018f6a8e-4f7d-7c2b-a4b9-7c771a4f1d41"); got != "018f6a8e-4f7d-7c2b-a4b9-7c771a4f1d41" {
		t.Fatalf("fallback basename = %q", got)
	}
}
