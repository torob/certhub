package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSCertificateLoaderRejectsUnusableCertificates(t *testing.T) {
	tests := map[string]struct {
		hostname  string
		dnsNames  []string
		notBefore time.Time
		notAfter  time.Time
	}{
		"expired": {
			hostname:  "certhub.example.com",
			dnsNames:  []string{"certhub.example.com"},
			notBefore: time.Now().Add(-2 * time.Hour),
			notAfter:  time.Now().Add(-time.Hour),
		},
		"not_yet_valid": {
			hostname:  "certhub.example.com",
			dnsNames:  []string{"certhub.example.com"},
			notBefore: time.Now().Add(time.Hour),
			notAfter:  time.Now().Add(2 * time.Hour),
		},
		"wrong_hostname": {
			hostname:  "certhub.example.com",
			dnsNames:  []string{"other.example.com"},
			notBefore: time.Now().Add(-time.Hour),
			notAfter:  time.Now().Add(time.Hour),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			certFile, keyFile := writeTLSMaterial(t, tc.dnsNames, tc.notBefore, tc.notAfter)
			_, err := NewTLSCertificateLoader(&Config{
				Server: ServerConfig{PublicHostname: tc.hostname},
				TLS:    TLSConfig{CertFile: certFile, KeyFile: keyFile},
			})
			if err == nil {
				t.Fatalf("NewTLSCertificateLoader() succeeded")
			}
			if !errors.Is(err, errTLSCertInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTLSCertificateLoaderRetainsLastGoodButReadinessReportsReloadFailure(t *testing.T) {
	certFile, keyFile := writeTLSMaterial(t, []string{"certhub.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	loader, err := NewTLSCertificateLoader(&Config{
		Server: ServerConfig{PublicHostname: "certhub.example.com"},
		TLS:    TLSConfig{CertFile: certFile, KeyFile: keyFile},
	})
	if err != nil {
		t.Fatalf("NewTLSCertificateLoader() error = %v", err)
	}
	if err := loader.ReadinessError(); err != nil {
		t.Fatalf("initial readiness error = %v", err)
	}

	writeTLSMaterialAt(t, certFile, keyFile, []string{"other.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	cert, err := loader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate() did not retain last-good certificate: %v", err)
	}
	if cert == nil || cert.Leaf == nil || cert.Leaf.DNSNames[0] != "certhub.example.com" {
		t.Fatalf("current certificate = %#v", cert)
	}
	err = loader.ReadinessError()
	if err == nil {
		t.Fatalf("ReadinessError() succeeded after invalid reload")
	}
	if !errors.Is(err, errTLSCertInvalid) {
		t.Fatalf("readiness error = %v", err)
	}
}

func TestTLSCertificateLoaderRejectsExpiredCurrentCertificate(t *testing.T) {
	certFile, keyFile := writeTLSMaterial(t, []string{"certhub.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	loader, err := NewTLSCertificateLoader(&Config{
		Server: ServerConfig{PublicHostname: "certhub.example.com"},
		TLS:    TLSConfig{CertFile: certFile, KeyFile: keyFile},
	})
	if err != nil {
		t.Fatalf("NewTLSCertificateLoader() error = %v", err)
	}

	loader.mu.Lock()
	loader.cert.Leaf.NotAfter = time.Now().Add(-time.Second)
	loader.mu.Unlock()

	if _, err := loader.GetCertificate(nil); !errors.Is(err, errTLSCertInvalid) {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	if err := loader.ReadinessError(); !errors.Is(err, errTLSCertInvalid) {
		t.Fatalf("ReadinessError() error = %v", err)
	}
}

func writeTLSMaterial(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	writeTLSMaterialAt(t, certFile, keyFile, dnsNames, notBefore, notAfter)
	return certFile, keyFile
}

func writeTLSMaterialAt(t *testing.T, certFile, keyFile string, dnsNames []string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFileHandle, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certFileHandle.Close()
		t.Fatal(err)
	}
	if err := certFileHandle.Close(); err != nil {
		t.Fatal(err)
	}
	keyFileHandle, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFileHandle, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		_ = keyFileHandle.Close()
		t.Fatal(err)
	}
	if err := keyFileHandle.Close(); err != nil {
		t.Fatal(err)
	}
}
