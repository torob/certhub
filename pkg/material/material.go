package material

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type TLSMaterial struct {
	CertificateID        string    `json:"certificate_id"`
	ApplicationID        string    `json:"application_id"`
	Domains              []string  `json:"domains"`
	KeyType              string    `json:"key_type"`
	IssuerID             string    `json:"issuer_id"`
	IssuerName           string    `json:"issuer_name"`
	Version              int       `json:"version"`
	CertPEM              string    `json:"cert_pem"`
	ChainPEM             string    `json:"chain_pem"`
	FullchainPEM         string    `json:"fullchain_pem"`
	PrivateKeyPEM        string    `json:"private_key_pem"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	SerialNumber         string    `json:"serial_number"`
	FingerprintSHA256    string    `json:"fingerprint_sha256"`
	KeyFingerprintSHA256 string    `json:"key_fingerprint_sha256"`
	MaterialETag         string    `json:"material_etag"`
}

func BuildTLSArchive(value TLSMaterial) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "cert.pem", data: []byte(value.CertPEM)},
		{name: "chain.pem", data: []byte(value.ChainPEM)},
		{name: "fullchain.pem", data: []byte(value.FullchainPEM)},
		{name: "privkey.pem", data: []byte(value.PrivateKeyPEM)},
	} {
		if err := writeTarEntry(tw, entry.name, entry.data); err != nil {
			return nil, err
		}
	}
	metadata := value
	metadata.PrivateKeyPEM = ""
	metadata.CertPEM = ""
	metadata.ChainPEM = ""
	metadata.FullchainPEM = ""
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeTarEntry(tw, "metadata.json", append(data, '\n')); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func SafeArchiveBasename(domains []string, fallback string) string {
	value := fallback
	if len(domains) > 0 && domains[0] != "" {
		value = domains[0]
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	value = strings.TrimPrefix(value, "*.")
	if len(domains) > 0 && strings.HasPrefix(domains[0], "*.") {
		value = "wildcard_" + value
	}
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.ReplaceAll(value, "*", "wildcard")
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			continue
		}
		if r == '_' {
			if lastUnderscore {
				continue
			}
			lastUnderscore = true
		} else {
			lastUnderscore = false
		}
		b.WriteRune(r)
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "certificate"
	}
	return out
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return errors.New("unsafe archive entry")
	}
	header := &tar.Header{
		Name: name,
		Mode: 0o600,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
