package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrTLSCertificatePending = errors.New("tls certificate pending")

	errTLSFileMissing    = errors.New("tls certificate file missing")
	errTLSFileUnreadable = errors.New("tls certificate file unreadable")
	errTLSFileMalformed  = errors.New("tls certificate file malformed")
	errTLSFileMismatched = errors.New("tls certificate and key mismatch")
	errTLSCertInvalid    = errors.New("tls certificate invalid")
)

type TLSCertificateLoader struct {
	certFile     string
	keyFile      string
	hostname     string
	allowPending bool

	mu          sync.RWMutex
	cert        *tls.Certificate
	certModTime time.Time
	keyModTime  time.Time
	certSize    int64
	keySize     int64
}

func NewTLSCertificateLoader(cfg *Config) (*TLSCertificateLoader, error) {
	if cfg == nil || cfg.TLS.CertFile == "" {
		return nil, nil
	}
	loader := &TLSCertificateLoader{
		certFile:     cfg.TLS.CertFile,
		keyFile:      cfg.TLS.KeyFile,
		hostname:     cfg.Server.PublicHostname,
		allowPending: selfCertificateCurrentTLSPaths(cfg),
	}
	if err := loader.loadInitial(); err != nil {
		return nil, err
	}
	return loader, nil
}

func (l *TLSCertificateLoader) TLSConfig() *tls.Config {
	if l == nil {
		return nil
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: l.GetCertificate,
	}
}

func (l *TLSCertificateLoader) Pending() bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cert == nil
}

func (l *TLSCertificateLoader) ReadinessError() error {
	if l == nil {
		return nil
	}
	if err := l.ReloadIfChanged(); err != nil {
		return err
	}
	cert := l.current()
	if cert == nil {
		return ErrTLSCertificatePending
	}
	return validateTLSCertificate(cert, l.hostname, time.Now())
}

func (l *TLSCertificateLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if l == nil {
		return nil, ErrTLSCertificatePending
	}
	reloadErr := l.ReloadIfChanged()
	cert := l.current()
	if cert == nil {
		if reloadErr != nil {
			return nil, reloadErr
		}
		return nil, ErrTLSCertificatePending
	}
	if err := validateTLSCertificate(cert, l.hostname, time.Now()); err != nil {
		if reloadErr != nil {
			return nil, reloadErr
		}
		return nil, err
	}
	return cert, nil
}

func (l *TLSCertificateLoader) ReloadIfChanged() error {
	certInfo, keyInfo, err := statTLSFiles(l.certFile, l.keyFile)
	if err != nil {
		if l.allowPending && errors.Is(err, errTLSFileMissing) {
			if err := validatePartialTLSFiles(l.certFile, l.keyFile); err != nil {
				return err
			}
			return ErrTLSCertificatePending
		}
		return err
	}

	l.mu.RLock()
	unchanged := l.cert != nil &&
		l.certModTime.Equal(certInfo.ModTime()) &&
		l.keyModTime.Equal(keyInfo.ModTime()) &&
		l.certSize == certInfo.Size() &&
		l.keySize == keyInfo.Size()
	l.mu.RUnlock()
	if unchanged {
		return nil
	}

	cert, err := loadTLSCertificatePair(l.certFile, l.keyFile, l.hostname, time.Now())
	if err != nil {
		return err
	}
	l.store(cert, certInfo, keyInfo)
	return nil
}

func (l *TLSCertificateLoader) loadInitial() error {
	certInfo, keyInfo, err := statTLSFiles(l.certFile, l.keyFile)
	if err != nil {
		if l.allowPending && errors.Is(err, errTLSFileMissing) {
			if err := validatePartialTLSFiles(l.certFile, l.keyFile); err != nil {
				return err
			}
			return nil
		}
		return err
	}
	cert, err := loadTLSCertificatePair(l.certFile, l.keyFile, l.hostname, time.Now())
	if err != nil {
		return err
	}
	l.store(cert, certInfo, keyInfo)
	return nil
}

func (l *TLSCertificateLoader) current() *tls.Certificate {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.cert == nil {
		return nil
	}
	cert := *l.cert
	return &cert
}

func (l *TLSCertificateLoader) store(cert tls.Certificate, certInfo, keyInfo os.FileInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cert = &cert
	l.certModTime = certInfo.ModTime()
	l.keyModTime = keyInfo.ModTime()
	l.certSize = certInfo.Size()
	l.keySize = keyInfo.Size()
}

func selfCertificateCurrentTLSPaths(cfg *Config) bool {
	if cfg == nil || !cfg.SelfCertificate.SyncEnabled || cfg.SelfCertificate.OutputDir == "" {
		return false
	}
	return sameCleanPath(cfg.TLS.CertFile, filepath.Join(cfg.SelfCertificate.OutputDir, "current", "fullchain.pem")) &&
		sameCleanPath(cfg.TLS.KeyFile, filepath.Join(cfg.SelfCertificate.OutputDir, "current", "privkey.pem"))
}

func sameCleanPath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func statTLSFiles(certFile, keyFile string) (os.FileInfo, os.FileInfo, error) {
	certInfo, err := os.Stat(certFile)
	if err != nil {
		return nil, nil, tlsValidationError("tls.cert_file", fileAccessReason(err), fileAccessSentinel(err))
	}
	if !certInfo.Mode().IsRegular() {
		return nil, nil, tlsValidationError("tls.cert_file", "must be a regular file", errTLSFileUnreadable)
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return nil, nil, tlsValidationError("tls.key_file", fileAccessReason(err), fileAccessSentinel(err))
	}
	if !keyInfo.Mode().IsRegular() {
		return nil, nil, tlsValidationError("tls.key_file", "must be a regular file", errTLSFileUnreadable)
	}
	return certInfo, keyInfo, nil
}

func fileAccessReason(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "is missing"
	}
	return "is unreadable"
}

func fileAccessSentinel(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return errTLSFileMissing
	}
	return errTLSFileUnreadable
}

func validatePartialTLSFiles(certFile, keyFile string) error {
	if exists, err := regularFileExists(certFile); err != nil {
		return err
	} else if exists {
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return tlsValidationError("tls.cert_file", "is unreadable", errTLSFileUnreadable)
		}
		if err := parseCertificatePEM(certPEM); err != nil {
			return tlsValidationError("tls.cert_file", "is malformed", errTLSFileMalformed)
		}
	}
	if exists, err := regularFileExists(keyFile); err != nil {
		return err
	} else if exists {
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return tlsValidationError("tls.key_file", "is unreadable", errTLSFileUnreadable)
		}
		if err := parsePrivateKeyPEM(keyPEM); err != nil {
			return tlsValidationError("tls.key_file", "is malformed", errTLSFileMalformed)
		}
	}
	return nil
}

func regularFileExists(name string) (bool, error) {
	info, err := os.Stat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, tlsValidationError(fileField(name), "is unreadable", errTLSFileUnreadable)
	}
	if !info.Mode().IsRegular() {
		return false, tlsValidationError(fileField(name), "must be a regular file", errTLSFileUnreadable)
	}
	return true, nil
}

func fileField(name string) string {
	if strings.HasSuffix(filepath.Clean(name), filepath.Clean("privkey.pem")) {
		return "tls.key_file"
	}
	return "tls.cert_file"
}

func loadTLSCertificatePair(certFile, keyFile, hostname string, now time.Time) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, tlsValidationError("tls.cert_file", fileAccessReason(err), fileAccessSentinel(err))
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, tlsValidationError("tls.key_file", fileAccessReason(err), fileAccessSentinel(err))
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		reason := "is malformed"
		sentinel := errTLSFileMalformed
		if strings.Contains(err.Error(), "private key does not match") {
			reason = "does not match tls.key_file"
			sentinel = errTLSFileMismatched
		}
		return tls.Certificate{}, tlsValidationError("tls.cert_file", reason, sentinel)
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, tlsValidationError("tls.cert_file", "is malformed", errTLSFileMalformed)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, tlsValidationError("tls.cert_file", "is malformed", errTLSFileMalformed)
	}
	cert.Leaf = leaf
	if err := validateTLSCertificate(&cert, hostname, now); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func validateTLSCertificate(cert *tls.Certificate, hostname string, now time.Time) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return tlsValidationError("tls.cert_file", "is malformed", errTLSFileMalformed)
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tlsValidationError("tls.cert_file", "is malformed", errTLSFileMalformed)
		}
	}
	if now.Before(leaf.NotBefore) {
		return tlsValidationError("tls.cert_file", "is not valid yet", errTLSCertInvalid)
	}
	if now.After(leaf.NotAfter) {
		return tlsValidationError("tls.cert_file", "is expired", errTLSCertInvalid)
	}
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return tlsValidationError("tls.cert_file", "does not match server.public_hostname", errTLSCertInvalid)
		}
	}
	return nil
}

func parseCertificatePEM(data []byte) error {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return errTLSFileMalformed
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return err
		}
		return nil
	}
}

func parsePrivateKeyPEM(data []byte) error {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return errTLSFileMalformed
		}
		data = rest
		switch block.Type {
		case "RSA PRIVATE KEY":
			_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			return err
		case "EC PRIVATE KEY":
			_, err := x509.ParseECPrivateKey(block.Bytes)
			return err
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			switch key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
				return nil
			default:
				return errTLSFileMalformed
			}
		}
	}
}

func tlsValidationError(field, reason string, sentinel error) error {
	if field == "" {
		field = "tls"
	}
	return fmt.Errorf("%s: %s: %w", field, reason, sentinel)
}
