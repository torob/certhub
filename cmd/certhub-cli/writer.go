package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/torob/certhub/pkg/material"
)

type Metadata struct {
	Domains           []string  `json:"domains"`
	KeyType           string    `json:"key_type"`
	Issuer            string    `json:"issuer,omitempty"`
	CertificateID     string    `json:"certificate_id"`
	Version           int       `json:"version"`
	MaterialETag      string    `json:"material_etag"`
	SerialNumber      string    `json:"serial_number"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	LastSyncedAt      time.Time `json:"last_synced_at"`
}

func ReadMetadata(outDir string) (Metadata, error) {
	data, err := os.ReadFile(filepath.Join(outDir, "current", ".certhub-material.json"))
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func PublishMaterial(outDir string, mat material.TLSMaterial, now time.Time) error {
	if err := prepareOutDir(outDir); err != nil {
		return err
	}
	unlock, err := lockOutDir(outDir)
	if err != nil {
		return err
	}
	defer unlock()
	if err := safeCurrentSymlink(outDir); err != nil {
		return err
	}
	releasesDir := filepath.Join(outDir, "releases")
	stagingRoot := filepath.Join(outDir, ".certhub-staging")
	if err := os.MkdirAll(releasesDir, 0o750); err != nil {
		return fmt.Errorf("create releases: %w", err)
	}
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		return fmt.Errorf("create staging root: %w", err)
	}
	if err := safeExistingDir(releasesDir); err != nil {
		return err
	}
	if err := safeExistingDir(stagingRoot); err != nil {
		return err
	}
	generation := releaseName(mat, now)
	stagingDir := filepath.Join(stagingRoot, generation)
	releaseDir := filepath.Join(releasesDir, generation)
	if err := os.Mkdir(stagingDir, 0o750); err != nil {
		return fmt.Errorf("create staging release: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stagingDir)
		}
	}()
	files := []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"cert.pem", mat.CertPEM, 0o644},
		{"chain.pem", mat.ChainPEM, 0o644},
		{"fullchain.pem", mat.FullchainPEM, 0o644},
		{"privkey.pem", mat.PrivateKeyPEM, 0o600},
	}
	for _, file := range files {
		if err := writeReleaseFile(stagingDir, file.name, []byte(file.data), file.mode); err != nil {
			return err
		}
	}
	metadata := Metadata{
		Domains:           mat.Domains,
		KeyType:           mat.KeyType,
		Issuer:            mat.IssuerName,
		CertificateID:     mat.CertificateID,
		Version:           mat.Version,
		MaterialETag:      mat.MaterialETag,
		SerialNumber:      mat.SerialNumber,
		FingerprintSHA256: mat.FingerprintSHA256,
		NotBefore:         mat.NotBefore,
		NotAfter:          mat.NotAfter,
		LastSyncedAt:      now.UTC(),
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	if err := writeReleaseFile(stagingDir, ".certhub-material.json", append(data, '\n'), 0o644); err != nil {
		return err
	}
	if err := fsyncDir(stagingDir); err != nil {
		return err
	}
	if err := os.Rename(stagingDir, releaseDir); err != nil {
		return fmt.Errorf("publish release: %w", err)
	}
	cleanup = false
	if err := fsyncDir(releasesDir); err != nil {
		return err
	}
	if err := safeCurrentSymlink(outDir); err != nil {
		return err
	}
	linkName := filepath.Join(outDir, ".current-"+generation)
	if err := os.Symlink(filepath.Join("releases", generation), linkName); err != nil {
		return fmt.Errorf("create current symlink: %w", err)
	}
	if err := os.Rename(linkName, filepath.Join(outDir, "current")); err != nil {
		_ = os.Remove(linkName)
		return fmt.Errorf("switch current symlink: %w", err)
	}
	return fsyncDir(outDir)
}

func prepareOutDir(outDir string) error {
	if outDir == "" {
		return fmt.Errorf("out_dir is required")
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("create out_dir: %w", err)
	}
	return safeExistingDir(outDir)
}

func safeExistingDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a non-symlink directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s has unsafe permissions", path)
	}
	if err := ownerIsCurrentOrRoot(info, path); err != nil {
		return err
	}
	return nil
}

func safeCurrentSymlink(outDir string) error {
	current := filepath.Join(outDir, "current")
	info, err := os.Lstat(current)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat current symlink: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s must be a symlink", current)
	}
	target, err := os.Readlink(current)
	if err != nil {
		return fmt.Errorf("read current symlink: %w", err)
	}
	if filepath.IsAbs(target) {
		return fmt.Errorf("%s must use a relative target", current)
	}
	clean := filepath.Clean(target)
	if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || clean == ".." {
		return fmt.Errorf("%s target escapes out_dir", current)
	}
	if filepath.Dir(clean) != "releases" {
		return fmt.Errorf("%s must point at a release", current)
	}
	return nil
}

func writeReleaseFile(dir, name string, data []byte, mode os.FileMode) error {
	path := filepath.Join(dir, name)
	if filepath.Dir(path) != dir || strings.Contains(name, string(os.PathSeparator)) {
		return fmt.Errorf("unsafe release filename")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat release file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create release file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write release file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync release file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close release file: %w", err)
	}
	return os.Chmod(path, mode)
}

func lockOutDir(outDir string) (func(), error) {
	lockPath := filepath.Join(outDir, ".certhub.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s must be a regular non-symlink file", lockPath)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s has unsafe permissions", lockPath)
		}
		if err := ownerIsCurrentOrRoot(info, lockPath); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat lock: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if info, err := f.Stat(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat lock: %w", err)
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s has unsafe permissions or type", lockPath)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock out_dir: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func fsyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func releaseName(mat material.TLSMaterial, now time.Time) string {
	etag := strings.Trim(mat.MaterialETag, `"`)
	if len(etag) > 16 {
		etag = etag[len(etag)-16:]
	}
	replacer := strings.NewReplacer(".", "_", "/", "_")
	return fmt.Sprintf("%s-v%d-%d", replacer.Replace(etag), mat.Version, now.UTC().UnixNano())
}
