package selfcert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tlsmaterial "github.com/torob/certhub/pkg/material"
)

type PublishOptions struct {
	OutputDir string
	Material  tlsmaterial.TLSMaterial
	Now       func() time.Time
}

type PublishResult struct {
	ReleaseDir string
	Current    string
	Changed    bool
}

func Publish(ctx context.Context, opts PublishOptions) (PublishResult, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.OutputDir == "" {
		return PublishResult{}, errors.New("self_certificate.output_dir is required")
	}
	if err := ctx.Err(); err != nil {
		return PublishResult{}, err
	}
	outputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return PublishResult{}, err
	}
	if err := prepareOutputDir(outputDir); err != nil {
		return PublishResult{}, err
	}
	if matches, releaseDir := currentMatches(outputDir, opts.Material); matches {
		return PublishResult{ReleaseDir: releaseDir, Current: filepath.Join(outputDir, "current"), Changed: false}, nil
	}
	releasesDir := filepath.Join(outputDir, "releases")
	stagingDir := filepath.Join(outputDir, ".staging-"+releaseName(opts.Material, opts.Now()))
	if err := os.MkdirAll(releasesDir, 0o700); err != nil {
		return PublishResult{}, err
	}
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		return PublishResult{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stagingDir)
		}
	}()
	for _, file := range publishFiles(opts.Material) {
		if err := writeFileSync(filepath.Join(stagingDir, file.name), file.data, file.mode); err != nil {
			return PublishResult{}, err
		}
	}
	if err := fsyncDir(stagingDir); err != nil {
		return PublishResult{}, err
	}
	releaseDir := filepath.Join(releasesDir, filepath.Base(strings.TrimPrefix(stagingDir, filepath.Join(outputDir, ".staging-"))))
	if err := os.Rename(stagingDir, releaseDir); err != nil {
		return PublishResult{}, err
	}
	cleanup = false
	if err := fsyncDir(releasesDir); err != nil {
		return PublishResult{}, err
	}
	nextLink := filepath.Join(outputDir, ".current-"+filepath.Base(releaseDir))
	_ = os.Remove(nextLink)
	if err := os.Symlink(filepath.Join("releases", filepath.Base(releaseDir)), nextLink); err != nil {
		return PublishResult{}, err
	}
	if err := os.Rename(nextLink, filepath.Join(outputDir, "current")); err != nil {
		_ = os.Remove(nextLink)
		return PublishResult{}, err
	}
	if err := fsyncDir(outputDir); err != nil {
		return PublishResult{}, err
	}
	return PublishResult{ReleaseDir: releaseDir, Current: filepath.Join(outputDir, "current"), Changed: true}, nil
}

type publishFile struct {
	name string
	data []byte
	mode os.FileMode
}

func publishFiles(material tlsmaterial.TLSMaterial) []publishFile {
	return []publishFile{
		{name: "cert.pem", data: []byte(material.CertPEM), mode: 0o644},
		{name: "chain.pem", data: []byte(material.ChainPEM), mode: 0o644},
		{name: "fullchain.pem", data: []byte(material.FullchainPEM), mode: 0o644},
		{name: "privkey.pem", data: []byte(material.PrivateKeyPEM), mode: 0o600},
		{name: ".certhub-material.json", data: metadataBytes(material), mode: 0o644},
	}
}

func metadataBytes(material tlsmaterial.TLSMaterial) []byte {
	metadata := material
	metadata.CertPEM = ""
	metadata.ChainPEM = ""
	metadata.FullchainPEM = ""
	metadata.PrivateKeyPEM = ""
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil
	}
	return append(metadataBytes, '\n')
}

func currentMatches(outputDir string, material tlsmaterial.TLSMaterial) (bool, string) {
	current := filepath.Join(outputDir, "current")
	for _, file := range publishFiles(material) {
		existing, err := os.ReadFile(filepath.Join(current, file.name))
		if err != nil || !bytes.Equal(existing, file.data) {
			return false, ""
		}
	}
	return true, currentReleaseDir(outputDir)
}

func currentReleaseDir(outputDir string) string {
	current := filepath.Join(outputDir, "current")
	target, err := os.Readlink(current)
	if err != nil {
		return current
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Clean(filepath.Join(outputDir, target))
}

func prepareOutputDir(outputDir string) error {
	if err := os.MkdirAll(filepath.Join(outputDir, "releases"), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(outputDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(outputDir, "releases"), 0o700); err != nil {
		return err
	}
	return checkSafePath(outputDir)
}

func checkSafePath(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", current)
		}
		if info.IsDir() && info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s has unsafe permissions", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func releaseName(material tlsmaterial.TLSMaterial, now time.Time) string {
	etag := strings.Trim(material.MaterialETag, `"`)
	var b strings.Builder
	for _, r := range etag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() >= 16 {
			break
		}
	}
	if b.Len() == 0 {
		b.WriteString("material")
	}
	return fmt.Sprintf("%s-v%d-%d", b.String(), material.Version, now.UTC().UnixNano())
}

func writeFileSync(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fsyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
