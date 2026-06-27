package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func EnsurePrivateDir(path string) error {
	if path == "" {
		return fmt.Errorf("private directory path is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("private directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("private directory: stat failed")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsDir() {
		return fmt.Errorf("private directory: must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private directory: unsafe permissions")
	}
	if err := ownerIsCurrentOrRoot(info, "private directory"); err != nil {
		return err
	}
	return nil
}

func WritePrivateFile(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("private file path is required")
	}
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("private file: must be a non-symlink regular file")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("private file: stat failed")
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("private file: create temp failed")
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("private file: chmod temp failed")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("private file: write failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("private file: sync failed")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("private file: close failed")
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("private file: rename failed")
	}
	return os.Chmod(path, 0o600)
}

func ownerIsCurrentOrRoot(info os.FileInfo, label string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: owner check unavailable", label)
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != uid {
		return fmt.Errorf("%s: unexpected owner", label)
	}
	return nil
}
