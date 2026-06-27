package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"certhub/pkg/certcriteria"
	"certhub/pkg/certhubclient"

	"go.yaml.in/yaml/v4"
)

type Config struct {
	URL                             string              `yaml:"url"`
	Token                           string              `yaml:"token"`
	AllowPlainHTTPForLocalDev       bool                `yaml:"allow_plain_http_for_local_development"`
	Sync                            SyncConfig          `yaml:"sync"`
	Scheduler                       SchedulerConfig     `yaml:"scheduler"`
	Certificates                    []CertificateConfig `yaml:"certificates"`
	Domains                         []string            `yaml:"domains"`
	KeyType                         string              `yaml:"key_type"`
	Issuer                          string              `yaml:"issuer"`
	OutDir                          string              `yaml:"out_dir"`
	configFileContainedRawToken     bool
	configFilePath                  string
	configFileWasSymlink            bool
	configFileParentHadUnsafePerms  bool
	configFileOwnedByOtherPrincipal bool
}

type SyncConfig struct {
	Wait         bool          `yaml:"wait"`
	Timeout      time.Duration `yaml:"timeout"`
	PollInterval time.Duration `yaml:"poll_interval"`
	Force        bool          `yaml:"force"`
	FailFast     bool          `yaml:"fail_fast"`
}

type SchedulerConfig struct {
	Interval   time.Duration `yaml:"interval"`
	Jitter     time.Duration `yaml:"jitter"`
	RunOnStart *bool         `yaml:"run_on_start"`
}

type CertificateConfig struct {
	Domains      []string      `yaml:"domains"`
	KeyType      string        `yaml:"key_type"`
	Issuer       string        `yaml:"issuer"`
	OutDir       string        `yaml:"out_dir"`
	Wait         *bool         `yaml:"wait"`
	Timeout      time.Duration `yaml:"timeout"`
	PollInterval time.Duration `yaml:"poll_interval"`
	Force        *bool         `yaml:"force"`
}

type PlanItem struct {
	Criteria     certhubclient.CertificateCriteria
	OutDir       string
	Wait         bool
	Timeout      time.Duration
	PollInterval time.Duration
	Force        bool
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Config{}, fmt.Errorf("resolve home directory: %w", err)
		}
		path = filepath.Join(home, ".config", "certhub", "config.yaml")
	}
	data, info, err := readConfigFile(path, false)
	if err != nil {
		return Config{}, err
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		return Config{}, err
	}
	cfg.configFilePath = path
	cfg.configFileWasSymlink = info.Mode()&os.ModeSymlink != 0
	cfg.configFileContainedRawToken = strings.TrimSpace(cfg.Token) != ""
	if cfg.configFileContainedRawToken {
		data, info, err = readConfigFile(path, true)
		if err != nil {
			return Config{}, err
		}
		cfg, err = decodeConfig(data)
		if err != nil {
			return Config{}, err
		}
		cfg.configFilePath = path
		cfg.configFileContainedRawToken = strings.TrimSpace(cfg.Token) != ""
		if err := validateTokenBearingConfigFile(path, info); err != nil {
			return Config{}, err
		}
	}
	if env := strings.TrimSpace(os.Getenv("CERTHUB_URL")); env != "" {
		cfg.URL = env
	}
	if env := strings.TrimSpace(os.Getenv("CERTHUB_TOKEN")); env != "" {
		cfg.Token = env
	}
	if err := validateURL(cfg.URL, cfg.AllowPlainHTTPForLocalDev); err != nil {
		return Config{}, err
	}
	if err := certhubclient.ValidateApplicationToken(cfg.Token); err != nil {
		return Config{}, err
	}
	defaultSync(&cfg)
	return cfg, nil
}

func readConfigFile(path string, noFollow bool) ([]byte, os.FileInfo, error) {
	flags := os.O_RDONLY
	if noFollow {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		if noFollow {
			return nil, nil, fmt.Errorf("open token-bearing config file safely: %w", err)
		}
		return nil, nil, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat config file: %w", err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("read config file: %w", err)
	}
	return data, info, nil
}

func decodeConfig(data []byte) (Config, error) {
	if err := rejectDuplicateYAMLKeys(data); err != nil {
		return Config{}, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	return cfg, nil
}

func defaultSync(cfg *Config) {
	if cfg.Sync.Timeout == 0 {
		cfg.Sync.Timeout = 5 * time.Minute
	}
	if cfg.Sync.PollInterval == 0 {
		cfg.Sync.PollInterval = 10 * time.Second
	}
}

func (c SchedulerConfig) RunOnStartValue() bool {
	if c.RunOnStart == nil {
		return true
	}
	return *c.RunOnStart
}

func BuildPlan(cfg Config) ([]PlanItem, error) {
	if len(cfg.Certificates) > 0 && (len(cfg.Domains) > 0 || cfg.OutDir != "" || cfg.KeyType != "" || cfg.Issuer != "") {
		return nil, fmt.Errorf("top-level certificate shorthand cannot be mixed with certificates")
	}
	entries := cfg.Certificates
	if len(entries) == 0 {
		entries = []CertificateConfig{{Domains: cfg.Domains, KeyType: cfg.KeyType, Issuer: cfg.Issuer, OutDir: cfg.OutDir}}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("at least one certificate entry is required")
	}
	plan := make([]PlanItem, 0, len(entries))
	for i, entry := range entries {
		if len(entry.Domains) == 0 {
			return nil, fmt.Errorf("certificates[%d].domains is required", i)
		}
		if strings.TrimSpace(entry.OutDir) == "" {
			return nil, fmt.Errorf("certificates[%d].out_dir is required", i)
		}
		normalized, err := certcriteria.Normalize(certcriteria.Criteria{Domains: entry.Domains, KeyType: entry.KeyType, Issuer: entry.Issuer})
		if err != nil {
			return nil, fmt.Errorf("certificates[%d]: %w", i, err)
		}
		wait := cfg.Sync.Wait
		if entry.Wait != nil {
			wait = *entry.Wait
		}
		force := cfg.Sync.Force
		if entry.Force != nil {
			force = *entry.Force
		}
		timeout := cfg.Sync.Timeout
		if entry.Timeout > 0 {
			timeout = entry.Timeout
		}
		poll := cfg.Sync.PollInterval
		if entry.PollInterval > 0 {
			poll = entry.PollInterval
		}
		if timeout <= 0 || poll <= 0 {
			return nil, fmt.Errorf("certificates[%d]: timeout and poll_interval must be positive", i)
		}
		plan = append(plan, PlanItem{
			Criteria:     certhubclient.CertificateCriteria{Domains: normalized.Domains, KeyType: normalized.KeyType, Issuer: normalized.Issuer},
			OutDir:       entry.OutDir,
			Wait:         wait,
			Timeout:      timeout,
			PollInterval: poll,
			Force:        force,
		})
	}
	return plan, nil
}

func validateURL(raw string, allowPlainHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("url must be absolute")
	}
	if u.User != nil {
		return fmt.Errorf("url must not contain userinfo")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !allowPlainHTTP {
			return fmt.Errorf("plain HTTP requires allow_plain_http_for_local_development=true")
		}
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("plain HTTP is allowed only for localhost")
		}
		return nil
	default:
		return fmt.Errorf("url scheme must be https")
	}
}

func validateTokenBearingConfigFile(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("token-bearing config file must not be a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("token-bearing config file must be mode 0600")
	}
	if err := ownerIsCurrentOrRoot(info, "config file"); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	for {
		parent, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("stat config parent: %w", err)
		}
		if parent.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config parent must not be a symlink")
		}
		if parent.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("config parent has unsafe permissions")
		}
		if err := ownerIsCurrentOrRoot(parent, "config parent"); err != nil {
			return err
		}
		next := filepath.Dir(dir)
		if next == dir || dir == filepath.VolumeName(dir)+string(os.PathSeparator) {
			break
		}
		dir = next
	}
	return nil
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

func rejectDuplicateYAMLKeys(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	return checkDuplicateNodeKeys(&node, "$")
}

func checkDuplicateNodeKeys(node *yaml.Node, path string) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return checkDuplicateNodeKeys(node.Content[0], path)
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate YAML key %q at %s", key.Value, path)
			}
			seen[key.Value] = struct{}{}
			if err := checkDuplicateNodeKeys(node.Content[i+1], path+"."+key.Value); err != nil {
				return err
			}
		}
	}
	if node.Kind == yaml.SequenceNode {
		for i, child := range node.Content {
			if err := checkDuplicateNodeKeys(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
