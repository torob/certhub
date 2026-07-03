package commands

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	qrcode "github.com/skip2/go-qrcode"
	acmedomain "github.com/torob/certhub/internal/acme"
	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/certificates"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/dnspropagation"
	"github.com/torob/certhub/internal/dnsproviders"
	"github.com/torob/certhub/internal/httpapi"
	"github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/selfcert"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
	"github.com/torob/certhub/internal/workers"
)

const bootstrapActorID = "00000000-0000-4000-8000-000000000001"
const serverConfigPathEnv = "CERTHUB_SERVER_CONFIG"

const ServerHelp = `certhub-server is the Certhub backend server command.

Usage:
  certhub-server help
  certhub-server --help
  certhub-server run [--migrate] [--config <path>]
  certhub-server migrate [--config <path>]
  certhub-server generate-encryption-key
  certhub-server bootstrap ...

Server config path must be provided by --config or CERTHUB_SERVER_CONFIG.
`

type ServerRunner struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (r ServerRunner) Execute(ctx context.Context, args []string) int {
	if r.Stdout == nil {
		r.Stdout = io.Discard
	}
	if r.Stderr == nil {
		r.Stderr = io.Discard
	}
	if r.Stdin == nil {
		r.Stdin = os.Stdin
	}
	if len(args) == 0 {
		fmt.Fprint(r.Stderr, ServerHelp)
		return 2
	}

	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(r.Stdout, ServerHelp)
		return 0
	case "generate-encryption-key":
		return r.generateEncryptionKey(args[1:])
	case "run":
		return r.run(ctx, args[1:])
	case "migrate":
		return r.migrate(args[1:])
	case "bootstrap":
		return r.bootstrap(args[1:])
	default:
		fmt.Fprintf(r.Stderr, "unknown certhub-server command %q\n\n", args[0])
		fmt.Fprint(r.Stderr, ServerHelp)
		return 2
	}
}

func (r ServerRunner) generateEncryptionKey(args []string) int {
	fs := flag.NewFlagSet("generate-encryption-key", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *help {
		fmt.Fprintln(r.Stdout, "Usage: certhub-server generate-encryption-key")
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(r.Stderr, "generate-encryption-key accepts no positional arguments")
		return 2
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		fmt.Fprintln(r.Stderr, "secure randomness unavailable")
		return 1
	}
	if _, err := fmt.Fprintln(r.Stdout, base64.StdEncoding.EncodeToString(key[:])); err != nil {
		return 1
	}
	return 0
}

func resolveServerConfigPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if envValue := os.Getenv(serverConfigPathEnv); envValue != "" {
		return envValue, nil
	}
	return "", fmt.Errorf("config path is required; pass --config <path> or set %s", serverConfigPathEnv)
}

func (r ServerRunner) run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	applyMigrations := fs.Bool("migrate", false, "apply pending database migrations before starting")
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *help {
		fmt.Fprintln(r.Stdout, "Usage: certhub-server run [--migrate] [--config <path>]\n\nServer config path must be provided by --config or CERTHUB_SERVER_CONFIG.")
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(r.Stderr, "run accepts no positional arguments")
		return 2
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		fmt.Fprintf(r.Stderr, "config validation failed: %v\n", err)
		return 1
	}
	cfg, err := config.LoadFile(resolvedConfigPath, config.LoadOptions{})
	if err != nil {
		fmt.Fprintf(r.Stderr, "config validation failed: %v\n", err)
		return 1
	}
	tlsLoader, err := config.NewTLSCertificateLoader(cfg)
	if err != nil {
		fmt.Fprintf(r.Stderr, "tls validation failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	migrationMode := runtimeMigrationsCheckOnly
	if *applyMigrations {
		migrationMode = runtimeMigrationsApply
	}
	resources, err := openRuntimeResources(ctx, cfg, tlsLoader, migrationMode)
	if err != nil {
		fmt.Fprintf(r.Stderr, "server readiness failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	defer resources.Close()

	authRepo := auth.NewRepository(resources.Storage)
	userRepo := users.NewRepository(resources.Storage)
	appRepo := applications.NewRepository(resources.Storage)
	auditRepo := audit.NewRepository(resources.Storage)
	issuerRepo := issuers.NewRepository(resources.Storage)
	certRepo := certificates.NewRepository(resources.Storage)
	dnsRepo := dnsproviders.NewRepository(resources.Storage)
	acmeHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.ACMEProxy)
	if err != nil {
		fmt.Fprintf(r.Stderr, "outbound http validation failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	cloudflareHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.Cloudflare)
	if err != nil {
		fmt.Fprintf(r.Stderr, "outbound http validation failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	arvanHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.ArvanCloud)
	if err != nil {
		fmt.Fprintf(r.Stderr, "outbound http validation failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	oidcHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.OIDCProxy)
	if err != nil {
		fmt.Fprintf(r.Stderr, "outbound http validation failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	appService := applications.NewService(applications.ServiceConfig{
		Repository:      appRepo,
		UserRepository:  userRepo,
		AuditRepository: auditRepo,
		KeySet:          resources.KeySet,
		Config:          cfg.ApplicationToken,
		Storage:         resources.Storage,
	})
	authService := auth.NewService(auth.ServiceConfig{
		AuthRepository:  authRepo,
		UserRepository:  userRepo,
		AuditRepository: auditRepo,
		KeySet:          resources.KeySet,
		Config:          cfg.Auth,
		Storage:         resources.Storage,
		HTTPClient:      oidcHTTP,
	})
	userService := users.NewService(users.ServiceConfig{
		Repository:      userRepo,
		AuditRepository: auditRepo,
		GrantReader:     appService,
		KeySet:          resources.KeySet,
		Config:          cfg.Auth,
		Storage:         resources.Storage,
	})
	auditService := audit.NewService(audit.ServiceConfig{
		Repository:        auditRepo,
		ApplicationReader: appService,
	})
	issuerService := issuers.NewService(issuers.ServiceConfig{
		Repository:       issuerRepo,
		AuditRepository:  auditRepo,
		AccountRegistrar: acmedomain.NewAccountClient(acmeHTTP),
		KeySet:           resources.KeySet,
		Storage:          resources.Storage,
	})
	cloudflareClient := dnsproviders.NewCloudflareClient(cloudflareHTTP)
	arvanCloudClient := dnsproviders.NewArvanCloudClient(arvanHTTP)
	propagationResolvers, err := buildPropagationResolvers(cfg)
	if err != nil {
		fmt.Fprintf(r.Stderr, "dns propagation resolver validation failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	dnsService := dnsproviders.NewService(dnsproviders.ServiceConfig{
		Repository:      dnsRepo,
		AuditRepository: auditRepo,
		KeySet:          resources.KeySet,
		ZoneListers: dnsproviders.ZoneListerRegistry{
			dnsproviders.ProviderTypeCloudflare: cloudflareClient,
			dnsproviders.ProviderTypeArvanCloud: arvanCloudClient,
		},
		Storage: resources.Storage,
	})
	certService := certificates.NewService(certificates.ServiceConfig{
		Repository:        certRepo,
		ApplicationReader: appRepo,
		IssuerReader:      issuerRepo,
		AuditRepository:   auditRepo,
		KeySet:            resources.KeySet,
		Storage:           resources.Storage,
	})
	handler := httpapi.New(cfg,
		httpapi.WithReadinessChecker(resources),
		httpapi.WithLogWriter(r.Stderr),
		httpapi.WithIdentityServices(authService, userService),
		httpapi.WithApplicationAccessServices(appService, auditService),
		httpapi.WithIssuerService(issuerService),
		httpapi.WithDNSProviderService(dnsService),
		httpapi.WithCertificateService(certService),
	).Handler()
	server := &http.Server{Addr: cfg.HTTP.BindAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if tlsLoader != nil {
		server.TLSConfig = tlsLoader.TLSConfig()
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dnsRefreshWorkers, err := workers.StartDNSRefreshWorkers(ctx, workers.DNSRefreshConfig{
		Service:      dnsService,
		Concurrency:  cfg.Workers.Concurrency,
		PollInterval: 2 * time.Second,
		LogWriter:    r.Stderr,
	})
	if err != nil {
		fmt.Fprintf(r.Stderr, "worker startup failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dnsRefreshWorkers.Stop(stopCtx); err != nil {
			fmt.Fprintf(r.Stderr, "worker shutdown failed: %s\n", security.RedactString(err.Error()))
		}
	}()
	renewalWorker, err := workers.StartCertificateRenewalWorker(ctx, workers.CertificateRenewalConfig{
		Store:        certRepo,
		Applications: appRepo,
		PollInterval: 5 * time.Minute,
		LogWriter:    r.Stderr,
	})
	if err != nil {
		fmt.Fprintf(r.Stderr, "worker startup failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := renewalWorker.Stop(stopCtx); err != nil {
			fmt.Fprintf(r.Stderr, "worker shutdown failed: %s\n", security.RedactString(err.Error()))
		}
	}()
	issuanceWorkers, err := workers.StartCertificateIssuanceWorkers(ctx, workers.CertificateIssuanceConfig{
		Service: &workers.CertificateIssuanceService{
			Certificates:         certRepo,
			Issuers:              issuerRepo,
			DNSProviders:         dnsRepo,
			OrderManager:         acmedomain.NewOrderClient(acmeHTTP),
			Cloudflare:           cloudflareClient,
			ArvanCloud:           arvanCloudClient,
			KeySet:               resources.KeySet,
			LeaseDuration:        time.Duration(cfg.ACME.OrderTimeoutSeconds+cfg.DNS.PropagationTimeoutSeconds+300) * time.Second,
			OrderTimeout:         time.Duration(cfg.ACME.OrderTimeoutSeconds) * time.Second,
			PropagationTimeout:   time.Duration(cfg.DNS.PropagationTimeoutSeconds) * time.Second,
			PropagationPoll:      time.Duration(cfg.DNS.PropagationPollSeconds) * time.Second,
			PropagationResolvers: propagationResolvers,
			DNSChallengeTTL:      120,
			MaxAttempts:          5,
			RetryBackoff:         30 * time.Second,
		},
		Concurrency:  cfg.Workers.Concurrency,
		PollInterval: 2 * time.Second,
		LogWriter:    r.Stderr,
	})
	if err != nil {
		fmt.Fprintf(r.Stderr, "worker startup failed: %s\n", security.RedactString(err.Error()))
		return 1
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := issuanceWorkers.Stop(stopCtx); err != nil {
			fmt.Fprintf(r.Stderr, "worker shutdown failed: %s\n", security.RedactString(err.Error()))
		}
	}()
	if cfg.SelfCertificate.SyncEnabled {
		selfCertService := selfcert.NewService(selfcert.ServiceConfig{
			Runtime:     selfcert.RuntimeConfigFromConfig(cfg),
			DB:          resources.Storage,
			Storage:     resources.Storage,
			KeySet:      resources.KeySet,
			TLSReloader: tlsLoader,
			LogWriter:   r.Stderr,
		})
		resources.SelfCertificate = selfCertService
		selfCertRunner, err := selfcert.Start(ctx, selfcert.RunnerConfig{
			Syncer:       selfCertService,
			PollInterval: time.Duration(cfg.SelfCertificate.SyncIntervalSeconds) * time.Second,
			LogWriter:    r.Stderr,
		})
		if err != nil {
			fmt.Fprintf(r.Stderr, "worker startup failed: %s\n", security.RedactString(err.Error()))
			return 1
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := selfCertRunner.Stop(stopCtx); err != nil {
				fmt.Fprintf(r.Stderr, "worker shutdown failed: %s\n", security.RedactString(err.Error()))
			}
		}()
	}
	errCh := make(chan error, 1)
	go func() {
		if tlsLoader != nil {
			errCh <- server.ListenAndServeTLS("", "")
			return
		}
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(r.Stderr, "server shutdown failed: %v\n", err)
			return 1
		}
		return 0
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		fmt.Fprintf(r.Stderr, "server failed: %v\n", err)
		return 1
	}
}

func buildPropagationResolvers(cfg *config.Config) (map[dnsproviders.ProviderType]workers.TXTVisibilityChecker, error) {
	out := make(map[dnsproviders.ProviderType]workers.TXTVisibilityChecker, len(cfg.DNS.PropagationResolvers))
	for providerType, resolverCfg := range cfg.DNS.PropagationResolvers {
		var proxyURL *url.URL
		var httpClient *http.Client
		var err error
		if resolverCfg.Proxy != "" {
			proxyURL, err = config.OutboundProxyURL(cfg.OutboundHTTP, resolverCfg.Proxy)
			if err != nil {
				return nil, fmt.Errorf("%s propagation proxy: %w", providerType, err)
			}
		}
		if resolverCfg.Type == dnspropagation.TypeDoH {
			httpClient, err = config.NewOutboundHTTPClient(cfg.OutboundHTTP, resolverCfg.Proxy)
			if err != nil {
				return nil, fmt.Errorf("%s doh propagation client: %w", providerType, err)
			}
		}
		checker, err := dnspropagation.NewChecker(dnspropagation.Config{
			Type:          resolverCfg.Type,
			Endpoint:      resolverCfg.Endpoint,
			TLSServerName: resolverCfg.TLSServerName,
			ProxyName:     resolverCfg.Proxy,
			ProxyURL:      proxyURL,
			HTTPClient:    httpClient,
		})
		if err != nil {
			return nil, fmt.Errorf("%s propagation resolver: %w", providerType, err)
		}
		out[dnsproviders.ProviderType(providerType)] = checker
	}
	return out, nil
}

func (r ServerRunner) migrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	jsonOut := fs.Bool("json", false, "print JSON output")
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *help {
		fmt.Fprintln(r.Stdout, "Usage: certhub-server migrate [--config <path>] [--json]\n\nServer config path must be provided by --config or CERTHUB_SERVER_CONFIG.")
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(r.Stderr, "migrate accepts no positional arguments")
		return 2
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		return r.reportMigrationFailure(*jsonOut, "config validation failed", "config_invalid", err)
	}
	cfg, err := config.LoadFile(resolvedConfigPath, config.LoadOptions{})
	if err != nil {
		return r.reportMigrationFailure(*jsonOut, "config validation failed", "config_invalid", err)
	}
	resources, err := openRuntimeResources(context.Background(), cfg, nil, runtimeMigrationsApply)
	if err != nil {
		return r.reportMigrationFailure(*jsonOut, "migration failed", "migration_failed", err)
	}
	defer resources.Close()
	status, err := resources.Migrations.Status(context.Background(), resources.MigrationDB)
	if err != nil {
		return r.reportMigrationFailure(*jsonOut, "migration status failed", "migration_status_failed", err)
	}
	if !status.Compatible {
		return r.reportMigrationFailure(*jsonOut, "migration failed", "migration_incompatible", migrations.IncompatibleError{Status: status})
	}
	if *jsonOut {
		_ = json.NewEncoder(r.Stdout).Encode(map[string]any{
			"status":          "ok",
			"current_version": status.CurrentVersion,
			"latest_version":  status.LatestVersion,
			"pending":         status.Pending,
			"compatible":      status.Compatible,
		})
	} else {
		fmt.Fprintf(r.Stdout, "migrations applied: current_version=%d latest_version=%d pending=%d compatible=%t\n", status.CurrentVersion, status.LatestVersion, status.Pending, status.Compatible)
	}
	return 0
}

func (r ServerRunner) reportMigrationFailure(jsonOut bool, prefix, code string, err error) int {
	var incompatible migrations.IncompatibleError
	if errors.As(err, &incompatible) {
		code = "migration_incompatible"
	}
	if jsonOut {
		body := map[string]any{
			"status": "failed",
			"error":  code,
		}
		if incompatible.Status != (migrations.Status{}) {
			body["current_version"] = incompatible.Status.CurrentVersion
			body["latest_version"] = incompatible.Status.LatestVersion
			body["pending"] = incompatible.Status.Pending
			body["compatible"] = incompatible.Status.Compatible
		}
		_ = json.NewEncoder(r.Stdout).Encode(body)
		return 1
	}
	fmt.Fprintf(r.Stderr, "%s: %s\n", prefix, security.RedactString(err.Error()))
	return 1
}

func (r ServerRunner) bootstrap(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(r.Stdout, "Usage: certhub-server bootstrap [--interactive|create-admin|create-issuer|create-dns-provider|add-dns-provider-zone|refresh-dns-provider-zones] [--config <path>]\n\nServer config path must be provided by --config or CERTHUB_SERVER_CONFIG.")
		return 0
	}
	if args[0] == "--interactive" {
		return r.bootstrapInteractive(args[1:])
	}
	switch args[0] {
	case "create-admin":
		return r.bootstrapCreateAdmin(args[1:])
	case "create-issuer":
		return r.bootstrapCreateIssuer(args[1:])
	case "create-dns-provider":
		return r.bootstrapCreateDNSProvider(args[1:])
	case "add-dns-provider-zone":
		return r.bootstrapAddDNSProviderZone(args[1:])
	case "refresh-dns-provider-zones":
		return r.bootstrapRefreshDNSProviderZones(args[1:])
	default:
		fmt.Fprintf(r.Stderr, "unknown bootstrap command %q\n", args[0])
		return 2
	}
}

func (r ServerRunner) bootstrapCreateAdmin(args []string) int {
	fs := flag.NewFlagSet("bootstrap create-admin", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	email := fs.String("email", "", "admin email")
	displayName := fs.String("display-name", "", "admin display name")
	passwordValue := fs.String("password", "", "admin password")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	passwordEnv := fs.String("password-env", "", "environment variable containing admin password")
	passwordFile := fs.String("password-file", "", "file containing admin password")
	allowExistingAdmin := fs.Bool("allow-existing-admin", false, "allow creation when an active admin already exists")
	interactive := fs.Bool("interactive", false, "run guided admin creation")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	passwordFlagSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "password" {
			passwordFlagSet = true
		}
	})
	if *interactive {
		return r.bootstrapCreateAdminInteractive(*configPath, *allowExistingAdmin, *jsonOut)
	}
	if fs.NArg() != 0 || *email == "" || *displayName == "" {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", errors.New("email and display-name are required"))
	}
	resolvedConfigPath, configErr := resolveServerConfigPath(*configPath)
	if configErr != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", configErr)
	}
	password, err := r.readBootstrapAdminPassword(passwordFlagSet, *passwordValue, *passwordStdin, *passwordEnv, *passwordFile, *jsonOut)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", err)
	}
	boot, err := r.openBootstrapServices(context.Background(), resolvedConfigPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_unavailable", err)
	}
	defer boot.Close()
	result, err := boot.users.BootstrapCreateAdmin(context.Background(), users.BootstrapCreateAdminParams{
		Email:              *email,
		DisplayName:        *displayName,
		Password:           password,
		AllowExistingAdmin: *allowExistingAdmin,
	}, users.AuditContext{CorrelationID: "bootstrap-create-admin", Command: "certhub-server bootstrap create-admin"})
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_admin_failed", err)
	}
	body := map[string]any{"status": "ok", "user_id": result.User.ID, "email": result.User.Email, "password_2fa_enabled": result.User.Password2FAEnabled}
	if result.Password2FA != nil {
		body["totp_provisioning_uri"] = result.Password2FA.ProvisioningURI
	}
	return r.reportBootstrapSuccess(*jsonOut, body, func() {
		fmt.Fprintf(r.Stdout, "created admin user %s (%s)\n", result.User.Email, result.User.ID)
		if result.Password2FA != nil {
			r.writeTOTPProvisioning(result.Password2FA.ProvisioningURI)
		}
	})
}

func (r ServerRunner) readBootstrapAdminPassword(flagSet bool, flagValue string, stdin bool, envName, filePath string, jsonOut bool) (*string, error) {
	selected := 0
	if flagSet {
		selected++
	}
	if stdin {
		selected++
	}
	if envName != "" {
		selected++
	}
	if filePath != "" {
		selected++
	}
	if selected > 1 {
		return nil, errors.New("at most one password source may be selected")
	}
	switch {
	case flagSet:
		return &flagValue, nil
	case stdin:
		raw, err := io.ReadAll(r.Stdin)
		if err != nil {
			return nil, err
		}
		value := strings.TrimRight(string(raw), "\r\n")
		return &value, nil
	case envName != "":
		value, ok := os.LookupEnv(envName)
		if !ok {
			return nil, errors.New("password environment variable is unset")
		}
		value = strings.TrimRight(value, "\r\n")
		return &value, nil
	case filePath != "":
		raw, err := readProtectedSecretFile("password file", filePath)
		if err != nil {
			return nil, err
		}
		value := strings.TrimRight(string(raw), "\r\n")
		return &value, nil
	default:
		if jsonOut || !r.canPromptSecret() {
			return nil, nil
		}
		password, err := r.promptSecret("Admin password [optional when OIDC is enabled]: ")
		if err != nil {
			return nil, err
		}
		confirm, err := r.promptSecret("Confirm admin password: ")
		if err != nil {
			return nil, err
		}
		if password != confirm {
			return nil, errors.New("password confirmation does not match")
		}
		if password == "" {
			return nil, nil
		}
		return &password, nil
	}
}

func (r ServerRunner) bootstrapInteractive(args []string) int {
	fs := flag.NewFlagSet("bootstrap --interactive", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return r.reportBootstrapFailure(false, "bootstrap failed", "invalid_request", errors.New("interactive bootstrap accepts only --config"))
	}
	if err := r.requireInteractiveTerminal(); err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_tty_required", err)
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "invalid_request", err)
	}
	action, err := r.promptLine("Bootstrap action [create-admin]: ")
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_input_failed", err)
	}
	if strings.TrimSpace(action) != "" && strings.TrimSpace(action) != "create-admin" {
		return r.reportBootstrapFailure(false, "bootstrap failed", "invalid_request", errors.New("unsupported interactive bootstrap action"))
	}
	return r.bootstrapCreateAdminInteractive(resolvedConfigPath, false, false)
}

func (r ServerRunner) bootstrapCreateAdminInteractive(configPath string, allowExistingAdmin bool, jsonOut bool) int {
	if jsonOut {
		return r.reportBootstrapFailure(true, "bootstrap failed", "invalid_request", errors.New("interactive bootstrap does not support json output"))
	}
	if err := r.requireInteractiveTerminal(); err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_tty_required", err)
	}
	resolvedConfigPath, err := resolveServerConfigPath(configPath)
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "invalid_request", err)
	}
	email, err := r.promptLine("Admin email: ")
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_input_failed", err)
	}
	displayName, err := r.promptLine("Admin display name: ")
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_input_failed", err)
	}
	password, err := r.promptSecret("Admin password [optional when OIDC is enabled]: ")
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_input_failed", err)
	}
	confirm, err := r.promptSecret("Confirm admin password: ")
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "interactive_input_failed", err)
	}
	if password != confirm {
		return r.reportBootstrapFailure(false, "bootstrap failed", "invalid_request", errors.New("password confirmation does not match"))
	}
	var passwordPtr *string
	if password != "" {
		passwordPtr = &password
	}
	boot, err := r.openBootstrapServices(context.Background(), resolvedConfigPath)
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "bootstrap_unavailable", err)
	}
	defer boot.Close()
	result, err := boot.users.BootstrapCreateAdmin(context.Background(), users.BootstrapCreateAdminParams{
		Email:              strings.TrimSpace(email),
		DisplayName:        strings.TrimSpace(displayName),
		Password:           passwordPtr,
		AllowExistingAdmin: allowExistingAdmin,
		ConfirmPassword2FA: func(p users.TOTPProvisioning) (string, error) {
			r.writeTOTPProvisioning(p.ProvisioningURI)
			return r.promptLine("Current TOTP code: ")
		},
	}, users.AuditContext{CorrelationID: "bootstrap-create-admin-interactive", Command: "certhub-server bootstrap create-admin --interactive"})
	if err != nil {
		return r.reportBootstrapFailure(false, "bootstrap failed", "bootstrap_admin_failed", err)
	}
	fmt.Fprintf(r.Stdout, "created admin user %s (%s)\n", result.User.Email, result.User.ID)
	return 0
}

func (r ServerRunner) writeTOTPProvisioning(uri string) {
	code, err := qrcode.New(uri, qrcode.Medium)
	if err == nil {
		fmt.Fprintln(r.Stdout, "totp_qr_code:")
		fmt.Fprint(r.Stdout, code.ToSmallString(false))
	}
	fmt.Fprintf(r.Stdout, "totp_provisioning_uri: %s\n", uri)
}

func (r ServerRunner) bootstrapCreateIssuer(args []string) int {
	fs := flag.NewFlagSet("bootstrap create-issuer", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	name := fs.String("name", "", "issuer machine name")
	directoryURL := fs.String("directory-url", "", "ACME directory URL")
	contactEmail := fs.String("contact-email", "", "ACME contact email")
	isDefault := fs.Bool("default", false, "make issuer default")
	renewalWindow := fs.Int("renewal-window-seconds", 0, "renewal window in seconds")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *name == "" || *directoryURL == "" || *contactEmail == "" {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", errors.New("name, directory-url, and contact-email are required"))
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", err)
	}
	boot, err := r.openBootstrapServices(context.Background(), resolvedConfigPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_unavailable", err)
	}
	defer boot.Close()
	issuer, err := boot.issuers.CreateIssuer(context.Background(), issuers.Actor{ID: bootstrapActorID, GlobalRole: users.GlobalRoleAdmin, System: true}, issuers.CreateIssuerParams{
		Name:                 *name,
		Type:                 issuers.TypeACME,
		DirectoryURL:         *directoryURL,
		IsDefault:            *isDefault,
		RenewalWindowSeconds: *renewalWindow,
		ContactEmail:         *contactEmail,
	}, issuers.AuditContext{CorrelationID: "bootstrap-create-issuer", Command: "certhub-server bootstrap create-issuer"})
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_issuer_failed", err)
	}
	body := map[string]any{"status": "ok", "issuer_id": issuer.ID, "name": issuer.Name, "default": issuer.IsDefault}
	return r.reportBootstrapSuccess(*jsonOut, body, func() {
		fmt.Fprintf(r.Stdout, "created issuer %s (%s)\n", issuer.Name, issuer.ID)
	})
}

func (r ServerRunner) bootstrapCreateDNSProvider(args []string) int {
	fs := flag.NewFlagSet("bootstrap create-dns-provider", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	name := fs.String("name", "", "DNS provider machine name")
	providerType := fs.String("type", "", "provider type")
	zoneMode := fs.String("zone-mode", "", "zone mode")
	credentialsStdin := fs.Bool("credentials-stdin", false, "read credential JSON from stdin")
	credentialsEnv := fs.String("credentials-env", "", "environment variable containing credential JSON")
	credentialsFile := fs.String("credentials-file", "", "file containing credential JSON")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *name == "" || *providerType == "" || *zoneMode == "" {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", errors.New("name, type, and zone-mode are required"))
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", err)
	}
	credentials, err := r.readBootstrapCredentials(*credentialsStdin, *credentialsEnv, *credentialsFile)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", err)
	}
	boot, err := r.openBootstrapServices(context.Background(), resolvedConfigPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_unavailable", err)
	}
	defer boot.Close()
	provider, err := boot.dns.CreateProvider(context.Background(), dnsproviders.Actor{ID: bootstrapActorID, GlobalRole: users.GlobalRoleAdmin, System: true}, dnsproviders.CreateProviderServiceParams{
		Name:        *name,
		Type:        dnsproviders.ProviderType(*providerType),
		Credentials: json.RawMessage(credentials),
		ZoneMode:    dnsproviders.ZoneMode(*zoneMode),
		Status:      dnsproviders.StatusActive,
	}, dnsproviders.AuditContext{CorrelationID: "bootstrap-create-dns-provider", Command: "certhub-server bootstrap create-dns-provider"})
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_dns_provider_failed", err)
	}
	body := map[string]any{"status": "ok", "dns_provider_id": provider.ID, "name": provider.Name, "type": provider.Type, "zone_mode": provider.ZoneMode}
	return r.reportBootstrapSuccess(*jsonOut, body, func() {
		fmt.Fprintf(r.Stdout, "created dns provider %s (%s)\n", provider.Name, provider.ID)
	})
}

func (r ServerRunner) bootstrapAddDNSProviderZone(args []string) int {
	fs := flag.NewFlagSet("bootstrap add-dns-provider-zone", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	providerRef := fs.String("dns-provider", "", "DNS provider name or ID")
	zoneName := fs.String("zone", "", "DNS zone name")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *providerRef == "" || *zoneName == "" {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", errors.New("dns-provider and zone are required"))
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", err)
	}
	boot, err := r.openBootstrapServices(context.Background(), resolvedConfigPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_unavailable", err)
	}
	defer boot.Close()
	provider, err := boot.dnsRepo.GetByName(context.Background(), *providerRef)
	if err != nil {
		provider, err = boot.dnsRepo.Get(context.Background(), *providerRef)
	}
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "dns_provider_not_found", err)
	}
	zone, err := boot.dns.AddZone(context.Background(), dnsproviders.Actor{ID: bootstrapActorID, GlobalRole: users.GlobalRoleAdmin, System: true}, provider.ID, *zoneName, dnsproviders.AuditContext{CorrelationID: "bootstrap-add-dns-provider-zone", Command: "certhub-server bootstrap add-dns-provider-zone"})
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_dns_zone_failed", err)
	}
	body := map[string]any{"status": "ok", "zone_id": zone.ID, "dns_provider_id": zone.DNSProviderID, "zone": zone.ZoneName}
	return r.reportBootstrapSuccess(*jsonOut, body, func() {
		fmt.Fprintf(r.Stdout, "added dns provider zone %s (%s)\n", zone.ZoneName, zone.ID)
	})
}

func (r ServerRunner) bootstrapRefreshDNSProviderZones(args []string) int {
	fs := flag.NewFlagSet("bootstrap refresh-dns-provider-zones", flag.ContinueOnError)
	fs.SetOutput(r.Stderr)
	configPath := fs.String("config", "", "server YAML config path (or CERTHUB_SERVER_CONFIG)")
	providerRef := fs.String("dns-provider", "", "DNS provider name or ID")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *providerRef == "" {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", errors.New("dns-provider is required"))
	}
	resolvedConfigPath, err := resolveServerConfigPath(*configPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "invalid_request", err)
	}
	boot, err := r.openBootstrapServices(context.Background(), resolvedConfigPath)
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_unavailable", err)
	}
	defer boot.Close()
	provider, err := boot.dnsRepo.GetByName(context.Background(), *providerRef)
	if err != nil {
		provider, err = boot.dnsRepo.Get(context.Background(), *providerRef)
	}
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "dns_provider_not_found", err)
	}
	job, err := boot.dns.RefreshZones(context.Background(), dnsproviders.Actor{ID: bootstrapActorID, GlobalRole: users.GlobalRoleAdmin, System: true}, provider.ID, dnsproviders.AuditContext{CorrelationID: "bootstrap-refresh-dns-provider-zones", Command: "certhub-server bootstrap refresh-dns-provider-zones"})
	if err != nil {
		return r.reportBootstrapFailure(*jsonOut, "bootstrap failed", "bootstrap_dns_zone_refresh_failed", err)
	}
	body := map[string]any{"status": "ok", "refresh_job_id": job.ID, "dns_provider_id": job.DNSProviderID}
	return r.reportBootstrapSuccess(*jsonOut, body, func() {
		fmt.Fprintf(r.Stdout, "queued dns provider zone refresh %s\n", job.ID)
	})
}

func (r ServerRunner) readBootstrapCredentials(stdin bool, envName, filePath string) ([]byte, error) {
	selected := 0
	if stdin {
		selected++
	}
	if envName != "" {
		selected++
	}
	if filePath != "" {
		selected++
	}
	if selected != 1 {
		return nil, errors.New("exactly one credential source is required")
	}
	switch {
	case stdin:
		return io.ReadAll(r.Stdin)
	case envName != "":
		value, ok := os.LookupEnv(envName)
		if !ok {
			return nil, errors.New("credential environment variable is unset")
		}
		return []byte(value), nil
	default:
		return readProtectedSecretFile("credential file", filePath)
	}
}

func (r ServerRunner) canPromptSecret() bool {
	in, ok := r.Stdin.(*os.File)
	if !ok || !isTerminal(in) {
		return false
	}
	out, ok := r.Stdout.(*os.File)
	return ok && isTerminal(out)
}

func (r ServerRunner) requireInteractiveTerminal() error {
	return r.requireInteractiveTerminalWith(isTerminal)
}

func (r ServerRunner) requireInteractiveTerminalWith(check func(*os.File) bool) error {
	in, ok := r.Stdin.(*os.File)
	if !ok || !check(in) {
		return errors.New("interactive bootstrap requires a TTY")
	}
	out, ok := r.Stdout.(*os.File)
	if !ok || !check(out) {
		return errors.New("interactive bootstrap requires a TTY")
	}
	errOut, ok := r.Stderr.(*os.File)
	if !ok || !check(errOut) {
		return errors.New("interactive bootstrap requires a TTY")
	}
	return nil
}

func (r ServerRunner) promptLine(prompt string) (string, error) {
	if _, err := fmt.Fprint(r.Stdout, prompt); err != nil {
		return "", err
	}
	line, err := readLine(r.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (r ServerRunner) promptSecret(prompt string) (string, error) {
	in, ok := r.Stdin.(*os.File)
	if !ok || !isTerminal(in) {
		return "", errors.New("secret prompts require a TTY")
	}
	if _, err := fmt.Fprint(r.Stdout, prompt); err != nil {
		return "", err
	}
	restore, err := setTerminalEcho(in, false)
	if err != nil {
		return "", err
	}
	line, readErr := readLine(in)
	restoreErr := restore()
	_, _ = fmt.Fprintln(r.Stdout)
	if readErr != nil {
		return "", readErr
	}
	if restoreErr != nil {
		return "", restoreErr
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readLine(r io.Reader) (string, error) {
	var b strings.Builder
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n > 0 {
			b.WriteByte(one[0])
			if one[0] == '\n' {
				return b.String(), nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
	}
}

func isTerminal(file *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

func setTerminalEcho(file *os.File, enabled bool) (func() error, error) {
	var oldState syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&oldState))); errno != 0 {
		return nil, errno
	}
	newState := oldState
	if enabled {
		newState.Lflag |= syscall.ECHO
	} else {
		newState.Lflag &^= syscall.ECHO
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newState))); errno != 0 {
		return nil, errno
	}
	return func() error {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&oldState))); errno != 0 {
			return errno
		}
		return nil
	}, nil
}

func readProtectedSecretFile(label, filePath string) ([]byte, error) {
	abs, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid path", label)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: stat failed", label)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: must be a regular non-symlink file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: unsafe permissions", label)
	}
	if err := checkCommandFileOwner(label, info); err != nil {
		return nil, err
	}
	dir := filepath.Dir(abs)
	for {
		dinfo, err := os.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("%s: parent directory stat failed", label)
		}
		if dinfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: parent directories must not be symlinks", label)
		}
		if dinfo.Mode().Perm()&0o002 != 0 {
			return nil, fmt.Errorf("%s: parent directory is world-writable", label)
		}
		if err := checkCommandFileOwner(label, dinfo); err != nil {
			return nil, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: read failed", label)
	}
	return data, nil
}

func checkCommandFileOwner(label string, info os.FileInfo) error {
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

func (r ServerRunner) reportBootstrapSuccess(jsonOut bool, body map[string]any, human func()) int {
	if jsonOut {
		_ = json.NewEncoder(r.Stdout).Encode(body)
		return 0
	}
	human()
	return 0
}

func (r ServerRunner) reportBootstrapFailure(jsonOut bool, prefix, code string, err error) int {
	if jsonOut {
		_ = json.NewEncoder(r.Stdout).Encode(map[string]any{"status": "failed", "error": code})
		return 1
	}
	fmt.Fprintf(r.Stderr, "%s: %s\n", prefix, security.RedactString(err.Error()))
	return 1
}

type bootstrapServices struct {
	resources *runtimeResources
	users     *users.Service
	issuers   *issuers.Service
	dns       *dnsproviders.Service
	dnsRepo   dnsproviders.Repository
}

func (s *bootstrapServices) Close() {
	if s != nil && s.resources != nil {
		s.resources.Close()
	}
}

func (r ServerRunner) openBootstrapServices(ctx context.Context, configPath string) (*bootstrapServices, error) {
	cfg, err := config.LoadFile(configPath, config.LoadOptions{})
	if err != nil {
		return nil, err
	}
	resources, err := openRuntimeResources(ctx, cfg, nil, runtimeMigrationsApply)
	if err != nil {
		return nil, err
	}
	userRepo := users.NewRepository(resources.Storage)
	appRepo := applications.NewRepository(resources.Storage)
	auditRepo := audit.NewRepository(resources.Storage)
	issuerRepo := issuers.NewRepository(resources.Storage)
	dnsRepo := dnsproviders.NewRepository(resources.Storage)
	acmeHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.ACMEProxy)
	if err != nil {
		resources.Close()
		return nil, err
	}
	cloudflareHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.Cloudflare)
	if err != nil {
		resources.Close()
		return nil, err
	}
	arvanHTTP, err := config.NewOutboundHTTPClient(cfg.OutboundHTTP, cfg.OutboundHTTP.ArvanCloud)
	if err != nil {
		resources.Close()
		return nil, err
	}
	usersService := users.NewService(users.ServiceConfig{
		Repository:      userRepo,
		AuditRepository: auditRepo,
		GrantReader:     applications.NewService(applications.ServiceConfig{Repository: appRepo}),
		KeySet:          resources.KeySet,
		Config:          cfg.Auth,
		Storage:         resources.Storage,
	})
	issuerService := issuers.NewService(issuers.ServiceConfig{
		Repository:       issuerRepo,
		AuditRepository:  auditRepo,
		AccountRegistrar: acmedomain.NewAccountClient(acmeHTTP),
		KeySet:           resources.KeySet,
		Storage:          resources.Storage,
	})
	dnsService := dnsproviders.NewService(dnsproviders.ServiceConfig{
		Repository:      dnsRepo,
		AuditRepository: auditRepo,
		KeySet:          resources.KeySet,
		ZoneListers: dnsproviders.ZoneListerRegistry{
			dnsproviders.ProviderTypeCloudflare: dnsproviders.NewCloudflareClient(cloudflareHTTP),
			dnsproviders.ProviderTypeArvanCloud: dnsproviders.NewArvanCloudClient(arvanHTTP),
		},
		Storage: resources.Storage,
	})
	return &bootstrapServices{resources: resources, users: usersService, issuers: issuerService, dns: dnsService, dnsRepo: dnsRepo}, nil
}

type runtimeResources struct {
	Storage         *storage.Pool
	MigrationDB     *sql.DB
	Migrations      migrations.Runner
	TLSLoader       *config.TLSCertificateLoader
	KeySet          *security.KeySet
	SelfCertificate *selfcert.Service
	cfg             *config.Config
}

type runtimeMigrationMode int

const (
	runtimeMigrationsCheckOnly runtimeMigrationMode = iota
	runtimeMigrationsApply
)

type migrationPendingError struct {
	Status migrations.Status
}

func (e migrationPendingError) Error() string {
	return fmt.Sprintf("database migrations are pending: current_version=%d latest_version=%d pending=%d; run certhub-server migrate or start with certhub-server run --migrate", e.Status.CurrentVersion, e.Status.LatestVersion, e.Status.Pending)
}

func openRuntimeResources(ctx context.Context, cfg *config.Config, tlsLoader *config.TLSCertificateLoader, migrationMode runtimeMigrationMode) (*runtimeResources, error) {
	keySet, err := security.NewKeySetFromBase64(string(cfg.Encryption.Key))
	if err != nil {
		return nil, fmt.Errorf("encryption key is unavailable")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	pool, err := storage.Open(checkCtx, storage.Config{URL: string(cfg.Database.URL)})
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(checkCtx); err != nil {
		pool.Close()
		return nil, err
	}
	migrationDB, err := migrations.OpenDB(string(cfg.Database.URL))
	if err != nil {
		pool.Close()
		return nil, err
	}
	runner := migrations.NewRunner(migrations.DefaultDir)
	status, err := runRuntimeMigrations(checkCtx, runner, migrationDB, migrationMode)
	if err != nil {
		_ = migrationDB.Close()
		pool.Close()
		return nil, err
	}
	if !status.Compatible {
		_ = migrationDB.Close()
		pool.Close()
		return nil, migrations.IncompatibleError{Status: status}
	}
	return &runtimeResources{Storage: pool, MigrationDB: migrationDB, Migrations: runner, TLSLoader: tlsLoader, KeySet: keySet, cfg: cfg}, nil
}

func runRuntimeMigrations(ctx context.Context, runner migrations.Runner, db *sql.DB, mode runtimeMigrationMode) (migrations.Status, error) {
	switch mode {
	case runtimeMigrationsApply:
		return runner.Up(ctx, db)
	case runtimeMigrationsCheckOnly:
		status, err := runner.Status(ctx, db)
		if err != nil {
			return migrations.Status{}, err
		}
		if status.CurrentVersion < status.LatestVersion {
			return status, migrationPendingError{Status: status}
		}
		return status, nil
	default:
		return migrations.Status{}, errors.New("invalid runtime migration mode")
	}
}

func (r *runtimeResources) Close() {
	if r == nil {
		return
	}
	if r.MigrationDB != nil {
		_ = r.MigrationDB.Close()
	}
	if r.Storage != nil {
		r.Storage.Close()
	}
}

func (r *runtimeResources) CheckReadiness() []httpapi.ReadinessCheck {
	checks := []httpapi.ReadinessCheck{
		{Name: "postgresql", Status: "ok"},
		{Name: "migrations", Status: "ok"},
		{Name: "encryption_key", Status: "ok"},
		{Name: "process_configuration", Status: "ok"},
	}
	tlsCheck := -1
	if r != nil && r.cfg != nil && r.cfg.TLS.CertFile != "" {
		tlsCheck = len(checks)
		checks = append(checks, httpapi.ReadinessCheck{Name: "tls_certificate", Status: "ok"})
	}
	if r == nil || r.cfg == nil {
		return failedAll(checks)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := security.NewKeySetFromBase64(string(r.cfg.Encryption.Key)); err != nil {
		checks[2].Status = "failed"
	}
	if r.Storage == nil || r.Storage.Ping(ctx) != nil {
		checks[0].Status = "failed"
	}
	if r.MigrationDB == nil {
		checks[1].Status = "failed"
	} else if status, err := r.Migrations.Status(ctx, r.MigrationDB); err != nil || !status.Compatible {
		checks[1].Status = "failed"
	}
	if tlsCheck >= 0 {
		if r.TLSLoader == nil {
			checks[tlsCheck].Status = "failed"
		} else if err := r.TLSLoader.ReadinessError(); err != nil {
			checks[tlsCheck].Status = "failed"
		}
	}
	if r.cfg.SelfCertificate.SyncEnabled {
		status := "failed"
		if r.SelfCertificate != nil {
			status = r.SelfCertificate.Status().ReadinessStatus()
		}
		checks = append(checks, httpapi.ReadinessCheck{Name: "server_self_certificate", Status: status})
	}
	return checks
}

func failedAll(checks []httpapi.ReadinessCheck) []httpapi.ReadinessCheck {
	for i := range checks {
		checks[i].Status = "failed"
	}
	return checks
}
