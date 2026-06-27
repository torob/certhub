package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"certhub/internal/operator"
)

const operatorHelp = `certhub-operator is the Certhub Kubernetes operator command.

Usage:
  certhub-operator help
  certhub-operator --help
  certhub-operator run

Configuration:
  CERTHUB_URL                         required absolute https URL
  CERTHUB_TOKEN_SECRET_NAME           required Kubernetes Secret name
  CERTHUB_TOKEN_SECRET_KEY            optional Secret data key, default token
  CERTHUB_TOKEN_SECRET_NAMESPACE      optional token Secret namespace
  WATCH_NAMESPACE                     optional namespace scope, empty means all namespaces
  CERTHUB_ALLOWED_SECRET_NAMES        optional comma-separated target Secret allowlist
  CERTHUB_METRICS_BIND_ADDR           optional metrics/probe bind address, default :8080
  CERTHUB_RESYNC_INTERVAL             optional duration, default 6h
  CERTHUB_RECONCILE_BACKOFF           optional duration, default 1m
  CERTHUB_HTTP_TIMEOUT                optional backend request timeout, default 30s
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, operatorHelp)
		return 0
	}

	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, operatorHelp)
		return 0
	case "run":
		cfg, err := operator.LoadConfigFromEnv()
		if err != nil {
			fmt.Fprintf(stderr, "invalid operator configuration: %s\n", err)
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		runtime, err := operator.NewInClusterRuntime(ctx, cfg)
		if err != nil {
			fmt.Fprintf(stderr, "operator startup failed: %s\n", operator.Sanitize(err.Error()))
			return 1
		}
		if err := runtime.Run(ctx, stderr); err != nil {
			fmt.Fprintf(stderr, "operator runtime failed: %s\n", operator.Sanitize(err.Error()))
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown certhub-operator command %q\n\n", args[0])
		fmt.Fprint(stderr, operatorHelp)
		return 2
	}
}
