package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/torob/certhub/internal/operator"
)

const operatorConfigHelp = `Configuration:
  CERTHUB_URL                         required absolute https URL
  CERTHUB_TOKEN                       required Certhub Application token
  WATCH_NAMESPACES                    optional comma-separated namespace scope, empty means all namespaces
  CERTHUB_METRICS_BIND_ADDR           optional metrics/probe bind address, default :8080
  CERTHUB_RESYNC_INTERVAL             optional duration, minimum 30s, default 6h
  CERTHUB_RECONCILE_BACKOFF           optional duration, default 1m
  CERTHUB_HTTP_TIMEOUT                optional backend request timeout, default 30s
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	exitCode := 0
	root := &cobra.Command{
		Use:           "certhub-operator",
		Short:         "Certhub Kubernetes operator command",
		Long:          "Certhub Kubernetes operator command.\n\n" + operatorConfigHelp,
		SilenceUsage:  true,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Start the Kubernetes operator",
		Long:  "Start the Kubernetes operator.\n\n" + operatorConfigHelp,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := operator.LoadConfigFromEnv()
			if err != nil {
				fmt.Fprintf(stderr, "invalid operator configuration: %s\n", err)
				exitCode = 2
				return
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			runtime, err := operator.NewInClusterRuntime(ctx, cfg)
			if err != nil {
				fmt.Fprintf(stderr, "operator startup failed: %s\n", operator.Sanitize(err.Error()))
				exitCode = 1
				return
			}
			if err := runtime.Run(ctx, stderr); err != nil {
				fmt.Fprintf(stderr, "operator runtime failed: %s\n", operator.Sanitize(err.Error()))
				exitCode = 1
				return
			}
		},
	})

	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return exitCode
}
