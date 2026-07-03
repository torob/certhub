package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
)

type commandOptions struct {
	configPath string
	once       bool
	json       bool
	quiet      bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	exitCode := ExitSuccess
	root := &cobra.Command{
		Use:           "certhub-cli",
		Short:         "Certhub local certificate material sync command",
		SilenceUsage:  true,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.CompletionOptions.DisableDefaultCmd = true

	opts := commandOptions{}
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Sync configured certificate material",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			exitCode = runCommand(ctx, opts, stdout, stderr)
		},
	}
	runCmd.Flags().StringVar(&opts.configPath, "config", "", "config file path")
	runCmd.Flags().BoolVar(&opts.once, "once", false, "run one sync cycle and exit")
	runCmd.Flags().BoolVar(&opts.json, "json", false, "print JSON summary")
	runCmd.Flags().BoolVar(&opts.quiet, "quiet", false, "suppress non-error human output")
	root.AddCommand(runCmd)

	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitInvalidArguments
	}
	return exitCode
}

func runCommand(ctx context.Context, opts commandOptions, stdout, stderr io.Writer) int {
	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return ExitInvalidArguments
	}
	plan, err := BuildPlan(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return ExitInvalidArguments
	}
	runner, err := NewSyncRunner(cfg, plan)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitCodeForError(err)
	}
	if opts.once {
		summary := runner.RunOnce(ctx)
		writeSummary(summary, opts, stdout, stderr)
		return summary.ExitCode()
	}
	if cfg.Scheduler.Interval <= 0 {
		fmt.Fprintln(stderr, "configuration error: scheduler.interval is required in scheduler mode")
		return ExitInvalidArguments
	}
	return runScheduler(ctx, cfg, runner, opts, stdout, stderr)
}

func runScheduler(ctx context.Context, cfg Config, runner *SyncRunner, opts commandOptions, stdout, stderr io.Writer) int {
	first := true
	for {
		if !first || !cfg.Scheduler.RunOnStartValue() {
			if !sleepContext(ctx, cfg.Scheduler.Interval+jitter(cfg.Scheduler.Jitter)) {
				return 0
			}
		}
		first = false
		summary := runner.RunOnce(ctx)
		writeSummary(summary, opts, stdout, stderr)
		if ctx.Err() != nil {
			return summary.ExitCode()
		}
	}
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max) + 1))
}

var sleepContext = sleepWithContext

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
