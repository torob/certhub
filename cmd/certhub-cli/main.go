package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"time"
)

const cliHelp = `certhub-cli is the Certhub local certificate material sync command.

Usage:
  certhub-cli help
  certhub-cli --help
  certhub-cli run [--config <path>] [--once] [--json] [--quiet]
`

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
	if len(args) == 0 {
		fmt.Fprint(stdout, cliHelp)
		return 0
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, cliHelp)
		return 0
	case "run":
		opts, code := parseRunFlags(args[1:], stderr)
		if code != 0 {
			return code
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runCommand(ctx, opts, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown certhub-cli command %q\n\n", args[0])
		fmt.Fprint(stderr, cliHelp)
		return ExitInvalidArguments
	}
}

func parseRunFlags(args []string, stderr io.Writer) (commandOptions, int) {
	opts := commandOptions{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.configPath, "config", "", "config file path")
	fs.BoolVar(&opts.once, "once", false, "run one sync cycle and exit")
	fs.BoolVar(&opts.json, "json", false, "print JSON summary")
	fs.BoolVar(&opts.quiet, "quiet", false, "suppress non-error human output")
	if err := fs.Parse(args); err != nil {
		return opts, ExitInvalidArguments
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return opts, ExitInvalidArguments
	}
	return opts, 0
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
