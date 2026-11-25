package main

import (
	"bufio"
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLIHelpSurfaces(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains []string
	}{
		{
			name:     "top level",
			args:     []string{"--help"},
			contains: []string{"Usage:", "certhub-cli [flags]", "run"},
		},
		{
			name:     "run help",
			args:     []string{"run", "--help"},
			contains: []string{"Usage:", "certhub-cli run", "--config", "--once", "--json", "--quiet"},
		},
		{
			name:     "help run",
			args:     []string{"help", "run"},
			contains: []string{"Usage:", "certhub-cli run", "--config", "--once", "--json", "--quiet"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			for _, want := range tt.contains {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("stdout missing %q: %s", want, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestSchedulerStopsGracefullyOnShutdownSignals(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain is required to build the CLI binary")
	}
	cliPath := filepath.Join(t.TempDir(), "certhub-cli")
	build := exec.Command(goBin, "build", "-o", cliPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	tests := []struct {
		name   string
		signal os.Signal
	}{
		{name: "SIGTERM", signal: syscall.SIGTERM},
		{name: "SIGINT", signal: os.Interrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outDir := t.TempDir()
			if err := os.Chmod(outDir, 0o700); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-ID", "req-shutdown")
				_, _ = w.Write([]byte(materialJSON()))
			}))
			defer server.Close()

			configPath := filepath.Join(t.TempDir(), "cli.yaml")
			config := "url: " + server.URL + "\n" +
				"allow_plain_http_for_local_development: true\n" +
				"sync:\n" +
				"  per_certificate_timeout: 5s\n" +
				"  request_timeout: 2s\n" +
				"scheduler:\n" +
				"  interval: 1h\n" +
				"  jitter: 0s\n" +
				"  run_on_start: true\n" +
				"certificates:\n" +
				"  - domains:\n" +
				"      - api.example.com\n" +
				"    out_dir: " + outDir + "\n"
			if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(cliPath, "run", "--config", configPath, "--json")
			cmd.Env = append(os.Environ(), "CERTHUB_TOKEN="+testAppToken)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitDone := make(chan error, 1)
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
			})

			// The first cycle summary proves the signal handler is installed and
			// the scheduler is idle, waiting for the next interval.
			firstSummary := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				if scanner.Scan() {
					firstSummary <- scanner.Text()
				}
				for scanner.Scan() {
				}
				waitDone <- cmd.Wait()
			}()
			select {
			case line := <-firstSummary:
				if !strings.Contains(line, `"succeeded":1`) || !strings.Contains(line, `"changed":true`) {
					t.Fatalf("first summary = %s stderr=%s", line, stderr.String())
				}
			case err := <-waitDone:
				t.Fatalf("CLI exited before first cycle: %v stderr=%s", err, stderr.String())
			case <-time.After(10 * time.Second):
				t.Fatalf("timed out waiting for first scheduler cycle; stderr=%s", stderr.String())
			}

			if err := cmd.Process.Signal(tt.signal); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-waitDone:
				if err != nil {
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						t.Fatalf("CLI did not stop gracefully after %s: %v (exit code %d) stderr=%s", tt.name, err, exitErr.ExitCode(), stderr.String())
					}
					t.Fatalf("CLI wait after %s: %v stderr=%s", tt.name, err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("timed out waiting for CLI to stop after %s", tt.name)
			}
			if _, err := os.Stat(filepath.Join(outDir, "current", "privkey.pem")); err != nil {
				t.Fatalf("current private key missing after shutdown: %v", err)
			}
		})
	}
}
