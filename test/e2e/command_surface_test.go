package e2e

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandHelpAndKeyGenerationPublicSurfaces(t *testing.T) {
	repoRoot := findRepoRoot(t)
	binDir := filepath.Join(repoRoot, "dist", "bin")
	for _, name := range []string{"certhub-server", "certhub-cli", "certhub-operator"} {
		path := filepath.Join(binDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Skipf("built binary is required for public-surface E2E: %s", path)
		}
		out, err := exec.Command(path, "help").CombinedOutput()
		if err != nil {
			t.Fatalf("%s help failed: %v\n%s", name, err, out)
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Fatalf("%s help did not include usage: %s", name, out)
		}
	}
	helpCases := []struct {
		name     string
		args     []string
		contains []string
	}{
		{"server bootstrap help", []string{"certhub-server", "bootstrap", "--help"}, []string{"create-admin", "--config"}},
		{"server bootstrap leaf help", []string{"certhub-server", "bootstrap", "create-admin", "--help"}, []string{"--email", "--password"}},
		{"cli run help", []string{"certhub-cli", "run", "--help"}, []string{"--config", "--once"}},
		{"operator run help", []string{"certhub-operator", "run", "--help"}, []string{"CERTHUB_URL", "CERTHUB_TOKEN_SECRET_NAME"}},
	}
	for _, tt := range helpCases {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{}, tt.args...)
			out, err := exec.Command(filepath.Join(binDir, args[0]), args[1:]...).CombinedOutput()
			if err != nil {
				t.Fatalf("%s failed: %v\n%s", tt.name, err, out)
			}
			for _, want := range tt.contains {
				if !strings.Contains(string(out), want) {
					t.Fatalf("%s missing %q: %s", tt.name, want, out)
				}
			}
		})
	}

	out, err := exec.Command(filepath.Join(binDir, "certhub-server"), "generate-encryption-key").CombinedOutput()
	if err != nil {
		t.Fatalf("generate-encryption-key failed: %v\n%s", err, out)
	}
	raw := strings.TrimSpace(string(out))
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("generated key is not standard base64: %q", raw)
	}
	if len(decoded) != 32 {
		t.Fatalf("generated key length = %d, want 32 bytes", len(decoded))
	}
}

func TestOperatorConfigErrorDoesNotLeakSecretCanary(t *testing.T) {
	repoRoot := findRepoRoot(t)
	operatorPath := filepath.Join(repoRoot, "dist", "bin", "certhub-operator")
	if _, err := os.Stat(operatorPath); err != nil {
		t.Skipf("built operator binary is required for public-surface E2E: %s", operatorPath)
	}

	cmd := exec.Command(operatorPath, "run")
	cmd.Env = append(os.Environ(), "CERTHUB_TOKEN=M10_OPERATOR_SECRET_CANARY")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("operator run unexpectedly succeeded")
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("operator run exit = %v, output=%s", err, output)
	}
	if strings.Contains(string(output), "M10_OPERATOR_SECRET_CANARY") || strings.Contains(string(output), "CERTHUB_TOKEN=") {
		t.Fatalf("operator config error leaked secret canary: %s", output)
	}
	if !strings.Contains(string(output), "invalid operator configuration") {
		t.Fatalf("operator config error missing expected message: %s", output)
	}
}
