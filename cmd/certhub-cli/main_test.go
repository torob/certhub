package main

import (
	"bytes"
	"strings"
	"testing"
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
