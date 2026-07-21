package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOperatorHelpSurfaces(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains []string
	}{
		{
			name:     "top level",
			args:     []string{"--help"},
			contains: []string{"Usage:", "certhub-operator [flags]", "run", "CERTHUB_URL"},
		},
		{
			name:     "run help",
			args:     []string{"run", "--help"},
			contains: []string{"Usage:", "certhub-operator run", "CERTHUB_TOKEN", "WATCH_NAMESPACES"},
		},
		{
			name:     "help run",
			args:     []string{"help", "run"},
			contains: []string{"Usage:", "certhub-operator run", "CERTHUB_TOKEN"},
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

func TestOperatorRunRejectsUnexpectedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown command") && !strings.Contains(stderr.String(), "accepts 0 arg") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
