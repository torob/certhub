package dnsproviders

import (
	"strings"
	"testing"
)

func assertNoDNSCanaryLeak(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked secret %q: %v", secret, err)
		}
	}
}
