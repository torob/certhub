package auth

import "testing"

func TestGenerateTOTPRFC6238SHA1Vector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := GenerateTOTP(secret, 1, 8); got != "94287082" {
		t.Fatalf("totp = %s", got)
	}
}
