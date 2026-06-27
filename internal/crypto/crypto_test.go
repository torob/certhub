package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKeySet(t *testing.T) *KeySet {
	t.Helper()
	key, err := NewKeySet(make([]byte, RootKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDatabaseEnvelopeRoundTripAndTamperFailures(t *testing.T) {
	keys := testKeySet(t)
	aad := "v1:table=users:column=totp_secret_encrypted:row_id=11111111-1111-1111-1111-111111111111"
	encoded, err := keys.SealDatabaseValue([]byte("SECRET-TOTP-CANARY"), aad)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := keys.OpenDatabaseValue(encoded, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "SECRET-TOTP-CANARY" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if strings.Contains(encoded, "SECRET-TOTP-CANARY") {
		t.Fatalf("envelope leaked plaintext: %s", encoded)
	}
	var env Envelope
	if err := json.Unmarshal([]byte(encoded), &env); err != nil {
		t.Fatal(err)
	}
	if env.Version != EnvelopeVersion || env.Alg != EnvelopeAlg || env.KeyID != EnvelopeKeyID || env.AADContext != aad {
		t.Fatalf("envelope fields = %#v", env)
	}
	if _, err := keys.OpenDatabaseValue(encoded, aad+"x"); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("AAD mismatch error = %v", err)
	}
	env.Ciphertext = base64.StdEncoding.EncodeToString([]byte("tampered"))
	tampered, _ := json.Marshal(env)
	if _, err := keys.OpenDatabaseValue(string(tampered), aad); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestDerivedHashesAndETags(t *testing.T) {
	keys := testKeySet(t)
	token := "cth_app_v1_0123456789012345678901234567890123456789012"
	hash := keys.HashToken(token)
	if len(hash) != 43 {
		t.Fatalf("token hash length = %d", len(hash))
	}
	if hash != keys.HashToken(token) || !ConstantTimeEqualString(hash, keys.HashToken(token)) {
		t.Fatalf("token hash not deterministic")
	}
	if keys.HashOIDCState("state") == hash {
		t.Fatalf("different derivation infos produced matching hashes")
	}
	etag := keys.MaterialETag("cert-version-id:sha256")
	if !strings.HasPrefix(etag, `"cth-mat-v1.`) || !strings.HasSuffix(etag, `"`) || len(etag) != len(`"cth-mat-v1."`)+43 {
		t.Fatalf("etag = %q", etag)
	}
}

func TestPasswordHashPHCVerifyPolicyAndRehashSignal(t *testing.T) {
	if err := ValidatePasswordPolicy("short", "user@example.com"); err == nil {
		t.Fatalf("short password accepted")
	}
	if err := ValidatePasswordPolicy("user@example.com", "user@example.com"); err == nil {
		t.Fatalf("email password accepted")
	}
	password := "  long enough password  "
	phc, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("phc = %q", phc)
	}
	match, rehash, err := VerifyPassword(password, phc)
	if err != nil || !match || rehash {
		t.Fatalf("VerifyPassword() match=%v rehash=%v err=%v", match, rehash, err)
	}
	match, _, err = VerifyPassword(strings.TrimSpace(password), phc)
	if err != nil || match {
		t.Fatalf("trimmed password matched: match=%v err=%v", match, err)
	}
}

func TestRedactionCanaries(t *testing.T) {
	input := `Authorization: Bearer cth_uat_v1_SECRETUSER Cookie: session=SECRETCOOKIE password=SECRETPASS otpauth://totp/Certhub:user?secret=SECRETTOTP -----BEGIN PRIVATE KEY-----SECRETKEY-----END PRIVATE KEY----- postgres://user:SECRETPG@db/certhub`
	output := RedactString(input)
	for _, canary := range []string{"SECRETUSER", "SECRETCOOKIE", "SECRETPASS", "SECRETTOTP", "SECRETKEY", "SECRETPG"} {
		if strings.Contains(output, canary) {
			t.Fatalf("redaction leaked %s in %q", canary, output)
		}
	}
}

func TestTOTPSecretHelpersUseDatabaseEnvelope(t *testing.T) {
	keys := testKeySet(t)
	aad := "v1:table=users:column=pending_totp_secret_encrypted:row_id=22222222-2222-2222-2222-222222222222"
	encoded, err := keys.EncryptTOTPSecret("JBSWY3DPEHPK3PXP", aad)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := keys.DecryptTOTPSecret(encoded, aad)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "JBSWY3DPEHPK3PXP" || strings.Contains(encoded, secret) {
		t.Fatalf("secret=%q envelope=%s", secret, encoded)
	}
}

func TestPrivateFileHelpers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := WritePrivateFile(filepath.Join(dir, "privkey.pem"), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(dir); err == nil {
		t.Fatalf("world/group accessible dir accepted")
	}
}
