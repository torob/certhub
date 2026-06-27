package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

const (
	PasswordMinLength = 12
	PasswordMaxLength = 1024
	argonMemoryKiB    = 64 * 1024
	argonIterations   = 3
	argonParallelism  = 1
	argonSaltLength   = 16
	argonKeyLength    = 32
)

var ErrInvalidPasswordHash = errors.New("invalid password hash")

type PasswordParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var CurrentPasswordParams = PasswordParams{
	MemoryKiB:   argonMemoryKiB,
	Iterations:  argonIterations,
	Parallelism: argonParallelism,
	SaltLength:  argonSaltLength,
	KeyLength:   argonKeyLength,
}

func ValidatePasswordPolicy(password, normalizedEmail string) error {
	if len(password) < PasswordMinLength {
		return errors.New("password is too short")
	}
	if len(password) > PasswordMaxLength {
		return errors.New("password is too long")
	}
	for _, r := range password {
		if r == 0 || unicode.IsControl(r) {
			return errors.New("password contains a control character")
		}
	}
	if normalizedEmail != "" && password == normalizedEmail {
		return errors.New("password must not equal email")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, CurrentPasswordParams.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, CurrentPasswordParams.Iterations, CurrentPasswordParams.MemoryKiB, CurrentPasswordParams.Parallelism, CurrentPasswordParams.KeyLength)
	return formatPHC(CurrentPasswordParams, salt, hash), nil
}

func VerifyPassword(password, phc string) (match bool, needsRehash bool, err error) {
	params, salt, expected, err := parsePHC(phc)
	if err != nil {
		return false, false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, uint32(len(expected)))
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return false, false, nil
	}
	return true, passwordParamsWeaker(params), nil
}

func formatPHC(params PasswordParams, salt, hash []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.MemoryKiB,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func parsePHC(phc string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	params, err := parsePHCParams(parts[3])
	if err != nil {
		return PasswordParams{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < argonSaltLength {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))
	return params, salt, hash, nil
}

func parsePHCParams(value string) (PasswordParams, error) {
	var params PasswordParams
	seen := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		key, raw, ok := strings.Cut(item, "=")
		if !ok || seen[key] {
			return PasswordParams{}, ErrInvalidPasswordHash
		}
		seen[key] = true
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n == 0 {
			return PasswordParams{}, ErrInvalidPasswordHash
		}
		switch key {
		case "m":
			params.MemoryKiB = uint32(n)
		case "t":
			params.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return PasswordParams{}, ErrInvalidPasswordHash
			}
			params.Parallelism = uint8(n)
		default:
			return PasswordParams{}, ErrInvalidPasswordHash
		}
	}
	if params.MemoryKiB == 0 || params.Iterations == 0 || params.Parallelism == 0 {
		return PasswordParams{}, ErrInvalidPasswordHash
	}
	return params, nil
}

func passwordParamsWeaker(params PasswordParams) bool {
	return params.MemoryKiB < CurrentPasswordParams.MemoryKiB ||
		params.Iterations < CurrentPasswordParams.Iterations ||
		params.Parallelism < CurrentPasswordParams.Parallelism ||
		params.SaltLength < CurrentPasswordParams.SaltLength ||
		params.KeyLength < CurrentPasswordParams.KeyLength
}
