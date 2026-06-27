package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	EnvelopeVersion = "1"
	EnvelopeAlg     = "AES-256-GCM"
	EnvelopeKeyID   = "default"
	nonceSize       = 12
)

var ErrDecryptFailed = errors.New("decryption failed")

type Envelope struct {
	Version    string `json:"version"`
	Alg        string `json:"alg"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	AADContext string `json:"aad_context"`
}

func (k *KeySet) SealDatabaseValue(plaintext []byte, aadContext string) (string, error) {
	if aadContext == "" {
		return "", errors.New("aad context is required")
	}
	block, err := aes.NewCipher(k.dbAEADKey)
	if err != nil {
		return "", fmt.Errorf("database envelope: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("database envelope: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("database envelope nonce: %w", err)
	}
	env := Envelope{
		Version:    EnvelopeVersion,
		Alg:        EnvelopeAlg,
		KeyID:      EnvelopeKeyID,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, []byte(aadContext))),
		AADContext: aadContext,
	}
	data, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (k *KeySet) OpenDatabaseValue(encoded string, expectedAADContext string) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal([]byte(encoded), &env); err != nil {
		return nil, ErrDecryptFailed
	}
	if env.Version != EnvelopeVersion || env.Alg != EnvelopeAlg || env.KeyID != EnvelopeKeyID || env.AADContext != expectedAADContext {
		return nil, ErrDecryptFailed
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(env.Nonce)
	if err != nil || len(nonce) != nonceSize {
		return nil, ErrDecryptFailed
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(env.Ciphertext)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(k.dbAEADKey)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(expectedAADContext))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

func (k *KeySet) EncryptTOTPSecret(secret, aadContext string) (string, error) {
	return k.SealDatabaseValue([]byte(secret), aadContext)
}

func (k *KeySet) DecryptTOTPSecret(encoded, aadContext string) (string, error) {
	plaintext, err := k.OpenDatabaseValue(encoded, aadContext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
