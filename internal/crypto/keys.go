package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	DatabaseAEADInfo    = "certhub-db-aead-v1"
	MaterialETagInfo    = "certhub-material-etag-v1"
	TokenHashInfo       = "certhub-token-hash-v1"
	OIDCStateHashInfo   = "certhub-oidc-state-v1"
	RootKeySize         = 32
	derivedKeySize      = 32
	materialETagPrefix  = `"cth-mat-v1.`
	materialETagPostfix = `"`
)

var ErrInvalidRootKey = errors.New("invalid encryption key")

type KeySet struct {
	dbAEADKey       []byte
	materialETagKey []byte
	tokenHashKey    []byte
	oidcStateKey    []byte
}

func NewKeySet(root []byte) (*KeySet, error) {
	if len(root) != RootKeySize {
		return nil, ErrInvalidRootKey
	}
	dbAEADKey, err := derive(root, DatabaseAEADInfo)
	if err != nil {
		return nil, err
	}
	materialETagKey, err := derive(root, MaterialETagInfo)
	if err != nil {
		return nil, err
	}
	tokenHashKey, err := derive(root, TokenHashInfo)
	if err != nil {
		return nil, err
	}
	oidcStateKey, err := derive(root, OIDCStateHashInfo)
	if err != nil {
		return nil, err
	}
	return &KeySet{
		dbAEADKey:       dbAEADKey,
		materialETagKey: materialETagKey,
		tokenHashKey:    tokenHashKey,
		oidcStateKey:    oidcStateKey,
	}, nil
}

func NewKeySetFromBase64(value string) (*KeySet, error) {
	root, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, ErrInvalidRootKey
	}
	return NewKeySet(root)
}

func derive(root []byte, info string) ([]byte, error) {
	reader := hkdf.New(sha256.New, root, nil, []byte(info))
	key := make([]byte, derivedKeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive %s: %w", info, err)
	}
	return key, nil
}

func (k *KeySet) HashToken(token string) string {
	return hmacBase64(k.tokenHashKey, token)
}

func (k *KeySet) HashOIDCState(state string) string {
	return hmacBase64(k.oidcStateKey, state)
}

func (k *KeySet) MaterialETag(canonicalDescriptor string) string {
	return materialETagPrefix + hmacBase64(k.materialETagKey, canonicalDescriptor) + materialETagPostfix
}

func hmacBase64(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func ConstantTimeEqualString(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
