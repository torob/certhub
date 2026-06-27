package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	xacme "golang.org/x/crypto/acme"
)

var (
	ErrAccountClientUnavailable = errors.New("acme account client unavailable")
	ErrAccountRegistration      = errors.New("acme account registration failed")
)

type AccountRegistrationParams struct {
	DirectoryURL string
	Email        string
}

type AccountRegistration struct {
	AccountURL    string
	PrivateKeyPEM []byte
}

type AccountRegistrar interface {
	RegisterOrReuseAccount(context.Context, AccountRegistrationParams) (AccountRegistration, error)
}

type AccountClient struct {
	HTTPClient *http.Client
}

func NewAccountClient(client *http.Client) *AccountClient {
	if client == nil {
		client = &http.Client{}
	}
	return &AccountClient{HTTPClient: client}
}

func (c *AccountClient) RegisterOrReuseAccount(ctx context.Context, params AccountRegistrationParams) (AccountRegistration, error) {
	if c == nil || c.HTTPClient == nil {
		return AccountRegistration{}, ErrAccountClientUnavailable
	}
	if params.DirectoryURL == "" || params.Email == "" {
		return AccountRegistration{}, ErrAccountRegistration
	}
	key, keyPEM, err := newECDSAPrivateKeyPEM()
	if err != nil {
		return AccountRegistration{}, err
	}
	client := &xacme.Client{
		Key:          key,
		HTTPClient:   c.HTTPClient,
		DirectoryURL: params.DirectoryURL,
		UserAgent:    "certhub",
	}
	account, err := client.Register(ctx, &xacme.Account{Contact: []string{"mailto:" + strings.TrimSpace(params.Email)}}, xacme.AcceptTOS)
	if err != nil {
		if !errors.Is(err, xacme.ErrAccountAlreadyExists) {
			return AccountRegistration{}, ErrAccountRegistration
		}
		account = &xacme.Account{URI: string(client.KID)}
	}
	if account.URI == "" {
		return AccountRegistration{}, ErrAccountRegistration
	}
	return AccountRegistration{
		AccountURL:    account.URI,
		PrivateKeyPEM: keyPEM,
	}, nil
}

func newECDSAPrivateKeyPEM() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("acme private key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("acme private key: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
