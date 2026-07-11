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
	"time"

	"github.com/torob/certhub/pkg/netretry"
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
	Retry      netretry.Policy
}

func NewAccountClient(client *http.Client, policies ...netretry.Policy) *AccountClient {
	if client == nil {
		client = &http.Client{}
	}
	policy := netretry.DefaultPolicy()
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &AccountClient{HTTPClient: client, Retry: policy}
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
		RetryBackoff: func(n int, _ *http.Request, resp *http.Response) time.Duration {
			retryAfter := time.Duration(0)
			if resp != nil {
				retryAfter = netretry.ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now().UTC())
			}
			return netretry.Backoff(c.Retry, n, retryAfter)
		},
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
