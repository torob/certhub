package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

	xacme "golang.org/x/crypto/acme"
)

var (
	ErrOrderClientUnavailable = errors.New("acme order client unavailable")
	ErrOrderOperation         = errors.New("acme order operation failed")
)

type OrderClientParams struct {
	DirectoryURL         string
	AccountURL           string
	AccountPrivateKeyPEM []byte
}

type CreateOrderParams struct {
	OrderClientParams
	Identifiers []string
}

type FetchOrderParams struct {
	OrderClientParams
	OrderURL string
}

type FetchAuthorizationParams struct {
	OrderClientParams
	AuthorizationURL string
}

type AcceptChallengeParams struct {
	OrderClientParams
	ChallengeURL string
	Token        string
}

type FinalizeOrderParams struct {
	OrderClientParams
	FinalizeURL string
	CSRDER      []byte
	Bundle      bool
}

type FetchCertificateParams struct {
	OrderClientParams
	CertificateURL string
	Bundle         bool
}

type RevokeCertificateParams struct {
	OrderClientParams
	CertificateDER []byte
	Reason         xacme.CRLReasonCode
}

type Order struct {
	URL               string
	Status            string
	Identifiers       []string
	AuthorizationURLs []string
	FinalizeURL       string
	CertificateURL    string
}

type Authorization struct {
	URL          string
	Status       string
	Identifier   string
	Wildcard     bool
	DNSChallenge *DNSChallenge
}

type DNSChallenge struct {
	URL      string
	Token    string
	TXTValue string
	Status   string
}

type CertificateBundle struct {
	CertificateURL string
	DERChain       [][]byte
}

type OrderManager interface {
	CreateOrder(context.Context, CreateOrderParams) (Order, error)
	FetchOrder(context.Context, FetchOrderParams) (Order, error)
	FetchAuthorization(context.Context, FetchAuthorizationParams) (Authorization, error)
	AcceptChallenge(context.Context, AcceptChallengeParams) error
	FinalizeOrder(context.Context, FinalizeOrderParams) (CertificateBundle, error)
	FetchCertificate(context.Context, FetchCertificateParams) ([][]byte, error)
	RevokeCertificate(context.Context, RevokeCertificateParams) error
}

type OrderClient struct {
	HTTPClient *http.Client
}

func NewOrderClient(client *http.Client) *OrderClient {
	if client == nil {
		client = &http.Client{}
	}
	return &OrderClient{HTTPClient: client}
}

func (c *OrderClient) CreateOrder(ctx context.Context, params CreateOrderParams) (Order, error) {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return Order{}, err
	}
	if len(params.Identifiers) == 0 {
		return Order{}, ErrOrderOperation
	}
	ids := make([]xacme.AuthzID, 0, len(params.Identifiers))
	for _, identifier := range params.Identifiers {
		identifier = strings.TrimSpace(identifier)
		if identifier == "" {
			return Order{}, ErrOrderOperation
		}
		ids = append(ids, xacme.AuthzID{Type: "dns", Value: identifier})
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return Order{}, ErrOrderOperation
	}
	return mapOrder(order), nil
}

func (c *OrderClient) FetchOrder(ctx context.Context, params FetchOrderParams) (Order, error) {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return Order{}, err
	}
	if params.OrderURL == "" {
		return Order{}, ErrOrderOperation
	}
	order, err := client.GetOrder(ctx, params.OrderURL)
	if err != nil {
		return Order{}, ErrOrderOperation
	}
	return mapOrder(order), nil
}

func (c *OrderClient) FetchAuthorization(ctx context.Context, params FetchAuthorizationParams) (Authorization, error) {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return Authorization{}, err
	}
	if params.AuthorizationURL == "" {
		return Authorization{}, ErrOrderOperation
	}
	authz, err := client.GetAuthorization(ctx, params.AuthorizationURL)
	if err != nil {
		return Authorization{}, ErrOrderOperation
	}
	return mapAuthorization(client, authz), nil
}

func (c *OrderClient) AcceptChallenge(ctx context.Context, params AcceptChallengeParams) error {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return err
	}
	if params.ChallengeURL == "" || params.Token == "" {
		return ErrOrderOperation
	}
	_, err = client.Accept(ctx, &xacme.Challenge{Type: "dns-01", URI: params.ChallengeURL, Token: params.Token})
	if err != nil {
		return ErrOrderOperation
	}
	return nil
}

func (c *OrderClient) FinalizeOrder(ctx context.Context, params FinalizeOrderParams) (CertificateBundle, error) {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return CertificateBundle{}, err
	}
	if params.FinalizeURL == "" || len(params.CSRDER) == 0 {
		return CertificateBundle{}, ErrOrderOperation
	}
	der, certURL, err := client.CreateOrderCert(ctx, params.FinalizeURL, params.CSRDER, params.Bundle)
	if err != nil {
		return CertificateBundle{}, ErrOrderOperation
	}
	return CertificateBundle{CertificateURL: certURL, DERChain: der}, nil
}

func (c *OrderClient) FetchCertificate(ctx context.Context, params FetchCertificateParams) ([][]byte, error) {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return nil, err
	}
	if params.CertificateURL == "" {
		return nil, ErrOrderOperation
	}
	der, err := client.FetchCert(ctx, params.CertificateURL, params.Bundle)
	if err != nil {
		return nil, ErrOrderOperation
	}
	return der, nil
}

func (c *OrderClient) RevokeCertificate(ctx context.Context, params RevokeCertificateParams) error {
	client, err := c.acmeClient(params.OrderClientParams)
	if err != nil {
		return err
	}
	if len(params.CertificateDER) == 0 {
		return ErrOrderOperation
	}
	if err := client.RevokeCert(ctx, nil, params.CertificateDER, params.Reason); err != nil {
		return ErrOrderOperation
	}
	return nil
}

func (c *OrderClient) acmeClient(params OrderClientParams) (*xacme.Client, error) {
	if c == nil || c.HTTPClient == nil {
		return nil, ErrOrderClientUnavailable
	}
	if params.DirectoryURL == "" || len(params.AccountPrivateKeyPEM) == 0 {
		return nil, ErrOrderOperation
	}
	key, err := parsePrivateKeyPEM(params.AccountPrivateKeyPEM)
	if err != nil {
		return nil, ErrOrderOperation
	}
	client := &xacme.Client{
		Key:          key,
		HTTPClient:   c.HTTPClient,
		DirectoryURL: params.DirectoryURL,
		UserAgent:    "certhub",
	}
	if params.AccountURL != "" {
		client.KID = xacme.KeyID(params.AccountURL)
	}
	return client, nil
}

func parsePrivateKeyPEM(privateKeyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("private key PEM is invalid")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	case *rsa.PrivateKey:
		return key, nil
	default:
		return nil, errors.New("private key type is unsupported")
	}
}

func mapOrder(order *xacme.Order) Order {
	if order == nil {
		return Order{}
	}
	identifiers := make([]string, 0, len(order.Identifiers))
	for _, id := range order.Identifiers {
		identifiers = append(identifiers, id.Value)
	}
	return Order{
		URL:               order.URI,
		Status:            order.Status,
		Identifiers:       identifiers,
		AuthorizationURLs: append([]string(nil), order.AuthzURLs...),
		FinalizeURL:       order.FinalizeURL,
		CertificateURL:    order.CertURL,
	}
}

func mapAuthorization(client *xacme.Client, authz *xacme.Authorization) Authorization {
	if authz == nil {
		return Authorization{}
	}
	out := Authorization{
		URL:        authz.URI,
		Status:     authz.Status,
		Identifier: authz.Identifier.Value,
		Wildcard:   authz.Wildcard,
	}
	for _, challenge := range authz.Challenges {
		if challenge == nil || challenge.Type != "dns-01" {
			continue
		}
		txtValue, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			continue
		}
		out.DNSChallenge = &DNSChallenge{
			URL:      challenge.URI,
			Token:    challenge.Token,
			TXTValue: txtValue,
			Status:   challenge.Status,
		}
		break
	}
	return out
}
