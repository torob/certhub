package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	acmedomain "github.com/torob/certhub/internal/acme"
	dnsproviders "github.com/torob/certhub/internal/dnsproviders"

	xacme "golang.org/x/crypto/acme"
)

const letsEncryptStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func TestExternalACMEStagingDNS01IssuanceAndRevocation(t *testing.T) {
	if os.Getenv("CERTHUB_EXTERNAL_ACME") != "1" {
		t.Skip("set CERTHUB_EXTERNAL_ACME=1 to run real ACME staging validation")
	}
	creds, err := loadExternalDNSCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if creds.CloudflareAPIToken == "" {
		t.Fatal("cloudflare credential is required for external ACME staging validation")
	}
	if creds.ArvanCloudAPIKey == "" {
		t.Fatal("arvancloud credential is required for external ACME staging validation")
	}

	cfZone := requiredExternalEnv(t, "CERTHUB_EXTERNAL_DNS_CLOUDFLARE_ZONE")
	arvanZone := requiredExternalEnv(t, "CERTHUB_EXTERNAL_DNS_ARVANCLOUD_ZONE")
	directoryURL := letsEncryptStagingDirectoryURL
	email := requiredExternalEnv(t, "CERTHUB_EXTERNAL_ACME_EMAIL")
	domains := []string{
		"certhub-test-acme-" + time.Now().UTC().Format("20060102") + "-" + randomHex(t, 5) + "." + cfZone,
		"certhub-test-acme-" + time.Now().UTC().Format("20060102") + "-" + randomHex(t, 5) + "." + arvanZone,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	account, err := acmedomain.NewAccountClient(httpClient()).RegisterOrReuseAccount(ctx, acmedomain.AccountRegistrationParams{
		DirectoryURL: directoryURL,
		Email:        email,
	})
	if err != nil {
		t.Fatalf("acme account registration failed")
	}
	orderParams := acmedomain.OrderClientParams{
		DirectoryURL:         directoryURL,
		AccountURL:           account.AccountURL,
		AccountPrivateKeyPEM: account.PrivateKeyPEM,
	}
	orderClient := acmedomain.NewOrderClient(httpClient())
	order, err := orderClient.CreateOrder(ctx, acmedomain.CreateOrderParams{
		OrderClientParams: orderParams,
		Identifiers:       domains,
	})
	if err != nil {
		t.Fatalf("acme order create failed")
	}
	if len(order.AuthorizationURLs) == 0 || order.FinalizeURL == "" {
		t.Fatalf("acme order missing required URLs")
	}

	cfClient := dnsproviders.NewCloudflareClient(httpClient())
	arvanClient := dnsproviders.NewArvanCloudClient(httpClient())
	var cleanup []func()
	defer func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}()

	for _, authzURL := range order.AuthorizationURLs {
		authz, err := orderClient.FetchAuthorization(ctx, acmedomain.FetchAuthorizationParams{
			OrderClientParams: orderParams,
			AuthorizationURL:  authzURL,
		})
		if err != nil {
			t.Fatalf("acme authorization fetch failed")
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		if authz.DNSChallenge == nil {
			t.Fatalf("acme authorization for %s has no dns-01 challenge", authz.Identifier)
		}
		op, cleanupFunc := presentACMEDNSChallenge(t, ctx, cfClient, arvanClient, creds, cfZone, arvanZone, authz)
		cleanup = append(cleanup, cleanupFunc)
		waitForTXTValue(t, ctx, op.RecordName, op.TXTValue)
		if err := orderClient.AcceptChallenge(ctx, acmedomain.AcceptChallengeParams{
			OrderClientParams: orderParams,
			ChallengeURL:      authz.DNSChallenge.URL,
			Token:             authz.DNSChallenge.Token,
		}); err != nil {
			t.Fatalf("acme challenge accept failed for %s", authz.Identifier)
		}
		waitForAuthorizationValid(t, ctx, orderClient, orderParams, authz.URL, authz.Identifier)
	}

	order = waitForOrderReady(t, ctx, orderClient, orderParams, order.URL)
	csrDER := newCSRDER(t, domains)
	bundle, err := orderClient.FinalizeOrder(ctx, acmedomain.FinalizeOrderParams{
		OrderClientParams: orderParams,
		FinalizeURL:       order.FinalizeURL,
		CSRDER:            csrDER,
		Bundle:            true,
	})
	if err != nil {
		t.Fatalf("acme order finalize failed")
	}
	if len(bundle.DERChain) == 0 {
		t.Fatal("acme order finalized without certificate chain")
	}
	leaf, err := x509.ParseCertificate(bundle.DERChain[0])
	if err != nil {
		t.Fatalf("acme leaf certificate parse failed")
	}
	for _, domain := range domains {
		if !slices.Contains(leaf.DNSNames, domain) {
			t.Fatalf("acme leaf certificate did not contain expected DNS name %s", domain)
		}
	}
	if err := orderClient.RevokeCertificate(ctx, acmedomain.RevokeCertificateParams{
		OrderClientParams: orderParams,
		CertificateDER:    bundle.DERChain[0],
		Reason:            xacme.CRLReasonCessationOfOperation,
	}); err != nil {
		t.Fatalf("acme certificate revocation failed")
	}
}

func presentACMEDNSChallenge(t *testing.T, ctx context.Context, cfClient *dnsproviders.CloudflareClient, arvanClient *dnsproviders.ArvanCloudClient, creds externalDNSCredentials, cfZone, arvanZone string, authz acmedomain.Authorization) (dnsproviders.DNS01ChallengeOperation, func()) {
	t.Helper()
	zoneName := ""
	var present func(context.Context, dnsproviders.DNS01ChallengeOperation) error
	var cleanup func(context.Context, dnsproviders.DNS01ChallengeOperation) error
	switch {
	case strings.HasSuffix(authz.Identifier, "."+cfZone) || authz.Identifier == cfZone:
		zoneName = cfZone
		present = func(ctx context.Context, op dnsproviders.DNS01ChallengeOperation) error {
			return cfClient.Present(ctx, dnsproviders.CloudflareCredentials{APIToken: creds.CloudflareAPIToken}, op)
		}
		cleanup = func(ctx context.Context, op dnsproviders.DNS01ChallengeOperation) error {
			return cfClient.CleanUp(ctx, dnsproviders.CloudflareCredentials{APIToken: creds.CloudflareAPIToken}, op)
		}
	case strings.HasSuffix(authz.Identifier, "."+arvanZone) || authz.Identifier == arvanZone:
		zoneName = arvanZone
		present = func(ctx context.Context, op dnsproviders.DNS01ChallengeOperation) error {
			return arvanClient.Present(ctx, dnsproviders.ArvanCloudCredentials{APIKey: creds.ArvanCloudAPIKey}, op)
		}
		cleanup = func(ctx context.Context, op dnsproviders.DNS01ChallengeOperation) error {
			return arvanClient.CleanUp(ctx, dnsproviders.ArvanCloudCredentials{APIKey: creds.ArvanCloudAPIKey}, op)
		}
	default:
		t.Fatalf("no DNS provider zone selected for %s", authz.Identifier)
	}
	op := dnsproviders.DNS01ChallengeOperation{
		ZoneName:   zoneName,
		RecordName: "_acme-challenge." + authz.Identifier,
		TXTValue:   authz.DNSChallenge.TXTValue,
		TTL:        120,
	}
	if err := present(ctx, op); err != nil {
		t.Fatalf("dns-01 present failed for %s", authz.Identifier)
	}
	return op, func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := cleanup(cleanupCtx, op); err != nil {
			t.Errorf("dns-01 cleanup failed for %s", authz.Identifier)
		}
	}
}

func waitForTXTValue(t *testing.T, ctx context.Context, recordName, txtValue string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	resolver := net.DefaultResolver
	for {
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		values, err := resolver.LookupTXT(lookupCtx, recordName)
		cancel()
		if err == nil {
			for _, value := range values {
				if value == txtValue {
					return
				}
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("dns-01 TXT value did not propagate for %s", recordName)
		}
		time.Sleep(10 * time.Second)
	}
}

func waitForAuthorizationValid(t *testing.T, ctx context.Context, client *acmedomain.OrderClient, params acmedomain.OrderClientParams, authzURL, identifier string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		authz, err := client.FetchAuthorization(ctx, acmedomain.FetchAuthorizationParams{OrderClientParams: params, AuthorizationURL: authzURL})
		if err != nil {
			t.Fatalf("acme authorization poll failed for %s", identifier)
		}
		switch authz.Status {
		case xacme.StatusValid:
			return
		case xacme.StatusInvalid:
			t.Fatalf("acme authorization became invalid for %s", identifier)
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("acme authorization did not become valid for %s", identifier)
		}
		time.Sleep(5 * time.Second)
	}
}

func waitForOrderReady(t *testing.T, ctx context.Context, client *acmedomain.OrderClient, params acmedomain.OrderClientParams, orderURL string) acmedomain.Order {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		order, err := client.FetchOrder(ctx, acmedomain.FetchOrderParams{OrderClientParams: params, OrderURL: orderURL})
		if err != nil {
			t.Fatalf("acme order poll failed")
		}
		switch order.Status {
		case xacme.StatusReady, xacme.StatusValid:
			return order
		case xacme.StatusInvalid:
			t.Fatalf("acme order became invalid")
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("acme order did not become ready")
		}
		time.Sleep(5 * time.Second)
	}
}

func newCSRDER(t *testing.T, domains []string) []byte {
	t.Helper()
	if len(domains) == 0 {
		t.Fatal("csr requires at least one DNS name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
