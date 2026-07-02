package workers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	acmedomain "github.com/torob/certhub/internal/acme"
	"github.com/torob/certhub/internal/certificates"
	security "github.com/torob/certhub/internal/crypto"
	dnsdomain "github.com/torob/certhub/internal/dnsproviders"
	issuerdomain "github.com/torob/certhub/internal/issuers"
	"github.com/torob/certhub/internal/storage"
)

func TestPresentAndValidatePresentsAllProvidersBeforeAccepting(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	order := acmedomain.Order{AuthorizationURLs: []string{"authz-cf", "authz-arvan"}}
	fixture.order.authz = map[string]acmedomain.Authorization{
		"authz-cf": {
			URL:        "authz-cf",
			Status:     "pending",
			Identifier: "api.cf.example.com",
			DNSChallenge: &acmedomain.DNSChallenge{
				URL:      "challenge-cf",
				Token:    "token-cf",
				TXTValue: "txt-cf",
			},
		},
		"authz-arvan": {
			URL:        "authz-arvan",
			Status:     "pending",
			Identifier: "api.arvan.example.net",
			DNSChallenge: &acmedomain.DNSChallenge{
				URL:      "challenge-arvan",
				Token:    "token-arvan",
				TXTValue: "txt-arvan",
			},
		},
	}

	err := fixture.service.presentAndValidate(context.Background(), acmedomain.OrderClientParams{}, fixture.job, fixture.version, order)
	if err != nil {
		t.Fatal(err)
	}

	events := fixture.recorder.events
	assertEventBefore(t, events, "present:cloudflare:_acme-challenge.api.cf.example.com:txt-cf", "accept:token-cf")
	assertEventBefore(t, events, "present:arvancloud:_acme-challenge.api.arvan.example.net:txt-arvan", "accept:token-cf")
	assertEventBefore(t, events, "present:cloudflare:_acme-challenge.api.cf.example.com:txt-cf", "accept:token-arvan")
	assertEventBefore(t, events, "present:arvancloud:_acme-challenge.api.arvan.example.net:txt-arvan", "accept:token-arvan")
	if len(fixture.store.cleanupMarks) != 2 {
		t.Fatalf("cleanup marks = %#v", fixture.store.cleanupMarks)
	}
}

func TestPresentAndValidateKeepsTwoTXTValuesForExactAndWildcard(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	order := acmedomain.Order{AuthorizationURLs: []string{"authz-exact", "authz-wildcard"}}
	fixture.order.authz = map[string]acmedomain.Authorization{
		"authz-exact": {
			URL:        "authz-exact",
			Status:     "pending",
			Identifier: "example.com",
			DNSChallenge: &acmedomain.DNSChallenge{
				URL:      "challenge-exact",
				Token:    "token-exact",
				TXTValue: "txt-exact",
			},
		},
		"authz-wildcard": {
			URL:        "authz-wildcard",
			Status:     "pending",
			Identifier: "*.example.com",
			Wildcard:   true,
			DNSChallenge: &acmedomain.DNSChallenge{
				URL:      "challenge-wildcard",
				Token:    "token-wildcard",
				TXTValue: "txt-wildcard",
			},
		},
	}

	err := fixture.service.presentAndValidate(context.Background(), acmedomain.OrderClientParams{}, fixture.job, fixture.version, order)
	if err != nil {
		t.Fatal(err)
	}

	events := fixture.recorder.events
	assertEventBefore(t, events, "present:cloudflare:_acme-challenge.example.com:txt-exact", "accept:token-exact")
	assertEventBefore(t, events, "present:cloudflare:_acme-challenge.example.com:txt-wildcard", "accept:token-exact")
	assertEventBefore(t, events, "present:cloudflare:_acme-challenge.example.com:txt-exact", "accept:token-wildcard")
	assertEventBefore(t, events, "present:cloudflare:_acme-challenge.example.com:txt-wildcard", "accept:token-wildcard")
	if len(fixture.store.records) != 2 {
		t.Fatalf("records = %#v", fixture.store.records)
	}
	for _, record := range fixture.store.records {
		if record.RecordName != "_acme-challenge.example.com" {
			t.Fatalf("record name = %q", record.RecordName)
		}
	}
}

func TestPresentAndValidateRePresentsCleanedChallengeOnRetry(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	encrypted, err := fixture.service.KeySet.SealDatabaseValue([]byte("txt-retry"), dnsChallengeTXTValueAAD("record-retry"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.records = []certificates.DNSChallengeRecord{{
		ID:                      "record-retry",
		IssuanceJobID:           fixture.job.ID,
		CertificateID:           fixture.job.CertificateID,
		CertificateVersionID:    fixture.version.ID,
		DNSProviderID:           "provider-cloudflare",
		DNSProviderZoneID:       "zone-cloudflare",
		RecordName:              "_acme-challenge.retry.cf.example.com",
		TXTValueEncrypted:       encrypted,
		Status:                  certificates.DNSChallengeStatusCleaned,
		AuthorizationIdentifier: "retry.cf.example.com",
	}}
	fixture.order.authz = map[string]acmedomain.Authorization{
		"authz-retry": {
			URL:        "authz-retry",
			Status:     "pending",
			Identifier: "retry.cf.example.com",
			DNSChallenge: &acmedomain.DNSChallenge{
				URL:      "challenge-retry",
				Token:    "token-retry",
				TXTValue: "txt-retry",
			},
		},
	}

	err = fixture.service.presentAndValidate(context.Background(), acmedomain.OrderClientParams{}, fixture.job, fixture.version, acmedomain.Order{AuthorizationURLs: []string{"authz-retry"}})
	if err != nil {
		t.Fatal(err)
	}

	assertEventBefore(t, fixture.recorder.events, "present:cloudflare:_acme-challenge.retry.cf.example.com:txt-retry", "accept:token-retry")
	if fixture.store.records[0].Status != certificates.DNSChallengeStatusCleanupPending {
		t.Fatalf("record status = %s", fixture.store.records[0].Status)
	}
}

func TestCompleteNextIssuanceJobSucceedsAndEnqueuesDNSCleanupWithoutInlineCleanup(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	configureSuccessfulIssuance(t, &fixture)
	fixture.service.Cloudflare = fakeCloudflareOperator{recorder: fixture.recorder, cleanupErr: fmt.Errorf("cleanup should not run inline")}

	job, processed, err := fixture.service.CompleteNextIssuanceJob(context.Background(), "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Fatal("expected job to be processed")
	}
	if job.Status != certificates.JobStatusSucceeded {
		t.Fatalf("job status = %s", job.Status)
	}
	if fixture.store.cert.Status != certificates.StatusReady {
		t.Fatalf("certificate status = %s", fixture.store.cert.Status)
	}
	if fixture.store.version.Status != certificates.VersionStatusValid {
		t.Fatalf("version status = %s", fixture.store.version.Status)
	}
	if len(fixture.store.storeMaterialCalls) != 1 {
		t.Fatalf("store material calls = %#v", fixture.store.storeMaterialCalls)
	}
	if len(fixture.store.succeedJobCalls) != 1 || fixture.store.succeedJobCalls[0].JobID != fixture.job.ID {
		t.Fatalf("succeed job calls = %#v", fixture.store.succeedJobCalls)
	}
	if len(fixture.store.ensureJobCalls) != 1 || fixture.store.ensureJobCalls[0].Reason != certificates.JobReasonDNSCleanup {
		t.Fatalf("ensure cleanup calls = %#v", fixture.store.ensureJobCalls)
	}
	for _, event := range fixture.recorder.events {
		if strings.HasPrefix(event, "cleanup:") {
			t.Fatalf("unexpected inline cleanup event %q in %#v", event, fixture.recorder.events)
		}
	}
}

func TestIssuanceFailureStoresSanitizedRootCauseInJobAndAuditEvent(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	configureSuccessfulIssuance(t, &fixture)
	fixture.service.Cloudflare = fakeCloudflareOperator{
		recorder:   fixture.recorder,
		presentErr: fmt.Errorf("provider rejected TXT txt-cf with token=cth_uat_v1_SECRETUSER"),
	}

	job, processed, err := fixture.service.CompleteNextIssuanceJob(context.Background(), "worker-1")
	if err == nil {
		t.Fatal("expected issuance failure")
	}
	if !processed {
		t.Fatal("expected job to be processed")
	}
	if job.Status != certificates.JobStatusPending {
		t.Fatalf("job status = %s", job.Status)
	}
	if len(fixture.store.failJobCalls) != 1 {
		t.Fatalf("fail job calls = %#v", fixture.store.failJobCalls)
	}
	failure := fixture.store.failJobCalls[0]
	if failure.FailureCode != "dns_challenge_present_failed" {
		t.Fatalf("failure code = %s", failure.FailureCode)
	}
	if failure.FailureMessage == nil {
		t.Fatal("missing failure message")
	}
	message := *failure.FailureMessage
	if !strings.Contains(message, "provider rejected TXT") {
		t.Fatalf("failure message lost root cause: %q", message)
	}
	for _, leaked := range []string{"txt-cf", "SECRETUSER"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("failure message leaked %s in %q", leaked, message)
		}
	}
	var failureEvent *certificates.RecordEventParams
	for i := range fixture.store.events {
		if fixture.store.events[i].EventType == "certificate_issuance_failed" {
			failureEvent = &fixture.store.events[i]
			break
		}
	}
	if failureEvent == nil {
		t.Fatalf("events = %#v", fixture.store.events)
	}
	var metadata map[string]any
	if err := json.Unmarshal(failureEvent.Metadata, &metadata); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if metadata["failure_code"] != "dns_challenge_present_failed" {
		t.Fatalf("metadata failure_code = %#v", metadata["failure_code"])
	}
	if got, ok := metadata["failure_message"].(string); !ok || got != message {
		t.Fatalf("metadata failure_message = %#v want %q", metadata["failure_message"], message)
	}
	if metadata["retryable"] != true {
		t.Fatalf("metadata retryable = %#v", metadata["retryable"])
	}
	if metadata["job_status_after_failure"] != string(certificates.JobStatusPending) {
		t.Fatalf("metadata job_status_after_failure = %#v", metadata["job_status_after_failure"])
	}
	for _, leaked := range []string{"txt-cf", "SECRETUSER"} {
		if strings.Contains(string(failureEvent.Metadata), leaked) {
			t.Fatalf("metadata leaked %s in %s", leaked, string(failureEvent.Metadata))
		}
	}
}

func TestRenewalGeneratesFreshPrivateKeyForNewVersion(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	fixture.job.Reason = certificates.JobReasonRenewal
	fixture.version.Reason = certificates.IssuanceReasonRenewal
	oldKeyFingerprint := "0000000000000000000000000000000000000000000000000000000000000000"
	configureSuccessfulIssuance(t, &fixture)

	if _, processed, err := fixture.service.CompleteNextIssuanceJob(context.Background(), "worker-1"); err != nil || !processed {
		t.Fatalf("processed=%v err=%v", processed, err)
	}
	if len(fixture.store.storeMaterialCalls) != 1 {
		t.Fatalf("store material calls = %#v", fixture.store.storeMaterialCalls)
	}
	got := fixture.store.storeMaterialCalls[0].KeyFingerprintSHA256
	if got == "" || got == oldKeyFingerprint {
		t.Fatalf("renewal key fingerprint = %q, old = %q", got, oldKeyFingerprint)
	}
}

func TestIssuanceRetryReusesPersistedVersionPrivateKey(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	signer, privateKeyPEM, err := generatePrivateKey(certificates.KeyTypeECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	keyFingerprint, err := keyFingerprint(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := fixture.service.KeySet.SealDatabaseValue([]byte(privateKeyPEM), certificatePrivateKeyAAD(fixture.version.ID))
	if err != nil {
		t.Fatal(err)
	}
	fixture.version.PrivateKeyPEMEncrypted = &encrypted
	fixture.version.KeyFingerprintSHA256 = &keyFingerprint
	configureSuccessfulIssuance(t, &fixture)

	if _, processed, err := fixture.service.CompleteNextIssuanceJob(context.Background(), "worker-1"); err != nil || !processed {
		t.Fatalf("processed=%v err=%v", processed, err)
	}
	if len(fixture.store.storeMaterialCalls) != 1 {
		t.Fatalf("store material calls = %#v", fixture.store.storeMaterialCalls)
	}
	call := fixture.store.storeMaterialCalls[0]
	if call.PrivateKeyPEMEncrypted != encrypted || call.KeyFingerprintSHA256 != keyFingerprint {
		t.Fatalf("material key changed: encrypted_equal=%v fingerprint=%q want=%q", call.PrivateKeyPEMEncrypted == encrypted, call.KeyFingerprintSHA256, keyFingerprint)
	}
}

func TestDNSCleanupJobFailureDoesNotChangeReadyCertificate(t *testing.T) {
	fixture := newIssuanceWorkerFixture(t)
	encrypted, err := fixture.service.KeySet.SealDatabaseValue([]byte("txt-cleanup"), dnsChallengeTXTValueAAD("record-cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	cleanupVersionID := fixture.version.ID
	fixture.store.claimJob = certificates.IssuanceJob{
		ID:                   "62345678-1234-4234-9234-123456789abc",
		CertificateID:        fixture.job.CertificateID,
		CertificateVersionID: nil,
		Reason:               certificates.JobReasonDNSCleanup,
		Status:               certificates.JobStatusRunning,
		Attempt:              1,
	}
	fixture.store.cert = certificates.Certificate{ID: fixture.job.CertificateID, Status: certificates.StatusReady}
	fixture.store.version = certificates.CertificateVersion{ID: cleanupVersionID, CertificateID: fixture.job.CertificateID, Status: certificates.VersionStatusValid}
	fixture.store.records = []certificates.DNSChallengeRecord{{
		ID:                      "record-cleanup",
		IssuanceJobID:           fixture.job.ID,
		CertificateID:           fixture.job.CertificateID,
		CertificateVersionID:    cleanupVersionID,
		DNSProviderID:           "provider-cloudflare",
		DNSProviderZoneID:       "zone-cloudflare",
		AuthorizationIdentifier: "api.cf.example.com",
		RecordName:              "_acme-challenge.api.cf.example.com",
		TXTValueEncrypted:       encrypted,
		Status:                  certificates.DNSChallengeStatusCleanupPending,
	}}
	fixture.service.Cloudflare = fakeCloudflareOperator{recorder: fixture.recorder, cleanupErr: fmt.Errorf("provider cleanup failed")}

	job, processed, err := fixture.service.CompleteNextIssuanceJob(context.Background(), "worker-1")
	if err == nil {
		t.Fatal("expected cleanup job error")
	}
	if !processed {
		t.Fatal("expected cleanup job to be processed")
	}
	if job.Status != certificates.JobStatusPending {
		t.Fatalf("cleanup job status = %s", job.Status)
	}
	if fixture.store.cert.Status != certificates.StatusReady {
		t.Fatalf("certificate status = %s", fixture.store.cert.Status)
	}
	if fixture.store.version.Status != certificates.VersionStatusValid {
		t.Fatalf("version status = %s", fixture.store.version.Status)
	}
	if fixture.store.records[0].Status != certificates.DNSChallengeStatusCleanupFailed {
		t.Fatalf("challenge status = %s", fixture.store.records[0].Status)
	}
	if len(fixture.store.failJobCalls) != 1 || fixture.store.failJobCalls[0].FailureCode != "dns_challenge_cleanup_failed" {
		t.Fatalf("fail job calls = %#v", fixture.store.failJobCalls)
	}
}

type issuanceWorkerFixture struct {
	service  *CertificateIssuanceService
	store    *fakeIssuanceStore
	order    *fakeOrderManager
	recorder *challengeRecorder
	job      certificates.IssuanceJob
	version  certificates.CertificateVersion
}

func newIssuanceWorkerFixture(t *testing.T) issuanceWorkerFixture {
	t.Helper()
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	recorder := &challengeRecorder{visible: map[string]map[string]bool{}}
	store := &fakeIssuanceStore{keys: keys}
	dnsStore := &fakeIssuanceDNSStore{keys: keys}
	dnsStore.addProvider(t, keys, dnsdomain.Provider{
		ID:     "provider-cloudflare",
		Name:   "cloudflare",
		Type:   dnsdomain.ProviderTypeCloudflare,
		Status: dnsdomain.StatusActive,
	}, dnsdomain.Zone{ID: "zone-cloudflare", DNSProviderID: "provider-cloudflare", ZoneName: "cf.example.com"}, dnsdomain.Zone{ID: "zone-example", DNSProviderID: "provider-cloudflare", ZoneName: "example.com"})
	dnsStore.addProvider(t, keys, dnsdomain.Provider{
		ID:     "provider-arvancloud",
		Name:   "arvancloud",
		Type:   dnsdomain.ProviderTypeArvanCloud,
		Status: dnsdomain.StatusActive,
	}, dnsdomain.Zone{ID: "zone-arvancloud", DNSProviderID: "provider-arvancloud", ZoneName: "arvan.example.net"})
	order := &fakeOrderManager{recorder: recorder}
	service := &CertificateIssuanceService{
		Certificates:       store,
		Issuers:            fakeIssuerStore{},
		DNSProviders:       dnsStore,
		OrderManager:       order,
		Cloudflare:         fakeCloudflareOperator{recorder: recorder},
		ArvanCloud:         fakeArvanCloudOperator{recorder: recorder},
		KeySet:             keys,
		PropagationTimeout: time.Second,
		PropagationPoll:    time.Millisecond,
		TXTVisible:         recorder.txtVisible,
	}
	versionID := "42345678-1234-4234-9234-123456789abc"
	job := certificates.IssuanceJob{
		ID:                   "12345678-1234-4234-9234-123456789abc",
		CertificateID:        "22345678-1234-4234-9234-123456789abc",
		CertificateVersionID: &versionID,
		Reason:               certificates.JobReasonInitialIssue,
		Attempt:              1,
	}
	version := certificates.CertificateVersion{
		ID:            versionID,
		CertificateID: job.CertificateID,
		Status:        certificates.VersionStatusIssuing,
		Reason:        certificates.IssuanceReasonInitialIssue,
	}
	return issuanceWorkerFixture{service: service, store: store, order: order, recorder: recorder, job: job, version: version}
}

func configureSuccessfulIssuance(t *testing.T, fixture *issuanceWorkerFixture) {
	t.Helper()
	accountKey, err := fixture.service.KeySet.SealDatabaseValue([]byte("account-key"), acmeAccountPrivateKeyAAD("issuer-account"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.Issuers = fakeIssuerStore{
		issuer: issuerdomain.Issuer{
			ID:           "issuer-1",
			DirectoryURL: "https://acme.test/directory",
			Status:       issuerdomain.StatusActive,
		},
		account: issuerdomain.ACMEAccount{
			ID:                     "issuer-account",
			IssuerID:               "issuer-1",
			AccountURL:             "https://acme.test/account/1",
			PrivateKeyPEMEncrypted: accountKey,
			Status:                 issuerdomain.ACMEAccountStatusActive,
		},
	}
	fixture.store.claimJob = fixture.job
	fixture.store.claimJob.Status = certificates.JobStatusRunning
	fixture.store.cert = certificates.Certificate{
		ID:             fixture.job.CertificateID,
		IssuerID:       "issuer-1",
		Status:         certificates.StatusPending,
		KeyType:        certificates.KeyTypeECDSAP256,
		NormalizedSANs: []string{"api.cf.example.com"},
	}
	fixture.store.version = fixture.version
	fixture.order.order = acmedomain.Order{
		URL:               "https://acme.test/order/1",
		FinalizeURL:       "https://acme.test/order/1/finalize",
		CertificateURL:    "https://acme.test/cert/1",
		AuthorizationURLs: []string{"authz-cf"},
	}
	fixture.order.authz = map[string]acmedomain.Authorization{
		"authz-cf": {
			URL:        "authz-cf",
			Status:     "pending",
			Identifier: "api.cf.example.com",
			DNSChallenge: &acmedomain.DNSChallenge{
				URL:      "challenge-cf",
				Token:    "token-cf",
				TXTValue: "txt-cf",
			},
		},
	}
	fixture.order.selfSignBundle = true
}

type challengeRecorder struct {
	events  []string
	visible map[string]map[string]bool
}

func (r *challengeRecorder) present(provider string, op dnsdomain.DNS01ChallengeOperation) {
	r.events = append(r.events, fmt.Sprintf("present:%s:%s:%s", provider, op.RecordName, op.TXTValue))
	if r.visible[op.RecordName] == nil {
		r.visible[op.RecordName] = map[string]bool{}
	}
	r.visible[op.RecordName][op.TXTValue] = true
}

func (r *challengeRecorder) cleanup(provider string, op dnsdomain.DNS01ChallengeOperation) {
	r.events = append(r.events, fmt.Sprintf("cleanup:%s:%s:%s", provider, op.RecordName, op.TXTValue))
}

func (r *challengeRecorder) txtVisible(_ context.Context, recordName, txtValue string) (bool, error) {
	r.events = append(r.events, fmt.Sprintf("wait:%s:%s", recordName, txtValue))
	return r.visible[recordName][txtValue], nil
}

type fakeCloudflareOperator struct {
	recorder   *challengeRecorder
	presentErr error
	cleanupErr error
}

func (o fakeCloudflareOperator) Present(_ context.Context, _ dnsdomain.CloudflareCredentials, op dnsdomain.DNS01ChallengeOperation) error {
	if o.recorder != nil {
		o.recorder.present(string(dnsdomain.ProviderTypeCloudflare), op)
	}
	return o.presentErr
}

func (o fakeCloudflareOperator) CleanUp(_ context.Context, _ dnsdomain.CloudflareCredentials, op dnsdomain.DNS01ChallengeOperation) error {
	if o.recorder != nil {
		o.recorder.cleanup(string(dnsdomain.ProviderTypeCloudflare), op)
	}
	return o.cleanupErr
}

type fakeArvanCloudOperator struct {
	recorder   *challengeRecorder
	presentErr error
	cleanupErr error
}

func (o fakeArvanCloudOperator) Present(_ context.Context, _ dnsdomain.ArvanCloudCredentials, op dnsdomain.DNS01ChallengeOperation) error {
	if o.recorder != nil {
		o.recorder.present(string(dnsdomain.ProviderTypeArvanCloud), op)
	}
	return o.presentErr
}

func (o fakeArvanCloudOperator) CleanUp(_ context.Context, _ dnsdomain.ArvanCloudCredentials, op dnsdomain.DNS01ChallengeOperation) error {
	if o.recorder != nil {
		o.recorder.cleanup(string(dnsdomain.ProviderTypeArvanCloud), op)
	}
	return o.cleanupErr
}

type fakeOrderManager struct {
	authz          map[string]acmedomain.Authorization
	order          acmedomain.Order
	selfSignBundle bool
	recorder       *challengeRecorder
}

func (m *fakeOrderManager) CreateOrder(context.Context, acmedomain.CreateOrderParams) (acmedomain.Order, error) {
	return m.order, nil
}

func (m *fakeOrderManager) FetchOrder(context.Context, acmedomain.FetchOrderParams) (acmedomain.Order, error) {
	return m.order, nil
}

func (m *fakeOrderManager) FetchAuthorization(_ context.Context, params acmedomain.FetchAuthorizationParams) (acmedomain.Authorization, error) {
	authz, ok := m.authz[params.AuthorizationURL]
	if !ok {
		return acmedomain.Authorization{}, storage.ErrNoRows
	}
	return authz, nil
}

func (m *fakeOrderManager) AcceptChallenge(_ context.Context, params acmedomain.AcceptChallengeParams) error {
	m.recorder.events = append(m.recorder.events, "accept:"+params.Token)
	return nil
}

func (m *fakeOrderManager) FinalizeOrder(_ context.Context, params acmedomain.FinalizeOrderParams) (acmedomain.CertificateBundle, error) {
	if !m.selfSignBundle {
		return acmedomain.CertificateBundle{}, nil
	}
	leafDER, issuerDER, err := testCertificateChainFromCSR(params.CSRDER)
	if err != nil {
		return acmedomain.CertificateBundle{}, err
	}
	return acmedomain.CertificateBundle{CertificateURL: "https://acme.test/cert/1", DERChain: [][]byte{leafDER, issuerDER}}, nil
}

func (m *fakeOrderManager) FetchCertificate(context.Context, acmedomain.FetchCertificateParams) ([][]byte, error) {
	return nil, nil
}

func (m *fakeOrderManager) RevokeCertificate(context.Context, acmedomain.RevokeCertificateParams) error {
	return nil
}

func testCertificateChainFromCSR(csrDER []byte) ([]byte, []byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, csr.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return leafDER, caDER, nil
}

type fakeIssuanceDNSStore struct {
	keys        *security.KeySet
	providers   map[string]dnsdomain.Provider
	zones       map[string][]dnsdomain.Zone
	credentials map[string]string
}

func (s *fakeIssuanceDNSStore) addProvider(t *testing.T, keys *security.KeySet, provider dnsdomain.Provider, zones ...dnsdomain.Zone) {
	t.Helper()
	if s.providers == nil {
		s.providers = map[string]dnsdomain.Provider{}
		s.zones = map[string][]dnsdomain.Zone{}
		s.credentials = map[string]string{}
	}
	s.providers[provider.ID] = provider
	s.zones[provider.ID] = append(s.zones[provider.ID], zones...)
	var raw []byte
	switch provider.Type {
	case dnsdomain.ProviderTypeCloudflare:
		raw, _ = json.Marshal(dnsdomain.CloudflareCredentials{APIToken: "token"})
	case dnsdomain.ProviderTypeArvanCloud:
		raw, _ = json.Marshal(dnsdomain.ArvanCloudCredentials{APIKey: "key"})
	}
	encrypted, err := keys.SealDatabaseValue(raw, dnsProviderCredentialsAAD(provider.ID))
	if err != nil {
		t.Fatal(err)
	}
	s.credentials[provider.ID] = encrypted
}

func (s *fakeIssuanceDNSStore) FindZoneForDNSName(_ context.Context, dnsName string) (dnsdomain.ZoneMatch, error) {
	var best dnsdomain.ZoneMatch
	for providerID, zones := range s.zones {
		provider := s.providers[providerID]
		for _, zone := range zones {
			if dnsName == zone.ZoneName || strings.HasSuffix(dnsName, "."+zone.ZoneName) {
				if best.Zone.ZoneName == "" || len(zone.ZoneName) > len(best.Zone.ZoneName) {
					best = dnsdomain.ZoneMatch{Provider: provider, Zone: zone}
				}
			}
		}
	}
	if best.Zone.ZoneName == "" {
		return dnsdomain.ZoneMatch{}, storage.ErrNoRows
	}
	return best, nil
}

func (s *fakeIssuanceDNSStore) Get(_ context.Context, id string) (dnsdomain.Provider, error) {
	provider, ok := s.providers[id]
	if !ok {
		return dnsdomain.Provider{}, storage.ErrNoRows
	}
	return provider, nil
}

func (s *fakeIssuanceDNSStore) GetCredentialsEncrypted(_ context.Context, id string) (string, error) {
	encrypted, ok := s.credentials[id]
	if !ok {
		return "", storage.ErrNoRows
	}
	return encrypted, nil
}

func (s *fakeIssuanceDNSStore) ListZones(_ context.Context, providerID string, _ storage.ListOptions) ([]dnsdomain.Zone, error) {
	return append([]dnsdomain.Zone(nil), s.zones[providerID]...), nil
}

type fakeIssuanceStore struct {
	keys               *security.KeySet
	claimJob           certificates.IssuanceJob
	cert               certificates.Certificate
	version            certificates.CertificateVersion
	records            []certificates.DNSChallengeRecord
	cleanupMarks       []string
	storeMaterialCalls []certificates.StoreMaterialParams
	ensureJobCalls     []certificates.EnsureIssuanceJobParams
	succeedJobCalls    []certificates.SucceedIssuanceJobParams
	failJobCalls       []certificates.FailIssuanceJobParams
	events             []certificates.RecordEventParams
}

func (s *fakeIssuanceStore) ClaimNextIssuanceJob(_ context.Context, params certificates.ClaimIssuanceJobParams) (certificates.IssuanceJob, error) {
	if s.claimJob.ID == "" {
		return certificates.IssuanceJob{}, storage.ErrNoRows
	}
	s.claimJob.Status = certificates.JobStatusRunning
	s.claimJob.LockedBy = &params.WorkerID
	s.claimJob.LockedUntil = &params.LockedUntil
	if s.claimJob.StartedAt == nil {
		now := time.Now().UTC()
		s.claimJob.StartedAt = &now
	}
	return s.claimJob, nil
}

func (s *fakeIssuanceStore) Get(_ context.Context, id string) (certificates.Certificate, error) {
	if s.cert.ID == id {
		return s.cert, nil
	}
	return certificates.Certificate{}, storage.ErrNoRows
}

func (s *fakeIssuanceStore) GetVersion(_ context.Context, id string) (certificates.CertificateVersion, error) {
	if s.version.ID == id {
		return s.version, nil
	}
	return certificates.CertificateVersion{}, storage.ErrNoRows
}

func (s *fakeIssuanceStore) ListVersions(context.Context, certificates.ListVersionsParams) ([]certificates.CertificateVersion, error) {
	return nil, nil
}

func (s *fakeIssuanceStore) CreateIssuingVersion(context.Context, certificates.CreateIssuingVersionParams) (certificates.CertificateVersion, error) {
	return certificates.CertificateVersion{}, nil
}

func (s *fakeIssuanceStore) AttachIssuingVersionToJob(context.Context, certificates.AttachIssuingVersionToJobParams) (certificates.IssuanceJob, error) {
	return certificates.IssuanceJob{}, nil
}

func (s *fakeIssuanceStore) PrepareIssuingVersion(_ context.Context, params certificates.PrepareIssuingVersionParams) (certificates.CertificateVersion, error) {
	if s.version.ID != params.CertificateVersionID {
		return certificates.CertificateVersion{}, storage.ErrNoRows
	}
	s.version.PrivateKeyPEMEncrypted = &params.PrivateKeyPEMEncrypted
	s.version.KeyFingerprintSHA256 = &params.KeyFingerprintSHA256
	s.version.ACMEOrderURL = &params.ACMEOrderURL
	return s.version, nil
}

func (s *fakeIssuanceStore) UpdateCertificateIssuanceStatus(_ context.Context, params certificates.UpdateCertificateIssuanceStatusParams) (certificates.Certificate, error) {
	if s.cert.ID != params.CertificateID {
		return certificates.Certificate{}, storage.ErrNoRows
	}
	s.cert.Status = params.Status
	return s.cert, nil
}

func (s *fakeIssuanceStore) StoreMaterial(_ context.Context, params certificates.StoreMaterialParams) (certificates.CertificateVersion, error) {
	if s.version.ID != params.CertificateVersionID {
		return certificates.CertificateVersion{}, storage.ErrNoRows
	}
	s.storeMaterialCalls = append(s.storeMaterialCalls, params)
	s.version.Status = certificates.VersionStatusValid
	s.version.CertPEM = &params.CertPEM
	s.version.ChainPEM = &params.ChainPEM
	s.version.FullchainPEM = &params.FullchainPEM
	s.version.PrivateKeyPEMEncrypted = &params.PrivateKeyPEMEncrypted
	s.version.NotBefore = &params.NotBefore
	s.version.NotAfter = &params.NotAfter
	s.version.SerialNumber = &params.SerialNumber
	s.version.FingerprintSHA256 = &params.FingerprintSHA256
	s.version.KeyFingerprintSHA256 = &params.KeyFingerprintSHA256
	s.version.MaterialETag = &params.MaterialETag
	s.version.ACMEOrderURL = params.ACMEOrderURL
	s.version.CertificateURL = params.CertificateURL
	now := time.Now().UTC()
	s.version.CompletedAt = &now
	s.version.IssuedAt = &now
	s.cert.Status = certificates.StatusReady
	return s.version, nil
}

func (s *fakeIssuanceStore) EnsureIssuanceJob(_ context.Context, params certificates.EnsureIssuanceJobParams) (certificates.IssuanceJob, error) {
	s.ensureJobCalls = append(s.ensureJobCalls, params)
	id := params.ID
	if id == "" {
		id = "72345678-1234-4234-9234-123456789abc"
	}
	return certificates.IssuanceJob{
		ID:                   id,
		CertificateID:        params.CertificateID,
		CertificateVersionID: params.CertificateVersionID,
		Reason:               params.Reason,
		Status:               certificates.JobStatusPending,
		NextRunAt:            params.NextRunAt,
	}, nil
}

func (s *fakeIssuanceStore) SucceedIssuanceJob(_ context.Context, params certificates.SucceedIssuanceJobParams) (certificates.IssuanceJob, error) {
	s.succeedJobCalls = append(s.succeedJobCalls, params)
	if s.claimJob.ID != params.JobID {
		return certificates.IssuanceJob{}, storage.ErrNoRows
	}
	s.claimJob.Status = certificates.JobStatusSucceeded
	now := time.Now().UTC()
	s.claimJob.CompletedAt = &now
	return s.claimJob, nil
}

func (s *fakeIssuanceStore) FailIssuanceJob(_ context.Context, params certificates.FailIssuanceJobParams) (certificates.IssuanceJob, error) {
	s.failJobCalls = append(s.failJobCalls, params)
	if s.claimJob.ID != params.JobID {
		return certificates.IssuanceJob{}, storage.ErrNoRows
	}
	s.claimJob.FailureCode = &params.FailureCode
	s.claimJob.FailureMessage = params.FailureMessage
	if params.Retryable && s.claimJob.Attempt < params.MaxAttempts {
		s.claimJob.Status = certificates.JobStatusPending
		s.claimJob.Attempt++
		s.claimJob.NextRunAt = time.Now().UTC().Add(params.RetryAfter)
		s.claimJob.LockedBy = nil
		s.claimJob.LockedUntil = nil
		s.claimJob.CompletedAt = nil
		return s.claimJob, nil
	}
	s.claimJob.Status = certificates.JobStatusFailed
	now := time.Now().UTC()
	s.claimJob.CompletedAt = &now
	return s.claimJob, nil
}

func (s *fakeIssuanceStore) RecordDNSChallenge(_ context.Context, params certificates.RecordDNSChallengeParams) (certificates.DNSChallengeRecord, error) {
	record := certificates.DNSChallengeRecord{
		ID:                      params.ID,
		IssuanceJobID:           params.IssuanceJobID,
		CertificateID:           params.CertificateID,
		CertificateVersionID:    params.CertificateVersionID,
		DNSProviderID:           params.DNSProviderID,
		DNSProviderZoneID:       params.DNSProviderZoneID,
		AuthorizationIdentifier: params.AuthorizationIdentifier,
		RecordName:              params.RecordName,
		TXTValueEncrypted:       params.TXTValueEncrypted,
		Status:                  params.Status,
	}
	s.records = append(s.records, record)
	return record, nil
}

func (s *fakeIssuanceStore) MarkDNSChallengePresented(_ context.Context, params certificates.MarkDNSChallengePresentedParams) (certificates.DNSChallengeRecord, error) {
	for i := range s.records {
		if s.records[i].ID != params.ID {
			continue
		}
		s.records[i].Status = certificates.DNSChallengeStatusPresented
		return s.records[i], nil
	}
	return certificates.DNSChallengeRecord{}, storage.ErrNoRows
}

func (s *fakeIssuanceStore) MarkDNSChallengeCleanup(_ context.Context, params certificates.MarkDNSChallengeCleanupParams) (certificates.DNSChallengeRecord, error) {
	for i := range s.records {
		if s.records[i].ID != params.ID {
			continue
		}
		s.records[i].Status = params.Status
		s.cleanupMarks = append(s.cleanupMarks, params.ID+":"+string(params.Status))
		return s.records[i], nil
	}
	return certificates.DNSChallengeRecord{}, storage.ErrNoRows
}

func (s *fakeIssuanceStore) ListDNSChallenges(_ context.Context, params certificates.ListDNSChallengesParams) ([]certificates.DNSChallengeRecord, error) {
	var out []certificates.DNSChallengeRecord
	for _, record := range s.records {
		if params.IssuanceJobID != nil && record.IssuanceJobID != *params.IssuanceJobID {
			continue
		}
		if params.Status != nil && record.Status != *params.Status {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *fakeIssuanceStore) MarkACMERevocationSucceeded(context.Context, certificates.MarkACMERevocationParams) (certificates.CertificateVersion, error) {
	return certificates.CertificateVersion{}, nil
}

func (s *fakeIssuanceStore) MarkACMERevocationFailed(context.Context, certificates.MarkACMERevocationParams) (certificates.CertificateVersion, error) {
	return certificates.CertificateVersion{}, nil
}

func (s *fakeIssuanceStore) RecordEvent(_ context.Context, params certificates.RecordEventParams) (certificates.Event, error) {
	s.events = append(s.events, params)
	return certificates.Event{
		ID:                   params.ID,
		CertificateID:        params.CertificateID,
		CertificateVersionID: params.CertificateVersionID,
		IssuanceJobID:        params.IssuanceJobID,
		EventType:            params.EventType,
		Result:               params.Result,
		CorrelationID:        params.CorrelationID,
		Message:              params.Message,
		Metadata:             params.Metadata,
		CreatedAt:            time.Now().UTC(),
	}, nil
}

type fakeIssuerStore struct {
	issuer  issuerdomain.Issuer
	account issuerdomain.ACMEAccount
}

func (s fakeIssuerStore) Get(_ context.Context, id string) (issuerdomain.Issuer, error) {
	if s.issuer.ID == id {
		return s.issuer, nil
	}
	return issuerdomain.Issuer{}, storage.ErrNoRows
}

func (s fakeIssuerStore) GetActiveACMEAccount(_ context.Context, issuerID string) (issuerdomain.ACMEAccount, error) {
	if s.account.ID != "" && s.account.IssuerID == issuerID {
		return s.account, nil
	}
	return issuerdomain.ACMEAccount{}, storage.ErrNoRows
}

func assertEventBefore(t *testing.T, events []string, before, after string) {
	t.Helper()
	beforeIndex, afterIndex := -1, -1
	for i, event := range events {
		if event == before && beforeIndex == -1 {
			beforeIndex = i
		}
		if event == after && afterIndex == -1 {
			afterIndex = i
		}
	}
	if beforeIndex == -1 || afterIndex == -1 || beforeIndex >= afterIndex {
		t.Fatalf("events order missing %q before %q: %#v", before, after, events)
	}
}
