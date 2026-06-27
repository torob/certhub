package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appdomain "certhub/internal/applications"
	auditdomain "certhub/internal/audit"
	"certhub/internal/auth"
	certdomain "certhub/internal/certificates"
	security "certhub/internal/crypto"
	issuerdomain "certhub/internal/issuers"
	"certhub/internal/storage"
	"certhub/pkg/certhubclient"
)

func TestSyncMaterialMatchingETagReturns204WithoutPrivateKeyAudit(t *testing.T) {
	fixture := newCertificateHTTPFixture(t)
	rawAppToken := appdomain.ApplicationTokenPrefix + strings.Repeat("A", 43)
	appStore := &certificateHTTPAppStore{
		app: fixture.app,
		scopes: []appdomain.DomainScope{{
			ID:            "42345678-1234-4234-9234-123456789abc",
			ApplicationID: fixture.app.ID,
			Value:         "*.example.com",
			Kind:          appdomain.DomainScopeKindWildcard,
			CreatedAt:     fixture.now,
		}},
		tokenIdentity: appdomain.TokenIdentity{
			Token: appdomain.ApplicationToken{
				ID:            "52345678-1234-4234-9234-123456789abc",
				ApplicationID: fixture.app.ID,
				Name:          "sync",
				TokenHash:     fixture.keys.HashToken(rawAppToken),
				Status:        appdomain.TokenStatusActive,
				CreatedAt:     fixture.now,
			},
			Application: fixture.app,
		},
	}
	auditStore := &certificateHTTPAuditStore{}
	certSvc := certdomain.NewService(certdomain.ServiceConfig{
		Repository:        fixture.certStore,
		ApplicationReader: appStore,
		IssuerReader:      fixture.issuerStore,
		AuditRepository:   auditStore,
		KeySet:            fixture.keys,
	})
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      appStore,
		AuditRepository: identityFakeAudit{},
		KeySet:          fixture.keys,
		Config:          testConfig(t, "").ApplicationToken,
	})
	handler := New(testConfig(t, ""), WithApplicationAccessServices(appSvc, nil), WithCertificateService(certSvc)).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sync/certificates/tls-material", strings.NewReader(`{"domains":["api.example.com"],"key_type":"ecdsa-p256","issuer":"letsencrypt"}`))
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Authorization", "Bearer "+rawAppToken)
	req.Header.Set("If-None-Match", fixture.etag)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 || rec.Header().Get("ETag") != fixture.etag || rec.Header().Get("Vary") != "Authorization" {
		t.Fatalf("headers/body mismatch: etag=%q vary=%q body=%q", rec.Header().Get("ETag"), rec.Header().Get("Vary"), rec.Body.String())
	}
	if len(auditStore.events) != 0 {
		t.Fatalf("unexpected private_key_read audit: %#v", auditStore.events)
	}
}

func TestIDMaterialMatchingETagReturns304WithoutPrivateKeyAudit(t *testing.T) {
	fixture := newCertificateHTTPFixture(t)
	user := fakeUser()
	userToken := auth.UserAccessTokenPrefix + strings.Repeat("B", 43)
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository: &identityFakeAuthRepo{session: auth.Session{
			ID:              "62345678-1234-4234-9234-123456789abc",
			UserID:          user.ID,
			AuthMethod:      auth.AuthMethodPassword,
			AccessTokenHash: fixture.keys.HashToken(userToken),
			Status:          auth.SessionStatusActive,
			AccessExpiresAt: time.Now().Add(time.Minute),
		}},
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          fixture.keys,
		Config:          testConfig(t, "").Auth,
	})
	auditStore := &certificateHTTPAuditStore{}
	certSvc := certdomain.NewService(certdomain.ServiceConfig{
		Repository:        fixture.certStore,
		ApplicationReader: &certificateHTTPAppStore{app: fixture.app},
		IssuerReader:      fixture.issuerStore,
		AuditRepository:   auditStore,
		KeySet:            fixture.keys,
	})
	handler := New(testConfig(t, ""), WithIdentityServices(authSvc, nil), WithCertificateService(certSvc)).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/certificates/"+fixture.cert.ID+"/tls-material", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("If-None-Match", fixture.etag)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 || rec.Header().Get("ETag") != fixture.etag || rec.Header().Get("Vary") != "Authorization" {
		t.Fatalf("headers/body mismatch: etag=%q vary=%q body=%q", rec.Header().Get("ETag"), rec.Header().Get("Vary"), rec.Body.String())
	}
	if len(auditStore.events) != 0 {
		t.Fatalf("unexpected private_key_read audit: %#v", auditStore.events)
	}
}

func TestCertificateCriteriaRejectsApplicationID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/certificates", strings.NewReader(`{
		"application_id":"22345678-1234-4234-9234-123456789abc",
		"domains":["api.example.com"],
		"key_type":"ecdsa-p256",
		"issuer":"letsencrypt"
	}`))
	if _, err := decodeCertificateCriteria(req); err == nil {
		t.Fatal("expected application_id to be rejected")
	}
}

func TestSyncCertificateAllowsExactAndCorrespondingWildcardSANs(t *testing.T) {
	fixture := newCertificateHTTPFixture(t)
	rawAppToken := appdomain.ApplicationTokenPrefix + strings.Repeat("A", 43)
	pendingCert := fixture.cert
	pendingCert.NormalizedSANs = []string{"*.example.com", "example.com"}
	pendingCert.Status = certdomain.StatusPending
	appStore := &certificateHTTPAppStore{
		app: fixture.app,
		scopes: []appdomain.DomainScope{
			{
				ID:            "42345678-1234-4234-9234-123456789abc",
				ApplicationID: fixture.app.ID,
				Value:         "example.com",
				Kind:          appdomain.DomainScopeKindExact,
				CreatedAt:     fixture.now,
			},
			{
				ID:            "52345678-1234-4234-9234-123456789abc",
				ApplicationID: fixture.app.ID,
				Value:         "*.example.com",
				Kind:          appdomain.DomainScopeKindWildcard,
				CreatedAt:     fixture.now,
			},
		},
		tokenIdentity: appdomain.TokenIdentity{
			Token: appdomain.ApplicationToken{
				ID:            "62345678-1234-4234-9234-123456789abc",
				ApplicationID: fixture.app.ID,
				Name:          "sync",
				TokenHash:     fixture.keys.HashToken(rawAppToken),
				Status:        appdomain.TokenStatusActive,
				CreatedAt:     fixture.now,
			},
			Application: fixture.app,
		},
	}
	certStore := fixture.certStore
	certStore.createOrReuseCert = pendingCert
	certSvc := certdomain.NewService(certdomain.ServiceConfig{
		Repository:        certStore,
		ApplicationReader: appStore,
		IssuerReader:      fixture.issuerStore,
		AuditRepository:   &certificateHTTPAuditStore{},
		KeySet:            fixture.keys,
	})
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      appStore,
		AuditRepository: identityFakeAudit{},
		KeySet:          fixture.keys,
		Config:          testConfig(t, "").ApplicationToken,
	})
	handler := New(testConfig(t, ""), WithApplicationAccessServices(appSvc, nil), WithCertificateService(certSvc)).Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sync/certificates", strings.NewReader(`{"domains":["Example.COM.","*.Example.COM."],"key_type":"ecdsa-p256","issuer":"letsencrypt"}`))
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Authorization", "Bearer "+rawAppToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	want := []string{"*.example.com", "example.com"}
	if len(certStore.createParams.NormalizedSANs) != len(want) {
		t.Fatalf("normalized sans = %#v", certStore.createParams.NormalizedSANs)
	}
	for i := range want {
		if certStore.createParams.NormalizedSANs[i] != want[i] {
			t.Fatalf("normalized sans = %#v want %#v", certStore.createParams.NormalizedSANs, want)
		}
	}
}

func TestSharedClientAgainstHTTPHandlerSyncContract(t *testing.T) {
	fixture := newCertificateHTTPFixture(t)
	rawAppToken := appdomain.ApplicationTokenPrefix + strings.Repeat("A", 43)
	appStore := &certificateHTTPAppStore{
		app: fixture.app,
		scopes: []appdomain.DomainScope{{
			ID:            "42345678-1234-4234-9234-123456789abc",
			ApplicationID: fixture.app.ID,
			Value:         "*.example.com",
			Kind:          appdomain.DomainScopeKindWildcard,
			CreatedAt:     fixture.now,
		}},
		tokenIdentity: appdomain.TokenIdentity{
			Token: appdomain.ApplicationToken{
				ID:            "52345678-1234-4234-9234-123456789abc",
				ApplicationID: fixture.app.ID,
				Name:          "sync",
				TokenHash:     fixture.keys.HashToken(rawAppToken),
				Status:        appdomain.TokenStatusActive,
				CreatedAt:     fixture.now,
			},
			Application: fixture.app,
		},
	}
	auditStore := &certificateHTTPAuditStore{}
	certSvc := certdomain.NewService(certdomain.ServiceConfig{
		Repository:        fixture.certStore,
		ApplicationReader: appStore,
		IssuerReader:      fixture.issuerStore,
		AuditRepository:   auditStore,
		KeySet:            fixture.keys,
	})
	appSvc := appdomain.NewService(appdomain.ServiceConfig{
		Repository:      appStore,
		AuditRepository: identityFakeAudit{},
		KeySet:          fixture.keys,
		Config:          testConfig(t, "").ApplicationToken,
	})
	server := httptest.NewServer(New(testConfig(t, ""), WithApplicationAccessServices(appSvc, nil), WithCertificateService(certSvc)).Handler())
	defer server.Close()
	client, err := certhubclient.New(server.URL, rawAppToken, certhubclient.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}

	pendingCert := fixture.cert
	pendingCert.Status = certdomain.StatusPending
	fixture.certStore.createOrReuseCert = pendingCert
	ensured, ensureMeta, err := client.EnsureCertificate(context.Background(), certhubclient.CertificateCriteria{
		Domains: []string{"api.example.com"},
		KeyType: "ecdsa-p256",
		Issuer:  "letsencrypt",
	}, certhubclient.RequestOptions{RequestID: "req-m10-ensure-contract"})
	if err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}
	if ensureMeta.StatusCode != http.StatusAccepted || ensureMeta.RequestID != "req-m10-ensure-contract" {
		t.Fatalf("ensure meta = %#v", ensureMeta)
	}
	if seconds, ok := ensureMeta.RetryAfterSeconds(); !ok || seconds != 5 {
		t.Fatalf("ensure Retry-After = %d, %v", seconds, ok)
	}
	if ensured == nil || ensured.Certificate.ID != fixture.cert.ID {
		t.Fatalf("ensure response = %#v", ensured)
	}

	mat, meta, err := client.GetTLSMaterial(context.Background(), certhubclient.CertificateCriteria{
		Domains: []string{"api.example.com"},
		KeyType: "ecdsa-p256",
		Issuer:  "letsencrypt",
	}, certhubclient.RequestOptions{RequestID: "req-m10-sync-contract"})
	if err != nil {
		t.Fatalf("GetTLSMaterial: %v", err)
	}
	if meta.StatusCode != http.StatusOK || meta.RequestID != "req-m10-sync-contract" || meta.ETag != fixture.etag {
		t.Fatalf("meta = %#v", meta)
	}
	if mat == nil || mat.CertificateID != fixture.cert.ID || mat.PrivateKeyPEM != "PRIVATE KEY" {
		t.Fatalf("material = %#v", mat)
	}
	if appStore.markedTokenID != "52345678-1234-4234-9234-123456789abc" {
		t.Fatalf("token was not marked used: %q", appStore.markedTokenID)
	}

	mat, meta, err = client.GetTLSMaterial(context.Background(), certhubclient.CertificateCriteria{
		Domains: []string{"api.example.com"},
		KeyType: "ecdsa-p256",
		Issuer:  "letsencrypt",
	}, certhubclient.RequestOptions{IfNoneMatch: fixture.etag})
	if err != nil {
		t.Fatalf("GetTLSMaterial 204: %v", err)
	}
	if mat != nil || meta.StatusCode != http.StatusNoContent || meta.ETag != fixture.etag {
		t.Fatalf("204 material/meta = %#v %#v", mat, meta)
	}
}

type certificateHTTPFixture struct {
	now         time.Time
	keys        *security.KeySet
	etag        string
	app         appdomain.Application
	issuer      issuerdomain.Issuer
	cert        certdomain.Certificate
	version     certdomain.CertificateVersion
	certStore   *certificateHTTPCertStore
	issuerStore *certificateHTTPIssuerStore
}

func newCertificateHTTPFixture(t *testing.T) certificateHTTPFixture {
	t.Helper()
	now := time.Now().UTC()
	keys := testKeySet(t)
	etag := `"cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E"`
	versionID := "82345678-1234-4234-9234-123456789abc"
	encrypted, err := keys.SealDatabaseValue([]byte("PRIVATE KEY"), "v1:table=certificate_versions:column=private_key_pem:row_id="+versionID)
	if err != nil {
		t.Fatal(err)
	}
	cert := certdomain.Certificate{
		ID:             "72345678-1234-4234-9234-123456789abc",
		ApplicationID:  "22345678-1234-4234-9234-123456789abc",
		IssuerID:       "32345678-1234-4234-9234-123456789abc",
		NormalizedSANs: []string{"api.example.com"},
		KeyType:        certdomain.KeyTypeECDSAP256,
		Status:         certdomain.StatusReady,
		CreatedAt:      now,
		UpdatedAt:      now,
		VersionCount:   1,
	}
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(time.Hour)
	certPEM := "CERT"
	chainPEM := "CHAIN"
	fullchainPEM := "FULLCHAIN"
	serial := "01"
	fp := strings.Repeat("a", 64)
	kfp := strings.Repeat("b", 64)
	version := certdomain.CertificateVersion{
		ID:                     versionID,
		CertificateID:          cert.ID,
		Version:                1,
		Status:                 certdomain.VersionStatusValid,
		Reason:                 certdomain.IssuanceReasonInitialIssue,
		CertPEM:                &certPEM,
		ChainPEM:               &chainPEM,
		FullchainPEM:           &fullchainPEM,
		PrivateKeyPEMEncrypted: &encrypted,
		NotBefore:              &notBefore,
		NotAfter:               &notAfter,
		SerialNumber:           &serial,
		FingerprintSHA256:      &fp,
		KeyFingerprintSHA256:   &kfp,
		MaterialETag:           &etag,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	app := appdomain.Application{
		ID:          cert.ApplicationID,
		Name:        "api_app",
		DisplayName: "API App",
		Status:      appdomain.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	issuer := issuerdomain.Issuer{
		ID:        cert.IssuerID,
		Name:      "letsencrypt",
		Status:    issuerdomain.StatusActive,
		IsDefault: true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return certificateHTTPFixture{
		now:         now,
		keys:        keys,
		etag:        etag,
		app:         app,
		issuer:      issuer,
		cert:        cert,
		version:     version,
		certStore:   &certificateHTTPCertStore{cert: cert, version: version},
		issuerStore: &certificateHTTPIssuerStore{issuer: issuer},
	}
}

type certificateHTTPCertStore struct {
	cert              certdomain.Certificate
	createOrReuseCert certdomain.Certificate
	createParams      certdomain.CreateOrReuseCertificateParams
	version           certdomain.CertificateVersion
}

func (s *certificateHTTPCertStore) CreateOrReuse(_ context.Context, params certdomain.CreateOrReuseCertificateParams) (certdomain.Certificate, error) {
	s.createParams = params
	if s.createOrReuseCert.ID != "" {
		return s.createOrReuseCert, nil
	}
	return s.cert, nil
}

func (s *certificateHTTPCertStore) Get(context.Context, string) (certdomain.Certificate, error) {
	return s.cert, nil
}

func (s *certificateHTTPCertStore) List(context.Context, certdomain.ListCertificatesParams) ([]certdomain.Certificate, error) {
	return []certdomain.Certificate{s.cert}, nil
}

func (s *certificateHTTPCertStore) Count(context.Context, certdomain.ListCertificatesParams) (int64, error) {
	return 1, nil
}

func (s *certificateHTTPCertStore) ListVersions(context.Context, certdomain.ListVersionsParams) ([]certdomain.CertificateVersion, error) {
	return []certdomain.CertificateVersion{s.version}, nil
}

func (s *certificateHTTPCertStore) CountVersions(context.Context, string) (int64, error) {
	return 1, nil
}

func (s *certificateHTTPCertStore) GetLatestValidMaterial(context.Context, string) (certdomain.CertificateVersion, error) {
	return s.version, nil
}

func (s *certificateHTTPCertStore) CreateIssuingVersion(context.Context, certdomain.CreateIssuingVersionParams) (certdomain.CertificateVersion, error) {
	version := s.version
	version.Status = certdomain.VersionStatusIssuing
	return version, nil
}

func (s *certificateHTTPCertStore) EnsureIssuanceJob(context.Context, certdomain.EnsureIssuanceJobParams) (certdomain.IssuanceJob, error) {
	return certdomain.IssuanceJob{ID: "a2345678-1234-4234-9234-123456789abc"}, nil
}

func (s *certificateHTTPCertStore) RevokeCertificate(context.Context, certdomain.RevokeCertificateParams) (certdomain.Certificate, error) {
	return certdomain.Certificate{}, errors.New("not implemented")
}

func (s *certificateHTTPCertStore) DeleteCertificate(context.Context, certdomain.DeleteCertificateParams) (certdomain.Certificate, error) {
	return certdomain.Certificate{}, errors.New("not implemented")
}

type certificateHTTPAppStore struct {
	app           appdomain.Application
	scopes        []appdomain.DomainScope
	tokenIdentity appdomain.TokenIdentity
	markedTokenID string
}

func (s *certificateHTTPAppStore) Create(context.Context, appdomain.CreateApplicationParams) (appdomain.Application, error) {
	return s.app, nil
}

func (s *certificateHTTPAppStore) Get(context.Context, string) (appdomain.Application, error) {
	if s.app.ID != "" {
		return s.app, nil
	}
	return appdomain.Application{}, storage.ErrNoRows
}

func (s *certificateHTTPAppStore) GetByName(context.Context, string) (appdomain.Application, error) {
	return s.Get(context.Background(), s.app.ID)
}

func (s *certificateHTTPAppStore) List(context.Context, appdomain.ListApplicationsParams) ([]appdomain.Application, error) {
	return []appdomain.Application{s.app}, nil
}

func (s *certificateHTTPAppStore) Count(context.Context, appdomain.ListApplicationsParams) (int64, error) {
	return 1, nil
}

func (s *certificateHTTPAppStore) ListVisible(context.Context, string, appdomain.ListApplicationsParams) ([]appdomain.Application, error) {
	return []appdomain.Application{s.app}, nil
}

func (s *certificateHTTPAppStore) CountVisible(context.Context, string, appdomain.ListApplicationsParams) (int64, error) {
	return 1, nil
}

func (s *certificateHTTPAppStore) ListAccessibleApplicationIDs(context.Context, string) ([]string, error) {
	return []string{s.app.ID}, nil
}

func (s *certificateHTTPAppStore) Update(context.Context, string, appdomain.UpdateApplicationParams) (appdomain.Application, error) {
	return s.app, nil
}

func (s *certificateHTTPAppStore) CreateToken(context.Context, appdomain.CreateTokenParams) (appdomain.ApplicationToken, error) {
	return appdomain.ApplicationToken{}, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) LookupTokenByHash(context.Context, string) (appdomain.TokenIdentity, error) {
	if s.tokenIdentity.Token.ID == "" {
		return appdomain.TokenIdentity{}, storage.ErrNoRows
	}
	return s.tokenIdentity, nil
}

func (s *certificateHTTPAppStore) MarkTokenUsed(_ context.Context, id string) error {
	s.markedTokenID = id
	return nil
}

func (s *certificateHTTPAppStore) ListTokens(context.Context, string, appdomain.ListTokensParams) ([]appdomain.ApplicationToken, error) {
	return nil, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) CountTokens(context.Context, string, appdomain.ListTokensParams) (int64, error) {
	return 0, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) RevokeToken(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) AddDomainScope(context.Context, appdomain.AddDomainScopeParams) (appdomain.DomainScope, error) {
	return appdomain.DomainScope{}, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) ListDomainScopes(context.Context, string, storage.ListOptions) ([]appdomain.DomainScope, error) {
	return s.scopes, nil
}

func (s *certificateHTTPAppStore) CountDomainScopes(context.Context, string, storage.ListOptions) (int64, error) {
	return int64(len(s.scopes)), nil
}

func (s *certificateHTTPAppStore) DeleteDomainScope(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) UpsertGrant(context.Context, appdomain.UpsertGrantParams) (appdomain.UserGrant, error) {
	return appdomain.UserGrant{}, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) ListGrants(context.Context, string, storage.ListOptions) ([]appdomain.UserGrant, error) {
	return nil, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) CountGrants(context.Context, string, storage.ListOptions) (int64, error) {
	return 0, errors.New("not implemented")
}

func (s *certificateHTTPAppStore) GetGrant(context.Context, string, string) (appdomain.UserGrant, error) {
	return appdomain.UserGrant{Role: appdomain.GrantRoleManager}, nil
}

func (s *certificateHTTPAppStore) DeleteGrant(context.Context, string, string) (bool, error) {
	return false, errors.New("not implemented")
}

type certificateHTTPIssuerStore struct {
	issuer issuerdomain.Issuer
}

func (s *certificateHTTPIssuerStore) Get(context.Context, string) (issuerdomain.Issuer, error) {
	return s.issuer, nil
}

func (s *certificateHTTPIssuerStore) GetByName(context.Context, string) (issuerdomain.Issuer, error) {
	return s.issuer, nil
}

func (s *certificateHTTPIssuerStore) GetActiveDefault(context.Context) (issuerdomain.Issuer, error) {
	return s.issuer, nil
}

type certificateHTTPAuditStore struct {
	events []auditdomain.AppendEventParams
}

func (s *certificateHTTPAuditStore) Append(_ context.Context, params auditdomain.AppendEventParams) (auditdomain.Event, error) {
	s.events = append(s.events, params)
	return auditdomain.Event{ID: "92345678-1234-4234-9234-123456789abc"}, nil
}
