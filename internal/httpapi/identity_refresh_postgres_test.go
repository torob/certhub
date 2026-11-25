package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	userdomain "github.com/torob/certhub/internal/users"
)

func TestRefreshUnknownTokenWithPostgresStorage(t *testing.T) {
	databaseURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := migrations.OpenDB(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.NewRunner(migrations.DefaultDir).Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	pool, err := storage.Open(ctx, storage.Config{URL: databaseURL})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	cfg := testConfig(t, "")
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository:  auth.NewRepository(pool),
		UserRepository:  userdomain.NewRepository(pool),
		AuditRepository: audit.NewRepository(pool),
		KeySet:          testKeySet(t),
		Config:          cfg.Auth,
		Storage:         pool,
	})
	handler := New(cfg, WithIdentityServices(authSvc, nil)).Handler()

	requestID, err := storage.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	unknownToken := auth.UserAccessTokenPrefix + strings.Repeat("Z", 43)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"access_token":"`+unknownToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", requestID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusUnauthorized, "invalid_token")

	var count int
	if err := pool.QueryRow(ctx, `
select count(*) from audit_events
where correlation_id = $1
  and action = 'user_session_refreshed'
  and result = 'failure'`, requestID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("refresh failure audit events = %d err=%v, want 1", count, err)
	}
}
