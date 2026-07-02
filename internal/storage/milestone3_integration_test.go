package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/torob/certhub/internal/applications"
	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestMilestone3RepositoriesWithPostgres(t *testing.T) {
	url := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set; skipping Milestone 3 repository integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrationDB, err := migrations.OpenDB(url)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close()
	if _, err := migrations.NewRunner(migrations.DefaultDir).Up(ctx, migrationDB); err != nil {
		t.Fatal(err)
	}

	pool, err := storage.Open(ctx, storage.Config{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	userRepo := users.NewRepository(tx)
	user, err := userRepo.Create(ctx, users.CreateUserParams{
		Email:       "M3.User@Example.COM",
		DisplayName: "Milestone 3 User",
		GlobalRole:  users.GlobalRoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "m3.user@example.com" {
		t.Fatalf("normalized user email = %q", user.Email)
	}

	appRepo := applications.NewRepository(tx)
	app, err := appRepo.Create(ctx, applications.CreateApplicationParams{
		Name:               "m3_app",
		DisplayName:        "Milestone 3 App",
		TrustedSourceCIDRs: []string{"203.0.113.10", "2001:db8::/64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(app.TrustedSourceCIDRs) != 2 {
		t.Fatalf("trusted_source_cidrs = %#v", app.TrustedSourceCIDRs)
	}
	token, err := appRepo.CreateToken(ctx, applications.CreateTokenParams{
		ApplicationID: app.ID,
		Name:          "primary",
		TokenHash:     testTokenHash("application-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := appRepo.LookupTokenByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Application.ID != app.ID {
		t.Fatalf("token identity application = %#v", identity.Application)
	}
	scope, err := appRepo.AddDomainScope(ctx, applications.AddDomainScopeParams{
		ApplicationID:   app.ID,
		Value:           "*.Bücher.Example.",
		CreatedByUserID: &user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Value != "*.xn--bcher-kva.example" {
		t.Fatalf("scope value = %q", scope.Value)
	}
	grant, err := appRepo.UpsertGrant(ctx, applications.UpsertGrantParams{
		ApplicationID:   app.ID,
		UserID:          user.ID,
		Role:            applications.GrantRoleManager,
		CreatedByUserID: &user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.Role != applications.GrantRoleManager {
		t.Fatalf("grant = %#v", grant)
	}

	now := time.Now().UTC()
	session, err := auth.CreateSessionTx(ctx, tx, auth.CreateSessionParams{
		UserID:           user.ID,
		AuthMethod:       auth.AuthMethodPassword,
		AccessTokenHash:  testTokenHash("access-1"),
		AccessExpiresAt:  now.Add(5 * time.Minute),
		SessionExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := auth.RotateAccessTokenTx(ctx, tx, auth.RotateAccessTokenParams{
		CurrentAccessTokenHash: session.AccessTokenHash,
		NewAccessTokenHash:     testTokenHash("access-2"),
		AccessExpiresAt:        now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessTokenHash == session.AccessTokenHash {
		t.Fatalf("access token did not rotate")
	}

	authRepo := auth.NewRepository(tx)
	state, err := authRepo.CreateOIDCState(ctx, auth.CreateOIDCStateParams{
		StateHash:             testTokenHash("oidc-state"),
		Nonce:                 "abcdefghijklmnopqrstuvwxyz",
		CodeVerifierEncrypted: `{"version":"1"}`,
		ProviderCallbackURL:   "https://certhub.example.com/v1/auth/oidc/callback",
		ExpiresAt:             now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	consumedState, err := authRepo.ConsumeOIDCState(ctx, state.StateHash)
	if err != nil {
		t.Fatal(err)
	}
	if consumedState.ConsumedAt == nil {
		t.Fatalf("OIDC state consume did not set consumed_at")
	}
	if _, err := authRepo.ConsumeOIDCState(ctx, state.StateHash); !errors.Is(err, storage.ErrNoRows) {
		t.Fatalf("consumed OIDC state replay err = %v", err)
	}
	expiredState, err := authRepo.CreateOIDCState(ctx, auth.CreateOIDCStateParams{
		StateHash:             testTokenHash("expired-oidc-state"),
		Nonce:                 "zyxwvutsrqponmlkjihgfedcba",
		CodeVerifierEncrypted: `{"version":"1"}`,
		ProviderCallbackURL:   "https://certhub.example.com/v1/auth/oidc/callback",
		ExpiresAt:             now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
update oidc_login_states
set created_at = now() - interval '10 minutes',
    expires_at = now() - interval '1 minute'
where id = $1`, expiredState.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := authRepo.ConsumeOIDCState(ctx, expiredState.StateHash); !errors.Is(err, storage.ErrNoRows) {
		t.Fatalf("expired OIDC state err = %v", err)
	}
	handoff, err := authRepo.CreateOIDCHandoff(ctx, auth.CreateOIDCHandoffParams{
		HandoffHash:      testTokenHash("oidc-handoff"),
		UserID:           user.ID,
		OIDCLoginStateID: &state.ID,
		ExpiresAt:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	consumedHandoff, err := authRepo.ConsumeOIDCHandoff(ctx, handoff.HandoffHash)
	if err != nil {
		t.Fatal(err)
	}
	if consumedHandoff.Status != auth.HandoffStatusConsumed || consumedHandoff.ConsumedAt == nil {
		t.Fatalf("OIDC handoff consume did not mark consumed")
	}
	if _, err := authRepo.ConsumeOIDCHandoff(ctx, handoff.HandoffHash); !errors.Is(err, storage.ErrNoRows) {
		t.Fatalf("consumed OIDC handoff replay err = %v", err)
	}
	expiredHandoff, err := authRepo.CreateOIDCHandoff(ctx, auth.CreateOIDCHandoffParams{
		HandoffHash:      testTokenHash("expired-oidc-handoff"),
		UserID:           user.ID,
		OIDCLoginStateID: &state.ID,
		ExpiresAt:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
update oidc_login_handoffs
set created_at = now() - interval '10 minutes',
    expires_at = now() - interval '1 minute'
where id = $1`, expiredHandoff.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := authRepo.ConsumeOIDCHandoff(ctx, expiredHandoff.HandoffHash); !errors.Is(err, storage.ErrNoRows) {
		t.Fatalf("expired OIDC handoff err = %v", err)
	}

	auditRepo := audit.NewRepository(tx)
	event, err := auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:       audit.IdentityTypeUser,
		IdentityID:         &user.ID,
		Action:             "application_created",
		TargetType:         "application",
		TargetID:           &app.ID,
		ScopeApplicationID: &app.ID,
		ScopeUserID:        &user.ID,
		Result:             audit.ResultSuccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := auditRepo.List(ctx, audit.ListEventsParams{ScopeApplicationID: &app.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].ID != event.ID {
		t.Fatalf("events = %#v", events)
	}

	systemApp, err := appRepo.EnsureSystemApplication(ctx, applications.CreateApplicationParams{
		DisplayName: "Certhub Server",
	})
	if err != nil {
		t.Fatal(err)
	}
	if systemApp.SystemKind == nil || *systemApp.SystemKind != applications.SystemKindCerthubServer {
		t.Fatalf("system application = %#v", systemApp)
	}
	if _, err := appRepo.CreateToken(ctx, applications.CreateTokenParams{
		ApplicationID: systemApp.ID,
		Name:          "forbidden",
		TokenHash:     testTokenHash("system-token"),
	}); err == nil {
		t.Fatalf("system application token creation unexpectedly succeeded")
	}
}

func testTokenHash(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
