import assert from "node:assert/strict";
import test from "node:test";
import { unauthorizedDecision } from "../src/unauthorized.ts";

function errorBody(code: string) {
  return { error: { code, message: code, retryable: false } };
}

const signedIn = { status: 401, canRefresh: true, sessionUsable: true, hasAccessToken: true };
// The request that api() sends again after a successful refresh.
const retried = { ...signedIn, canRefresh: false };

test("wrong password or 2FA code on an authenticated request keeps the session and shows the error", () => {
  for (const code of ["invalid_2fa_code", "invalid_credentials", "oidc_auth_failed"]) {
    assert.deepEqual(unauthorizedDecision({ ...signedIn, body: errorBody(code) }), { refresh: false, clearSession: false }, code);
    assert.deepEqual(unauthorizedDecision({ ...retried, body: errorBody(code) }), { refresh: false, clearSession: false }, code);
  }
});

test("rejected or expired access tokens refresh once, then clear the session", () => {
  for (const code of ["invalid_token", "session_expired"]) {
    assert.deepEqual(unauthorizedDecision({ ...signedIn, body: errorBody(code) }), { refresh: true, clearSession: true }, code);
    assert.deepEqual(unauthorizedDecision({ ...retried, body: errorBody(code) }), { refresh: false, clearSession: true }, code);
  }
});

test("a 401 without a readable error code is treated as a session failure", () => {
  for (const body of [undefined, "<html>Unauthorized</html>", {}, { error: {} }]) {
    assert.deepEqual(unauthorizedDecision({ ...signedIn, body }), { refresh: true, clearSession: true });
  }
});

test("a locally expired session is cleared without a refresh", () => {
  assert.deepEqual(unauthorizedDecision({ ...signedIn, sessionUsable: false, body: errorBody("invalid_token") }), { refresh: false, clearSession: true });
});

test("requests without a session never refresh or clear a session", () => {
  for (const code of ["invalid_credentials", "invalid_2fa_code", "invalid_token"]) {
    assert.deepEqual(unauthorizedDecision({ status: 401, canRefresh: false, sessionUsable: false, hasAccessToken: false, body: errorBody(code) }), { refresh: false, clearSession: false }, code);
  }
});

test("other statuses never refresh or clear a session", () => {
  for (const status of [200, 400, 403, 404, 500]) {
    assert.deepEqual(unauthorizedDecision({ ...signedIn, status, body: errorBody("invalid_token") }), { refresh: false, clearSession: false }, String(status));
  }
});
