import assert from "node:assert/strict";
import test from "node:test";
import {
  accessRefreshDelayMs,
  isAccessExpired,
  isSessionExpired,
  sessionTimesFromTokens,
  shouldRefreshAccess
} from "../src/session-clock.ts";

const second = 1_000;
const minute = 60 * second;
const hour = 60 * minute;
// Server time when the server sends the login or refresh response.
const serverNow = Date.parse("2026-11-25T10:00:00.000Z");

function iso(ms: number) {
  return new Date(ms).toISOString();
}

// HTTP Date header of a response sent at serverMs (one second resolution).
function httpDate(serverMs: number) {
  return new Date(serverMs).toUTCString();
}

function tokens(accessTTL: number, sessionTTL = 8 * hour) {
  return { access_expires_at: iso(serverNow + accessTTL), session_expires_at: iso(serverNow + sessionTTL) };
}

// A response that the server sends at serverNow + sendFraction, to a client
// whose clock is skew ahead of the server clock. The request takes `up` ms to
// arrive, and the response `down` ms (including a busy browser main thread).
function exchange(skew: number, { up = 40, down = 80, sendFraction = 0 } = {}) {
  const serverSend = serverNow + sendFraction;
  return {
    sentAt: serverSend - up + skew,
    receivedAt: serverSend + down + skew,
    serverDate: httpDate(serverSend)
  };
}

test("client clock 20 minutes ahead: a 15 minute access token is usable and refreshes before it expires", () => {
  const timing = exchange(20 * minute);
  const times = sessionTimesFromTokens(tokens(15 * minute), timing);
  const now = timing.receivedAt;
  assert.equal(isAccessExpired(times, now), false, "access token is treated as expired at login");
  assert.equal(isSessionExpired(times, now), false, "session is treated as expired at login");
  const delay = accessRefreshDelayMs(times, now);
  assert.ok(delay !== undefined && delay > 0, `refresh delay ${delay}`);
  // Same refresh lead as with a correct clock: 60 s before expiry (Date header resolution: 1 s).
  assert.ok(delay <= 14 * minute && delay >= 14 * minute - 2 * second, `refresh delay ${delay}`);
  assert.equal(shouldRefreshAccess(times, now), false);
});

test("client clock 20 minutes behind: the 5 minute access token refreshes after 4 minutes, not after 24", () => {
  const skew = -20 * minute;
  const timing = exchange(skew);
  const times = sessionTimesFromTokens(tokens(5 * minute), timing);
  const delay = accessRefreshDelayMs(times, timing.receivedAt);
  assert.ok(delay !== undefined && delay <= 4 * minute && delay >= 4 * minute - 2 * second, `refresh delay ${delay}`);
  // When the server expires the token, the client also sees it as expired.
  assert.equal(isAccessExpired(times, serverNow + skew + 5 * minute), true);
});

test("client clock ahead or behind: the absolute session expiry follows the server clock", () => {
  for (const skew of [20 * minute, -20 * minute, 3 * hour]) {
    const times = sessionTimesFromTokens(tokens(5 * minute), exchange(skew));
    assert.equal(isSessionExpired(times, serverNow + skew + 8 * hour - 2 * second), false, `skew ${skew}`);
    assert.equal(isSessionExpired(times, serverNow + skew + 8 * hour), true, `skew ${skew}`);
  }
});

test("correct client clock: the session times are the server values, as before, also for slow responses", () => {
  for (const [up, down, sendFraction] of [[0, 0, 0], [40, 80, 999], [500, 1_500, 300], [200, 8_000, 0], [3_000, 50, 999]]) {
    const timing = exchange(0, { up, down, sendFraction });
    assert.deepEqual(sessionTimesFromTokens(tokens(5 * minute), timing), {
      accessIssuedAt: iso(timing.receivedAt),
      accessExpiresAt: iso(serverNow + 5 * minute),
      sessionExpiresAt: iso(serverNow + 8 * hour)
    }, `up ${up} down ${down} send +${sendFraction}`);
  }
});

test("any clock: a corrected expiry is never later than the server expiry, and at most the round trip plus 1 s earlier", () => {
  const serverExpiry = serverNow + 5 * minute;
  for (const skew of [-3 * hour, -20 * minute, -5 * second, -1_500, 0, 1_500, 5 * second, 20 * minute, 3 * hour]) {
    for (const [up, down] of [[0, 0], [30, 60], [400, 4_000], [5_000, 20]]) {
      for (const sendFraction of [0, 1, 500, 999]) {
        const timing = exchange(skew, { up, down, sendFraction });
        const times = sessionTimesFromTokens(tokens(5 * minute), timing);
        const label = `skew ${skew} up ${up} down ${down} send +${sendFraction}`;
        if (times.accessExpiresAt === iso(serverExpiry)) {
          // Server value as before: only when the response cannot show a clock difference.
          assert.ok(Math.abs(skew) < up + down + second, `${label}: clock difference not corrected`);
          continue;
        }
        // Server clock time of the local expiry.
        const expiry = Date.parse(times.accessExpiresAt as string) - skew;
        assert.ok(expiry <= serverExpiry, `${label}: ${expiry - serverExpiry} ms late`);
        assert.ok(expiry >= serverExpiry - (up + down + second), `${label}: ${serverExpiry - expiry} ms early`);
      }
    }
  }
});

test("missing or unreadable Date header: the session times are the server values, as before", () => {
  const receivedAt = serverNow + 20 * minute;
  for (const serverDate of [undefined, null, "", "not a date"]) {
    assert.deepEqual(sessionTimesFromTokens(tokens(5 * minute), { sentAt: receivedAt - 50, receivedAt, serverDate }), {
      accessIssuedAt: iso(receivedAt),
      accessExpiresAt: iso(serverNow + 5 * minute),
      sessionExpiresAt: iso(serverNow + 8 * hour)
    }, String(serverDate));
  }
});

test("refresh lead is unchanged: 60 s, or 20% of a short lifetime, at least 1 s", () => {
  for (const [ttl, lead] of [[5 * minute, minute], [30 * second, 6 * second], [2 * second, second]]) {
    const times = sessionTimesFromTokens(tokens(ttl), { sentAt: serverNow, receivedAt: serverNow, serverDate: httpDate(serverNow) });
    assert.equal(accessRefreshDelayMs(times, serverNow), ttl - lead, `ttl ${ttl}`);
  }
});

test("an access token capped by the session expiry is not refreshed", () => {
  const timing = exchange(20 * minute);
  const times = sessionTimesFromTokens(tokens(5 * minute, 5 * minute), timing);
  assert.equal(accessRefreshDelayMs(times, timing.receivedAt), undefined);
});
