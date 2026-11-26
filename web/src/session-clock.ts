// Expiry times of the browser session.
//
// The server sends absolute times (access_expires_at, session_expires_at) on
// its own clock. The UI compares them with Date.now(), the clock of this
// computer. When the two clocks are different, a new token looks expired
// (client clock ahead) or the UI refreshes it too late (client clock behind).
// So the UI moves the server times to the local clock when it receives them:
// local time = server time - (server clock - local clock). The difference is
// measured from the HTTP Date header of the same response. All times in
// SessionTimes are on the local clock.

export type SessionTimes = {
  accessIssuedAt?: string;
  accessExpiresAt?: string;
  sessionExpiresAt?: string;
};

// Token fields of the login, OIDC handoff, 2FA setup and refresh responses.
export type TokenTimes = {
  access_expires_at?: string;
  session_expires_at?: string;
};

// Local times (Date.now()) when the request was sent and when the response
// arrived, and the HTTP Date header of the response.
export type ResponseTiming = {
  sentAt?: number;
  receivedAt: number;
  serverDate?: string | null;
};

const accessRefreshSkewMs = 60_000;
const minAccessRefreshLeadMs = 1_000;

export function sessionTimesFromTokens(tokens: TokenTimes, timing: ResponseTiming): SessionTimes {
  const offset = serverClockOffsetMs(timing);
  return {
    accessIssuedAt: new Date(timing.receivedAt).toISOString(),
    accessExpiresAt: toLocalClock(tokens.access_expires_at, offset),
    sessionExpiresAt: toLocalClock(tokens.session_expires_at, offset)
  };
}

// Server clock minus local clock in milliseconds, or 0.
//
// The server sent the response after the request was sent and before the
// response arrived, at a time in the second that the Date header shows (the
// header has a resolution of one second). So:
//   Date - receivedAt <= server clock - local clock < Date + 1 s - sentAt
// When 0 is in this range, the clocks can be the same: the UI uses the server
// times without change, as before. Otherwise the UI uses the highest value of
// the range. Then the local expiry times are never later than the real ones,
// so a slow response cannot make the UI refresh too late.
export function serverClockOffsetMs(timing: ResponseTiming): number {
  if (!timing.serverDate) return 0;
  const serverMs = Date.parse(timing.serverDate);
  const sentAt = timing.sentAt ?? timing.receivedAt;
  if (!Number.isFinite(serverMs) || !Number.isFinite(sentAt) || !Number.isFinite(timing.receivedAt)) return 0;
  const lowest = serverMs - timing.receivedAt;
  const highest = serverMs + 1_000 - sentAt;
  if (lowest <= 0 && highest >= 0) return 0;
  return highest;
}

function toLocalClock(value: string | undefined, offset: number): string | undefined {
  if (!value || offset === 0) return value;
  const serverMs = parseExpiresAt(value);
  return serverMs === undefined ? value : new Date(serverMs - offset).toISOString();
}

export function parseExpiresAt(value?: string): number | undefined {
  if (!value) return undefined;
  const expiresAt = Date.parse(value);
  return Number.isFinite(expiresAt) ? expiresAt : undefined;
}

export function accessRefreshDelayMs(session: SessionTimes, now = Date.now()): number | undefined {
  const expiresAt = parseExpiresAt(session.accessExpiresAt);
  if (expiresAt === undefined) return undefined;
  if (isAccessCappedBySession(session)) return undefined;
  const issuedAt = parseExpiresAt(session.accessIssuedAt);
  const lifetime = issuedAt !== undefined && expiresAt > issuedAt ? expiresAt - issuedAt : expiresAt - now;
  const lead = Math.min(accessRefreshSkewMs, Math.max(minAccessRefreshLeadMs, Math.floor(lifetime * 0.2)));
  return expiresAt - now - lead;
}

export function isAccessCappedBySession(session: SessionTimes): boolean {
  const accessExpiresAt = parseExpiresAt(session.accessExpiresAt);
  const sessionExpiresAt = parseExpiresAt(session.sessionExpiresAt);
  return accessExpiresAt !== undefined && sessionExpiresAt !== undefined && accessExpiresAt >= sessionExpiresAt - 1_000;
}

export function shouldRefreshAccess(session: SessionTimes, now = Date.now()): boolean {
  const delay = accessRefreshDelayMs(session, now);
  return delay !== undefined && delay <= 0 && !isAccessExpired(session, now) && !isSessionExpired(session, now);
}

export function isAccessExpired(session: SessionTimes, now = Date.now()): boolean {
  const expiresAt = parseExpiresAt(session.accessExpiresAt);
  return expiresAt !== undefined && expiresAt <= now;
}

export function isSessionExpired(session: SessionTimes, now = Date.now()): boolean {
  const expiresAt = parseExpiresAt(session.sessionExpiresAt);
  return expiresAt !== undefined && expiresAt <= now;
}
