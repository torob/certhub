export type UnauthorizedInput = {
  status: number;
  // The request may refresh the access token and retry once.
  canRefresh: boolean;
  // The local session and access token are not expired.
  sessionUsable: boolean;
  // The request was sent with an access token.
  hasAccessToken: boolean;
  // The parsed response body.
  body: unknown;
};

export type UnauthorizedDecision = {
  refresh: boolean;
  clearSession: boolean;
};

// Error codes that mean the access token or session is no longer accepted.
// Other 401 codes (for example invalid_credentials or invalid_2fa_code) report
// a wrong password or code for this request and must reach the caller.
const sessionFailureCodes = new Set(["invalid_token", "session_expired"]);

export function unauthorizedDecision(input: UnauthorizedInput): UnauthorizedDecision {
  const sessionFailure = input.status === 401 && isSessionFailure(input.body);
  return {
    refresh: sessionFailure && input.canRefresh && input.sessionUsable,
    clearSession: sessionFailure && input.hasAccessToken
  };
}

function isSessionFailure(body: unknown): boolean {
  const code = errorCode(body);
  // A 401 without a readable error code did not come from a known API error.
  // Treat it as a rejected token.
  return code === undefined || sessionFailureCodes.has(code);
}

function errorCode(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const error = (body as { error?: unknown }).error;
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && code ? code : undefined;
}
