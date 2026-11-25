// The Home page reads readiness from the server's operational endpoint. Allow
// only this exact path (no query or fragment) outside the /v1/ API prefix.
const readinessPath = "/readyz";

// Return the complete checked URL. Converting it back to a pathname can turn
// a normalized path beginning with // into a request to another origin.
export function apiRequestURL(path: string, origin: string): string {
  const url = new URL(path, origin);
  const readiness = url.pathname === readinessPath && !url.search && !url.hash;
  if (url.origin !== origin || url.username || url.password || !(url.pathname.startsWith("/v1/") || readiness)) {
    throw new Error("API requests must target this server's API.");
  }
  return url.href;
}
