// Return the complete checked URL. Converting it back to a pathname can turn
// a normalized path beginning with // into a request to another origin.
export function apiRequestURL(path: string, origin: string): string {
  const url = new URL(path, origin);
  if (url.origin !== origin || url.username || url.password || !url.pathname.startsWith("/v1/")) {
    throw new Error("API requests must target this server's API.");
  }
  return url.href;
}
