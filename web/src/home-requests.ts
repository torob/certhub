// Issuance setup requests of the Home page. An empty path means "do not send".
// The server allows these endpoints only for users with the admin global role
// (internal/issuers ListIssuers, internal/dnsproviders ListProviders and
// ListZones: actor.admin()). It returns 403 for other users. Until
// GET /v1/auth/me returns the identity, the role is not known and nothing is sent.
export type HomeAdminRequestPaths = {
  activeIssuerCount: string;
  providers: string;
  activeProviderCount: string;
};

export function homeAdminRequestPaths(admin: boolean): HomeAdminRequestPaths {
  if (!admin) return { activeIssuerCount: "", providers: "", activeProviderCount: "" };
  return {
    activeIssuerCount: "/v1/issuers?limit=1&status=active",
    providers: "/v1/dns-providers?limit=100",
    activeProviderCount: "/v1/dns-providers?limit=1&status=active"
  };
}

export function homeZonesPath(admin: boolean, firstProviderID?: string): string {
  return admin && firstProviderID ? `/v1/dns-providers/${firstProviderID}/zones?limit=100` : "";
}
