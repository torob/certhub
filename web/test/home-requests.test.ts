import assert from "node:assert/strict";
import test from "node:test";
import { asyncEffectDeps, asyncStateIsStale } from "../src/async-request.ts";
import { homeAdminRequestPaths, homeZonesPath } from "../src/home-requests.ts";

// A model of one useAsync call. After a render, React runs the request effect
// when an item of the effect deps changed (Object.is). useAsync sends the
// request only when the path is not empty.
class RequestHook {
  private previous?: unknown[];
  readonly sent: string[] = [];

  render(path: string, deps: unknown[]) {
    const next = asyncEffectDeps(path, deps);
    const previous = this.previous;
    const changed = !previous || previous.length !== next.length || next.some((value, i) => !Object.is(value, previous[i]));
    this.previous = next;
    if (changed && path) this.sent.push(path);
  }
}

type HomeRender = {
  // isAdmin(session). It is false until GET /v1/auth/me returns the identity.
  admin: boolean;
  // The id of the first row of the DNS provider list response.
  firstProviderID?: string;
  refresh?: number;
};

// Renders the issuance setup requests of HomePage (src/app.ts) with the same
// paths and deps, and returns the requests that each one sent.
function renderHome(renders: HomeRender[]) {
  const hooks = {
    activeIssuerCount: new RequestHook(),
    providers: new RequestHook(),
    activeProviderCount: new RequestHook(),
    zones: new RequestHook()
  };
  for (const { admin, firstProviderID, refresh = 0 } of renders) {
    const paths = homeAdminRequestPaths(admin);
    hooks.activeIssuerCount.render(paths.activeIssuerCount, [refresh]);
    hooks.providers.render(paths.providers, [refresh]);
    hooks.activeProviderCount.render(paths.activeProviderCount, [refresh]);
    hooks.zones.render(homeZonesPath(admin, firstProviderID), [firstProviderID, refresh]);
  }
  return {
    activeIssuerCount: hooks.activeIssuerCount.sent,
    providers: hooks.providers.sent,
    activeProviderCount: hooks.activeProviderCount.sent,
    zones: hooks.zones.sent
  };
}

const adminRequests = {
  activeIssuerCount: ["/v1/issuers?limit=1&status=active"],
  providers: ["/v1/dns-providers?limit=100"],
  activeProviderCount: ["/v1/dns-providers?limit=1&status=active"]
};

test("useAsync sends the request again when only its path changes", () => {
  assert.notDeepEqual(asyncEffectDeps("", [0]), asyncEffectDeps("/v1/issuers?limit=1&status=active", [0]));
  assert.deepEqual(asyncEffectDeps("/v1/applications?limit=100", [0]), asyncEffectDeps("/v1/applications?limit=100", [0]));
});

test("admin Home sends the issuance setup requests after GET /v1/auth/me returns the admin role", () => {
  // Right after login the session has no identity yet, so isAdmin() is false.
  const sent = renderHome([{ admin: false }, { admin: true }, { admin: true, firstProviderID: "provider-1" }]);
  assert.deepEqual(sent, { ...adminRequests, zones: ["/v1/dns-providers/provider-1/zones?limit=100"] });
});

test("admin Home shows Loading, not zero counts, before the first issuance setup response", () => {
  // While the role is not known, useAsync stores a state without a path for
  // the empty path. In the first render after GET /v1/auth/me returns the
  // admin role, that state is stale until the effect sends the request.
  const paths = homeAdminRequestPaths(true);
  for (const path of [paths.activeIssuerCount, paths.providers, paths.activeProviderCount, homeZonesPath(true, "provider-1")]) {
    assert.equal(asyncStateIsStale(undefined, path), true, path);
    assert.equal(asyncStateIsStale("", path), true, path);
  }
  assert.equal(asyncStateIsStale(paths.activeIssuerCount, paths.activeIssuerCount), false);
  assert.equal(asyncStateIsStale(undefined, ""), false);
});

test("admin Home sends the zones request in either response order", () => {
  // The DNS provider list response arrives before GET /v1/auth/me returns.
  const sent = renderHome([{ admin: false }, { admin: false, firstProviderID: "provider-1" }, { admin: true, firstProviderID: "provider-1" }]);
  assert.deepEqual(sent.zones, ["/v1/dns-providers/provider-1/zones?limit=100"]);
});

test("admin Home sends each request once per refresh", () => {
  const sent = renderHome([{ admin: true }, { admin: true }, { admin: true, refresh: 1 }]);
  assert.deepEqual(sent, {
    activeIssuerCount: [...adminRequests.activeIssuerCount, ...adminRequests.activeIssuerCount],
    providers: [...adminRequests.providers, ...adminRequests.providers],
    activeProviderCount: [...adminRequests.activeProviderCount, ...adminRequests.activeProviderCount],
    zones: []
  });
});

test("non-admin Home sends no issuer or DNS provider request", () => {
  // The server allows these list endpoints only for the admin global role
  // (internal/issuers ListIssuers, internal/dnsproviders ListProviders and
  // ListZones: actor.admin()). It returns 403 for other users.
  assert.deepEqual(homeAdminRequestPaths(false), { activeIssuerCount: "", providers: "", activeProviderCount: "" });
  assert.equal(homeZonesPath(false, "provider-1"), "");
  const sent = renderHome([{ admin: false }, { admin: false }, { admin: false, refresh: 1 }]);
  assert.deepEqual(sent, { activeIssuerCount: [], providers: [], activeProviderCount: [], zones: [] });
});

test("admin Home request paths are unchanged", () => {
  assert.deepEqual(homeAdminRequestPaths(true), {
    activeIssuerCount: "/v1/issuers?limit=1&status=active",
    providers: "/v1/dns-providers?limit=100",
    activeProviderCount: "/v1/dns-providers?limit=1&status=active"
  });
  assert.equal(homeZonesPath(true, "provider-1"), "/v1/dns-providers/provider-1/zones?limit=100");
  assert.equal(homeZonesPath(true, undefined), "");
});
