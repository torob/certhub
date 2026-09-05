import assert from "node:assert/strict";
import test from "node:test";
import { apiRequestURL } from "../src/api-url.ts";

const origin = "https://certhub.example";

test("crafted certificate creation links cannot send credentials to another host", () => {
  for (const applicationID of ["../../..//attacker.example", "../../..///attacker.example", "../../../\\attacker.example", "%2e%2e/%2e%2e/%2e%2e//attacker.example"]) {
    const link = new URL("/certificates/new", origin);
    link.searchParams.set("application_id", applicationID);
    const id = new URL(link).searchParams.get("application_id");
    assert.throws(() => apiRequestURL(`/v1/applications/${id}/domain-scopes?limit=100`, origin));
  }
});

test("API requests reject foreign origins, userinfo, and non-API paths", () => {
  for (const path of ["https://attacker.example/v1/users", "//attacker.example/v1/users", "https://user@certhub.example/v1/users", "/healthz", "/v1/../metrics"]) {
    assert.throws(() => apiRequestURL(path, origin));
  }
});

test("checked URLs remain absolute when passed to fetch", () => {
  for (const path of ["/v1/auth/me", "/v1/applications?limit=100", "/v1/certificates/123/versions?limit=20", "/v1/applications/..%2f..%2fexample/domain-scopes"]) {
    const target = apiRequestURL(path, origin);
    assert.equal(new URL(target).origin, origin);
    assert.equal(new URL(target, "https://attacker.example").origin, origin);
  }
});
