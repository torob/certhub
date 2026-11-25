import assert from "node:assert/strict";
import test from "node:test";
import { auditTargetTypeOptions } from "../src/audit-targets.ts";

// Every target_type that the server writes into audit_events. Source:
// - internal/users/service.go: "user"
// - internal/auth/service.go: "user", "user_session"
// - internal/applications/service.go: "application", "application_token", "domain_scope", "application_access"
// - internal/certificates/service.go: "certificate", "certificate_version"
// - internal/selfcert/service.go: "certificate_version"
// - internal/issuers/service.go: "issuer"
// - internal/dnsproviders/service.go: "dns_provider"
const serverTargetTypes = [
  "user",
  "user_session",
  "application",
  "application_token",
  "application_access",
  "domain_scope",
  "certificate",
  "certificate_version",
  "issuer",
  "dns_provider"
];

test("every audit target type filter option is a target type that the server writes", () => {
  const unknown = auditTargetTypeOptions.map(([value]) => value).filter((value) => !serverTargetTypes.includes(value));
  assert.deepEqual(unknown, []);
});

test("every target type that the server writes has an audit filter option", () => {
  const values = auditTargetTypeOptions.map(([value]) => value);
  const missing = serverTargetTypes.filter((type) => !values.includes(type));
  assert.deepEqual(missing, []);
});

test("audit target type filter options have unique values and non-empty labels", () => {
  const values = auditTargetTypeOptions.map(([value]) => value);
  assert.equal(new Set(values).size, values.length);
  for (const [value, label] of auditTargetTypeOptions) assert.ok(label.trim(), value);
});

test("removed audit target type values are absent", () => {
  const values = auditTargetTypeOptions.map(([value]) => value);
  assert.ok(!values.includes("application_user_grant"));
  assert.ok(!values.includes("session"));
});
