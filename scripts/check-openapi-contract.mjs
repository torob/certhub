#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const [bundlePath, examplesDir] = process.argv.slice(2);
if (!bundlePath || !examplesDir) {
  console.error('usage: check-openapi-contract.mjs <bundled-openapi.json> <examples-dir>');
  process.exit(2);
}

const doc = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
const failures = [];

const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);
const expectedOperations = new Set([
  'GET /healthz',
  'GET /readyz',
  'GET /metrics',
  'POST /v1/auth/login',
  'POST /v1/auth/password-2fa/setup',
  'POST /v1/auth/password-2fa/confirm',
  'DELETE /v1/auth/password-2fa',
  'GET /v1/auth/oidc/login',
  'GET /v1/auth/oidc/callback',
  'POST /v1/auth/oidc/handoff',
  'POST /v1/auth/refresh',
  'POST /v1/auth/logout',
  'GET /v1/auth/me',
  'POST /v1/sync/certificates',
  'POST /v1/sync/certificates/tls-material',
  'POST /v1/sync/certificates/tls-archive',
  'GET /v1/certificates',
  'GET /v1/certificates/{certificate_id}',
  'PATCH /v1/certificates/{certificate_id}',
  'DELETE /v1/certificates/{certificate_id}',
  'GET /v1/certificates/{certificate_id}/versions',
  'GET /v1/certificates/{certificate_id}/tls-archive',
  'GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/events',
  'GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/tls-archive',
  'POST /v1/certificates/{certificate_id}/renew',
  'POST /v1/certificates/{certificate_id}/rotate-key',
  'POST /v1/certificates/{certificate_id}/reissue',
  'POST /v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke',
  'GET /v1/certificates/{certificate_id}/events',
  'GET /v1/auth/user-invites/{invite_token}',
  'POST /v1/auth/user-invites/{invite_token}/signup',
  'POST /v1/auth/user-invites/{invite_token}/signup/confirm-2fa',
  'GET /v1/auth/password-resets/{reset_token}',
  'POST /v1/auth/password-resets/{reset_token}',
  'POST /v1/auth/password-2fa/login-setup/confirm',
  'GET /v1/users',
  'POST /v1/users',
  'GET /v1/users/lookup',
  'GET /v1/users/{user_id}',
  'PATCH /v1/users/{user_id}',
  'POST /v1/users/{user_id}/password-reset-link',
  'DELETE /v1/users/{user_id}/password-2fa',
  'GET /v1/applications',
  'POST /v1/applications',
  'GET /v1/applications/{application_id}',
  'PATCH /v1/applications/{application_id}',
  'DELETE /v1/applications/{application_id}',
  'POST /v1/applications/{application_id}/certificates',
  'GET /v1/applications/{application_id}/tokens',
  'POST /v1/applications/{application_id}/tokens',
  'POST /v1/applications/{application_id}/tokens/{token_id}/rotate',
  'DELETE /v1/applications/{application_id}/tokens/{token_id}',
  'GET /v1/applications/{application_id}/domain-scopes',
  'POST /v1/applications/{application_id}/domain-scopes',
  'DELETE /v1/applications/{application_id}/domain-scopes/{scope_id}',
  'GET /v1/applications/{application_id}/users',
  'PUT /v1/applications/{application_id}/users/{user_id}',
  'DELETE /v1/applications/{application_id}/users/{user_id}',
  'GET /v1/issuers',
  'POST /v1/issuers',
  'GET /v1/issuers/{issuer_id}',
  'PATCH /v1/issuers/{issuer_id}',
  'GET /v1/dns-providers',
  'POST /v1/dns-providers',
  'GET /v1/dns-providers/{dns_provider_id}',
  'PATCH /v1/dns-providers/{dns_provider_id}',
  'GET /v1/dns-providers/{dns_provider_id}/zones',
  'POST /v1/dns-providers/{dns_provider_id}/zones',
  'DELETE /v1/dns-providers/{dns_provider_id}/zones/{zone_id}',
  'GET /v1/dns-providers/{dns_provider_id}/zones/discovered',
  'POST /v1/dns-providers/{dns_provider_id}/zones/refresh',
  'GET /v1/audit-events',
]);

function fail(message) {
  failures.push(message);
}

function resolveRef(value) {
  let current = value;
  const seen = new Set();
  while (current && typeof current === 'object' && typeof current.$ref === 'string') {
    const ref = current.$ref;
    if (!ref.startsWith('#/')) {
      fail(`unsupported external ref in bundled contract: ${ref}`);
      return current;
    }
    if (seen.has(ref)) {
      fail(`cyclic ref in bundled contract: ${ref}`);
      return current;
    }
    seen.add(ref);
    current = ref
      .slice(2)
      .split('/')
      .map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
      .reduce((cursor, part) => (cursor ? cursor[part] : undefined), doc);
  }
  return current;
}

function operationEntries() {
  const entries = [];
  for (const [apiPath, pathItem] of Object.entries(doc.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem || {})) {
      if (!methods.has(method)) continue;
      entries.push({ method: method.toUpperCase(), apiPath, operation });
    }
  }
  return entries;
}

function securityKey(security) {
  if (!Array.isArray(security)) return '<missing>';
  if (security.length === 0) return 'Public';
  return security
    .map((requirement) => Object.keys(requirement).sort().join('+'))
    .sort()
    .join('|');
}

function expectSecurity(entry, expected) {
  const actual = securityKey(entry.operation.security);
  if (actual !== expected) {
    fail(`${entry.method} ${entry.apiPath} expected security ${expected}, got ${actual}`);
  }
}

function isStandardErrorSchema(schema) {
  const resolved = resolveRef(schema);
  const error = resolveRef(resolved?.properties?.error);
  return (
    resolved?.type === 'object' &&
    Array.isArray(resolved.required) &&
    resolved.required.includes('error') &&
    error?.type === 'object' &&
    Array.isArray(error.required) &&
    error.required.includes('code') &&
    error.required.includes('message') &&
    error.required.includes('retryable')
  );
}

function hasOwnExample(value) {
  return (
    value &&
    typeof value === 'object' &&
    (Object.prototype.hasOwnProperty.call(value, 'example') ||
      Object.prototype.hasOwnProperty.call(value, 'examples'))
  );
}

function isJsonMediaType(contentType) {
  const mediaType = contentType.toLowerCase().split(';', 1)[0].trim();
  return mediaType === 'application/json' || mediaType.endsWith('+json');
}

function mediaHasExample(mediaValue, responseValue) {
  const media = resolveRef(mediaValue);
  const response = resolveRef(responseValue);
  const schema = resolveRef(media?.schema);

  return (
    hasOwnExample(mediaValue) ||
    hasOwnExample(media) ||
    hasOwnExample(responseValue) ||
    hasOwnExample(response) ||
    hasOwnExample(mediaValue?.schema) ||
    hasOwnExample(media?.schema) ||
    hasOwnExample(schema)
  );
}

function assertJsonContentExamples(label, owner, content, responseValue) {
  for (const [contentType, mediaValue] of Object.entries(content || {})) {
    if (!isJsonMediaType(contentType)) continue;
    if (!mediaHasExample(mediaValue, responseValue)) {
      fail(`${label} ${owner} ${contentType} is missing JSON example/examples`);
    }
  }
}

if (doc.openapi !== '3.0.3') {
  fail(`expected OpenAPI 3.0.3, got ${doc.openapi || '<missing>'}`);
}

const entries = operationEntries();
const actualOperations = new Set(entries.map((entry) => `${entry.method} ${entry.apiPath}`));
for (const expected of expectedOperations) {
  if (!actualOperations.has(expected)) fail(`missing expected operation ${expected}`);
}
for (const actual of actualOperations) {
  if (!expectedOperations.has(actual)) fail(`unexpected public operation ${actual}`);
}

const operationIds = new Map();
for (const entry of entries) {
  const label = `${entry.method} ${entry.apiPath}`;
  if (!entry.operation.operationId) {
    fail(`${label} is missing operationId`);
  } else if (operationIds.has(entry.operation.operationId)) {
    fail(`${label} duplicates operationId ${entry.operation.operationId}`);
  } else {
    operationIds.set(entry.operation.operationId, label);
  }

  if (!Object.prototype.hasOwnProperty.call(entry.operation, 'security')) {
    fail(`${label} is missing operation-level security declaration`);
  }

  if (entry.operation.requestBody) {
    const requestBody = resolveRef(entry.operation.requestBody);
    assertJsonContentExamples(label, 'requestBody', requestBody?.content, undefined);
  }

  for (const [status, responseValue] of Object.entries(entry.operation.responses || {})) {
    const response = resolveRef(responseValue);
    assertJsonContentExamples(label, `${status} response`, response?.content, responseValue);

    if (!/^[45]/.test(status)) continue;
    const media = response?.content?.['application/json'];
    if (!media?.schema || !isStandardErrorSchema(media.schema)) {
      fail(`${label} ${status} response does not use the standard JSON error envelope`);
    }
  }
}

for (const entry of entries) {
  const p = entry.apiPath;
  if (p.startsWith('/v1/sync/')) {
    expectSecurity(entry, 'ApplicationBearerAuth');
  } else if (p === '/v1/auth/me') {
    expectSecurity(entry, 'ApplicationBearerAuth|UserBearerAuth');
  } else if (
    p === '/healthz' ||
    p === '/readyz' ||
    p === '/metrics' ||
    p === '/v1/auth/login' ||
    p === '/v1/auth/oidc/login' ||
    p === '/v1/auth/oidc/callback' ||
    p === '/v1/auth/oidc/handoff' ||
    p === '/v1/auth/refresh' ||
    p === '/v1/auth/password-2fa/login-setup/confirm' ||
    p.startsWith('/v1/auth/password-resets/') ||
    p.startsWith('/v1/auth/user-invites/')
  ) {
    expectSecurity(entry, 'Public');
  } else if (p.startsWith('/v1/')) {
    expectSecurity(entry, 'UserBearerAuth');
  }
}

const exampleFiles = fs
  .readdirSync(examplesDir, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
  .map((entry) => path.join(examplesDir, entry.name))
  .sort();

if (exampleFiles.length === 0) {
  fail(`${examplesDir} contains no JSON examples`);
}

for (const examplePath of exampleFiles) {
  try {
    JSON.parse(fs.readFileSync(examplePath, 'utf8'));
  } catch (error) {
    fail(`${examplePath} is not valid JSON: ${error.message}`);
  }
}

if (failures.length > 0) {
  console.error('Contract baseline failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`Contract baseline passed: ${entries.length} operations, ${exampleFiles.length} JSON examples.`);
