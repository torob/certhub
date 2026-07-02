# Certhub Frontend Spec

## Summary

Certhub frontend is a TypeScript client-side rendered (CSR) web application for operators, platform engineers, application owners, and security reviewers. It is the primary management surface for Certhub. It manages certificate inventory, Applications, User access grants, issuer configuration, DNS provider configuration, and audit events.

Users are humans. Applications are the certificate-owning identities. A User cannot create personal certificates, but an authorized User can create a Certificate for an Application through the web console. Application clients still create or reuse Certificates with Application tokens.

The frontend is an operational console, not a marketing site. It should be dense, predictable, and optimized for repeated administrative workflows.

## Technology Choices

- Language: TypeScript.
- Rendering mode: client-side rendering (CSR).
- Runtime: browser-only web UI that communicates with the Certhub backend JSON APIs.
- Production serving mode: built static assets are served by the Certhub backend server binary.
- Server-side rendering is out of scope for v1.

## Asset Serving

The web UI must not rely on externally hosted assets at runtime. All UI assets must be served by the same web server that serves the JavaScript application files.

The v1 production deployment model is embedded static serving from the Certhub server binary. The frontend build output is served by the same process and listener as the backend API. Deploying a separate Nginx, CDN, object-storage website, or other static file server is not required for v1.

Mandatory rules:

- Do not load JavaScript, CSS, fonts, icons, images, favicons, source maps, or other UI assets from CDNs or third-party origins.
- Do not use external font providers or externally hosted icon/image URLs.
- Keep required UI assets in the repository under `web/` and include them in the normal frontend build output.
- Release builds must embed the production frontend build output into the Go server binary.
- The deployed HTML, JavaScript bundles, CSS files, fonts, icons, and images must be same-origin from the browser's perspective.
- Runtime calls to the Certhub backend API are not UI assets and are governed by the API/auth specs.
- OIDC redirects to an identity provider are authentication flows, not UI asset loading; the Certhub UI itself still must not load visual or script assets from the identity provider.
- Production builds must not publish source maps by default. Source maps may exist only in explicit internal/debug builds.

Security considerations:

- Because the web UI and API are same-origin, frontend XSS can become authenticated API access while User tokens are present in `sessionStorage`.
- The UI must not render backend-provided or user-provided text as HTML. Avoid `dangerouslySetInnerHTML`; any future exception requires a documented sanitizer and test coverage.
- The UI must not use `eval`, dynamic script injection, remote scripts, remote styles, remote fonts, or remote images in production.
- The UI must never put User tokens, Application tokens, certificate material, private keys, DNS credentials, OIDC authorization codes, OIDC state, PKCE code verifiers, passwords, TOTP codes, or TOTP secrets in URLs, logs, telemetry, crash reports, or persistent browser storage.
- Client-side permission checks are only UX. Backend authorization and audit requirements remain authoritative for every action.

## Goals

- Show the current certificate inventory and issuance health.
- Let Users manage Applications when explicitly allowed.
- Let Users with `manager` grant create Application tokens and domain scopes for Applications they manage.
- Let Users with `manager` grant create Certificates for Applications they manage.
- Let authorized Users download certificate material for Applications they can access.
- Let admins perform all Certhub management work through the web interface without requiring CLI, Kubernetes operator, direct database access, or raw API calls.
- Let admins manage Users, Applications, issuers, DNS providers, DNS provider zones, and audit events.
- Let Users authenticate with password login or OIDC when enabled by backend configuration.
- Make certificate status, expiry, SANs, owning Application, and private-key access easy to inspect.
- Protect private-key access with explicit permission-aware UI.

## Non-Goals

- The frontend does not issue personal/User-owned certificates.
- The frontend does not call the Application-token `POST /v1/sync/certificates` runtime endpoint with a User access token; User-authenticated certificate creation uses the Application ID-based management endpoint.
- The frontend does not call Let's Encrypt, Cloudflare, or ArvanCloud directly.
- The frontend does not persist User access tokens, Application tokens, or private keys across browser restarts.
- The frontend does not provide personal access-token creation, listing, or revocation UI.
- The frontend does not expose raw DNS provider credentials after creation.
- The frontend does not expose first-bootstrap or emergency-recovery server-binary commands.
- The frontend does not call Application-token runtime certificate endpoints with a User login session.

## Input Validation

The frontend must validate user input before submitting forms so operators get fast feedback without waiting for a backend round trip. Backend validation remains authoritative and must still be handled on every API response.

Client-side validation rules:

- Validate fields on blur and before submit.
- Disable or block submit while a field has a known validation error.
- Show field-level errors next to the relevant control.
- Keep error messages consistent with backend validation concepts, such as invalid domain, invalid machine name, invalid issuer URL, invalid email, unsupported key type, invalid expiration, and duplicate/empty values.
- Revalidate dependent fields when related form state changes, such as Application selection changing which domain scopes are relevant.
- Do not use client-side validation to skip permission checks or backend validation.
- Do not send invalid requests merely to discover basic syntax errors the frontend can determine locally.
- Still display backend validation errors because backend rules are authoritative and may be stricter or newer than the deployed frontend.

The preferred implementation is to share validation definitions through generated API schemas or a small shared validation package. If validation logic is duplicated in TypeScript, tests must cover drift-prone formats.

Fields that must use backend-compatible machine validators include:

- Application machine names.
- Issuer names and ACME directory URLs.
- DNS provider names.
- DNS provider zones.
- Domain scope values.
- Application trusted source IP/CIDR values.
- Certificate domains.
- ACME account emails.
- User emails.
- OIDC link status. Raw OIDC issuer and subject values are internal provider-derived identifiers and must not be edited by admins.
- Token expiration timestamps.
- Key type and enum fields.

Human-facing fields such as display names, token names, descriptions, operator notes, and failure messages must use length limits and reject control characters, but they must not use machine-name validation.

Sensitive fields such as passwords, TOTP codes, Application tokens, and DNS provider credentials must be validated for required shape and length where possible, but the frontend must not log, persist, or send their raw values to telemetry.

## Users and Access

Primary human users:

- Platform operators.
- SRE/on-call engineers.
- Application owners.
- Security reviewers.

Access rules:

- A normal User has no Application access by default.
- A User must be explicitly granted access to each Application.
- Only Users with global role `admin` can create Applications.
- A User with global role `admin` has full access to every Application and all administrative views.
- User-to-Application grant roles are `viewer`, `certificate_reader`, and `manager`.

Grant role behavior:

- `viewer`: can inspect Application and certificate metadata.
- `certificate_reader`: can download certificate material, including private keys.
- `manager`: includes `certificate_reader` and can manage Application tokens, domain scopes, certificate lifecycle actions, and User grants.

## Authentication

The login screen supports:

- Username/password login through `POST /v1/auth/login` when password auth is enabled.
- OIDC Authorization Code with PKCE through `GET /v1/auth/oidc/login`, backend-handled `GET /v1/auth/oidc/callback`, and frontend exchange through `POST /v1/auth/oidc/handoff` when OIDC is enabled.

Rules:

- Password and OIDC login return a short-lived opaque User access token and fixed session expiry.
- The frontend must treat User access tokens as opaque strings and must not parse them as JWTs or depend on embedded claims.
- User access tokens have prefix `cth_uat_v1_`. The prefix is only a public token-class marker. The remainder is opaque.
- Password login supports Certhub-native TOTP 2FA when enabled or required by backend policy.
- When password login returns `password_2fa_setup_required`, the frontend must render the returned provisioning URI as a QR code, submit the setup token and TOTP code to `/v1/auth/password-2fa/login-setup/confirm`, and must not store session tokens until confirmation succeeds.
- OIDC login does not require Certhub-native 2FA and must not ask for a TOTP code.
- The login screen must show the OIDC sign-in control only when the same-origin runtime frontend config indicates OIDC login is enabled.
- The frontend must support TOTP setup, confirmation, and disable flows through `/v1/auth/password-2fa/*`.
- TOTP setup screens must render the backend `provisioning_uri` as a QR code and must require the User to enter a current TOTP code before setup is considered complete.
- Profile/Security must show password-2FA configuration only for logged-in Users with password login enabled. Passwordless Users and Application identities must not see password-2FA controls.
- When password 2FA is enabled but cannot be disabled because instance policy requires it, Profile/Security must omit the disable form and show a message explaining that password 2FA is required by instance policy.
- OIDC must use Certhub's backend-managed PKCE flow. The frontend must not implement implicit flow, hybrid flow, or direct provider token exchange.
- The frontend must never handle an OIDC client secret.
- The frontend must not store provider access tokens, ID tokens, authorization codes, OIDC handoff IDs, or PKCE code verifiers in persistent browser storage.
- After OIDC redirect, the frontend exchanges the handoff ID once with `POST /v1/auth/oidc/handoff`, stores only the returned Certhub tokens in `sessionStorage`, and removes the handoff ID from the URL and browser history.
- The frontend must store User access tokens in browser `sessionStorage`.
- The frontend must not store User access tokens in `localStorage`, IndexedDB, cookies, or persistent browser storage.
- Browser restart must drop the frontend's User login session because `sessionStorage` is not restored as durable application state.
- The frontend refreshes near-expired access tokens with `POST /v1/auth/refresh`.
- Refresh success replaces the access token in `sessionStorage`.
- Refresh failure clears session storage and returns the User to the login screen.
- Logout calls `POST /v1/auth/logout` and clears session storage.
- The frontend must not persist Application tokens, raw passwords, private keys, or DNS provider credentials in browser storage.
- Login errors use backend error codes. `invalid_credentials` must be displayed as a generic failed login, not as "unknown email" or "wrong password".
- `password_auth_disabled` hides or disables the password login form.
- `user_not_provisioned` tells the User to contact an admin.

## Application Structure

Main navigation:

- Certificates
- Applications
- Users
- Issuers
- DNS Providers
- Audit Events

The application must show only actions allowed by the current User's global role and per-Application grants.

## Management Coverage

The web interface must cover every management operation exposed by the backend's User-authenticated public API. A management workflow is complete only when the UI supports the relevant list, detail, create, update, delete, or action flow; mirrors backend validation for operator-entered fields; handles permission-specific states; and shows backend error and audit context.

No management task may require the CLI, Kubernetes operator, direct database access, or a raw API call when the backend exposes a User-authenticated management endpoint.

Required web management workflows:

- User authentication, logout, refresh, current identity display, and password-login TOTP self-service.
- User administration: list, create, inspect, update mutable fields, manage password availability, show OIDC link status, and administrative password-2FA provisioning or reset where backend policy allows it.
- Application administration: list, create, inspect, update mutable fields, disable/enable through status, and inspect related certificates and audit events.
- Application token management: list token metadata, create tokens, display raw token value exactly once, support expiring and non-expiring tokens, and revoke tokens.
- Application User grant management: list grants, create or replace grants, and remove grants.
- Domain scope management: list scopes, add immutable scopes, and delete scopes.
- Certificate management: create Application-owned certificates, list and inspect certificates, download current and version-specific ID-based archives when authorized, inspect events, renew, rotate key, reissue, and revoke specific CertificateVersions.
- Issuer management: list, create, inspect, update mutable fields, disable/enable through status, configure default issuer, renewal-window, and contact email.
- DNS provider management: list, create, inspect, update mutable metadata, replace write-only credentials, list zones, manually add/delete zones in manual mode, view discovered zones, and trigger auto-mode zone refresh.
- Audit management: list and filter global audit events for admins, scoped Application/certificate audit events for Users with relevant Application access, and certificate-specific events.

Runtime and support endpoints not treated as web management workflows:

- `certhub-server bootstrap ...` and `certhub-server migrate` are server-binary commands, not browser workflows or public HTTP APIs.
- `POST /v1/sync/certificates`, `POST /v1/sync/certificates/tls-material`, and `POST /v1/sync/certificates/tls-archive` are Application-token runtime endpoints. The web console may document or copy example calls, but it must not use a User login session to call them.
- `/healthz`, `/readyz`, and `/metrics` are service health/observability endpoints. The frontend may use `/readyz` for startup health checks, but these are not operator management workflows.

When the backend adds a new User-authenticated management endpoint, the frontend spec and UI must add the matching workflow before the feature is considered complete.

## Certificate Inventory

The Certificates view lists metadata only by default.

The Certificates view and each Application detail page must provide a create Certificate action when the current User has Application `manager` access or global `admin`.

Certificate creation form:

- Application selector when launched from the global Certificates view.
- Fixed Application context when launched from an Application detail page.
- Domains/SANs.
- Key type, defaulting to backend default when omitted.
- Issuer, optional and defaulting to backend default issuer behavior when omitted.

Creating a Certificate from the web UI calls `POST /v1/applications/{application_id}/certificates`. The UI must not call `POST /v1/sync/certificates`.

Certificate creation rules:

- The created Certificate is owned by the selected Application.
- The current User must have Application `manager` access or global `admin`.
- The selected Application's domain scopes must cover every requested SAN.
- The UI must validate domain syntax, wildcard syntax, duplicate SANs after normalization, key type, and optional issuer name before submit.
- When Application domain scopes are loaded, the UI should warn before submit when requested SANs appear uncovered by the selected Application. Backend authorization remains authoritative.
- The UI should show uncovered SANs from `domain_not_authorized` error details when available.
- A successful create response returns Certificate metadata only; the UI should navigate to the Certificate detail page or show it in the Application's certificate list.
- If issuance is pending, the UI should show pending status and allow metadata refresh. It should not poll criteria-based material endpoints.

Columns:

- Status.
- Domains / SAN summary.
- Key type.
- Issuer.
- Application.
- Not after.
- Renewal state.
- Last event.

Filters:

- Domain.
- Status.
- Application.
- Issuer.
- Expiry before.
- Key type.

Certificate detail page:

- Full SAN list.
- Certificate identity options.
- Owning Application.
- Validity window.
- Serial number.
- SHA-256 fingerprint.
- Latest valid version.
- Latest issuance status.
- Renewal history.
- Version history.
- Audit events for this certificate.
- Archive download button only when the User has `certificate_reader`, `manager`, or global `admin`.
- Metadata-only Users can inspect certificate metadata but cannot download archives in v1 because current archive endpoints include private-key material.

Current certificate archive downloads from the web UI must call `GET /v1/certificates/{certificate_id}/tls-archive`. Version-specific archive downloads must call `GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/tls-archive` and be offered for downloadable `valid` or `revoked` CertificateVersions. The frontend must not use criteria-based material endpoints for User/browser downloads. Every archive download is a private-key-capable operation and must require an explicit audited user action.

Certificate renewal and version history must call `GET /v1/certificates/{certificate_id}/versions`. The frontend must not try to reconstruct complete version history from the single `latest_version` field.

Browser downloads of the tar.gz archive must use the backend `Content-Disposition` filename, which must be `<safe_certificate_name>.tar.gz`. The `<safe_certificate_name>` basename is derived by the backend from the first normalized SAN, falls back to Certificate ID, and must not contain `*` or `.`.

Certificate lifecycle actions:

- Manual renew calls `POST /v1/certificates/{certificate_id}/renew`.
- Key rotation calls `POST /v1/certificates/{certificate_id}/rotate-key`.
- Renew and key rotation buttons are disabled when `has_active_valid_version=false`.
- Reissue calls `POST /v1/certificates/{certificate_id}/reissue` when no active valid CertificateVersion exists and no CertificateVersion is issuing.
- Reissue is disabled when `has_active_valid_version=true` or `has_issuing_version=true`.
- Revocation calls `POST /v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke`.
- Certificate-specific event history calls `GET /v1/certificates/{certificate_id}/events`.

Lifecycle actions are visible only to Users with Application `manager` access or global `admin`.

When the frontend already has a `material_etag` for a certificate detail view, it may send `If-None-Match` to the ID-based archive endpoint. A `304 Not Modified` response means the current detail/download material has not changed. The frontend must not rely on browser or proxy caching for private-key material; backend responses use `Cache-Control: no-store`.

If a current download endpoint returns `409 certificate_no_active_version`, the frontend must not offer stale current archives. It should show the latest version state and the reissue action when the User has `manager` access or global `admin`.

If manual renew returns `409 renewal_overlap_exists`, the frontend must show that another valid renewal overlap already exists and must not retry automatically. The User can retry after the older valid CertificateVersion expires.

Revocation UX:

- Revoke actions must explain that current material endpoints stop serving that CertificateVersion immediately after backend acceptance, while other active valid versions may remain current.
- Revoke actions must require a reason from the backend enum and support an optional note.

Private-key access must require an explicit click and show that the action is audited. The key must not be rendered automatically on page load.

## Applications

Application list:

- Name.
- Status.
- User's role on the Application.
- Domain scope count.
- Token count.
- Trusted source CIDR count.
- Certificate count.
- Last used.
- Created at.

Application detail:

- Metadata.
- Edit mutable fields: display name, description, status, and trusted source CIDRs.
- User grants.
- Tokens.
- Domain scopes.
- Trusted source CIDRs.
- Create Certificate action when the User has `manager` access or global `admin`.
- Certificates created.
- Certificates consumed.
- Audit events.

Application token creation must show the token value once. Token values must never be displayed again.

Application tokens have no roles or permissions. They authenticate the Application, and certificate creation/reuse is controlled by the Application's domain scopes. If the Application has trusted source CIDRs configured, the backend also requires Application-token requests to come from one of those effective source IP ranges.

Application creation is visible only to Users with global role `admin`.

Application `name` is treated as immutable in the UI after creation. The UI uses `PATCH /v1/applications/{application_id}` only for mutable fields supported by the backend.

Reserved Application rules:

- The reserved Application `certhub_server` represents Certhub's own HTTPS serving certificate.
- Show `certhub_server` with a clear system/reserved and config-managed indicator.
- Only global admins can view `certhub_server`.
- Do not show create-token, revoke-token, grant-management, domain-scope edit, Certificate creation, lifecycle, disable, rename, update, or delete controls for `certhub_server`.
- Show its public hostname/domain scope and single serving Certificate as read-only state reconciled from server process configuration.
- Explain in operator-facing copy that changes require updating backend process configuration (`server.public_hostname`, `self_certificate.issuer`, or `self_certificate.key_type`) and restarting the backend process.
- If the backend returns `409 system_managed_resource`, render it as expected read-only/config-managed behavior, not as an unexpected failure.

Application trusted source CIDR workflows:

- Show whether the Application has no source-IP restriction or a configured CIDR list.
- Let Users with `manager` access or global `admin` replace the full CIDR list through the Application update endpoint.
- Accept exact IPv4/IPv6 addresses and CIDR values in the UI, but show the backend-normalized CIDR values after save.
- Reject malformed IP/CIDR values client-side before submit.
- Explain in field help that trusted source CIDRs do not replace the Application token; the client must still send the token.

Application token workflows:

- List token metadata without raw token values.
- Create a token with a human token name and optional expiration.
- Support explicit non-expiring tokens by sending nullable expiration according to backend API rules.
- Display the raw token value only in the creation success screen.
- Revoke tokens with `DELETE /v1/applications/{application_id}/tokens/{token_id}`.
- Hide token management for the reserved `certhub_server` Application because server self-certificate sync does not use Application tokens.

The UI must never store raw Application tokens in persistent browser storage.

## Application User Grants

Grant form:

- Application.
- User email lookup.
- Grant role: `viewer`, `certificate_reader`, or `manager`.

Rules:

- Users with `manager` access can manage grants for that Application.
- Users with global role `admin` can manage grants for every Application.
- Non-admin managers resolve target Users by exact email using `GET /v1/users/lookup?email=...&application_id=...`; they must not need global User list access.
- Creating or changing a grant uses replace semantics through `PUT /v1/applications/{application_id}/users/{user_id}`.
- Removing a grant immediately removes that User's access to Application-owned certificates.
- Hide grant management for the reserved `certhub_server` Application because v1 allows only global admin access to it.

## Domain Scopes

Domain scopes belong to Applications only.

Domain scope form:

- Application.
- Value.
- Derived kind display: `exact` or `wildcard`.

Examples shown in form help:

- `torob.io` for exact.
- `*.torob.dev` for one-label wildcard authorization.
- `*.b.torob.dev` for one-label wildcard authorization at a deeper level.

The UI must not submit a separate scope type. It submits only `value` and displays the backend-derived kind.

Created domain scope records are immutable. The UI must model changes as remove old scope plus add new scope, not inline edit.

The UI must reject wildcard values where `*` is not the full left-most label, such as `*.*.torob.dev`, `a.*.torob.dev`, and `api.*.torob.dev`.

Authorization edge cases shown in validation/help:

- Exact scope `torob.dev` authorizes only `torob.dev`.
- Exact scope `api.torob.dev` does not authorize `*.torob.dev`.
- Wildcard scope `*.torob.dev` authorizes `api.torob.dev` and `*.torob.dev`, but not `torob.dev`, `a.b.torob.dev`, or `*.b.torob.dev`.
- Public-suffix boundary scopes such as `*.com` and `*.co.uk` are rejected.

## Users Management

User list:

- Display name.
- Email or login.
- Global role.
- Status.
- Application grant count.
- Last login.

User detail:

- Metadata.
- Global role.
- Status.
- Password login availability.
- Password replacement/removal controls for admins.
- Password 2FA status and administrative provisioning/reset controls where backend policy allows them.
- OIDC link status.
- Application grants.
- Private-key access audit events.
- Administrative audit events.

Users do not have domain scopes directly assigned to them.
Users do not have personal access tokens in v1.

User creation and update forms:

- Admin-only in v1.
- Must support email, display name, global role, and status.
- May set an initial password when password authentication is enabled.
- May create a passwordless User when OIDC is enabled so the backend can link the User by verified email during first OIDC login.
- May provision password-login TOTP when required by backend policy. The provisioning URI is shown only once and must not be persisted.
- Must not expose controls to set, replace, or clear OIDC issuer or subject.
- Must not expose or manage User personal tokens.

## Issuers

Issuer list:

- Name.
- Type.
- ACME directory URL.
- Environment.
- Status.
- Default flag.
- Renewal window.

Common issuer examples:

- `letsencrypt_production`
- `letsencrypt_staging`

Issuer management:

- Admin-only in v1.
- Issuer creation must support `name`, `type=acme`, `directory_url`, `environment`, `default`, `status`, `renewal_window_seconds`, and contact email.
- Certhub creates or reuses the ACME account during issuer creation; the UI does not manage ACME accounts directly.
- The UI must show the default issuer constraint: at most one active issuer can be default.
- The UI must show that omitted-issuer certificate requests require exactly one active default issuer.
- The UI must expose issuer detail and edit workflows for mutable fields: default issuer, status, renewal window, and contact email. Immutable fields such as name, type, directory URL, and environment must be shown as read-only after creation.

## DNS Providers

DNS provider list:

- Name.
- Type.
- Zone mode.
- Zones.
- Discovered zones.
- Status.
- Last zone refresh.

Supported v1 provider types:

- Cloudflare.
- ArvanCloud.

Provider credentials must be write-only. The UI can allow replacement but must not display existing secrets.

DNS provider detail page:

- Shows configured `zone_mode`: `auto` or `manual`.
- Allows admins to update mutable provider metadata and status.
- Allows admins to replace credentials without showing existing credentials.
- Shows zones used for DNS-01 provider selection.
- Shows discovered zones when the provider supports zone discovery.
- Allows admins to trigger zone refresh in `auto` mode.
- Disables manual zone add/remove controls in `auto` mode.
- Allows admins to add or remove zones in `manual` mode.
- Allows admins to add a discovered zone as a manual zone when `zone_mode=manual`.

Zone mode behavior:

- `auto`: Certhub syncs available zones from the provider API and users cannot edit the zone list.
- `manual`: admins specify zones manually; discovered zones are suggestions only. Zone records are immutable, so the UI must model a user-facing update as remove old zone plus add new zone.
- The UI must show discovery failures without exposing credentials.

## Audit Events

Audit event list:

- Timestamp.
- Identity.
- Identity type.
- Action.
- Target.
- Result.
- Source IP or client metadata when available.
- Raw backend IDs, correlation IDs, request IDs, and audit metadata must not be shown as expandable technical detail panels.

Filters:

- Identity.
- Identity type.
- Action.
- Target certificate.
- Target User.
- Target Application.
- Result.
- Date range.

List filters must use typed controls where values are known, show active filter chips, and keep advanced filters in a compact expandable area rather than a generic raw field form.

Private-key read events must be easy to filter.

## Observability

The frontend should:

- Generate or propagate a correlation ID for backend requests when the backend supports it.
- Include backend error code in user-visible support details.
- Record client-side route errors and API failures in the browser telemetry system if one is configured.
- Never send private keys, raw tokens, passwords, DNS provider credentials, or certificate material to frontend telemetry.

## API Integration

The frontend calls the backend API only.

Required backend endpoints used directly by the frontend or as browser authentication-flow redirects:

- `GET /readyz`

Authentication and current identity:

- `POST /v1/auth/login`
- `POST /v1/auth/password-2fa/setup`
- `POST /v1/auth/password-2fa/confirm`
- `DELETE /v1/auth/password-2fa`
- `GET /v1/auth/oidc/login`
- `GET /v1/auth/oidc/callback`
- `POST /v1/auth/oidc/handoff`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`
- `GET /v1/auth/me`

Certificate inventory, archive downloads, and lifecycle management:

- `POST /v1/applications/{application_id}/certificates`
- `GET /v1/certificates`
- `GET /v1/certificates/{certificate_id}`
- `GET /v1/certificates/{certificate_id}/versions`
- `GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/tls-archive`
- `POST /v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke`
- `GET /v1/certificates/{certificate_id}/tls-archive`
- `POST /v1/certificates/{certificate_id}/renew`
- `POST /v1/certificates/{certificate_id}/rotate-key`
- `POST /v1/certificates/{certificate_id}/reissue`
- `GET /v1/certificates/{certificate_id}/events`

User administration:

- `GET /v1/users`
- `GET /v1/users/lookup`
- `POST /v1/users` to generate a one-time invite link
- `GET /v1/auth/user-invites/{invite_token}`
- `POST /v1/auth/user-invites/{invite_token}/signup`
- `POST /v1/auth/user-invites/{invite_token}/signup/confirm-2fa`
- `GET /v1/auth/password-resets/{reset_token}`
- `POST /v1/auth/password-resets/{reset_token}`
- `GET /v1/users/{user_id}`
- `PATCH /v1/users/{user_id}`
- `POST /v1/users/{user_id}/password-reset-link`
- `DELETE /v1/users/{user_id}/password-2fa`

Application administration:

- `GET /v1/applications`
- `POST /v1/applications`
- `GET /v1/applications/{application_id}`
- `PATCH /v1/applications/{application_id}`

Application token management:

- `POST /v1/applications/{application_id}/tokens`
- `GET /v1/applications/{application_id}/tokens`
- `DELETE /v1/applications/{application_id}/tokens/{token_id}`

Domain scope management:

- `POST /v1/applications/{application_id}/domain-scopes`
- `GET /v1/applications/{application_id}/domain-scopes`
- `DELETE /v1/applications/{application_id}/domain-scopes/{scope_id}`

Application User grant management:

- `GET /v1/applications/{application_id}/users`
- `PUT /v1/applications/{application_id}/users/{user_id}`
- `DELETE /v1/applications/{application_id}/users/{user_id}`

Issuer management:

- `GET /v1/issuers`
- `POST /v1/issuers`
- `GET /v1/issuers/{issuer_id}`
- `PATCH /v1/issuers/{issuer_id}`

DNS provider management:

- `GET /v1/dns-providers`
- `POST /v1/dns-providers`
- `GET /v1/dns-providers/{dns_provider_id}`
- `PATCH /v1/dns-providers/{dns_provider_id}`
- `GET /v1/dns-providers/{dns_provider_id}/zones`
- `POST /v1/dns-providers/{dns_provider_id}/zones`
- `DELETE /v1/dns-providers/{dns_provider_id}/zones/{zone_id}`

DNS provider zone discovery and refresh:

- `GET /v1/dns-providers/{dns_provider_id}/zones/discovered`
- `POST /v1/dns-providers/{dns_provider_id}/zones/refresh`

Audit:

- `GET /v1/audit-events`

Application-token local material sync endpoints are intentionally not part of browser management:

- `POST /v1/sync/certificates`
- `POST /v1/sync/certificates/tls-material`
- `POST /v1/sync/certificates/tls-archive`

## Error UX

The frontend must handle backend errors using the standard JSON envelope:

```json
{
  "error": {
    "code": "certificate_not_ready",
    "message": "Certificate is not ready",
    "retryable": true,
    "retry_after_seconds": 10,
    "details": {}
  }
}
```

Rules:

- Branch UI behavior on `error.code`, not on message text.
- Show `error.message` only when it is safe for the current context.
- Use `error.details` for field-level hints, such as uncovered SANs, when present.
- If `retryable=true`, show pending state and retry only when the workflow expects polling.
- If `Retry-After` or `retry_after_seconds` is present, use it instead of a hard-coded retry delay.
- Do not display secrets, raw credential payloads, raw tokens, or private key material from any error details.

## Permissions UX

The frontend must handle these cases:

- User has no Application access and sees no Application-owned certificates.
- User has `viewer` access and can inspect metadata but cannot download private keys.
- User has `certificate_reader` access and can download private keys with an audited explicit action.
- User has `manager` access, includes `certificate_reader`, can download private keys with an audited explicit action, and can manage Application tokens, scopes, grants, and lifecycle actions.
- User has global `admin` and can access every Application.
- User can inspect audit events without downloading certificate material when audit permissions allow it.
- Non-admin User can inspect scoped audit events only for Applications and Certificates they can access; global audit views are hidden unless the User is admin.

Forbidden actions should be hidden when possible and shown disabled only when helpful for understanding permissions.

## Tests

Required frontend scenarios:

- Every User-authenticated management endpoint listed in `API Integration` has a reachable web workflow or an explicit test that the workflow is intentionally hidden by permissions.
- User with no Application grants sees no Application certificates.
- User with `viewer` access can inspect metadata but cannot access private-key actions.
- User with `certificate_reader` access can explicitly download private keys.
- User with `manager` access can create a Certificate for an Application when every SAN is covered by the Application's domain scopes.
- User with `manager` access can resolve target Users by exact email for grant workflows without global User list access.
- User with `viewer` or `certificate_reader` access cannot create Certificates for an Application.
- Web certificate creation calls `POST /v1/applications/{application_id}/certificates`, never Application-token `POST /v1/sync/certificates`.
- Tar.gz certificate archive downloads use browser filename `<safe_certificate_name>.tar.gz`, and `<safe_certificate_name>` contains no `*` or `.`.
- User with `manager` access can create an Application token and sees the token once.
- User with `manager` access can list and revoke Application tokens, add/delete domain scopes, and create/replace/remove Application User grants.
- Non-admin User cannot create Applications.
- Admin can create Applications and update mutable Application fields.
- Admin can generate User invite links from email and selected global role, update mutable User fields, configure password availability for existing Users, and inspect OIDC link status without setting, replacing, or clearing the link fields.
- Invited Users can open `/signup?invite=...` without an existing session, review the invited email/role, enter display name, set password, and complete signup.
- If forced password 2FA is configured, invite signup shows a QR code for the TOTP provisioning URI and blocks completion until the User enters a valid current TOTP code.
- Invite links are not stored in browser persistent storage and cannot be reused after successful signup.
- Renewal, key rotation, and reissue create a higher-numbered certificate version shown in certificate detail.
- Admin can view and manage all Applications.
- Admin can create, inspect, update mutable issuer fields, disable issuers through status, and sees the default issuer uniqueness constraint.
- Admin can create DNS providers, replace credentials without reading old credentials, update mutable provider metadata, and manage provider status.
- Failed backend action displays backend error code and message.
- Forms validate user input client-side before submit and show field-level errors for invalid machine names, domains, wildcard domains, emails, URLs, enum values, duplicate SANs, invalid token expirations, and control characters in human text.
- Backend validation errors still render correctly when server-side validation rejects an input the frontend allowed.
- Login supports password and conditionally enabled OIDC modes and handles `invalid_credentials`, `password_auth_disabled`, and `user_not_provisioned`.
- Password login supports TOTP 2FA and handles `password_2fa_required`, `password_2fa_setup_required`, and `invalid_2fa_code`; OIDC login does not show TOTP prompts.
- Admin User edit uses separate controls for generating password reset links and disabling password 2FA; it does not send plaintext passwords or TOTP provisioning flags through the User patch endpoint.
- Public `/reset-password?token=...` previews the reset target and completes a one-time password reset without requiring an existing session.
- Profile/Security conditionally shows password-2FA setup, disable, or required-by-policy status from `/v1/auth/me` identity capability fields.
- OIDC login uses Authorization Code with PKCE only and never uses implicit flow or client secrets.
- Login stores the access token only in `sessionStorage`; refresh rotates that value; logout clears them.
- Access tokens and OIDC authorization codes are never written to URLs, `localStorage`, `IndexedDB`, cookies, persisted React Query caches, telemetry payloads, or browser console output.
- Login, OIDC handoff, refresh, and logout tests verify token-like query parameters are removed from the address bar and browser history state after handling.
- API clients attach User bearer tokens only to same-origin Certhub API requests and never to embedded static assets, OIDC provider URLs, downloaded files, or third-party origins.
- API client redirect tests verify bearer tokens are not forwarded when a request is redirected to a different origin or scheme.
- Refresh failure, logout, browser tab close, and session-expired handling clear in-memory query caches that may contain identity-specific or private-key metadata.
- After implementation, redeploy to `/tmp/certhub-compose-test` and use the exposed Tailscale HTTPS endpoint in a browser to verify admin invite generation, invite signup, QR-code 2FA validation, login after signup, and reused invite failure.
- Browser restart does not preserve the User login session.
- Production UI uses no external scripts, styles, fonts, icons, images, or source maps.
- Built production HTML, CSS, and JavaScript contain no `http://` or `https://` references to UI assets, font providers, icon providers, analytics scripts, or CDNs.
- UI tests or static checks cover no unsafe HTML rendering, no `dangerouslySetInnerHTML` without an approved sanitizer, no `eval`, no dynamic remote script loading, and no persistent token storage.
- XSS tests render hostile backend-controlled strings in domains, Application names, User display fields, issuer names, DNS provider names, audit metadata, validation errors, and upstream failure messages as inert text.
- XSS tests cover HTML-like values in table cells, filters, details pages, toasts, modals, form errors, download filenames, and empty-state/error-boundary views.
- Frontend error boundaries, API error displays, telemetry hooks, and console logging never include access tokens, Application tokens, private keys, certificate PEM, DNS provider credentials, passwords, TOTP codes, OIDC state, or authorization codes.
- Raw Application token creation displays the token exactly once, clears it on navigation/reload, and never writes it to browser storage, telemetry, or logs.
- Raw Application token creation cannot be redisplayed through browser back/forward navigation, route state restoration, or persisted component state.
- Reserved `certhub_server` UI tests show the system/reserved/config-managed indicator and hide token, grant, domain-scope edit, Certificate creation, lifecycle, disable, rename, update, and delete controls.
- Reserved `certhub_server` UI tests render the public hostname/domain scope and the single Certhub serving Certificate as read-only state, and render backend `409 system_managed_resource` responses as expected config-managed behavior.
- Private-key material is fetched only after an explicit User action, is not prefetched on detail-page load, and is cleared from component state when the download/view flow closes.
- Private-key download/view tests verify PEM material is not retained in React Query caches, route state, clipboard helpers, telemetry, error boundaries, or hidden DOM after the flow closes.
- Private-key download/view tests revoke temporary blob URLs and clear any explicit copy-to-clipboard state when the flow closes or the route changes.
- Permission-hidden actions are backed by tests that the UI does not call forbidden endpoints during normal flows and still handles backend `403` responses when a request is denied.
- Trusted source IP/CIDR forms validate exact IPv4/IPv6 and CIDR inputs client-side, reject malformed values before submit, and render backend-normalized values after save.
- No personal access-token management UI is shown.
- Domain scope validation explains exact versus wildcard edge cases, including that `*.torob.dev` does not authorize `torob.dev` or `a.b.torob.dev`.
- Version revoke flows require explicit reason selection and keep Certificate deletion unavailable.
- Retryable backend errors use `Retry-After` or `retry_after_seconds` when polling.
- Current material responses with `certificate_no_active_version` hide current download actions and show reissue guidance instead of stale material.
- DNS provider credential replacement never displays existing secret.
- DNS provider credential forms clear submitted secret values after success, cancellation, and backend validation failure without copying them into errors or telemetry.
- DNS provider auto mode shows refreshed zones, last refresh status, and disables manual zone edits.
- DNS provider manual mode lets admins add/delete zones manually and add discovered zones as zones; zone updates are represented as delete plus insert.
- Domain scope UI rejects invalid wildcard values such as `*.*.torob.dev`.
