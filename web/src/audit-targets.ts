// Options for the audit events page "Target type" filter.
// Each value must be a target_type that the server writes into audit_events
// (internal/*/service.go, audit.AppendEventParams.TargetType). The server
// accepts any well-formed value as a filter and returns an empty page for
// values that it never writes, so a wrong value here fails silently.
export const auditTargetTypeOptions: ReadonlyArray<readonly [value: string, label: string]> = [
  ["user", "User"],
  ["application", "Application"],
  ["certificate", "Certificate"],
  ["certificate_version", "Certificate version"],
  ["issuer", "Issuer"],
  ["dns_provider", "DNS provider"],
  ["domain_scope", "Domain scope"],
  ["application_token", "Application token"],
  ["application_access", "Application access"],
  ["user_session", "User session"]
];
