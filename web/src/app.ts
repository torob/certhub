import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Activity,
  AppWindow,
  BadgeCheck,
  Download,
  Globe2,
  Home,
  KeyRound,
  Lock,
  LogOut,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  Trash2,
  Users,
  X
} from "lucide-react";
import { createElement, useEffect, useMemo, useState } from "react";
import type { components } from "./api-types";

type ErrorBody = components["schemas"]["ErrorEnvelope"];
type Identity = components["schemas"]["UserIdentity"] | components["schemas"]["ApplicationIdentity"];

type Session = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt?: string;
  refreshExpiresAt?: string;
  identity?: Identity;
};

type APIResult<T> = {
  data?: T;
  error?: ErrorBody;
  status: number;
  requestID: string;
  retryAfter?: number;
};

const queryClient = new QueryClient();
const sessionKey = "certhub.session.v1";
const authExpiredEvent = "certhub-auth-expired";
const accessRefreshSkewMs = 60_000;
let refreshInFlight: Promise<boolean> | undefined;

const nav = [
  ["home", "Home", Home],
  ["certificates", "Certificates", BadgeCheck],
  ["applications", "Applications", AppWindow],
  ["users", "Users", Users],
  ["issuers", "Issuers", KeyRound],
  ["dns", "DNS Providers", Globe2],
  ["audit", "Audit Events", Activity]
] as const;
type NavID = (typeof nav)[number][0];
type RouteState = {
  page: NavID;
  create?: "certificate" | "application" | "user" | "issuer" | "dns";
  path: string;
  query: URLSearchParams;
};

const navPaths: Record<NavID, string> = {
  home: "/",
  certificates: "/certificates",
  applications: "/applications",
  users: "/users",
  issuers: "/issuers",
  dns: "/dns-providers",
  audit: "/audit"
};

function parseRoute(): RouteState {
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const query = url.searchParams;
  switch (path) {
    case "/":
      return { page: "home", path, query };
    case "/certificates":
      return { page: "certificates", path, query };
    case "/certificates/new":
      return { page: "certificates", create: "certificate", path, query };
    case "/applications":
      return { page: "applications", path, query };
    case "/applications/new":
      return { page: "applications", create: "application", path, query };
    case "/users":
      return { page: "users", path, query };
    case "/users/new":
      return { page: "users", create: "user", path, query };
    case "/issuers":
      return { page: "issuers", path, query };
    case "/issuers/new":
      return { page: "issuers", create: "issuer", path, query };
    case "/dns-providers":
      return { page: "dns", path, query };
    case "/dns-providers/new":
      return { page: "dns", create: "dns", path, query };
    case "/audit":
      return { page: "audit", path, query };
    default:
      return { page: "home", path: "/", query };
  }
}

function requestID() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function loadSession(): Session | undefined {
  const raw = sessionStorage.getItem(sessionKey);
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    sessionStorage.removeItem(sessionKey);
    return undefined;
  }
}

function saveSession(session?: Session) {
  if (!session) {
    sessionStorage.removeItem(sessionKey);
    return;
  }
  sessionStorage.setItem(sessionKey, JSON.stringify(session));
}

function clearSession(notify = false) {
  saveSession(undefined);
  queryClient.clear();
  if (notify) window.dispatchEvent(new Event(authExpiredEvent));
}

function clientError(message: string, retryable = false): APIResult<never> {
  return {
    status: 0,
    requestID: requestID(),
    error: { code: "invalid_request", message, retryable }
  };
}

function authExpiredResult(requestID: string): APIResult<never> {
  return {
    status: 401,
    requestID,
    error: { code: "session_expired", message: "session expired", retryable: false }
  };
}

function parseExpiresAt(value?: string): number | undefined {
  if (!value) return undefined;
  const expiresAt = Date.parse(value);
  return Number.isFinite(expiresAt) ? expiresAt : undefined;
}

function shouldRefreshAccess(session: Session): boolean {
  const expiresAt = parseExpiresAt(session.accessExpiresAt);
  return expiresAt !== undefined && expiresAt <= Date.now() + accessRefreshSkewMs;
}

function isRefreshableRequest(pathname: string): boolean {
  return ![
    "/v1/auth/login",
    "/v1/auth/logout",
    "/v1/auth/refresh",
    "/v1/auth/oidc/handoff"
  ].includes(pathname);
}

function copyLatestTokens(session: Session) {
  const latest = loadSession();
  if (!latest?.accessToken || !latest.refreshToken) return;
  session.accessToken = latest.accessToken;
  session.refreshToken = latest.refreshToken;
  session.accessExpiresAt = latest.accessExpiresAt;
  session.refreshExpiresAt = latest.refreshExpiresAt;
}

async function performRefreshSession(session: Session): Promise<boolean> {
  if (!session.refreshToken) return false;
  const result = await api<{
    access_token: string;
    access_expires_at?: string;
    refresh_token: string;
    refresh_expires_at?: string;
  }>("/v1/auth/refresh", undefined, {
    method: "POST",
    body: JSON.stringify({ refresh_token: session.refreshToken })
  }, false);
  if (!result.data) {
    clearSession(true);
    return false;
  }
  session.accessToken = result.data.access_token;
  session.refreshToken = result.data.refresh_token;
  session.accessExpiresAt = result.data.access_expires_at;
  session.refreshExpiresAt = result.data.refresh_expires_at;
  saveSession(session);
  return true;
}

async function refreshSession(session: Session): Promise<boolean> {
  if (!session.refreshToken) return false;
  if (!refreshInFlight) {
    refreshInFlight = performRefreshSession(session).finally(() => {
      refreshInFlight = undefined;
    });
  }
  try {
    const refreshed = await refreshInFlight;
    if (refreshed) copyLatestTokens(session);
    return refreshed;
  } catch {
    clearSession(true);
    return false;
  }
}

async function api<T>(path: string, session: Session | undefined, init: RequestInit = {}, allowRefresh = true): Promise<APIResult<T>> {
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin) return clientError("cross-origin API requests are blocked");
  const rid = requestID();
  const requestPath = `${url.pathname}${url.search}`;
  const canRefresh = Boolean(allowRefresh && session?.refreshToken && isRefreshableRequest(url.pathname));
  if (canRefresh && session && shouldRefreshAccess(session)) {
    const refreshed = await refreshSession(session);
    if (!refreshed) return authExpiredResult(rid);
  }
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  headers.set("X-Request-ID", rid);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (session?.accessToken) headers.set("Authorization", `Bearer ${session.accessToken}`);
  let response: Response;
  try {
    response = await fetch(requestPath, { ...init, headers, cache: "no-store", redirect: "error" });
  } catch (err) {
    return clientError(`network error: ${(err as Error).message}`, true);
  }
  if (response.status === 401 && canRefresh && session) {
    const refreshed = await refreshSession(session);
    if (refreshed) return api<T>(path, session, init, false);
  }
  const requestHeader = response.headers.get("X-Request-ID") || rid;
  const retryAfter = Number(response.headers.get("Retry-After") || "0") || undefined;
  if (response.status === 401 && session?.accessToken) clearSession(true);
  if (response.status === 204 || response.status === 304) {
    return { status: response.status, requestID: requestHeader, retryAfter };
  }
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : undefined;
  if (!response.ok) return { status: response.status, requestID: requestHeader, retryAfter, error: parsed?.error || parsed };
  return { status: response.status, requestID: requestHeader, retryAfter, data: parsed };
}

function useAsync<T>(session: Session | undefined, path: string, deps: unknown[] = []) {
  const [state, setState] = useState<APIResult<T> & { loading: boolean }>({ status: 0, requestID: "", loading: true });
  useEffect(() => {
    let canceled = false;
    if (!path) {
      setState({ status: 0, requestID: "", loading: false });
      return () => {
        canceled = true;
      };
    }
    setState((s) => ({ ...s, loading: true }));
    api<T>(path, session)
      .then((result) => !canceled && setState({ ...result, loading: false }))
      .catch((err: Error) => !canceled && setState({ ...clientError(`network error: ${err.message}`, true), loading: false }));
    return () => {
      canceled = true;
    };
  }, deps);
  return state;
}

function AppShell() {
  const [session, setSession] = useState<Session | undefined>(() => loadSession());
  const [route, setRoute] = useState<RouteState>(() => parseRoute());
  const [notice, setNotice] = useState("");
  const visibleNav = isAdmin(session) ? nav : nav.filter(([id]) => id === "home" || id === "certificates" || id === "applications");
  const navigate = (to: string, replace = false) => {
    if (to !== `${window.location.pathname}${window.location.search}`) {
      window.history[replace ? "replaceState" : "pushState"]({}, "", to);
    }
    setRoute(parseRoute());
  };

  useEffect(() => {
    const listener = () => setSession(undefined);
    window.addEventListener(authExpiredEvent, listener);
    return () => window.removeEventListener(authExpiredEvent, listener);
  }, []);

  useEffect(() => {
    const listener = () => setRoute(parseRoute());
    window.addEventListener("popstate", listener);
    return () => window.removeEventListener("popstate", listener);
  }, []);

  useEffect(() => {
    if (!session?.refreshToken) return;
    const expiresAt = parseExpiresAt(session.accessExpiresAt);
    if (expiresAt === undefined) return;
    let canceled = false;
    const timeout = window.setTimeout(() => {
      refreshSession(session).then((refreshed) => {
        if (canceled) return;
        if (!refreshed) return;
        const latest = loadSession();
        if (latest?.accessToken) setSession(latest);
      });
    }, Math.max(0, expiresAt - Date.now() - accessRefreshSkewMs));
    return () => {
      canceled = true;
      window.clearTimeout(timeout);
    };
  }, [session?.accessExpiresAt, session?.accessToken, session?.refreshToken]);

  useEffect(() => {
    if (!session?.accessToken) return;
    api<{ identity: Identity }>("/v1/auth/me", session).then((result) => {
      if (result.data?.identity) {
        const next = { ...session, identity: result.data.identity };
        saveSession(next);
        setSession(next);
      }
      if (result.status === 401 || result.status === 403) {
        saveSession(undefined);
        setSession(undefined);
      }
    });
  }, [session?.accessToken]);

  useEffect(() => {
    const url = new URL(window.location.href);
    const handoff = url.searchParams.get("handoff_id") || url.searchParams.get("handoff");
    if (!handoff) return;
    url.search = "";
    window.history.replaceState({}, "", url);
    api<{ access_token: string; access_expires_at?: string; refresh_token: string; refresh_expires_at?: string }>("/v1/auth/oidc/handoff", undefined, {
      method: "POST",
      body: JSON.stringify({ handoff_id: handoff })
    }).then((result) => {
      if (result.data) {
        const next = { accessToken: result.data.access_token, refreshToken: result.data.refresh_token, accessExpiresAt: result.data.access_expires_at, refreshExpiresAt: result.data.refresh_expires_at };
        saveSession(next);
        setSession(next);
      } else {
        setNotice(errorText(result));
      }
    });
  }, []);

  useEffect(() => {
    if (!visibleNav.some(([id]) => id === route.page)) navigate("/", true);
  }, [session?.identity, route.page]);

  if (!session?.accessToken) {
    return createElement(Login, { onLogin: setSession, notice });
  }

  const Page = route.create === "certificate" ? CertificateCreatePage :
    route.create === "application" ? ApplicationCreatePage :
    route.create === "user" ? UserCreatePage :
    route.create === "issuer" ? IssuerCreatePage :
    route.create === "dns" ? DNSCreatePage : {
      home: HomePage,
      certificates: CertificatesPage,
      applications: ApplicationsPage,
      users: UsersPage,
      issuers: IssuersPage,
      dns: DNSPage,
      audit: AuditPage
    }[route.page];

  return createElement(
    "div",
    { className: "app-shell" },
    createElement(
      "aside",
      { className: "sidebar" },
      createElement("div", { className: "brand" }, createElement(ShieldCheck, { size: 24 }), createElement("strong", null, "Certhub")),
      createElement(
        "nav",
        null,
        visibleNav.map(([id, label, Icon]) =>
          createElement(
            "button",
            { key: id, className: id === route.page ? "nav active" : "nav", onClick: () => navigate(navPaths[id]), title: label },
            createElement(Icon, { size: 18 }),
            createElement("span", null, label)
          )
        )
      ),
      createElement("div", { className: "identity" }, identityText(session.identity)),
      createElement(AccountSecurity, { session, setNotice }),
      createElement(
        "button",
        {
          className: "nav",
          onClick: async () => {
            await api("/v1/auth/logout", session, { method: "POST" });
            clearSession();
            setSession(undefined);
          }
        },
        createElement(LogOut, { size: 18 }),
        createElement("span", null, "Logout")
      )
    ),
    createElement("main", { className: "workspace" }, createElement(Page, { session, setNotice, navigate, route }), notice ? createElement("div", { className: "toast" }, notice) : null)
  );
}

function Login(props: { onLogin: (s: Session) => void; notice: string }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState(props.notice);
  async function submit() {
    const result = await api<{ access_token: string; access_expires_at?: string; refresh_token: string; refresh_expires_at?: string }>("/v1/auth/login", undefined, {
      method: "POST",
      body: JSON.stringify({ email, password, totp_code: totp || undefined })
    });
    if (result.data) {
      const session = { accessToken: result.data.access_token, refreshToken: result.data.refresh_token, accessExpiresAt: result.data.access_expires_at, refreshExpiresAt: result.data.refresh_expires_at };
      saveSession(session);
      props.onLogin(session);
    } else setError(errorText(result));
  }
  return createElement(
    "main",
    { className: "login" },
    createElement("section", { className: "login-panel" },
      createElement("div", { className: "brand large" }, createElement(ShieldCheck, { size: 30 }), createElement("strong", null, "Certhub")),
      input("Email", email, setEmail, "email"),
      input("Password", password, setPassword, "password"),
      input("TOTP code", totp, setTotp, "text"),
      createElement("button", { className: "primary", onClick: submit }, createElement(Lock, { size: 16 }), "Sign in"),
      createElement("button", { className: "secondary", onClick: () => (window.location.href = "/v1/auth/oidc/login") }, "OIDC sign in"),
      error ? createElement("p", { className: "error" }, error) : null
    )
  );
}

function AccountSecurity(props: { session: Session; setNotice: (s: string) => void }) {
  const [open, setOpen] = useState(false);
  const [provisioning, setProvisioning] = useState<any>(undefined);
  const [totp, setTotp] = useState("");
  const [password, setPassword] = useState("");
  if (!open) {
    return createElement("button", { className: "nav compact", onClick: () => setOpen(true) }, createElement(Lock, { size: 16 }), createElement("span", null, "2FA"));
  }
  return createElement("section", { className: "security-panel" },
    createElement("div", { className: "security-head" },
      createElement("strong", null, "Password 2FA"),
      createElement("button", { type: "button", onClick: () => setOpen(false), title: "Close" }, "x")
    ),
    provisioning ? createElement("div", { className: "secret-once" },
      kv("Issuer", provisioning.issuer),
      kv("Account", provisioning.account_label),
      kv("Secret", provisioning.secret),
      kv("Provisioning URI", provisioning.provisioning_uri)
    ) : null,
    provisioning ? input("TOTP code", totp, setTotp) : null,
    provisioning ? createElement("button", {
      className: "primary",
      onClick: async () => {
        const result = await api("/v1/auth/password-2fa/confirm", props.session, { method: "POST", body: JSON.stringify({ totp_code: totp }) });
        props.setNotice(errorOrOK(result));
        if (!result.error) {
          setProvisioning(undefined);
          setTotp("");
        }
      }
    }, "Confirm") : createElement("button", {
      onClick: async () => {
        const result = await api<any>("/v1/auth/password-2fa/setup", props.session, { method: "POST" });
        if (result.data) {
          setProvisioning(result.data);
          props.setNotice("scan or save the provisioning secret now; it is not stored by the UI");
        } else props.setNotice(errorText(result));
      }
    }, "Set up"),
    input("Password for disable", password, setPassword, "password"),
    input("TOTP for disable", totp, setTotp),
    createElement("button", {
      onClick: async () => {
        const result = await api("/v1/auth/password-2fa", props.session, { method: "DELETE", body: JSON.stringify(emptyToUndefined({ password, totp_code: totp })) });
        props.setNotice(errorOrOK(result));
        if (!result.error) {
          setProvisioning(undefined);
          setTotp("");
          setPassword("");
        }
      }
    }, "Disable")
  );
}

function HomePage(props: PageProps) {
  const ready = useAsync<{ ready: boolean; checks: { name: string; status: string }[] }>(props.session, "/readyz", []);
  const applications = useAsync<{ applications: any[] }>(props.session, "/v1/applications?limit=100", []);
  const certificates = useAsync<{ certificates: any[] }>(props.session, "/v1/certificates?limit=100", []);
  const issuers = useAsync<{ issuers: any[] }>(props.session, "/v1/issuers?limit=100", []);
  const providers = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", []);
  const firstProvider = rowsOf(providers)[0];
  const zones = useAsync<{ zones: any[] }>(props.session, isAdmin(props.session) && firstProvider ? `/v1/dns-providers/${firstProvider.id}/zones?limit=100` : "", [firstProvider?.id]);
  const apps = rowsOf(applications).filter((app) => app.system_kind !== "certhub_server" && app.name !== "certhub_server");
  const manageableApps = apps.filter((app) => canManageApplication(app, props.session));
  const certs = rowsOf(certificates);
  const issuing = certs.filter((cert) => ["pending", "validating_dns", "issuing", "renewing", "rotating_key"].includes(cert.status));
  const expiring = certs.filter((cert) => cert.latest_version?.not_after && Date.parse(cert.latest_version.not_after) < Date.now() + 30 * 86400 * 1000);
  return pageFrame(
    "Home",
    createElement("div", { className: "toolbar" },
      createElement("button", { className: "primary", disabled: manageableApps.length === 0, onClick: () => props.navigate("/certificates/new") }, createElement(BadgeCheck, { size: 16 }), "Create Certificate"),
      createElement("button", { onClick: () => props.navigate("/certificates") }, "Certificates"),
      createElement("button", { onClick: () => props.navigate("/applications") }, "Applications")
    ),
    createElement("section", { className: "dashboard-grid" },
      readinessCard("Service", ready.loading ? "Loading" : ready.data?.ready ? "Ready" : "Attention", ready.data?.checks?.map((check) => `${check.name}: ${check.status}`) || (ready.error ? [errorText(ready)] : [])),
      readinessCard("Applications", String(apps.length), [
        `${manageableApps.length} manageable`,
        `${apps.reduce((sum, app) => sum + Number(app.domain_scope_count || 0), 0)} domain scopes`,
        `${apps.reduce((sum, app) => sum + Number(app.certificate_count || 0), 0)} certificates`
      ]),
      readinessCard("Certificates", String(certs.length), [
        `${issuing.length} in progress`,
        `${expiring.length} expiring within 30 days`,
        `${certs.filter((cert) => cert.status === "failed").length} failed`
      ]),
      isAdmin(props.session) ? readinessCard("Issuance setup", zones.loading ? "Loading" : setupStatus(rowsOf(issuers), rowsOf(providers), rowsOf(zones)), [
        `${rowsOf(issuers).filter((issuer) => issuer.status === "active").length} active issuers`,
        `${rowsOf(providers).filter((provider) => provider.status === "active").length} active DNS providers`,
        firstProvider ? zones.loading ? `loading zones on ${firstProvider.name}` : `${rowsOf(zones).length} zones on ${firstProvider.name}` : "no DNS provider selected"
      ]) : readinessCard("Your access", manageableApps.length ? "Can issue" : "View only", manageableApps.map((app) => `${app.name}: ${app.current_user_role}`).slice(0, 4))
    ),
    createElement("section", { className: "detail" },
      createElement("h2", null, "Your Applications"),
      table({ data: { applications: apps.slice(0, 8) }, loading: applications.loading, error: applications.error }, ["name", "status", "current_user_role", "domain_scope_count", "certificate_count"])
    ),
    createElement("section", { className: "detail" },
      createElement("h2", null, "Recent Certificates"),
      table({ data: { certificates: certs.slice(0, 8) }, loading: certificates.loading, error: certificates.error }, ["status", "normalized_sans", "key_type", "issuer_name", "updated_at"])
    )
  );
}

function CertificatesPage(props: PageProps) {
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<any>(undefined);
  const [filters, setFilters] = useState({ domain: "", status: "", application: "", issuer: "", key_type: "", expires_before: "" });
  const query = queryString({ ...filters, limit: "100" });
  const list = useAsync<{ certificates: any[] }> (props.session, `/v1/certificates?${query}`, [refresh, query]);
  const applications = useAsync<{ applications: any[] }>(props.session, "/v1/applications?limit=100", [refresh]);
  const manageableApps = rowsOf(applications).filter((app) => canManageApplication(app, props.session) && app.system_kind !== "certhub_server" && app.name !== "certhub_server");
  return pageFrame(
    "Certificates",
    createElement("div", { className: "header-actions" },
      createElement("button", { className: "primary", disabled: manageableApps.length === 0, onClick: () => props.navigate("/certificates/new") }, createElement(BadgeCheck, { size: 16 }), "Create Certificate"),
      createElement(GenericCreate, { title: "Filters", fields: ["domain", "status", "application", "issuer", "key_type", "expires_before"], onSubmit: (body: Record<string, string>) => setFilters({ ...filters, ...body }) })
    ),
    table(list, ["status", "normalized_sans", "key_type", "issuer_name", "application_id", "updated_at"], (cert) => setSelected(cert)),
    selected ? createElement(CertificateDetail, { cert: selected, session: props.session, setNotice: props.setNotice, onRefresh: () => setRefresh(refresh + 1) }) : null
  );
}

function CertificateDetail(props: { cert: any; session: Session; setNotice: (s: string) => void; onRefresh: () => void }) {
  const [refresh, setRefresh] = useState(0);
  const detail = useAsync<{ certificate: any }>(props.session, `/v1/certificates/${props.cert.id}`, [props.cert.id, refresh]);
  const cert = detail.data?.certificate || props.cert;
  const appAccess = useAsync<{ application: any }>(props.session, cert.application_id ? `/v1/applications/${cert.application_id}` : "/v1/applications/00000000-0000-0000-0000-000000000000", [cert.application_id]);
  const versions = useAsync<{ versions: any[] }>(props.session, `/v1/certificates/${props.cert.id}/versions?limit=20`, [props.cert.id, refresh]);
  const events = useAsync<{ audit_events: any[] }>(props.session, `/v1/certificates/${props.cert.id}/events?limit=20`, [props.cert.id, refresh]);
  const action = (path: string, body?: unknown, method = "POST") =>
    api(`/v1/certificates/${props.cert.id}${path}`, props.session, { method, body: body ? JSON.stringify(body) : undefined }).then((r) => {
      props.setNotice(r.error ? errorText(r) : "request accepted");
      setRefresh(refresh + 1);
      props.onRefresh();
    });
  const revoked = cert.status === "revoked" || cert.revoked_at;
  const expired = cert.status === "expired";
  const appRole = appAccess.data?.application?.current_user_role;
  const appLoaded = Boolean(appAccess.data?.application);
  const appReserved = appAccess.data?.application?.system_kind === "certhub_server" || appAccess.data?.application?.name === "certhub_server";
  const canReadMaterial = appLoaded && !appReserved && (isAdmin(props.session) || appRole === "certificate_reader" || appRole === "manager");
  const canLifecycle = appLoaded && !appReserved && (isAdmin(props.session) || appRole === "manager");
  return createElement(
    "section",
    { className: "detail" },
    createElement("h2", null, "Certificate detail"),
    kv("ID", cert.id),
    kv("Domains", (cert.normalized_sans || []).join(", ")),
    kv("Status", cert.status),
    kv("Latest not after", cert.latest_version?.not_after || ""),
    kv("Fingerprint", cert.latest_version?.fingerprint_sha256 || ""),
    revoked ? kv("Revoked", `${cert.revocation_reason || ""} ${cert.revoked_at || ""}`) : null,
    createElement("div", { className: "toolbar" },
      canReadMaterial && !revoked && !expired ? createElement("button", { onClick: () => downloadMaterial(props.session, cert.id, props.setNotice) }, createElement(Download, { size: 16 }), "TLS material") : null,
      canReadMaterial && !revoked && !expired ? createElement("button", { onClick: () => downloadArchive(props.session, cert.id, props.setNotice) }, createElement(Download, { size: 16 }), "Archive") : null,
      canLifecycle ? createElement("button", { onClick: () => action("/renew") }, createElement(RefreshCw, { size: 16 }), "Renew") : null,
      canLifecycle ? createElement("button", { onClick: () => action("/rotate-key") }, "Rotate key") : null,
      canLifecycle ? createElement("button", { onClick: () => action("/revoke", { reason: "cessation_of_operation" }) }, "Revoke") : null,
      canLifecycle ? createElement("button", { onClick: () => action("", { revoke: false }, "DELETE") }, createElement(Trash2, { size: 16 }), "Local delete") : null,
      canLifecycle ? createElement("button", { onClick: () => action("", { revoke: true, reason: "cessation_of_operation" }, "DELETE") }, createElement(Trash2, { size: 16 }), "Revoke and delete") : null
    ),
    createElement("h3", null, "Versions"),
    table(versions, ["version", "status", "reason", "not_after", "failure_code"]),
    createElement("h3", null, "Events"),
    table(events, ["created_at", "action", "result", "request_id"])
  );
}

function ApplicationsPage(props: PageProps) {
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<any>(undefined);
  const list = useAsync<{ applications: any[] }>(props.session, "/v1/applications?limit=100", [refresh]);
  return pageFrame(
    "Applications",
    isAdmin(props.session) ? createElement("button", { className: "primary", onClick: () => props.navigate("/applications/new") }, "Create Application") : null,
    table(list, ["name", "status", "current_user_role", "domain_scope_count", "token_count", "trusted_source_cidr_count", "certificate_count", "system_kind"], setSelected),
    selected ? createElement(ApplicationDetail, { key: selected.id, app: selected, session: props.session, setNotice: props.setNotice, navigate: props.navigate }) : null
  );
}

function ApplicationDetail(props: { app: any; session: Session; setNotice: (s: string) => void; navigate: (path: string) => void }) {
  const base = `/v1/applications/${props.app.id}`;
  const [refresh, setRefresh] = useState(0);
  const [tokenValue, setTokenValue] = useState("");
  useEffect(() => {
    setTokenValue("");
  }, [props.app.id]);
  const detail = useAsync<{ application: any }>(props.session, base, [props.app.id, refresh]);
  const app = detail.data?.application || props.app;
  const scopes = useAsync<{ domain_scopes: any[] }>(props.session, `${base}/domain-scopes?limit=100`, [props.app.id, refresh]);
  const tokens = useAsync<{ tokens: any[] }>(props.session, `${base}/tokens?limit=100`, [props.app.id, refresh]);
  const grants = useAsync<{ grants: any[] }>(props.session, `${base}/users?limit=100`, [props.app.id, refresh]);
  const certs = useAsync<{ certificates: any[] }>(props.session, `/v1/certificates?application=${encodeURIComponent(props.app.id)}&limit=100`, [props.app.id, refresh]);
  const events = useAsync<{ audit_events: any[] }>(props.session, `/v1/audit-events?application_id=${encodeURIComponent(props.app.id)}&limit=50`, [props.app.id, refresh]);
  const reserved = props.app.system_kind === "certhub_server" || props.app.name === "certhub_server";
  const canManage = !reserved && canManageApplication(app, props.session);
  return createElement("section", { className: "detail" },
    createElement("h2", null, app.name),
    reserved ? createElement("p", { className: "note" }, "System-managed Application. Changes come from backend process configuration.") : null,
    kv("Status", app.status),
    kv("Trusted CIDRs", (app.trusted_source_cidrs || []).join(", ") || "none"),
    canManage ? createElement(GenericCreate, {
      title: "Update application",
      fields: ["display_name", "description", "status", "trusted_source_cidrs comma separated"],
      onSubmit: (body: Record<string, string>) => patchJSON({ session: props.session, setNotice: props.setNotice }, base, {
        display_name: body.display_name || undefined,
        description: body.description || null,
        status: body.status || undefined,
        trusted_source_cidrs: splitList(body["trusted_source_cidrs comma separated"])
      }, () => setRefresh(refresh + 1))
    }) : null,
    createElement("h3", null, "Domain scopes"),
    canManage ? createElement(GenericCreate, { title: "Add scope", fields: ["value"], onSubmit: (body: Record<string, string>) => post({ session: props.session, setNotice: props.setNotice }, `${base}/domain-scopes`, body, () => setRefresh(refresh + 1)) }) : null,
    table(scopes, ["value", "kind", "created_at"]),
    canManage ? rowActions(scopes, (scope) => createElement("button", { key: scope.id, onClick: () => del({ session: props.session, setNotice: props.setNotice }, `${base}/domain-scopes/${scope.id}`, () => setRefresh(refresh + 1)) }, `Delete ${scope.value}`)) : null,
    createElement("h3", null, "Tokens"),
    canManage ? createElement(GenericCreate, { title: "Create token", fields: ["name", "expires_at"], onSubmit: (body: Record<string, string>) => {
      setTokenValue("");
        api<any>(`${base}/tokens`, props.session, { method: "POST", body: JSON.stringify(tokenCreateBody(body)) }).then((r) => {
      if (!r.error && r.data?.token_value) setTokenValue(r.data.token_value);
      props.setNotice(errorOrOK(r));
      setRefresh(refresh + 1);
    });
    } }) : null,
    tokenValue ? createElement("div", { className: "secret-once" },
      createElement("strong", null, "Raw token value, shown once"),
      createElement("code", null, tokenValue),
      createElement("button", { onClick: () => setTokenValue("") }, "Clear")
    ) : null,
    table(tokens, ["name", "status", "expires_at", "last_used_at"]),
    canManage ? rowActions(tokens, (token) => createElement("button", { key: token.id, onClick: () => del({ session: props.session, setNotice: props.setNotice }, `${base}/tokens/${token.id}`, () => setRefresh(refresh + 1)) }, `Revoke ${token.name}`)) : null,
    createElement("h3", null, "Grants"),
    canManage ? createElement(GrantForm, { session: props.session, applicationID: app.id, setNotice: props.setNotice, onDone: () => setRefresh(refresh + 1) }) : null,
    table(grants, ["user_id", "role", "created_at"]),
    canManage ? rowActions(grants, (grant) => createElement("button", { key: grant.id, onClick: () => del({ session: props.session, setNotice: props.setNotice }, `${base}/users/${grant.user_id}`, () => setRefresh(refresh + 1)) }, `Remove ${grant.user?.email || grant.user_id}`)) : null,
    createElement("div", { className: "section-head" },
      createElement("h3", null, "Certificates"),
      canManage ? createElement("button", { className: "primary", onClick: () => props.navigate(`/certificates/new?application_id=${encodeURIComponent(app.id)}`) }, createElement(BadgeCheck, { size: 16 }), "Create Certificate") : null
    ),
    table(certs, ["status", "normalized_sans", "key_type", "issuer_name", "updated_at"]),
    createElement("h3", null, "Audit events"),
    table(events, ["created_at", "action", "result", "request_id"])
  );
}

function UsersPage(props: PageProps) {
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<any>(undefined);
  const list = useAsync<{ users: any[] }>(props.session, "/v1/users?limit=100", [refresh]);
  if (!isAdmin(props.session)) return forbiddenPage("Users");
  return pageFrame("Users",
    createElement("button", { className: "primary", onClick: () => props.navigate("/users/new") }, "Create User"),
    table(list, ["email", "display_name", "global_role", "status", "oidc_linked", "application_grant_count", "last_login_at"], setSelected),
    selected ? createElement(UserDetail, { user: selected, session: props.session, setNotice: props.setNotice, onDone: () => setRefresh(refresh + 1) }) : null
  );
}

function UserDetail(props: { user: any; session: Session; setNotice: (s: string) => void; onDone: () => void }) {
  const [refresh, setRefresh] = useState(0);
  const [password2FA, setPassword2FA] = useState<any>(undefined);
  const detail = useAsync<{ user: any }>(props.session, `/v1/users/${props.user.id}`, [props.user.id, refresh]);
  const user = detail.data?.user || props.user;
  return createElement("section", { className: "detail" },
    createElement("h2", null, user.email),
    kv("Password login", user.password_login_enabled ? "enabled" : "disabled"),
    kv("Password 2FA", user.password_2fa_enabled ? "enabled" : "disabled"),
    kv("OIDC", user.oidc_linked ? "linked" : "not linked"),
    createElement(GenericCreate, {
      title: "Update user",
      fields: ["display_name", "global_role", "status", "password", "provision_password_2fa", "reset_password_2fa"],
      onSubmit: (body: Record<string, string>) => {
        setPassword2FA(undefined);
        api<any>(`/v1/users/${user.id}`, props.session, { method: "PATCH", body: JSON.stringify(emptyToPatch(body)) }).then((r) => {
          if (r.data?.password_2fa) setPassword2FA(r.data.password_2fa);
          props.setNotice(errorOrOK(r));
          if (!r.error) {
            setRefresh(refresh + 1);
            props.onDone();
          }
        });
      }
    }),
    password2FA?.provisioning_uri ? createElement("div", { className: "secret-once" }, kv("Provisioning URI", password2FA.provisioning_uri), kv("Secret", password2FA.secret)) : null,
    createElement("h3", null, "Application grants"),
    table({ data: { grants: user.application_grants || [] } }, ["application_name", "role", "created_at"])
  );
}

function IssuersPage(props: PageProps) {
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<any>(undefined);
  const list = useAsync<{ issuers: any[] }>(props.session, "/v1/issuers?limit=100", [refresh]);
  if (!isAdmin(props.session)) return forbiddenPage("Issuers");
  return pageFrame("Issuers",
    createElement("button", { className: "primary", onClick: () => props.navigate("/issuers/new") }, "Create Issuer"),
    table(list, ["name", "type", "directory_url", "environment", "status", "default", "renewal_window_seconds"], setSelected),
    selected ? createElement(IssuerDetail, { issuer: selected, session: props.session, setNotice: props.setNotice, onDone: () => setRefresh(refresh + 1) }) : null
  );
}

function IssuerDetail(props: { issuer: any; session: Session; setNotice: (s: string) => void; onDone: () => void }) {
  const [refresh, setRefresh] = useState(0);
  const detail = useAsync<{ issuer: any }>(props.session, `/v1/issuers/${props.issuer.id}`, [props.issuer.id, refresh]);
  const issuer = detail.data?.issuer || props.issuer;
  return createElement("section", { className: "detail" },
    createElement("h2", null, issuer.name),
    kv("Directory URL", issuer.directory_url),
    kv("Environment", issuer.environment),
    kv("ACME account", issuer.acme_account_status || ""),
    createElement(GenericCreate, {
      title: "Update issuer",
      fields: ["default", "status", "renewal_window_seconds", "contact_email"],
      onSubmit: (body: Record<string, string>) => patchJSON({ session: props.session, setNotice: props.setNotice }, `/v1/issuers/${issuer.id}`, {
        default: body.default ? body.default === "true" : undefined,
        status: body.status || undefined,
        renewal_window_seconds: body.renewal_window_seconds ? Number(body.renewal_window_seconds) : undefined,
        contact_email: body.contact_email || undefined
      }, () => {
        setRefresh(refresh + 1);
        props.onDone();
      })
    })
  );
}

function DNSPage(props: PageProps) {
  const [selected, setSelected] = useState<any>(undefined);
  const [refresh, setRefresh] = useState(0);
  const list = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", [refresh]);
  if (!isAdmin(props.session)) return forbiddenPage("DNS Providers");
  return pageFrame(
    "DNS Providers",
    createElement("button", { className: "primary", onClick: () => props.navigate("/dns-providers/new") }, "Create DNS Provider"),
    table(list, ["name", "type", "zone_mode", "status", "zone_refresh_status", "last_zone_refresh_at"], setSelected),
    selected ? createElement(DNSDetail, { provider: selected, session: props.session, setNotice: props.setNotice, onDone: () => setRefresh(refresh + 1) }) : null
  );
}

function DNSDetail(props: { provider: any; session: Session; setNotice: (s: string) => void; onDone: () => void }) {
  const [refresh, setRefresh] = useState(0);
  const detail = useAsync<{ dns_provider: any }>(props.session, `/v1/dns-providers/${props.provider.id}`, [props.provider.id, refresh]);
  const provider = detail.data?.dns_provider || props.provider;
  const zones = useAsync<{ zones: any[] }>(props.session, `/v1/dns-providers/${props.provider.id}/zones?limit=100`, [props.provider.id, refresh]);
  const discovered = useAsync<{ zones: any[] }>(props.session, `/v1/dns-providers/${props.provider.id}/zones/discovered?limit=100`, [props.provider.id, refresh]);
  const base = `/v1/dns-providers/${props.provider.id}`;
  return createElement("section", { className: "detail" },
    createElement("h2", null, provider.name),
    kv("Refresh status", provider.zone_refresh_status),
    provider.zone_refresh_failure_code ? kv("Refresh failure", `${provider.zone_refresh_failure_code}: ${provider.zone_refresh_failure_message || ""}`) : null,
    createElement(GenericCreate, { title: "Update provider", fields: ["zone_mode", "status", "credentials_json"], onSubmit: (body: Record<string, string>) => {
      const credentials = body.credentials_json ? safeJSON(body.credentials_json) : undefined;
      if (body.credentials_json && !credentials) return props.setNotice("invalid credentials_json");
      patchJSON({ session: props.session, setNotice: props.setNotice }, base, { zone_mode: body.zone_mode || undefined, status: body.status || undefined, credentials }, () => {
        setRefresh(refresh + 1);
        props.onDone();
      });
    } }),
    createElement("div", { className: "toolbar" }, createElement("button", { onClick: () => post({ session: props.session, setNotice: props.setNotice }, `${base}/zones/refresh`, {}, () => setRefresh(refresh + 1)) }, createElement(RefreshCw, { size: 16 }), "Refresh zones")),
    provider.zone_mode === "manual" ? createElement(GenericCreate, { title: "Add zone", fields: ["zone_name"], onSubmit: (body: Record<string, string>) => post({ session: props.session, setNotice: props.setNotice }, `${base}/zones`, body, () => setRefresh(refresh + 1)) }) : null,
    createElement("h3", null, "Zones"),
    table(zones, ["zone_name", "created_at"]),
    provider.zone_mode === "manual" ? rowActions(zones, (zone) => createElement("button", { key: zone.id, onClick: () => del({ session: props.session, setNotice: props.setNotice }, `${base}/zones/${zone.id}`, () => setRefresh(refresh + 1)) }, `Delete ${zone.zone_name}`)) : null,
    createElement("h3", null, "Discovered zones"),
    table(discovered, ["zone_name", "already_configured", "conflict_dns_provider_id"]),
    provider.zone_mode === "manual" ? rowActions(discovered, (zone) => createElement("button", { key: zone.zone_name, disabled: zone.already_configured, onClick: () => post({ session: props.session, setNotice: props.setNotice }, `${base}/zones`, { zone_name: zone.zone_name }, () => setRefresh(refresh + 1)) }, `Add ${zone.zone_name}`)) : null
  );
}

function AuditPage(props: PageProps) {
  const [filters, setFilters] = useState({ identity_id: "", identity_type: "", action: "", certificate_id: "", application_id: "", target_type: "", target_id: "", result: "", created_at_from: "", created_at_to: "" });
  const query = queryString({ ...filters, limit: "100" });
  const list = useAsync<{ audit_events: any[] }>(props.session, `/v1/audit-events?${query}`, [query]);
  if (!isAdmin(props.session)) return forbiddenPage("Audit Events");
  return pageFrame("Audit Events",
    createElement(GenericCreate, { title: "Filters", fields: ["identity_id", "identity_type", "action", "certificate_id", "application_id", "target_type", "target_id", "result", "created_at_from", "created_at_to"], onSubmit: (body: Record<string, string>) => setFilters({ ...filters, ...body }) }),
    table(list, ["created_at", "identity_type", "identity_id", "action", "target_type", "result", "request_id", "source_ip"])
  );
}

function CertificateCreatePage(props: PageProps) {
  const applicationID = props.route.query.get("application_id") || undefined;
  return pageFrame(
    "Create Certificate",
    createElement("button", { onClick: () => props.navigate("/certificates") }, "Back to Certificates"),
    createElement(IssueCertificateFlow, {
      session: props.session,
      setNotice: props.setNotice,
      applicationID,
      onDone: () => {
        props.setNotice("saved");
        props.navigate("/certificates");
      },
      onCancel: () => props.navigate("/certificates")
    })
  );
}

function ApplicationCreatePage(props: PageProps) {
  const [body, setBody] = useState({ name: "", display_name: "", description: "", status: "active", trusted_source_cidrs: [] as string[], domain_scopes: [] as string[] });
  if (!isAdmin(props.session)) return forbiddenPage("Applications");
  const submit = async (e: Event) => {
    e.preventDefault();
    const scopeError = listError(body.domain_scopes, "domain_scopes", "domain");
    const cidrError = listError(body.trusted_source_cidrs, "trusted_source_cidrs", "ip_or_cidr");
    const error = required(body.name, "name") || required(body.display_name, "display_name") || validateField("name", body.name) || validateField("status", body.status) || cidrError || scopeError;
    if (error) return props.setNotice(error);
    const payload = emptyToUndefined({
      name: body.name,
      display_name: body.display_name,
      description: body.description,
      status: body.status
    }) as Record<string, unknown> & { trusted_source_cidrs?: string[] };
    if (body.trusted_source_cidrs.length) {
      payload.trusted_source_cidrs = body.trusted_source_cidrs;
    }
    const result = await api<any>("/v1/applications", props.session, { method: "POST", body: JSON.stringify(payload) });
    if (result.error) return props.setNotice(errorOrOK(result));
    const appID = result.data?.application?.id;
    if (appID) {
      for (const scope of body.domain_scopes) {
        const scopeResult = await api(`/v1/applications/${appID}/domain-scopes`, props.session, { method: "POST", body: JSON.stringify({ value: scope }) });
        if (scopeResult.error) {
          props.setNotice(`application created; domain scope ${scope}: ${errorText(scopeResult)}`);
          props.navigate("/applications");
          return;
        }
      }
    }
    props.setNotice("saved");
    props.navigate("/applications");
  };
  return createPage("Create Application", "/applications", props.navigate,
    createElement("form", { className: "create-form", onSubmit: submit },
      input("name", body.name, (v) => setBody({ ...body, name: v })),
      input("display_name", body.display_name, (v) => setBody({ ...body, display_name: v })),
      textAreaInput("description", body.description, (v) => setBody({ ...body, description: v })),
      selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
      createElement(ListInput, { label: "trusted_source_cidrs", values: body.trusted_source_cidrs, onChange: (v: string[]) => setBody({ ...body, trusted_source_cidrs: v }), mode: "ip_or_cidr", placeholder: "203.0.113.10" }),
      createElement(ListInput, { label: "domain_scopes", values: body.domain_scopes, onChange: (v: string[]) => setBody({ ...body, domain_scopes: v }), mode: "domain", placeholder: "example.com" }),
      formActions("Create", "/applications", props.navigate)
    )
  );
}

function UserCreatePage(props: PageProps) {
  const [step, setStep] = useState(1);
  const [result2FA, setResult2FA] = useState<any>(undefined);
  const [body, setBody] = useState({
    email: "",
    display_name: "",
    global_role: "user",
	    status: "active",
	    auth_method: "password",
	    password: "",
	    provision_password_2fa: true
	  });
  if (!isAdmin(props.session)) return forbiddenPage("Users");
  const identityError = required(body.email, "email") || required(body.display_name, "display_name") || validateField("email", body.email) || validateField("global_role", body.global_role) || validateField("status", body.status);
	  const authError = body.auth_method === "password" ?
	    (!body.password ? "password is required" : body.password.length < 12 ? "password must be at least 12 characters" : "") :
	    "";
  const submit = async (e: Event) => {
    e.preventDefault();
    if (identityError || authError) return props.setNotice(identityError || authError);
    const payload = body.auth_method === "password" ? {
      email: body.email,
      display_name: body.display_name,
      global_role: body.global_role,
      status: body.status,
      password: body.password,
      provision_password_2fa: body.provision_password_2fa
	    } : {
	      email: body.email,
	      display_name: body.display_name,
	      global_role: body.global_role,
	      status: body.status
	    };
    const result = await api<any>("/v1/users", props.session, { method: "POST", body: JSON.stringify(payload) });
    props.setNotice(errorOrOK(result));
    if (result.data?.password_2fa) {
      setResult2FA(result.data.password_2fa);
      setStep(3);
    } else if (!result.error) props.navigate("/users");
  };
  if (step === 3) {
    return createPage("User Created", "/users", props.navigate,
      createElement("section", { className: "detail" },
        createElement("h2", null, "Password 2FA"),
        kv("Issuer", result2FA?.issuer),
        kv("Account", result2FA?.account_label),
        kv("Secret", result2FA?.secret),
        kv("Provisioning URI", result2FA?.provisioning_uri),
        createElement("div", { className: "toolbar" }, createElement("button", { className: "primary", onClick: () => props.navigate("/users") }, "Back to Users"))
      )
    );
  }
  return createPage("Create User", "/users", props.navigate,
    createElement("form", { className: "create-form", onSubmit: submit },
      createElement("div", { className: "stepper" }, createElement("span", { className: step === 1 ? "active" : "" }, "Identity"), createElement("span", { className: step === 2 ? "active" : "" }, "Authentication")),
      step === 1 ? createElement("section", { className: "form-section" },
        input("email", body.email, (v) => setBody({ ...body, email: v }), "email"),
        input("display_name", body.display_name, (v) => setBody({ ...body, display_name: v })),
        selectInput("global_role", body.global_role, (v) => setBody({ ...body, global_role: v }), [["user", "User"], ["admin", "Admin"]]),
        selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
        identityError ? createElement("span", { className: "field-error" }, identityError) : null,
        createElement("div", { className: "toolbar" },
          createElement("button", { type: "button", onClick: () => props.navigate("/users") }, "Cancel"),
          createElement("button", { className: "primary", type: "button", disabled: Boolean(identityError), onClick: () => setStep(2) }, "Next")
        )
      ) : createElement("section", { className: "form-section" },
	        selectInput("auth_method", body.auth_method, (v) => setBody({ ...body, auth_method: v }), [["password", "Password"], ["oidc", "OIDC"]]),
	        body.auth_method === "password" ? input("password", body.password, (v) => setBody({ ...body, password: v }), "password") : null,
	        body.auth_method === "password" ? checkboxInput("provision_password_2fa", body.provision_password_2fa, (v) => setBody({ ...body, provision_password_2fa: v })) : null,
	        authError ? createElement("span", { className: "field-error" }, authError) : null,
        createElement("div", { className: "toolbar" },
          createElement("button", { type: "button", onClick: () => setStep(1) }, "Back"),
          createElement("button", { className: "primary", disabled: Boolean(authError) }, "Create")
        )
      )
    )
  );
}

function IssuerCreatePage(props: PageProps) {
  const [preset, setPreset] = useState("letsencrypt_production");
  const [body, setBody] = useState({
    name: "letsencrypt_production",
    type: "acme",
    directory_url: "https://acme-v02.api.letsencrypt.org/directory",
    environment: "production",
    default: true,
    status: "active",
    renewal_window_seconds: "2592000",
    contact_email: ""
  });
  if (!isAdmin(props.session)) return forbiddenPage("Issuers");
  const applyPreset = (value: string) => {
    setPreset(value);
    if (value === "letsencrypt_production") setBody({ ...body, name: "letsencrypt_production", directory_url: "https://acme-v02.api.letsencrypt.org/directory", environment: "production" });
    if (value === "letsencrypt_staging") setBody({ ...body, name: "letsencrypt_staging", directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory", environment: "staging", default: false });
  };
  const submit = async (e: Event) => {
    e.preventDefault();
    const error = required(body.name, "name") || required(body.directory_url, "directory_url") || required(body.contact_email, "contact_email") || validateField("name", body.name) || validateField("directory_url", body.directory_url) || validateField("environment", body.environment) || validateField("status", body.status) || validateField("contact_email", body.contact_email);
    if (error) return props.setNotice(error);
    const result = await api("/v1/issuers", props.session, { method: "POST", body: JSON.stringify({
      name: body.name,
      type: "acme",
      directory_url: body.directory_url,
      environment: body.environment,
      default: body.default,
      status: body.status,
      renewal_window_seconds: Number(body.renewal_window_seconds || 2592000),
      contact_email: body.contact_email
    }) });
    props.setNotice(errorOrOK(result));
    if (!result.error) props.navigate("/issuers");
  };
  return createPage("Create Issuer", "/issuers", props.navigate,
    createElement("form", { className: "create-form", onSubmit: submit },
      selectInput("directory_preset", preset, applyPreset, [["letsencrypt_production", "Let's Encrypt production"], ["letsencrypt_staging", "Let's Encrypt staging"], ["custom", "Custom"]]),
      input("name", body.name, (v) => setBody({ ...body, name: v })),
      selectInput("type", body.type, (v) => setBody({ ...body, type: v }), [["acme", "ACME"]]),
      input("directory_url", body.directory_url, (v) => setBody({ ...body, directory_url: v }), "url"),
      selectInput("environment", body.environment, (v) => setBody({ ...body, environment: v }), [["production", "Production"], ["staging", "Staging"]]),
      checkboxInput("default", body.default, (v) => setBody({ ...body, default: v })),
      selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
      input("renewal_window_seconds", body.renewal_window_seconds, (v) => setBody({ ...body, renewal_window_seconds: v }), "number"),
      input("contact_email", body.contact_email, (v) => setBody({ ...body, contact_email: v }), "email"),
      formActions("Create", "/issuers", props.navigate)
    )
  );
}

function DNSCreatePage(props: PageProps) {
  const [body, setBody] = useState({ name: "", type: "cloudflare", zone_mode: "auto", status: "active", api_token: "", api_key: "", manual_zones: [] as string[] });
  if (!isAdmin(props.session)) return forbiddenPage("DNS Providers");
  const submit = async (e: Event) => {
    e.preventDefault();
    const secret = body.type === "cloudflare" ? body.api_token : body.api_key;
    const zoneError = body.zone_mode === "manual" ? listError(body.manual_zones, "manual_zones", "domain") : "";
    const error = required(body.name, "name") || validateField("name", body.name) || validateField("type", body.type) || validateField("zone_mode", body.zone_mode) || validateField("status", body.status) || (!secret ? "credentials are required" : "") || zoneError;
    if (error) return props.setNotice(error);
    const credentials = body.type === "cloudflare" ? { api_token: body.api_token } : { api_key: body.api_key };
    const result = await api<any>("/v1/dns-providers", props.session, { method: "POST", body: JSON.stringify({
      name: body.name,
      type: body.type,
      zone_mode: body.zone_mode,
      status: body.status,
      credentials
    }) });
    if (result.error) return props.setNotice(errorOrOK(result));
    const providerID = result.data?.dns_provider?.id;
    if (providerID && body.zone_mode === "manual") {
      for (const zone of body.manual_zones) {
        const zoneResult = await api(`/v1/dns-providers/${providerID}/zones`, props.session, { method: "POST", body: JSON.stringify({ zone_name: zone }) });
        if (zoneResult.error) {
          props.setNotice(`dns provider created; zone ${zone}: ${errorText(zoneResult)}`);
          props.navigate("/dns-providers");
          return;
        }
      }
    }
    props.setNotice("saved");
    props.navigate("/dns-providers");
  };
  return createPage("Create DNS Provider", "/dns-providers", props.navigate,
    createElement("form", { className: "create-form", onSubmit: submit },
      input("name", body.name, (v) => setBody({ ...body, name: v })),
      selectInput("type", body.type, (v) => setBody({ ...body, type: v }), [["cloudflare", "Cloudflare"], ["arvancloud", "ArvanCloud"]]),
      selectInput("zone_mode", body.zone_mode, (v) => setBody({ ...body, zone_mode: v }), [["auto", "Auto"], ["manual", "Manual"]]),
      selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
      body.type === "cloudflare" ? input("api_token", body.api_token, (v) => setBody({ ...body, api_token: v }), "password") : null,
      body.type === "arvancloud" ? input("api_key", body.api_key, (v) => setBody({ ...body, api_key: v }), "password") : null,
      body.zone_mode === "manual" ? createElement(ListInput, { label: "manual_zones", values: body.manual_zones, onChange: (v: string[]) => setBody({ ...body, manual_zones: v }), mode: "domain", placeholder: "example.com" }) : null,
      formActions("Create", "/dns-providers", props.navigate)
    )
  );
}

type PageProps = { session: Session; setNotice: (s: string) => void; navigate: (path: string, replace?: boolean) => void; route: RouteState };

function GenericCreate(props: { title: string; fields: string[]; onSubmit: (body: Record<string, string>) => void }) {
  const initial = useMemo(() => Object.fromEntries(props.fields.map((f) => [f, ""])), [props.fields.join("|")]);
  const [body, setBody] = useState<Record<string, string>>(initial);
  const [errors, setErrors] = useState<Record<string, string>>({});
  return createElement("form", { className: "inline-form", onSubmit: (e: Event) => {
    e.preventDefault();
    props.onSubmit(body);
    if (props.fields.some((field) => field.includes("credentials"))) {
      setBody(Object.fromEntries(props.fields.map((field) => [field, field.includes("credentials") ? "" : body[field] || ""])));
    }
  } },
    createElement("strong", null, props.title),
    props.fields.map((field) => createElement("div", { className: "field", key: field },
      input(field, body[field] || "", (v) => {
        setBody({ ...body, [field]: v });
        setErrors({ ...errors, [field]: validateField(field, v) });
      }),
      errors[field] ? createElement("span", { className: "field-error" }, errors[field]) : null
    )),
    createElement("button", { className: "primary", disabled: Object.values(errors).some(Boolean) }, "Submit")
  );
}

function GrantForm(props: { session: Session; applicationID: string; setNotice: (s: string) => void; onDone: () => void }) {
  const [body, setBody] = useState({ email: "", user_id: "", role: "viewer" });
  return createElement("form", { className: "inline-form", onSubmit: async (e: Event) => {
    e.preventDefault();
    let userID = body.user_id;
    if (!userID && body.email) {
      const lookup = await api<any>(`/v1/users/lookup?email=${encodeURIComponent(body.email)}&application_id=${encodeURIComponent(props.applicationID)}`, props.session);
      if (!lookup.data?.user?.id) {
        props.setNotice(errorText(lookup));
        return;
      }
      userID = lookup.data.user.id;
    }
    const result = await api(`/v1/applications/${props.applicationID}/users/${userID}`, props.session, { method: "PUT", body: JSON.stringify({ role: body.role }) });
    props.setNotice(errorOrOK(result));
    if (!result.error) props.onDone();
  } },
    createElement("strong", null, "Put grant"),
    input("email lookup", body.email, (v) => setBody({ ...body, email: v })),
    input("user_id", body.user_id, (v) => setBody({ ...body, user_id: v })),
    input("role", body.role, (v) => setBody({ ...body, role: v })),
    createElement("button", { className: "primary" }, "Save grant")
  );
}

function IssueCertificateFlow(props: { session: Session; setNotice: (s: string) => void; onDone: () => void; onCancel?: () => void; applicationID?: string; applications?: any[] }) {
  const locked = Boolean(props.applicationID);
  const appList = useAsync<{ applications: any[] }>(props.session, props.applications ? "" : "/v1/applications?limit=100", []);
  const issuers = useAsync<{ issuers: any[] }>(props.session, "/v1/issuers?limit=100", []);
  const providers = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", []);
  const [body, setBody] = useState({ application_id: props.applicationID || "", domains: [] as string[], key_type: "ecdsa-p256", issuer: "" });
  const scopePath = body.application_id ? `/v1/applications/${body.application_id}/domain-scopes?limit=100` : "";
  const scopes = useAsync<{ domain_scopes: any[] }>(props.session, scopePath, [body.application_id]);
  const applications = (props.applications || rowsOf(appList)).filter((app) => canManageApplication(app, props.session) && app.system_kind !== "certhub_server" && app.name !== "certhub_server");
  const selectedApp = applications.find((app) => app.id === body.application_id);
  const domains = body.domains;
  const scopeValues = rowsOf(scopes).map((scope) => String(scope.value || "").toLowerCase());
  const uncovered = domains.filter((domain) => !scopeValues.some((scope) => domainCoveredByScope(domain, scope)));
  const activeIssuers = rowsOf(issuers).filter((issuer) => issuer.status === "active");
  const activeProviders = rowsOf(providers).filter((provider) => provider.status === "active");
  const fieldError = validateField("application_id", body.application_id) || listError(domains, "Domains / SANs", "domain") || validateField("key_type", body.key_type);
  const canSubmit = Boolean(body.application_id && domains.length && !fieldError);
  return createElement("form", { className: "inline-form issue-flow", onSubmit: (e: Event) => {
    e.preventDefault();
    if (fieldError) return props.setNotice(fieldError);
    if (!selectedApp) return props.setNotice("select a visible non-system Application you can manage");
    if (selectedApp?.system_kind === "certhub_server" || selectedApp?.name === "certhub_server") return props.setNotice("system_managed_resource: certhub_server is read-only and config-managed");
    post(props, `/v1/applications/${body.application_id}/certificates`, { domains, key_type: body.key_type || undefined, issuer: body.issuer || undefined }, props.onDone);
  } },
    locked ? createElement("div", { className: "field" }, createElement("span", null, "Application"), createElement("strong", null, appLabel(selectedApp) || body.application_id)) :
      selectInput("Application", body.application_id, (v) => setBody({ ...body, application_id: v }), [["", "Select Application"], ...applications.map((app) => [app.id, appLabel(app)])]),
    createElement(ListInput, { label: "Domains / SANs", values: body.domains, onChange: (v: string[]) => setBody({ ...body, domains: v }), mode: "domain", placeholder: "example.com" }),
    selectInput("Key type", body.key_type, (v) => setBody({ ...body, key_type: v }), [
      ["ecdsa-p256", "ECDSA P-256"],
      ["ecdsa-p384", "ECDSA P-384"],
      ["rsa-2048", "RSA 2048"],
      ["rsa-3072", "RSA 3072"],
      ["rsa-4096", "RSA 4096"]
    ]),
    selectInput("Issuer", body.issuer, (v) => setBody({ ...body, issuer: v }), [["", "Backend default"], ...activeIssuers.map((issuer) => [issuer.name, `${issuer.name}${issuer.default ? " (default)" : ""}`])]),
    createElement("div", { className: "prereq-panel" },
      createElement("strong", null, "Prerequisites"),
      createElement("span", null, selectedApp ? `Application: ${appLabel(selectedApp)}` : "Application: select one"),
      createElement("span", null, scopes.loading ? "Domain scopes: loading" : `${scopeValues.length} domain scopes`),
      createElement("span", { className: uncovered.length ? "warn" : "" }, uncovered.length ? `Uncovered SANs: ${uncovered.join(", ")}` : domains.length ? "Requested SANs appear covered by visible scopes" : "Enter SANs to check scope coverage"),
      createElement("span", null, issuers.error ? "Issuers: not visible to this user" : `${activeIssuers.length} active issuers`),
      createElement("span", null, providers.error ? "DNS providers: not visible to this user" : `${activeProviders.length} active DNS providers`)
    ),
    domains.length ? createElement("div", { className: "chips" }, domains.map((domain) => createElement("span", { key: domain, className: uncovered.includes(domain) ? "chip warn" : "chip" }, domain))) : null,
    fieldError ? createElement("span", { className: "field-error" }, fieldError) : null,
    createElement("div", { className: "toolbar" },
      createElement("button", { className: "primary", disabled: !canSubmit }, "Issue"),
      props.onCancel ? createElement("button", { type: "button", onClick: props.onCancel }, "Cancel") : null
    )
  );
}

function pageFrame(title: string, action: unknown, ...children: unknown[]) {
  return createElement("section", { className: "page" }, createElement("header", { className: "page-header" }, createElement("h1", null, title), action), ...children);
}

function forbiddenPage(title: string) {
  return pageFrame(title, null, createElement("div", { className: "empty" }, "This global management view is available to admins only."));
}

function table(result: { data?: any; error?: ErrorBody; loading?: boolean }, columns: string[], onSelect?: (row: any) => void) {
  const rows = rowsOf(result);
  if (result.loading) return createElement("div", { className: "empty" }, "Loading");
  if (result.error) return createElement("div", { className: "error" }, result.error.code, ": ", result.error.message);
  return createElement("div", { className: "table-wrap" }, createElement("table", null,
    createElement("thead", null, createElement("tr", null, columns.map((c) => createElement("th", { key: c }, c)))),
    createElement("tbody", null, rows.map((row: any) => createElement("tr", { key: row.id || JSON.stringify(row), onClick: () => onSelect?.(row), className: onSelect ? "selectable" : "" }, columns.map((c) => createElement("td", { key: c }, cell(row[c]))))))
  ));
}

function rowsOf(result: { data?: any }): any[] {
  const key = Object.keys(result.data || {}).find((k) => Array.isArray(result.data[k]));
  return key ? result.data[key] : [];
}

function rowActions(result: { data?: any }, render: (row: any) => unknown) {
  const rows = rowsOf(result);
  if (!rows.length) return null;
  return createElement("div", { className: "row-actions" }, rows.map(render));
}

function input(label: string, value: string, onChange: (v: string) => void, type = "text") {
  return createElement("label", null, createElement("span", null, label), createElement("input", { value, type, onChange: (e: Event) => onChange((e.target as HTMLInputElement).value), autoComplete: "off" }));
}

function selectInput(label: string, value: string, onChange: (v: string) => void, options: string[][]) {
  return createElement("label", null,
    createElement("span", null, label),
    createElement("select", { value, onChange: (e: Event) => onChange((e.target as HTMLSelectElement).value) }, options.map(([optionValue, optionLabel]) => createElement("option", { key: optionValue || "empty", value: optionValue }, optionLabel)))
  );
}

function textAreaInput(label: string, value: string, onChange: (v: string) => void, placeholder = "") {
  return createElement("label", null,
    createElement("span", null, label),
    createElement("textarea", { value, placeholder, rows: 3, onChange: (e: Event) => onChange((e.target as HTMLTextAreaElement).value), autoComplete: "off" })
  );
}

function checkboxInput(label: string, checked: boolean, onChange: (v: boolean) => void) {
  return createElement("label", { className: "check-field" },
    createElement("input", { checked, type: "checkbox", onChange: (e: Event) => onChange((e.target as HTMLInputElement).checked) }),
    createElement("span", null, label)
  );
}

type ListInputMode = "domain" | "ip_or_cidr";

function ListInput(props: { label: string; values: string[]; onChange: (values: string[]) => void; mode: ListInputMode; placeholder: string }) {
  const [draft, setDraft] = useState("");
  const add = (raw: string) => {
    const next = normalizeListValues([...props.values, ...splitList(raw)], props.mode);
    props.onChange(next);
    setDraft("");
  };
  const draftError = draft ? listItemError(draft, props.mode) : "";
  const valuesError = listError(props.values, props.label, props.mode);
  return createElement("div", { className: "list-input" },
    createElement("span", { className: "list-label" }, props.label),
    createElement("div", { className: "list-entry" },
      createElement("input", {
        value: draft,
        placeholder: props.placeholder,
        autoComplete: "off",
        onChange: (e: Event) => {
          const value = (e.target as HTMLInputElement).value;
          if (/[,;\n]/.test(value)) add(value);
          else setDraft(value);
        },
        onBlur: () => draft.trim() && !draftError ? add(draft) : undefined,
        onKeyDown: (e: any) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            if (draft.trim() && !draftError) add(draft);
          }
        },
        onPaste: (e: any) => {
          const text = e.clipboardData?.getData("text") || "";
          if (/[,;\n]/.test(text)) {
            e.preventDefault();
            add(text);
          }
        }
      }),
      createElement("button", { type: "button", disabled: !draft.trim() || Boolean(draftError), onClick: () => add(draft) }, "Add")
    ),
    draftError ? createElement("span", { className: "field-error" }, draftError) : null,
    createElement("div", { className: "chips list-chips" },
      props.values.length ? props.values.map((value) => createElement("span", { key: value, className: "chip editable-chip" },
        createElement("span", null, value),
        createElement("button", { type: "button", title: `Remove ${value}`, onClick: () => props.onChange(props.values.filter((item) => item !== value)) }, createElement(X, { size: 14 }))
      )) : createElement("span", { className: "empty-chip" }, "No values")
    ),
    valuesError ? createElement("span", { className: "field-error" }, valuesError) : null
  );
}

function statusOptions() {
  return [["active", "Active"], ["disabled", "Disabled"]];
}

function formActions(primary: string, cancelPath: string, navigate: (path: string) => void) {
  return createElement("div", { className: "toolbar form-actions" },
    createElement("button", { className: "primary" }, primary),
    createElement("button", { type: "button", onClick: () => navigate(cancelPath) }, "Cancel")
  );
}

function createPage(title: string, backPath: string, navigate: (path: string) => void, ...children: unknown[]) {
  return pageFrame(
    title,
    createElement("button", { onClick: () => navigate(backPath) }, "Back"),
    ...children
  );
}

function kv(label: string, value: unknown) {
  return createElement("div", { className: "kv" }, createElement("span", null, label), createElement("strong", null, cell(value)));
}

function readinessCard(title: string, status: string, items: string[]) {
  return createElement("section", { className: "metric" },
    createElement("span", null, title),
    createElement("strong", null, status),
    createElement("div", null, items.filter(Boolean).slice(0, 5).map((item) => createElement("small", { key: item }, item)))
  );
}

function setupStatus(issuers: any[], providers: any[], zones: any[]) {
  if (!issuers.some((issuer) => issuer.status === "active")) return "Needs issuer";
  if (!providers.some((provider) => provider.status === "active")) return "Needs DNS provider";
  if (providers.length && zones.length === 0) return "Needs DNS zone";
  return "Ready";
}

function appLabel(app: any) {
  if (!app) return "";
  const display = app.display_name && app.display_name !== app.name ? ` - ${app.display_name}` : "";
  return `${app.name}${display}`;
}

function domainCoveredByScope(domain: string, scope: string) {
  if (!scope) return false;
  if (scope.startsWith("*.")) {
    const suffix = scope.slice(1);
    return domain.endsWith(suffix) && domain !== scope.slice(2);
  }
  return domain === scope;
}

function cell(value: unknown): string {
  if (value == null) return "";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function errorText(result: APIResult<unknown>) {
  if (result.error?.code === "system_managed_resource") return `system_managed_resource: this resource is read-only and managed by backend process configuration request_id=${result.requestID}`;
  return `${result.error?.code || "request_failed"}: ${result.error?.message || `HTTP ${result.status}`} request_id=${result.requestID}`;
}

function errorOrOK(result: APIResult<unknown>) {
  return result.error ? errorText(result) : "saved";
}

function identityText(identity?: Identity) {
  if (!identity) return "Signed in";
  return cell((identity as any).email || (identity as any).name || (identity as any).id);
}

function isAdmin(session?: Session) {
  return (session?.identity as any)?.global_role === "admin";
}

function canManageApplication(app: any, session: Session) {
  return isAdmin(session) || app.current_user_role === "manager";
}

function post(props: { session: Session; setNotice: (s: string) => void }, path: string, body: unknown, onOK?: () => void) {
  return api(path, props.session, { method: "POST", body: JSON.stringify(body) }).then((r) => {
    props.setNotice(errorOrOK(r));
    if (!r.error) onOK?.();
  });
}

function patchJSON(props: { session: Session; setNotice: (s: string) => void }, path: string, body: unknown, onOK?: () => void) {
  return api(path, props.session, { method: "PATCH", body: JSON.stringify(body) }).then((r) => {
    props.setNotice(errorOrOK(r));
    if (!r.error) onOK?.();
  });
}

function del(props: { session: Session; setNotice: (s: string) => void }, path: string, onOK?: () => void, body?: unknown) {
  return api(path, props.session, { method: "DELETE", body: body ? JSON.stringify(body) : undefined }).then((r) => {
    props.setNotice(errorOrOK(r));
    if (!r.error) onOK?.();
  });
}

function splitList(value: string) {
  return value.split(/[,;\n]+/).map((v) => v.trim()).filter(Boolean);
}

function queryString(values: Record<string, string>) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== "") params.set(key, value);
  });
  return params.toString();
}

function emptyToUndefined(body: Record<string, string>) {
  return Object.fromEntries(Object.entries(body).map(([k, v]) => [k, v === "" ? undefined : v]));
}

function emptyToPatch(body: Record<string, string>) {
  return Object.fromEntries(Object.entries(body).map(([k, v]) => {
    if (v === "") return [k, undefined];
    if (v === "null") return [k, null];
    if (v === "true") return [k, true];
    if (v === "false") return [k, false];
    return [k, v];
  }));
}

function required(value: string, label: string) {
  return value.trim() ? "" : `${label} is required`;
}

function normalizeListValues(values: string[], mode: ListInputMode) {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of values) {
    const value = normalizeListValue(raw, mode);
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function normalizeListValue(value: string, mode: ListInputMode) {
  const trimmed = value.trim().replace(/\.$/, "");
  if (mode === "domain") return trimmed.toLowerCase();
  return trimmed.toLowerCase();
}

function listError(values: string[], label: string, mode: ListInputMode) {
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizeListValue(value, mode);
    if (!normalized) return `${label} has an empty value`;
    const key = normalized.toLowerCase();
    if (seen.has(key)) return `${label} has duplicate value`;
    seen.add(key);
    const error = listItemError(normalized, mode);
    if (error) return `${label}: ${error}`;
  }
  return "";
}

function listItemError(value: string, mode: ListInputMode) {
  const normalized = normalizeListValue(value, mode);
  if (!normalized) return "";
  return mode === "domain" ? validateField("domain", normalized) : validateField("cidr", normalized);
}

function emptyToNull(body: Record<string, string>) {
  return Object.fromEntries(Object.entries(body).map(([k, v]) => [k, v === "" ? null : v]));
}

function tokenCreateBody(body: Record<string, string>) {
  return {
    name: body.name,
    expires_at: body.expires_at === "null" ? null : body.expires_at || undefined
  };
}

function safeJSON(value: string): unknown | undefined {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function validateField(field: string, value: string) {
  if (!value) return "";
  const label = field.toLowerCase();
  if (label.includes("email") && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "invalid email";
  if ((label.includes("url") || label.includes("issuer")) && value && !/^https:\/\/[^\s/$.?#].[^\s]*$/.test(value) && label.includes("url")) return "must be an https URL";
  if (["name", "issuer", "type", "zone_mode", "status", "role", "key_type", "global_role"].some((k) => label === k || label.endsWith(`_${k}`))) {
    if (!/^[a-z0-9][a-z0-9_.-]*$/.test(value)) return "invalid machine value";
  }
  if (label.includes("domain") || (label.includes("zone") && label !== "zone_mode") || label === "value") {
    const domains = splitList(value);
    if (new Set(domains.map((v) => v.toLowerCase())).size !== domains.length) return "duplicate domain";
    for (const domain of domains) {
      if (!/^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i.test(domain)) return "invalid domain";
      if (domain.includes("*") && !domain.startsWith("*.")) return "wildcard must be the full left-most label";
      if (/^\*\.(com|co\.uk)$/i.test(domain)) return "public-suffix wildcard is not allowed";
    }
  }
  if (label.includes("cidr")) {
    for (const cidr of splitList(value)) {
      if (!/^([0-9a-f:.]+)(\/\d{1,3})?$/i.test(cidr)) return "invalid IP or CIDR";
    }
  }
  if (label.includes("expires_at") && value && Number.isNaN(Date.parse(value))) return "invalid date-time";
  if (/[\u0000-\u001f\u007f]/.test(value)) return "control characters are not allowed";
  return "";
}

async function downloadMaterial(session: Session, id: string, setNotice: (s: string) => void) {
  const result = await api<any>(`/v1/certificates/${id}/tls-material`, session);
  if (result.error || !result.data) return setNotice(errorText(result));
  const material = result.data;
  const files = {
    "cert.pem": material.cert_pem,
    "chain.pem": material.chain_pem,
    "fullchain.pem": material.fullchain_pem,
    "privkey.pem": material.private_key_pem
  };
  Object.entries(files).forEach(([name, content]) => saveBlob(name, String(content), "application/x-pem-file"));
  setNotice("downloaded material; private-key access was audited");
}

async function downloadArchive(session: Session, id: string, setNotice: (s: string) => void) {
  const rid = requestID();
  let response = await fetch(`/v1/certificates/${id}/tls-archive`, { headers: { Authorization: `Bearer ${session.accessToken}`, Accept: "application/gzip", "X-Request-ID": rid }, cache: "no-store", redirect: "error" });
  if (response.status === 401 && await refreshSession(session)) {
    response = await fetch(`/v1/certificates/${id}/tls-archive`, { headers: { Authorization: `Bearer ${session.accessToken}`, Accept: "application/gzip", "X-Request-ID": rid }, cache: "no-store", redirect: "error" });
  }
  if (!response.ok) {
    const requestIDHeader = response.headers.get("X-Request-ID") || rid;
    const text = await response.text();
    try {
      const parsed = text ? JSON.parse(text) : undefined;
      const error = parsed?.error || parsed;
      return setNotice(`${error?.code || "archive_failed"}: ${error?.message || `HTTP ${response.status}`} request_id=${requestIDHeader}`);
    } catch {
      return setNotice(`archive_failed: HTTP ${response.status} request_id=${requestIDHeader}`);
    }
  }
  const name = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] || `${id}.tar.gz`;
  saveBlob(name, await response.blob(), "application/gzip");
  setNotice("downloaded archive; private-key access was audited");
}

function saveBlob(name: string, content: BlobPart | Blob, type: string) {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.rel = "noopener";
  a.click();
  URL.revokeObjectURL(a.href);
}

export function App() {
  return createElement(QueryClientProvider, { client: queryClient }, createElement(AppShell));
}
