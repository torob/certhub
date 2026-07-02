import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Activity,
  AppWindow,
  BadgeCheck,
  Copy,
  Download,
  Globe2,
  Home,
  KeyRound,
  Lock,
  LogOut,
  Plus,
  Settings,
  Search,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Users,
  X
} from "lucide-react";
import QRCode from "qrcode";
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
type PageMeta = {
  limit?: number;
  offset?: number;
  total?: number;
};
type ToastNotice = {
  id: number;
  message: string;
  closing: boolean;
};
type TableColumn = string | {
  key: string;
  label?: string;
  render?: (row: any) => unknown;
};
type FilterOption = [string, string];
type FilterField = {
  key: string;
  label: string;
  type?: "text" | "select" | "datetime" | "datalist";
  options?: FilterOption[];
  placeholder?: string;
};
type RuntimeConfig = {
  auth?: {
    oidcEnabled?: boolean;
  };
};

declare global {
  interface Window {
    __CERTHUB_CONFIG__?: RuntimeConfig;
  }
}

const queryClient = new QueryClient();
const sessionKey = "certhub.session.v1";
const authExpiredEvent = "certhub-auth-expired";
const accessRefreshSkewMs = 60_000;
const toastLimit = 4;
const toastVisibleMs = 6_000;
const toastFadeMs = 3_000;
let refreshInFlight: Promise<boolean> | undefined;
let nextNoticeID = 0;
const noticeTimers = new Map<number, number[]>();

function oidcLoginEnabled() {
  return window.__CERTHUB_CONFIG__?.auth?.oidcEnabled === true;
}

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
type ResourceType = "certificate" | "application" | "user" | "issuer" | "dns";
type ApplicationTab = "overview" | "scopes" | "tokens" | "access" | "certificates" | "audit";
type ProfileTab = "overview" | "security";
type RouteState = {
  page: NavID;
  create?: "certificate" | "application" | "user" | "issuer" | "dns";
  detail?: ResourceType;
  edit?: ResourceType;
  id?: string;
  profile?: boolean;
  signup?: boolean;
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
const applicationTabs: { id: ApplicationTab; label: string; managerOnly?: boolean }[] = [
  { id: "overview", label: "Overview" },
  { id: "scopes", label: "Domain scopes", managerOnly: true },
  { id: "tokens", label: "Tokens", managerOnly: true },
  { id: "access", label: "Access", managerOnly: true },
  { id: "certificates", label: "Certificates" },
  { id: "audit", label: "Audit" }
];
const profileTabs: { id: ProfileTab; label: string; userOnly?: boolean }[] = [
  { id: "overview", label: "Overview" },
  { id: "security", label: "Security", userOnly: true }
];

function parseRoute(): RouteState {
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const query = url.searchParams;
  const parts = path.split("/").filter(Boolean);
  if (path === "/signup") return { page: "home", signup: true, path, query };
  if (path === "/profile") return { page: "home", profile: true, path, query };
  if (parts.length === 2 && parts[0] === "certificates" && parts[1] !== "new") return { page: "certificates", detail: "certificate", id: parts[1], path, query };
  if (parts.length === 2 && parts[0] === "applications" && parts[1] !== "new") return { page: "applications", detail: "application", id: parts[1], path, query };
  if (parts.length === 3 && parts[0] === "applications" && parts[2] === "edit") return { page: "applications", detail: "application", edit: "application", id: parts[1], path, query };
  if (parts.length === 2 && parts[0] === "users" && parts[1] !== "new") return { page: "users", detail: "user", id: parts[1], path, query };
  if (parts.length === 3 && parts[0] === "users" && parts[2] === "edit") return { page: "users", detail: "user", edit: "user", id: parts[1], path, query };
  if (parts.length === 2 && parts[0] === "issuers" && parts[1] !== "new") return { page: "issuers", detail: "issuer", id: parts[1], path, query };
  if (parts.length === 3 && parts[0] === "issuers" && parts[2] === "edit") return { page: "issuers", detail: "issuer", edit: "issuer", id: parts[1], path, query };
  if (parts.length === 2 && parts[0] === "dns-providers" && parts[1] !== "new") return { page: "dns", detail: "dns", id: parts[1], path, query };
  if (parts.length === 3 && parts[0] === "dns-providers" && parts[2] === "edit") return { page: "dns", detail: "dns", edit: "dns", id: parts[1], path, query };
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
  const [loginNotice, setLoginNotice] = useState("");
  const [notices, setNotices] = useState<ToastNotice[]>([]);
  const visibleNav = isAdmin(session) ? nav : nav.filter(([id]) => id === "home" || id === "certificates" || id === "applications");
  const clearNoticeTimers = (id: number) => {
    noticeTimers.get(id)?.forEach((timer) => window.clearTimeout(timer));
    noticeTimers.delete(id);
  };
  const dismissNotice = (id: number) => {
    clearNoticeTimers(id);
    setNotices((current) => current.filter((notice) => notice.id !== id));
  };
  const fadeNotice = (id: number) => {
    setNotices((current) => current.map((notice) => notice.id === id ? { ...notice, closing: true } : notice));
    const removeTimer = window.setTimeout(() => dismissNotice(id), toastFadeMs);
    noticeTimers.set(id, [...(noticeTimers.get(id) || []), removeTimer]);
  };
  const setNotice = (message: string) => {
    if (!message) return;
    const id = nextNoticeID + 1;
    nextNoticeID = id;
    setNotices((current) => [...current, { id, message, closing: false }].slice(-toastLimit));
    const fadeTimer = window.setTimeout(() => fadeNotice(id), toastVisibleMs);
    noticeTimers.set(id, [fadeTimer]);
  };
  const navigate = (to: string, replace = false) => {
    if (to !== `${window.location.pathname}${window.location.search}`) {
      window.history[replace ? "replaceState" : "pushState"]({}, "", to);
    }
    setRoute(parseRoute());
  };
  const refreshIdentity = async () => {
    if (!session?.accessToken) return false;
    const result = await api<{ identity: Identity }>("/v1/auth/me", session);
    if (result.data?.identity) {
      const next = { ...session, identity: result.data.identity };
      saveSession(next);
      setSession(next);
      return true;
    }
    if (result.status === 401 || result.status === 403) {
      saveSession(undefined);
      setSession(undefined);
    }
    return false;
  };

  useEffect(() => {
    const listener = () => setSession(undefined);
    window.addEventListener(authExpiredEvent, listener);
    return () => window.removeEventListener(authExpiredEvent, listener);
  }, []);

  useEffect(() => {
    return () => {
      noticeTimers.forEach((timers) => timers.forEach((timer) => window.clearTimeout(timer)));
      noticeTimers.clear();
    };
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
    void refreshIdentity();
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
        setLoginNotice(errorText(result));
      }
    });
  }, []);

  useEffect(() => {
    if (!visibleNav.some(([id]) => id === route.page)) navigate("/", true);
  }, [session?.identity, route.page]);

  if (!session?.accessToken) {
    if (route.signup) return createElement(PublicSignupPage, { route, navigate, onDone: setLoginNotice });
    return createElement(Login, { onLogin: setSession, notice: loginNotice });
  }

  const Page = route.profile ? ProfilePage :
    route.edit === "application" ? ApplicationEditPage :
    route.edit === "user" ? UserEditPage :
    route.edit === "issuer" ? IssuerEditPage :
    route.edit === "dns" ? DNSEditPage :
    route.detail === "certificate" ? CertificateDetailPage :
    route.detail === "application" ? ApplicationDetailPage :
    route.detail === "user" ? UserDetailPage :
    route.detail === "issuer" ? IssuerDetailPage :
    route.detail === "dns" ? DNSDetailPage :
    route.create === "certificate" ? CertificateCreatePage :
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
            { key: id, className: id === route.page && !route.profile ? "nav active" : "nav", onClick: () => navigate(navPaths[id]), title: label },
            createElement(Icon, { size: 18 }),
            createElement("span", null, label)
          )
        )
      ),
      createElement("button", { className: route.profile ? "nav active profile-nav" : "nav profile-nav", onClick: () => navigate("/profile"), title: "Profile" },
        createElement(Settings, { size: 18 }),
        createElement("span", null, identityText(session.identity))
      ),
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
    createElement("main", { className: "workspace" }, createElement(Page, { session, setNotice, navigate, route, refreshIdentity })),
    notices.length ? createElement(ToastStack, { notices, onDismiss: dismissNotice }) : null
  );
}

function Login(props: { onLogin: (s: Session) => void; notice: string }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState(props.notice);
  const showOIDCLogin = oidcLoginEnabled();
  useEffect(() => setError(props.notice), [props.notice]);
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
      showOIDCLogin ? createElement("button", { className: "secondary", onClick: () => (window.location.href = "/v1/auth/oidc/login") }, "OIDC sign in") : null,
      error ? createElement("p", { className: "error" }, error) : null
    )
  );
}

function PublicSignupPage(props: { route: RouteState; navigate: (path: string, replace?: boolean) => void; onDone: (message: string) => void }) {
  const token = props.route.query.get("invite") || "";
  const preview = useAsync<{ invite: any }>(undefined, token ? `/v1/auth/user-invites/${encodeURIComponent(token)}` : "", [token]);
  const invite = preview.data?.invite;
  const [step, setStep] = useState<"profile" | "password" | "totp" | "done">("profile");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [provisioning, setProvisioning] = useState<any>(undefined);
  const [error, setError] = useState("");
  const profileError = required(displayName, "display_name");
  const passwordError = !password ? "password is required" : password.length < 12 ? "password must be at least 12 characters" : password !== confirmPassword ? "passwords do not match" : "";
  const submitPassword = async (e: Event) => {
    e.preventDefault();
    if (passwordError) return setError(passwordError);
    const result = await api<any>(`/v1/auth/user-invites/${encodeURIComponent(token)}/signup`, undefined, {
      method: "POST",
      body: JSON.stringify({ display_name: displayName, password })
    });
    if (result.error) return setError(errorText(result));
    if (result.data?.status === "password_2fa_required") {
      setProvisioning(result.data.password_2fa);
      setStep("totp");
      setError("");
      return;
    }
    props.onDone("Signup completed. Sign in with your new password.");
    props.navigate("/", true);
  };
  const confirm2FA = async (e: Event) => {
    e.preventDefault();
    if (!totp) return setError("totp_code is required");
    const result = await api<any>(`/v1/auth/user-invites/${encodeURIComponent(token)}/signup/confirm-2fa`, undefined, {
      method: "POST",
      body: JSON.stringify({ totp_code: totp })
    });
    if (result.error) return setError(errorText(result));
    props.onDone("Signup completed. Sign in with your new password.");
    props.navigate("/", true);
  };
  if (!token) {
    return createElement("main", { className: "login" },
      createElement("section", { className: "login-panel" },
        createElement("div", { className: "brand large" }, createElement(ShieldCheck, { size: 30 }), createElement("strong", null, "Certhub")),
        createElement("p", { className: "error" }, "invalid_invite: invite token is missing")
      )
    );
  }
  return createElement("main", { className: "login signup-screen" },
    createElement("section", { className: "login-panel signup-panel" },
      createElement("div", { className: "brand large" }, createElement(ShieldCheck, { size: 30 }), createElement("strong", null, "Certhub")),
      preview.loading ? createElement("p", { className: "empty" }, "Loading") : preview.error ? createElement("p", { className: "error" }, errorText(preview)) :
        createElement("form", { className: "create-form signup-form", onSubmit: step === "totp" ? confirm2FA : submitPassword },
          createElement("div", { className: "stepper" },
            createElement("span", { className: step === "profile" ? "active" : "" }, "Profile"),
            createElement("span", { className: step === "password" ? "active" : "" }, "Password"),
            invite?.password_2fa_required ? createElement("span", { className: step === "totp" ? "active" : "" }, "2FA") : null
          ),
          kv("Email", invite?.email),
          kv("Global role", invite?.global_role),
          kv("Expires at", invite?.expires_at),
          step === "profile" ? createElement("section", { className: "form-section" },
            input("display_name", displayName, setDisplayName),
            profileError ? createElement("span", { className: "field-error" }, profileError) : null,
            createElement("div", { className: "toolbar" },
              createElement("button", { className: "primary", type: "button", disabled: Boolean(profileError), onClick: () => setStep("password") }, "Next")
            )
          ) : null,
          step === "password" ? createElement("section", { className: "form-section" },
            input("password", password, setPassword, "password"),
            input("confirm_password", confirmPassword, setConfirmPassword, "password"),
            passwordError ? createElement("span", { className: "field-error" }, passwordError) : null,
            createElement("div", { className: "toolbar" },
              createElement("button", { type: "button", onClick: () => setStep("profile") }, "Back"),
              createElement("button", { className: "primary", disabled: Boolean(passwordError) }, invite?.password_2fa_required ? "Set up 2FA" : "Complete signup")
            )
          ) : null,
          step === "totp" ? createElement("section", { className: "form-section" },
            provisioning?.provisioning_uri ? createElement(QRCodeImage, { value: provisioning.provisioning_uri }) : null,
            kv("Secret", provisioning?.secret),
            input("totp_code", totp, setTotp),
            createElement("div", { className: "toolbar" },
              createElement("button", { type: "button", onClick: () => setStep("password") }, "Back"),
              createElement("button", { className: "primary", disabled: !totp }, "Confirm")
            )
          ) : null,
          error ? createElement("p", { className: "error" }, error) : null
        )
    )
  );
}

function ToastStack(props: { notices: ToastNotice[]; onDismiss: (id: number) => void }) {
  return createElement(
    "div",
    { className: "toast-stack", role: "status", "aria-live": "polite", "aria-atomic": "false" },
    props.notices.map((notice) =>
      createElement(
        "div",
        { key: notice.id, className: notice.closing ? "toast closing" : "toast" },
        createElement("span", null, notice.message),
        createElement(
          "button",
          { type: "button", className: "toast-close", onClick: () => props.onDismiss(notice.id), "aria-label": "Dismiss notification", title: "Dismiss notification" },
          createElement(X, { size: 16 })
        )
      )
    )
  );
}

function ProfilePage(props: PageProps) {
  const identity = props.session.identity as any;
  const identityKnown = Boolean(identity?.id);
  const isUser = Boolean(identity?.email);
  const passwordCapabilityKnown = identityKnown && (!isUser || Object.prototype.hasOwnProperty.call(identity || {}, "password_login_enabled"));
  const hasPasswordLogin = isUser && identity?.password_login_enabled === true;
  const rawTab = props.route.query.get("tab") || "overview";
  const requestedTab = profileTab(rawTab);
  const activeTab = requestedTab === "security" && passwordCapabilityKnown && !hasPasswordLogin ? "overview" : requestedTab;
  const visibleTabs = profileTabs.filter((tab) => !tab.userOnly || hasPasswordLogin || !identityKnown || (isUser && !passwordCapabilityKnown));
  useEffect(() => {
    if (rawTab === activeTab) return;
    props.navigate(profileTabPath(activeTab), true);
  }, [rawTab, activeTab]);
  const overview = createElement("section", { className: "detail" },
    createElement("h2", null, identityText(props.session.identity)),
    kv("Identity type", isUser ? "user" : identity?.name ? "application" : "unknown"),
    identity?.email ? kv("Email", identity.email) : null,
    identity?.name ? kv("Name", identity.name) : null,
    kv("Display name", identity?.display_name || ""),
    identity?.global_role ? kv("Global role", identity.global_role) : null,
    identity?.status ? kv("Status", identity.status) : null
  );
  const tabContent = activeTab === "security" && isUser ?
    createElement(Password2FASection, { session: props.session, setNotice: props.setNotice, refreshIdentity: props.refreshIdentity }) :
    overview;
  return pageFrame(
    identityText(props.session.identity) || "Profile",
    null,
    createElement("div", { className: "tabbed-detail" },
      createElement(Tabs, { activeTab, tabs: visibleTabs, ariaLabel: "Profile sections", pathFor: profileTabPath, navigate: props.navigate }),
      tabContent
    )
  );
}

function Password2FASection(props: { session: Session; setNotice: (s: string) => void; refreshIdentity: () => Promise<boolean> }) {
  const identity = props.session.identity as any;
  const password2FAEnabled = identity?.password_2fa_enabled === true;
  const disableAllowed = identity?.password_2fa_disable_allowed === true;
  const [provisioning, setProvisioning] = useState<any>(undefined);
  const [totp, setTotp] = useState("");
  const [password, setPassword] = useState("");
  return createElement("section", { className: "security-panel" },
    createElement("h2", null, "Password 2FA"),
    kv("Status", password2FAEnabled ? "enabled" : "not configured"),
    provisioning ? createElement("div", { className: "secret-once" },
      provisioning.provisioning_uri ? createElement(QRCodeImage, { value: provisioning.provisioning_uri }) : null,
      kv("Issuer", provisioning.issuer),
      kv("Account", provisioning.account_label),
      kv("Secret", provisioning.secret),
      kv("Provisioning URI", provisioning.provisioning_uri)
    ) : null,
    createElement("div", { className: "split-grid" },
      !password2FAEnabled ? createElement("section", { className: "form-section" },
        createElement("h3", null, "Set up"),
        provisioning ? input("TOTP code", totp, setTotp) : null,
        provisioning ? createElement("button", {
          className: "primary",
          onClick: async () => {
            const result = await api("/v1/auth/password-2fa/confirm", props.session, { method: "POST", body: JSON.stringify({ totp_code: totp }) });
            props.setNotice(errorOrOK(result));
            if (!result.error) {
              setProvisioning(undefined);
              setTotp("");
              await props.refreshIdentity();
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
        }, "Set up")
      ) : null,
      password2FAEnabled && disableAllowed ? createElement("section", { className: "form-section" },
        createElement("h3", null, "Disable"),
        input("Password", password, setPassword, "password"),
        input("TOTP code", totp, setTotp),
        createElement("button", {
          onClick: async () => {
            const result = await api("/v1/auth/password-2fa", props.session, { method: "DELETE", body: JSON.stringify(emptyToUndefined({ password, totp_code: totp })) });
            props.setNotice(errorOrOK(result));
            if (!result.error) {
              setProvisioning(undefined);
              setTotp("");
              setPassword("");
              await props.refreshIdentity();
            }
          }
        }, "Disable")
      ) : null,
      password2FAEnabled && !disableAllowed ? createElement("section", { className: "form-section" },
        createElement("h3", null, "Required by policy"),
        createElement("p", { className: "note" }, "Password 2FA is required by instance policy and cannot be disabled from your profile.")
      ) : null
    )
  );
}

function HomePage(props: PageProps) {
  const ready = useAsync<{ ready: boolean; checks: { name: string; status: string }[] }>(props.session, "/readyz", []);
  const applications = useAsync<{ applications: any[]; pagination?: PageMeta }>(props.session, "/v1/applications?limit=100", []);
  const certificates = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=100", []);
  const pendingCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=1&status=pending", []);
  const validatingCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=1&status=validating_dns", []);
  const issuingCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=1&status=issuing", []);
  const renewingCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=1&status=renewing", []);
  const rotatingCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=1&status=rotating_key", []);
  const failedCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, "/v1/certificates?limit=1&status=failed", []);
  const expiresBefore = useMemo(() => new Date(Date.now() + 30 * 86400 * 1000).toISOString(), []);
  const expiringCerts = useAsync<{ certificates: any[]; pagination?: PageMeta }>(props.session, `/v1/certificates?limit=1&expires_before=${encodeURIComponent(expiresBefore)}`, [expiresBefore]);
  const activeIssuerCount = useAsync<{ issuers: any[]; pagination?: PageMeta }>(props.session, isAdmin(props.session) ? "/v1/issuers?limit=1&status=active" : "", []);
  const providers = useAsync<{ dns_providers: any[]; pagination?: PageMeta }>(props.session, "/v1/dns-providers?limit=100", []);
  const activeProviderCount = useAsync<{ dns_providers: any[]; pagination?: PageMeta }>(props.session, isAdmin(props.session) ? "/v1/dns-providers?limit=1&status=active" : "", []);
  const firstProvider = rowsOf(providers)[0];
  const zones = useAsync<{ zones: any[]; pagination?: PageMeta }>(props.session, isAdmin(props.session) && firstProvider ? `/v1/dns-providers/${firstProvider.id}/zones?limit=100` : "", [firstProvider?.id]);
  const apps = rowsOf(applications).filter((app) => app.system_kind !== "certhub_server" && app.name !== "certhub_server");
  const manageableApps = apps.filter((app) => canManageApplication(app, props.session));
  const certs = rowsOf(certificates);
  const inProgressCounts = [pendingCerts, validatingCerts, issuingCerts, renewingCerts, rotatingCerts];
  const inProgress = inProgressCounts.some((result) => result.loading) ? "Loading" : String(inProgressCounts.reduce((sum, result) => sum + pageTotal(result, 0), 0));
  const setup = activeIssuerCount.loading || activeProviderCount.loading || zones.loading ? "Loading" : setupStatusFromCounts(pageTotal(activeIssuerCount, 0), pageTotal(activeProviderCount, 0), firstProvider ? pageTotal(zones, 0) : 0);
  return pageFrame(
    "Home",
    createElement("div", { className: "toolbar" },
      createElement("button", { className: "primary", disabled: manageableApps.length === 0, onClick: () => props.navigate("/certificates/new") }, createElement(BadgeCheck, { size: 16 }), "Create Certificate"),
      createElement("button", { onClick: () => props.navigate("/certificates") }, "Certificates"),
      createElement("button", { onClick: () => props.navigate("/applications") }, "Applications")
    ),
    createElement("section", { className: "dashboard-grid" },
      readinessCard("Service", ready.loading ? "Loading" : ready.data?.ready ? "Ready" : "Attention", ready.data?.checks?.map((check) => `${check.name}: ${check.status}`) || (ready.error ? [errorText(ready)] : [])),
      readinessCard("Applications", countText(applications), [
        `${manageableApps.length} manageable shown`,
        `${apps.reduce((sum, app) => sum + Number(app.domain_scope_count || 0), 0)} domain scopes shown`,
        `${apps.reduce((sum, app) => sum + Number(app.certificate_count || 0), 0)} certificates shown`
      ]),
      readinessCard("Certificates", countText(certificates), [
        `${inProgress} in progress`,
        `${countText(expiringCerts)} expiring within 30 days`,
        `${countText(failedCerts)} failed`
      ]),
      isAdmin(props.session) ? readinessCard("Issuance setup", setup, [
        `${countText(activeIssuerCount)} active issuers`,
        `${countText(activeProviderCount)} active DNS providers`,
        firstProvider ? zones.loading ? `loading zones on ${firstProvider.name}` : `${pageTotal(zones, rowsOf(zones).length)} zones on ${firstProvider.name}` : "no DNS provider selected"
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
  const [filters, setFilters] = useState({ domain: "", status: "", application_id: "", issuer: "", key_type: "", expires_before: "" });
  const query = queryString({ ...filters, limit: "100" });
  const list = useAsync<{ certificates: any[] }> (props.session, `/v1/certificates?${query}`, [refresh, query]);
  const applications = useAsync<{ applications: any[] }>(props.session, "/v1/applications?limit=100", [refresh]);
  const issuers = useAsync<{ issuers: any[] }>(props.session, isAdmin(props.session) ? "/v1/issuers?limit=100" : "", [refresh]);
  const appByID = resourceMap(rowsOf(applications));
  const manageableApps = rowsOf(applications).filter((app) => canManageApplication(app, props.session) && app.system_kind !== "certhub_server" && app.name !== "certhub_server");
  const issuerOptions: FilterOption[] = rowsOf(issuers).map((issuer) => [issuer.name, `${issuer.name}${issuer.default ? " (default)" : ""}`]);
  const certificateFilterFields: FilterField[] = [
    { key: "domain", label: "Domain", placeholder: "api.example.com" },
    { key: "status", label: "Status", type: "select", options: certificateStatusOptions() },
    { key: "application_id", label: "Application", type: "select", options: rowsOf(applications).map((app) => [app.id, appLabel(app)]) },
    issuerOptions.length ? { key: "issuer", label: "Issuer", type: "select", options: issuerOptions } : { key: "issuer", label: "Issuer", placeholder: "letsencrypt_production" },
    { key: "key_type", label: "Key type", type: "select", options: keyTypeOptions() },
    { key: "expires_before", label: "Expires before", type: "datetime" }
  ];
  return pageFrame(
    "Certificates",
    createElement("div", { className: "header-actions" },
      createElement("button", { className: "primary", disabled: manageableApps.length === 0, onClick: () => props.navigate("/certificates/new") }, createElement(BadgeCheck, { size: 16 }), "Create Certificate"),
      createElement(ListFilters, {
        values: filters,
        quick: certificateFilterFields.slice(0, 2),
        advanced: certificateFilterFields.slice(2),
        onApply: (next: Record<string, string>) => setFilters({ ...filters, ...next })
      })
    ),
    table(list, [
      "status",
      { key: "normalized_sans", label: "Domains" },
      "key_type",
      { key: "issuer_name", label: "Issuer", render: (cert) => cert.issuer_name || "Default issuer" },
      { key: "application", render: (cert) => appLabel(appByID.get(cert.application_id)) || "Application not visible" },
      "updated_at"
    ], (cert) => props.navigate(`/certificates/${cert.id}`))
  );
}

function CertificateDetailPage(props: PageProps) {
  const id = resourceID(props);
  const [refresh, setRefresh] = useState(0);
  const detail = useAsync<{ certificate: any }>(props.session, id ? `/v1/certificates/${id}` : "", [id, refresh]);
  const cert = detail.data?.certificate || {};
  const appAccess = useAsync<{ application: any }>(props.session, cert.application_id ? `/v1/applications/${cert.application_id}` : "", [cert.application_id]);
  const versions = useAsync<{ versions: any[] }>(props.session, id ? `/v1/certificates/${id}/versions?limit=20` : "", [id, refresh]);
  const events = useAsync<{ audit_events: any[] }>(props.session, id ? `/v1/certificates/${id}/events?limit=20` : "", [id, refresh]);
  const action = (path: string, body?: unknown, method = "POST") =>
    api(`/v1/certificates/${id}${path}`, props.session, { method, body: body ? JSON.stringify(body) : undefined }).then((r) => {
      props.setNotice(r.error ? errorText(r) : "request accepted");
      setRefresh(refresh + 1);
    });
  const versionAction = (version: any, path: string, body?: unknown) =>
    api(`/v1/certificates/${id}/versions/${version.id}${path}`, props.session, { method: "POST", body: body ? JSON.stringify(body) : undefined }).then((r) => {
      props.setNotice(r.error ? errorText(r) : "request accepted");
      setRefresh(refresh + 1);
    });
  const expired = cert.status === "expired";
  const appRole = appAccess.data?.application?.current_user_role;
  const applicationLabel = appLabel(appAccess.data?.application) || "Application not visible";
  const appLoaded = Boolean(appAccess.data?.application);
  const appReserved = appAccess.data?.application?.system_kind === "certhub_server" || appAccess.data?.application?.name === "certhub_server";
  const canDownloadArchive = appLoaded && !appReserved && (isAdmin(props.session) || appRole === "certificate_reader" || appRole === "manager");
  const canLifecycle = appLoaded && !appReserved && (isAdmin(props.session) || appRole === "manager");
  const hasActiveValidVersion = cert.has_active_valid_version === true;
  const hasIssuingVersion = cert.has_issuing_version === true;
  const activeVersionRequired = "Requires an active valid certificate version";
  const reissueUnavailable = hasActiveValidVersion ? "Reissue is only available when there is no active valid certificate version" : "Reissue is unavailable while a certificate version is issuing";
  return pageFrame(
    "Certificate",
    createElement("div", { className: "header-actions" },
      createElement("button", { onClick: () => props.navigate("/certificates") }, "Back"),
      canDownloadArchive && !expired ? createElement("button", { onClick: () => downloadArchive(props.session, cert.id, props.setNotice) }, createElement(Download, { size: 16 }), "Download") : null,
      canLifecycle ? createElement("button", { disabled: !hasActiveValidVersion, title: !hasActiveValidVersion ? activeVersionRequired : undefined, onClick: () => action("/renew") }, createElement(RefreshCw, { size: 16 }), "Renew") : null,
      canLifecycle ? createElement("button", { disabled: !hasActiveValidVersion, title: !hasActiveValidVersion ? activeVersionRequired : undefined, onClick: () => action("/rotate-key") }, "Rotate key") : null,
      canLifecycle ? createElement("button", { disabled: hasActiveValidVersion || hasIssuingVersion, title: hasActiveValidVersion || hasIssuingVersion ? reissueUnavailable : undefined, onClick: () => action("/reissue") }, createElement(RefreshCw, { size: 16 }), "Reissue") : null
    ),
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) : createElement("section", { className: "detail" },
      createElement("h2", null, certificateLabel(cert)),
      kv("Application", applicationLabel),
      kv("Domains", (cert.normalized_sans || []).join(", ")),
      kv("Status", cert.status),
      kv("Key type", cert.key_type),
      kv("Issuer", cert.issuer_name || "Default issuer"),
      kv("Latest not after", cert.latest_version?.not_after || ""),
      kv("Fingerprint", cert.latest_version?.fingerprint_sha256 || ""),
      kv("Created at", cert.created_at),
      kv("Updated at", cert.updated_at)
    ),
    createElement("h2", null, "Versions"),
    table(versions, ["version", "status", "reason", "not_after", "revocation_reason", "failure_code",
      actionsColumn((version) => [
        canDownloadArchive && versionDownloadable(version) ? rowAction("Download", () => downloadArchive(props.session, cert.id, props.setNotice, version.id), { icon: Download, label: `Download version ${version.version}` }) : null,
        canLifecycle && version.status === "valid" ? rowAction("Revoke", () => versionAction(version, "/revoke", { reason: "cessation_of_operation" }), { icon: X, danger: true, label: `Revoke version ${version.version}` }) : null
      ])
    ]),
    createElement("h2", null, "Events"),
    table(events, auditColumns())
  );
}

function ApplicationsPage(props: PageProps) {
  const list = useAsync<{ applications: any[] }>(props.session, "/v1/applications?limit=100", []);
  return pageFrame(
    "Applications",
    isAdmin(props.session) ? createElement("button", { className: "primary", onClick: () => props.navigate("/applications/new") }, "Create Application") : null,
    table(list, ["name", "status", "current_user_role", "domain_scope_count", "token_count", "trusted_source_cidr_count", "certificate_count", "system_kind"], (app) => props.navigate(`/applications/${app.id}`))
  );
}

function ApplicationDetailPage(props: PageProps) {
  const id = resourceID(props);
  const base = `/v1/applications/${id}`;
  const [refresh, setRefresh] = useState(0);
  const [tokenValue, setTokenValue] = useState("");
  const detail = useAsync<{ application: any }>(props.session, id ? base : "", [id, refresh]);
  const app = detail.data?.application || {};
  const reserved = app.system_kind === "certhub_server" || app.name === "certhub_server";
  const canManage = !reserved && canManageApplication(app, props.session);
  const appLoaded = Boolean(detail.data?.application);
  const rawTab = props.route.query.get("tab") || "overview";
  const requestedTab = applicationTab(rawTab);
  const activeTab = appLoaded && isManagerApplicationTab(requestedTab) && !canManage ? "overview" : requestedTab;
  const visibleTabs = applicationTabs.filter((tab) => !tab.managerOnly || !appLoaded || canManage);
  const scopes = useAsync<{ domain_scopes: any[] }>(props.session, activeTab === "scopes" && canManage ? `${base}/domain-scopes?limit=100` : "", [id, refresh, activeTab, canManage]);
  const tokens = useAsync<{ tokens: any[] }>(props.session, activeTab === "tokens" && canManage ? `${base}/tokens?limit=100` : "", [id, refresh, activeTab, canManage]);
  const grants = useAsync<{ grants: any[] }>(props.session, activeTab === "access" && canManage ? `${base}/users?limit=100` : "", [id, refresh, activeTab, canManage]);
  const certs = useAsync<{ certificates: any[] }>(props.session, activeTab === "certificates" ? `/v1/certificates?application=${encodeURIComponent(id)}&limit=100` : "", [id, refresh, activeTab]);
  const events = useAsync<{ audit_events: any[] }>(props.session, activeTab === "audit" ? `/v1/audit-events?application_id=${encodeURIComponent(id)}&limit=50` : "", [id, refresh, activeTab]);
  useEffect(() => {
    setTokenValue("");
  }, [id]);
  useEffect(() => {
    if (activeTab !== "tokens") setTokenValue("");
  }, [activeTab]);
  useEffect(() => {
    if (!id || !appLoaded || rawTab === activeTab) return;
    props.navigate(applicationTabPath(id, activeTab), true);
  }, [id, appLoaded, rawTab, activeTab]);
  const overview = createElement("section", { className: "detail" },
    createElement("h2", null, appLabel(app)),
    reserved ? createElement("p", { className: "note" }, "System-managed Application. Changes come from backend process configuration.") : null,
    kv("Status", app.status),
    kv("Current user role", app.current_user_role),
    kv("Description", app.description || ""),
    kv("Trusted CIDRs", (app.trusted_source_cidrs || []).join(", ") || "none"),
    kv("Domain scopes", app.domain_scope_count),
    kv("Tokens", app.token_count),
    kv("Certificates", app.certificate_count),
    kv("Created at", app.created_at),
    kv("Updated at", app.updated_at)
  );
  const tabContent =
    activeTab === "overview" ? overview :
    activeTab === "scopes" ? createElement("section", { className: "tab-panel" },
      createElement("div", { className: "section-head" }, createElement("h2", null, "Domain scopes")),
      canManage ? createElement(GenericCreate, { title: "Add scope", fields: ["value"], onSubmit: (body: Record<string, string>) => post({ session: props.session, setNotice: props.setNotice }, `${base}/domain-scopes`, body, () => setRefresh(refresh + 1)) }) : null,
      table(scopes, ["value", "kind", "created_at", canManage ? actionsColumn((scope) => rowAction("Delete", () => del({ session: props.session, setNotice: props.setNotice }, `${base}/domain-scopes/${scope.id}`, () => setRefresh(refresh + 1)), { icon: Trash2, danger: true, label: `Delete ${scope.value}` })) : null].filter(Boolean) as TableColumn[])
    ) :
    activeTab === "tokens" ? createElement("section", { className: "tab-panel" },
      createElement("div", { className: "section-head" }, createElement("h2", null, "Tokens")),
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
      table(tokens, ["name", "status", "expires_at", "last_used_at", canManage ? actionsColumn((token) => rowAction("Revoke", () => del({ session: props.session, setNotice: props.setNotice }, `${base}/tokens/${token.id}`, () => setRefresh(refresh + 1)), { icon: Trash2, danger: true, label: `Revoke ${token.name}` })) : null].filter(Boolean) as TableColumn[])
    ) :
    activeTab === "access" ? createElement("section", { className: "tab-panel" },
      createElement("div", { className: "section-head" }, createElement("h2", null, "Access")),
      canManage ? createElement(GrantForm, { session: props.session, applicationID: app.id, setNotice: props.setNotice, onDone: () => setRefresh(refresh + 1) }) : null,
      table(grants, [{ key: "user", render: (grant: any) => userLabel(grant.user) || "User not visible" }, "role", "created_at", canManage ? actionsColumn((grant) => rowAction("Remove", () => del({ session: props.session, setNotice: props.setNotice }, `${base}/users/${grant.user_id}`, () => setRefresh(refresh + 1)), { icon: Trash2, danger: true, label: `Remove ${userLabel(grant.user) || "user"}` })) : null].filter(Boolean) as TableColumn[])
    ) :
    activeTab === "certificates" ? createElement("section", { className: "tab-panel" },
      createElement("div", { className: "section-head" },
        createElement("h2", null, "Certificates"),
        canManage ? createElement("button", { className: "primary", onClick: () => props.navigate(`/certificates/new?application_id=${encodeURIComponent(app.id)}`) }, createElement(BadgeCheck, { size: 16 }), "Create Certificate") : null
      ),
      table(certs, ["status", "normalized_sans", "key_type", "issuer_name", "updated_at"], (cert) => props.navigate(`/certificates/${cert.id}`))
    ) :
    createElement("section", { className: "tab-panel" },
      createElement("div", { className: "section-head" }, createElement("h2", null, "Audit events")),
      table(events, auditColumns({ application: app }))
    );
  return pageFrame(app.name || "Application",
    createElement("div", { className: "header-actions" },
      createElement("button", { onClick: () => props.navigate("/applications") }, "Back"),
      canManage ? createElement("button", { className: "primary", onClick: () => props.navigate(`/applications/${id}/edit`) }, "Edit") : null
    ),
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) : createElement("div", { className: "tabbed-detail" },
      createElement(Tabs, { activeTab, tabs: visibleTabs, ariaLabel: "Application sections", pathFor: (tab: ApplicationTab) => applicationTabPath(id, tab), navigate: props.navigate }),
      tabContent
    )
  );
}

function ApplicationEditPage(props: PageProps) {
  const id = resourceID(props);
  const detail = useAsync<{ application: any }>(props.session, id ? `/v1/applications/${id}` : "", [id]);
  const app = detail.data?.application;
  const [body, setBody] = useState({ display_name: "", description: "", status: "active", trusted_source_cidrs: [] as string[] });
  useEffect(() => {
    if (!app) return;
    setBody({ display_name: app.display_name || "", description: app.description || "", status: app.status || "active", trusted_source_cidrs: app.trusted_source_cidrs || [] });
  }, [app?.id]);
  const submit = (e: Event) => {
    e.preventDefault();
    const cidrError = listError(body.trusted_source_cidrs, "trusted_source_cidrs", "ip_or_cidr");
    const error = required(body.display_name, "display_name") || validateField("status", body.status) || cidrError;
    if (error) return props.setNotice(error);
    patchJSON({ session: props.session, setNotice: props.setNotice }, `/v1/applications/${id}`, {
      display_name: body.display_name,
      description: body.description || null,
      status: body.status,
      trusted_source_cidrs: body.trusted_source_cidrs
    }, () => props.navigate(`/applications/${id}`));
  };
  return createPage("Edit Application", `/applications/${id}`, props.navigate,
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) :
      createElement("form", { className: "create-form", onSubmit: submit },
        input("display_name", body.display_name, (v) => setBody({ ...body, display_name: v })),
        textAreaInput("description", body.description, (v) => setBody({ ...body, description: v })),
        selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
        createElement(ListInput, { label: "trusted_source_cidrs", values: body.trusted_source_cidrs, onChange: (v: string[]) => setBody({ ...body, trusted_source_cidrs: v }), mode: "ip_or_cidr", placeholder: "203.0.113.10" }),
        formActions("Save", `/applications/${id}`, props.navigate)
      )
  );
}

function UsersPage(props: PageProps) {
  const list = useAsync<{ users: any[] }>(props.session, "/v1/users?limit=100", []);
  if (!isAdmin(props.session)) return forbiddenPage("Users");
  return pageFrame("Users",
    createElement("button", { className: "primary", onClick: () => props.navigate("/users/new") }, "Create User"),
    table(list, ["email", "display_name", "global_role", "status", "oidc_linked", "application_grant_count", "last_login_at"], (user) => props.navigate(`/users/${user.id}`))
  );
}

function UserDetailPage(props: PageProps) {
  const id = resourceID(props);
  const detail = useAsync<{ user: any }>(props.session, id ? `/v1/users/${id}` : "", [id]);
  const user = detail.data?.user || {};
  if (!isAdmin(props.session)) return forbiddenPage("Users");
  return pageFrame(user.email || "User",
    createElement("div", { className: "header-actions" },
      createElement("button", { onClick: () => props.navigate("/users") }, "Back"),
      createElement("button", { className: "primary", onClick: () => props.navigate(`/users/${id}/edit`) }, "Edit")
    ),
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) : createElement("section", { className: "detail" },
      createElement("h2", null, user.email),
      kv("Display name", user.display_name),
      kv("Global role", user.global_role),
      kv("Status", user.status),
      kv("Password login", user.password_login_enabled ? "enabled" : "disabled"),
      kv("Password 2FA", user.password_2fa_enabled ? "enabled" : "disabled"),
      kv("OIDC", user.oidc_linked ? "linked" : "not linked"),
      kv("Application grants", user.application_grant_count),
      kv("Last login", user.last_login_at || ""),
      kv("Created at", user.created_at),
      kv("Updated at", user.updated_at)
    ),
    createElement("h2", null, "Application grants"),
    table({ data: { grants: user.application_grants || [] } }, ["application_name", "role", "created_at"])
  );
}

function UserEditPage(props: PageProps) {
  const id = resourceID(props);
  const detail = useAsync<{ user: any }>(props.session, id ? `/v1/users/${id}` : "", [id]);
  const user = detail.data?.user;
  const [password2FA, setPassword2FA] = useState<any>(undefined);
  const [body, setBody] = useState({ display_name: "", global_role: "user", status: "active", password: "", provision_password_2fa: false, reset_password_2fa: false });
  useEffect(() => {
    if (!user) return;
    setBody((current) => ({ ...current, display_name: user.display_name || "", global_role: user.global_role || "user", status: user.status || "active", password: "" }));
  }, [user?.id]);
  if (!isAdmin(props.session)) return forbiddenPage("Users");
  const submit = async (e: Event) => {
    e.preventDefault();
    const error = required(body.display_name, "display_name") || validateField("global_role", body.global_role) || validateField("status", body.status) || (body.password && body.password.length < 12 ? "password must be at least 12 characters" : "");
    if (error) return props.setNotice(error);
    setPassword2FA(undefined);
    const patch: Record<string, unknown> = {
      display_name: body.display_name,
      global_role: body.global_role,
      status: body.status
    };
    if (body.password) {
      patch.password = body.password;
      patch.provision_password_2fa = body.provision_password_2fa;
    }
    if (body.reset_password_2fa) patch.reset_password_2fa = true;
    const result = await api<any>(`/v1/users/${id}`, props.session, { method: "PATCH", body: JSON.stringify(patch) });
    if (result.data?.password_2fa) setPassword2FA(result.data.password_2fa);
    props.setNotice(errorOrOK(result));
    if (!result.error && !result.data?.password_2fa) props.navigate(`/users/${id}`);
  };
  return createPage("Edit User", `/users/${id}`, props.navigate,
    password2FA?.provisioning_uri ? createElement("div", { className: "secret-once" }, kv("Provisioning URI", password2FA.provisioning_uri), kv("Secret", password2FA.secret), createElement("button", { className: "primary", onClick: () => props.navigate(`/users/${id}`) }, "Done")) : null,
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) :
      createElement("form", { className: "create-form", onSubmit: submit },
        input("display_name", body.display_name, (v) => setBody({ ...body, display_name: v })),
        selectInput("global_role", body.global_role, (v) => setBody({ ...body, global_role: v }), [["user", "User"], ["admin", "Admin"]]),
        selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
        input("password", body.password, (v) => setBody({ ...body, password: v }), "password"),
        checkboxInput("provision_password_2fa", body.provision_password_2fa, (v) => setBody({ ...body, provision_password_2fa: v })),
        checkboxInput("reset_password_2fa", body.reset_password_2fa, (v) => setBody({ ...body, reset_password_2fa: v })),
        formActions("Save", `/users/${id}`, props.navigate)
      )
  );
}

function IssuersPage(props: PageProps) {
  const list = useAsync<{ issuers: any[] }>(props.session, "/v1/issuers?limit=100", []);
  if (!isAdmin(props.session)) return forbiddenPage("Issuers");
  return pageFrame("Issuers",
    createElement("button", { className: "primary", onClick: () => props.navigate("/issuers/new") }, "Create Issuer"),
    table(list, ["name", "type", "directory_url", "environment", "status", "default", "renewal_window_seconds"], (issuer) => props.navigate(`/issuers/${issuer.id}`))
  );
}

function IssuerDetailPage(props: PageProps) {
  const id = resourceID(props);
  const detail = useAsync<{ issuer: any }>(props.session, id ? `/v1/issuers/${id}` : "", [id]);
  const issuer = detail.data?.issuer || {};
  if (!isAdmin(props.session)) return forbiddenPage("Issuers");
  return pageFrame(issuer.name || "Issuer",
    createElement("div", { className: "header-actions" },
      createElement("button", { onClick: () => props.navigate("/issuers") }, "Back"),
      createElement("button", { className: "primary", onClick: () => props.navigate(`/issuers/${id}/edit`) }, "Edit")
    ),
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) : createElement("section", { className: "detail" },
      createElement("h2", null, issuer.name),
      kv("Type", issuer.type),
      kv("Directory URL", issuer.directory_url),
      kv("Environment", issuer.environment),
      kv("Default", issuer.default ? "yes" : "no"),
      kv("Status", issuer.status),
      kv("Renewal window seconds", issuer.renewal_window_seconds),
      kv("Contact email", issuer.contact_email),
      kv("ACME account", issuer.acme_account_status || ""),
      kv("Created at", issuer.created_at),
      kv("Updated at", issuer.updated_at)
    )
  );
}

function IssuerEditPage(props: PageProps) {
  const id = resourceID(props);
  const detail = useAsync<{ issuer: any }>(props.session, id ? `/v1/issuers/${id}` : "", [id]);
  const issuer = detail.data?.issuer;
  const [body, setBody] = useState({ default: false, status: "active", renewal_window_seconds: "2592000", contact_email: "" });
  useEffect(() => {
    if (!issuer) return;
    setBody({ default: Boolean(issuer.default), status: issuer.status || "active", renewal_window_seconds: String(issuer.renewal_window_seconds || 2592000), contact_email: issuer.contact_email || "" });
  }, [issuer?.id]);
  if (!isAdmin(props.session)) return forbiddenPage("Issuers");
  const submit = (e: Event) => {
    e.preventDefault();
    const error = validateField("status", body.status) || validateField("contact_email", body.contact_email) || (Number(body.renewal_window_seconds) <= 0 ? "renewal_window_seconds must be positive" : "");
    if (error) return props.setNotice(error);
    patchJSON({ session: props.session, setNotice: props.setNotice }, `/v1/issuers/${id}`, {
      default: body.default,
      status: body.status,
      renewal_window_seconds: Number(body.renewal_window_seconds),
      contact_email: body.contact_email
    }, () => props.navigate(`/issuers/${id}`));
  };
  return createPage("Edit Issuer", `/issuers/${id}`, props.navigate,
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) :
      createElement("form", { className: "create-form", onSubmit: submit },
        checkboxInput("default", body.default, (v) => setBody({ ...body, default: v })),
        selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
        input("renewal_window_seconds", body.renewal_window_seconds, (v) => setBody({ ...body, renewal_window_seconds: v }), "number"),
        input("contact_email", body.contact_email, (v) => setBody({ ...body, contact_email: v }), "email"),
        formActions("Save", `/issuers/${id}`, props.navigate)
      )
  );
}

function DNSPage(props: PageProps) {
  const list = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", []);
  if (!isAdmin(props.session)) return forbiddenPage("DNS Providers");
  return pageFrame(
    "DNS Providers",
    createElement("button", { className: "primary", onClick: () => props.navigate("/dns-providers/new") }, "Create DNS Provider"),
    table(list, ["name", "type", "zone_mode", "status", "zone_refresh_status", "last_zone_refresh_at"], (provider) => props.navigate(`/dns-providers/${provider.id}`))
  );
}

function DNSDetailPage(props: PageProps) {
  const id = resourceID(props);
  const [refresh, setRefresh] = useState(0);
  const detail = useAsync<{ dns_provider: any }>(props.session, id ? `/v1/dns-providers/${id}` : "", [id, refresh]);
  const provider = detail.data?.dns_provider || {};
  const providers = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", [refresh]);
  const providerByID = resourceMap(rowsOf(providers));
  const zones = useAsync<{ zones: any[] }>(props.session, id ? `/v1/dns-providers/${id}/zones?limit=100` : "", [id, refresh]);
  const discovered = useAsync<{ zones: any[] }>(props.session, id ? `/v1/dns-providers/${id}/zones/discovered?limit=100` : "", [id, refresh]);
  const base = `/v1/dns-providers/${id}`;
  if (!isAdmin(props.session)) return forbiddenPage("DNS Providers");
  return pageFrame(provider.name || "DNS Provider",
    createElement("div", { className: "header-actions" },
      createElement("button", { onClick: () => props.navigate("/dns-providers") }, "Back"),
      createElement("button", { className: "primary", onClick: () => props.navigate(`/dns-providers/${id}/edit`) }, "Edit")
    ),
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) : createElement("section", { className: "detail" },
      createElement("h2", null, provider.name),
      kv("Type", provider.type),
      kv("Zone mode", provider.zone_mode),
      kv("Status", provider.status),
      kv("Refresh status", provider.zone_refresh_status),
      provider.zone_refresh_failure_code ? kv("Refresh failure", `${provider.zone_refresh_failure_code}: ${provider.zone_refresh_failure_message || ""}`) : null,
      kv("Last zone refresh", provider.last_zone_refresh_at || ""),
      kv("Created at", provider.created_at),
      kv("Updated at", provider.updated_at)
    ),
    createElement("div", { className: "toolbar" }, createElement("button", { onClick: () => post({ session: props.session, setNotice: props.setNotice }, `${base}/zones/refresh`, {}, () => setRefresh(refresh + 1)) }, createElement(RefreshCw, { size: 16 }), "Refresh zones")),
    provider.zone_mode === "manual" ? createElement(GenericCreate, { title: "Add zone", fields: ["zone_name"], onSubmit: (body: Record<string, string>) => post({ session: props.session, setNotice: props.setNotice }, `${base}/zones`, body, () => setRefresh(refresh + 1)) }) : null,
    createElement("h2", null, "Zones"),
    table(zones, ["zone_name", "created_at", provider.zone_mode === "manual" ? actionsColumn((zone) => rowAction("Delete", () => del({ session: props.session, setNotice: props.setNotice }, `${base}/zones/${zone.id}`, () => setRefresh(refresh + 1)), { icon: Trash2, danger: true, label: `Delete ${zone.zone_name}` })) : null].filter(Boolean) as TableColumn[]),
    createElement("h2", null, "Discovered zones"),
    table(discovered, ["zone_name", "already_configured", { key: "conflict_dns_provider", render: (zone: any) => dnsProviderLabel(providerByID.get(zone.conflict_dns_provider_id)) || (zone.conflict_dns_provider_id ? "Configured by another provider" : "") }, provider.zone_mode === "manual" ? actionsColumn((zone) => rowAction("Add", () => post({ session: props.session, setNotice: props.setNotice }, `${base}/zones`, { zone_name: zone.zone_name }, () => setRefresh(refresh + 1)), { icon: Plus, disabled: zone.already_configured, label: `Add ${zone.zone_name}` })) : null].filter(Boolean) as TableColumn[])
  );
}

function DNSEditPage(props: PageProps) {
  const id = resourceID(props);
  const detail = useAsync<{ dns_provider: any }>(props.session, id ? `/v1/dns-providers/${id}` : "", [id]);
  const provider = detail.data?.dns_provider;
  const [body, setBody] = useState({ zone_mode: "auto", status: "active", api_token: "", api_key: "" });
  useEffect(() => {
    if (!provider) return;
    setBody({ zone_mode: provider.zone_mode || "auto", status: provider.status || "active", api_token: "", api_key: "" });
  }, [provider?.id]);
  if (!isAdmin(props.session)) return forbiddenPage("DNS Providers");
  const submit = (e: Event) => {
    e.preventDefault();
    const error = validateField("zone_mode", body.zone_mode) || validateField("status", body.status);
    if (error) return props.setNotice(error);
    const payload: Record<string, unknown> = { zone_mode: body.zone_mode, status: body.status };
    if (provider?.type === "cloudflare" && body.api_token) payload.credentials = { api_token: body.api_token };
    if (provider?.type === "arvancloud" && body.api_key) payload.credentials = { api_key: body.api_key };
    patchJSON({ session: props.session, setNotice: props.setNotice }, `/v1/dns-providers/${id}`, payload, () => props.navigate(`/dns-providers/${id}`));
  };
  return createPage("Edit DNS Provider", `/dns-providers/${id}`, props.navigate,
    detail.loading ? createElement("div", { className: "empty" }, "Loading") : detail.error ? createElement("div", { className: "error" }, detail.error.code, ": ", detail.error.message) :
      createElement("form", { className: "create-form", onSubmit: submit },
        selectInput("zone_mode", body.zone_mode, (v) => setBody({ ...body, zone_mode: v }), [["auto", "Auto"], ["manual", "Manual"]]),
        selectInput("status", body.status, (v) => setBody({ ...body, status: v }), statusOptions()),
        provider?.type === "cloudflare" ? input("api_token", body.api_token, (v) => setBody({ ...body, api_token: v }), "password") : null,
        provider?.type === "arvancloud" ? input("api_key", body.api_key, (v) => setBody({ ...body, api_key: v }), "password") : null,
        formActions("Save", `/dns-providers/${id}`, props.navigate)
      )
  );
}

function AuditPage(props: PageProps) {
  const [filters, setFilters] = useState({ identity_id: "", identity_type: "", action: "", certificate_id: "", application_id: "", target_type: "", target_id: "", result: "", created_at_from: "", created_at_to: "" });
  const query = queryString({ ...filters, limit: "100" });
  const list = useAsync<{ audit_events: any[] }>(props.session, `/v1/audit-events?${query}`, [query]);
  const applications = useAsync<{ applications: any[] }>(props.session, "/v1/applications?limit=100", []);
  const users = useAsync<{ users: any[] }>(props.session, "/v1/users?limit=100", []);
  const certificates = useAsync<{ certificates: any[] }>(props.session, "/v1/certificates?limit=100", []);
  const issuers = useAsync<{ issuers: any[] }>(props.session, "/v1/issuers?limit=100", []);
  const providers = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", []);
  const labels = {
    applications: resourceMap(rowsOf(applications)),
    users: resourceMap(rowsOf(users)),
    certificates: resourceMap(rowsOf(certificates)),
    issuers: resourceMap(rowsOf(issuers)),
    providers: resourceMap(rowsOf(providers))
  };
  const auditFields: FilterField[] = [
    { key: "action", label: "Action", type: "datalist", options: auditActionOptions(), placeholder: "private_key_read" },
    { key: "result", label: "Result", type: "select", options: [["success", "Success"], ["failure", "Failure"]] },
    { key: "created_at_from", label: "From", type: "datetime" },
    { key: "created_at_to", label: "To", type: "datetime" },
    { key: "identity_type", label: "Identity type", type: "select", options: [["user", "User"], ["application", "Application"], ["system", "System"]] },
    { key: "identity_id", label: "Identity ID", placeholder: "UUID" },
    { key: "application_id", label: "Application", type: "select", options: rowsOf(applications).map((app) => [app.id, appLabel(app)]) },
    { key: "certificate_id", label: "Certificate", type: "select", options: rowsOf(certificates).map((cert) => [cert.id, certificateLabel(cert)]) },
    { key: "target_type", label: "Target type", type: "datalist", options: targetTypeOptions(), placeholder: "certificate" },
    { key: "target_id", label: "Target ID", placeholder: "UUID" }
  ];
  if (!isAdmin(props.session)) return forbiddenPage("Audit Events");
  return pageFrame("Audit Events",
    createElement(ListFilters, {
      values: filters,
      quick: auditFields.slice(0, 4),
      advanced: auditFields.slice(4),
      onApply: (next: Record<string, string>) => setFilters({ ...filters, ...next })
    }),
    table(list, auditColumns(labels))
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
  const [body, setBody] = useState({ email: "", global_role: "user" });
  const [invite, setInvite] = useState<any>(undefined);
  if (!isAdmin(props.session)) return forbiddenPage("Users");
  const formError = required(body.email, "email") || validateField("email", body.email) || validateField("global_role", body.global_role);
  const submit = async (e: Event) => {
    e.preventDefault();
    if (formError) return props.setNotice(formError);
    const result = await api<any>("/v1/users", props.session, { method: "POST", body: JSON.stringify(body) });
    props.setNotice(errorOrOK(result));
    if (result.data?.invite) setInvite(result.data.invite);
  };
  const copyInvite = async () => {
    if (!invite?.invite_url) return;
    await navigator.clipboard.writeText(invite.invite_url);
    props.setNotice("copied");
  };
  return createPage("Invite User", "/users", props.navigate,
    invite ? createElement("section", { className: "detail secret-once" },
      createElement("h2", null, "Invite Link"),
      kv("Email", invite.email),
      kv("Global role", invite.global_role),
      kv("Expires at", invite.expires_at),
      kv("Invite URL", invite.invite_url),
      createElement("div", { className: "toolbar" },
        createElement("button", { className: "primary", type: "button", onClick: copyInvite }, createElement(Copy, { size: 16 }), "Copy"),
        createElement("button", { type: "button", onClick: () => props.navigate("/users") }, "Back to Users")
      )
    ) : null,
    createElement("form", { className: "create-form", onSubmit: submit },
      createElement("section", { className: "form-section" },
        input("email", body.email, (v) => setBody({ ...body, email: v }), "email"),
        selectInput("global_role", body.global_role, (v) => setBody({ ...body, global_role: v }), [["user", "User"], ["admin", "Admin"]]),
        formError ? createElement("span", { className: "field-error" }, formError) : null,
        formActions("Create Invite", "/users", props.navigate)
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

type PageProps = { session: Session; setNotice: (s: string) => void; navigate: (path: string, replace?: boolean) => void; route: RouteState; refreshIdentity: () => Promise<boolean> };

function ListFilters(props: { values: Record<string, string>; quick: FilterField[]; advanced: FilterField[]; onApply: (values: Record<string, string>) => void }) {
  const allFields = [...props.quick, ...props.advanced];
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<Record<string, string>>(props.values);
  const fieldSignature = allFields.map((field) => `${field.key}:${field.options?.map(([value]) => value).join(",") || ""}`).join("|");
  useEffect(() => {
    setDraft(props.values);
  }, [JSON.stringify(props.values), fieldSignature]);
  const activeFields = allFields.filter((field) => props.values[field.key]);
  const apply = (next = draft) => props.onApply(cleanFilterValues(next, allFields));
  const reset = () => {
    const empty = emptyFilterValues(allFields);
    setDraft(empty);
    props.onApply(empty);
  };
  const remove = (key: string) => {
    const next = { ...props.values, [key]: "" };
    setDraft(next);
    props.onApply(cleanFilterValues(next, allFields));
  };
  return createElement("form", { className: "filter-panel", onSubmit: (e: Event) => {
    e.preventDefault();
    apply();
  } },
    createElement("div", { className: "filter-toolbar" },
      createElement("div", { className: "filter-quick" },
        props.quick.map((field) => renderFilterField(field, draft[field.key] || "", (value) => setDraft({ ...draft, [field.key]: value })))
      ),
      createElement("div", { className: "filter-actions" },
        createElement("button", { className: "primary", type: "submit" }, createElement(Search, { size: 15 }), "Apply"),
        createElement("button", { type: "button", onClick: () => setOpen(!open), "aria-expanded": open },
          createElement(SlidersHorizontal, { size: 15 }),
          "Filters",
          activeFields.length ? createElement("span", { className: "filter-count" }, activeFields.length) : null
        ),
        activeFields.length ? createElement("button", { type: "button", onClick: reset }, "Clear") : null
      )
    ),
    open ? createElement("div", { className: "filter-drawer" },
      createElement("div", { className: "filter-grid" },
        props.advanced.map((field) => renderFilterField(field, draft[field.key] || "", (value) => setDraft({ ...draft, [field.key]: value })))
      )
    ) : null,
    activeFields.length ? createElement("div", { className: "filter-chips" },
      activeFields.map((field) => createElement("button", { key: field.key, type: "button", className: "filter-chip", onClick: () => remove(field.key), title: `Remove ${field.label}` },
        createElement("span", null, `${field.label}: ${filterValueLabel(field, props.values[field.key])}`),
        createElement(X, { size: 13 })
      ))
    ) : null
  );
}

function renderFilterField(field: FilterField, value: string, onChange: (value: string) => void) {
  const listID = `filter-${field.key}-options`;
  if (field.type === "select") {
    return createElement("label", { key: field.key, className: "filter-field" },
      createElement("span", null, field.label),
      createElement("select", { value, onChange: (e: Event) => onChange((e.target as HTMLSelectElement).value) },
        createElement("option", { value: "" }, "Any"),
        (field.options || []).map(([optionValue, optionLabel]) => createElement("option", { key: optionValue, value: optionValue }, optionLabel))
      )
    );
  }
  if (field.type === "datetime") {
    return createElement("label", { key: field.key, className: "filter-field" },
      createElement("span", null, field.label),
      createElement("input", {
        value: localDateTimeInputValue(value),
        type: "datetime-local",
        onChange: (e: Event) => onChange(rfc3339FromLocalInput((e.target as HTMLInputElement).value)),
        autoComplete: "off"
      })
    );
  }
  return createElement("label", { key: field.key, className: "filter-field" },
    createElement("span", null, field.label),
    createElement("input", {
      value,
      list: field.type === "datalist" ? listID : undefined,
      placeholder: field.placeholder || "",
      onChange: (e: Event) => onChange((e.target as HTMLInputElement).value),
      autoComplete: "off"
    }),
    field.type === "datalist" ? createElement("datalist", { id: listID }, (field.options || []).map(([optionValue, optionLabel]) => createElement("option", { key: optionValue, value: optionValue, label: optionLabel }))) : null
  );
}

function filterValueLabel(field: FilterField, value: string) {
  if (field.type === "datetime") return formatDateTime(value);
  const option = field.options?.find(([optionValue]) => optionValue === value);
  return option?.[1] || value;
}

function cleanFilterValues(values: Record<string, string>, fields: FilterField[]) {
  return Object.fromEntries(fields.map((field) => [field.key, values[field.key] || ""]));
}

function emptyFilterValues(fields: FilterField[]) {
  return Object.fromEntries(fields.map((field) => [field.key, ""]));
}

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
  const [body, setBody] = useState({ email: "", role: "viewer" });
  return createElement("form", { className: "inline-form", onSubmit: async (e: Event) => {
    e.preventDefault();
    if (!body.email) {
      props.setNotice("email is required");
      return;
    }
    const lookup = await api<any>(`/v1/users/lookup?email=${encodeURIComponent(body.email)}&application_id=${encodeURIComponent(props.applicationID)}`, props.session);
    const userID = lookup.data?.user?.id;
    if (!userID) {
      props.setNotice(errorText(lookup));
      return;
    }
    const result = await api(`/v1/applications/${props.applicationID}/users/${userID}`, props.session, { method: "PUT", body: JSON.stringify({ role: body.role }) });
    props.setNotice(errorOrOK(result));
    if (!result.error) props.onDone();
  } },
    createElement("strong", null, "Put grant"),
    input("email", body.email, (v) => setBody({ ...body, email: v }), "email"),
    selectInput("role", body.role, (v) => setBody({ ...body, role: v }), [["viewer", "Viewer"], ["certificate_reader", "Certificate reader"], ["manager", "Manager"]]),
    createElement("button", { className: "primary" }, "Save grant")
  );
}

function IssueCertificateFlow(props: { session: Session; setNotice: (s: string) => void; onDone: () => void; onCancel?: () => void; applicationID?: string; applications?: any[] }) {
  const locked = Boolean(props.applicationID);
  const appList = useAsync<{ applications: any[] }>(props.session, props.applications ? "" : "/v1/applications?limit=100", []);
  const issuers = useAsync<{ issuers: any[] }>(props.session, "/v1/issuers?limit=100", []);
  const activeIssuerCount = useAsync<{ issuers: any[]; pagination?: PageMeta }>(props.session, "/v1/issuers?limit=1&status=active", []);
  const providers = useAsync<{ dns_providers: any[] }>(props.session, "/v1/dns-providers?limit=100", []);
  const activeProviderCount = useAsync<{ dns_providers: any[]; pagination?: PageMeta }>(props.session, "/v1/dns-providers?limit=1&status=active", []);
  const [body, setBody] = useState({ application_id: props.applicationID || "", domains: [] as string[], key_type: "ecdsa-p256", issuer: "" });
  const scopePath = body.application_id ? `/v1/applications/${body.application_id}/domain-scopes?limit=100` : "";
  const scopes = useAsync<{ domain_scopes: any[] }>(props.session, scopePath, [body.application_id]);
  const applications = (props.applications || rowsOf(appList)).filter((app) => canManageApplication(app, props.session) && app.system_kind !== "certhub_server" && app.name !== "certhub_server");
  const selectedApp = applications.find((app) => app.id === body.application_id);
  const domains = body.domains;
  const scopeValues = rowsOf(scopes).map((scope) => String(scope.value || "").toLowerCase());
  const uncovered = domains.filter((domain) => !scopeValues.some((scope) => domainCoveredByScope(domain, scope)));
  const activeIssuers = rowsOf(issuers).filter((issuer) => issuer.status === "active");
  const fieldError = validateField("application_id", body.application_id) || listError(domains, "Domains / SANs", "domain") || validateField("key_type", body.key_type);
  const canSubmit = Boolean(body.application_id && domains.length && !fieldError);
  return createElement("form", { className: "inline-form issue-flow", onSubmit: (e: Event) => {
    e.preventDefault();
    if (fieldError) return props.setNotice(fieldError);
    if (!selectedApp) return props.setNotice("select a visible non-system Application you can manage");
    if (selectedApp?.system_kind === "certhub_server" || selectedApp?.name === "certhub_server") return props.setNotice("system_managed_resource: certhub_server is read-only and config-managed");
    post(props, `/v1/applications/${body.application_id}/certificates`, { domains, key_type: body.key_type || undefined, issuer: body.issuer || undefined }, props.onDone);
  } },
    locked ? createElement("div", { className: "field" }, createElement("span", null, "Application"), createElement("strong", null, appLabel(selectedApp) || "Selected application")) :
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
      createElement("span", null, issuers.error || activeIssuerCount.error ? "Issuers: not visible to this user" : `${countText(activeIssuerCount)} active issuers`),
      createElement("span", null, providers.error || activeProviderCount.error ? "DNS providers: not visible to this user" : `${countText(activeProviderCount)} active DNS providers`)
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

function resourceID(props: PageProps) {
  return props.route.id || "";
}

function applicationTab(raw: string): ApplicationTab {
  return applicationTabs.some((tab) => tab.id === raw) ? raw as ApplicationTab : "overview";
}

function profileTab(raw: string): ProfileTab {
  return profileTabs.some((tab) => tab.id === raw) ? raw as ProfileTab : "overview";
}

function isManagerApplicationTab(tab: ApplicationTab) {
  return applicationTabs.some((item) => item.id === tab && item.managerOnly);
}

function applicationTabPath(appID: string, tab: ApplicationTab) {
  return tab === "overview" ? `/applications/${appID}` : `/applications/${appID}?tab=${tab}`;
}

function profileTabPath(tab: ProfileTab) {
  return tab === "overview" ? "/profile" : `/profile?tab=${tab}`;
}

function Tabs<T extends string>(props: { activeTab: T; tabs: { id: T; label: string }[]; ariaLabel: string; pathFor: (tab: T) => string; navigate: (path: string, replace?: boolean) => void }) {
  return createElement("div", { className: "tabs", role: "tablist", "aria-label": props.ariaLabel },
    props.tabs.map((tab) => createElement("button", {
      key: tab.id,
      type: "button",
      role: "tab",
      className: tab.id === props.activeTab ? "tab active" : "tab",
      "aria-selected": tab.id === props.activeTab,
      onClick: () => props.navigate(props.pathFor(tab.id))
    }, tab.label))
  );
}

function table(result: { data?: any; error?: ErrorBody; loading?: boolean }, columns: TableColumn[], onSelect?: (row: any) => void) {
  const rows = rowsOf(result);
  if (result.loading) return createElement("div", { className: "empty" }, "Loading");
  if (result.error) return createElement("div", { className: "error" }, result.error.code, ": ", result.error.message);
  const meta = pageMeta(result);
  const shown = rows.length;
  const specs = columns.map((column) => typeof column === "string" ? { key: column, label: labelForColumn(column), render: undefined } : { ...column, label: column.label || labelForColumn(column.key) });
  return createElement("div", { className: "table-wrap" },
    meta ? createElement("div", { className: "table-meta" }, `Showing ${shown} of ${meta.total ?? shown}`) : null,
    createElement("table", null,
      createElement("thead", null, createElement("tr", null, specs.map((c) => createElement("th", { key: c.key, className: c.key === "actions" ? "actions-head" : "" }, c.label)))),
      createElement("tbody", null, rows.map((row: any) => createElement("tr", { key: row.id || JSON.stringify(row), onClick: () => onSelect?.(row), className: onSelect ? "selectable" : "" }, specs.map((c) => createElement("td", { key: c.key, className: c.key === "actions" ? "actions-td" : "" }, c.render ? c.render(row) : cell(row[c.key]))))))
    )
  );
}

function rowsOf(result: { data?: any }): any[] {
  const key = Object.keys(result.data || {}).find((k) => Array.isArray(result.data[k]));
  return key ? result.data[key] : [];
}

function pageMeta(result: { data?: { pagination?: PageMeta } }): PageMeta | undefined {
  return result.data?.pagination;
}

function pageTotal(result: { data?: { pagination?: PageMeta } }, fallback: number | any[] = rowsOf(result)): number {
  const total = result.data?.pagination?.total;
  return typeof total === "number" ? total : Array.isArray(fallback) ? fallback.length : fallback;
}

function countText(result: { data?: { pagination?: PageMeta }; loading?: boolean }): string {
  if (result.loading) return "Loading";
  return String(pageTotal(result, 0));
}

function actionsColumn(render: (row: any) => unknown): TableColumn {
  return { key: "actions", label: "Actions", render: (row) => createElement("div", { className: "actions-cell" }, render(row)) };
}

function rowAction(label: string, onClick: () => void, options: { icon?: any; danger?: boolean; disabled?: boolean; label?: string } = {}) {
  const Icon = options.icon;
  const accessibleLabel = options.label || label;
  return createElement("button", {
    type: "button",
    className: options.danger ? "row-action danger" : "row-action",
    disabled: options.disabled,
    title: accessibleLabel,
    "aria-label": accessibleLabel,
    onClick: (event: any) => {
      event.stopPropagation();
      onClick();
    }
  }, Icon ? createElement(Icon, { size: 14 }) : null, label);
}

function input(label: string, value: string, onChange: (v: string) => void, type = "text") {
  return createElement("label", null, createElement("span", null, label), createElement("input", { value, type, onChange: (e: Event) => onChange((e.target as HTMLInputElement).value), autoComplete: "off" }));
}

function QRCodeImage(props: { value: string }) {
  const [canvas, setCanvas] = useState<HTMLCanvasElement | null>(null);
  useEffect(() => {
    let canceled = false;
    if (!canvas) return () => {
      canceled = true;
    };
    QRCode.toCanvas(canvas, props.value, { margin: 1, width: 192, errorCorrectionLevel: "M" })
      .catch(() => {
        if (!canceled) {
          const ctx = canvas.getContext("2d");
          ctx?.clearRect(0, 0, canvas.width, canvas.height);
        }
      })
    return () => {
      canceled = true;
    };
  }, [props.value, canvas]);
  return createElement("canvas", { ref: setCanvas, className: "qr-code", width: 192, height: 192, role: "img", "aria-label": "Authenticator QR code" });
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

function certificateStatusOptions(): FilterOption[] {
  return [
    ["pending", "Pending"],
    ["validating_dns", "Validating DNS"],
    ["issuing", "Issuing"],
    ["ready", "Ready"],
    ["renewing", "Renewing"],
    ["rotating_key", "Rotating key"],
    ["expired", "Expired"],
    ["revoked", "Revoked"],
    ["failed", "Failed"],
    ["deleted", "Deleted"]
  ];
}

function keyTypeOptions(): FilterOption[] {
  return [
    ["ecdsa-p256", "ECDSA P-256"],
    ["ecdsa-p384", "ECDSA P-384"],
    ["rsa-2048", "RSA 2048"],
    ["rsa-3072", "RSA 3072"],
    ["rsa-4096", "RSA 4096"]
  ];
}

function targetTypeOptions(): FilterOption[] {
  return [
    ["user", "User"],
    ["application", "Application"],
    ["certificate", "Certificate"],
    ["issuer", "Issuer"],
    ["dns_provider", "DNS provider"],
    ["domain_scope", "Domain scope"],
    ["application_token", "Application token"],
    ["application_user_grant", "Application user grant"],
    ["session", "Session"]
  ];
}

function auditActionOptions(): FilterOption[] {
  return [
    "bootstrap_admin_created",
    "user_created",
    "user_updated",
    "user_login_succeeded",
    "user_login_failed",
    "user_session_created",
    "user_session_refreshed",
    "user_session_revoked",
    "password_2fa_setup_started",
    "password_2fa_enabled",
    "password_2fa_disabled",
    "application_created",
    "application_updated",
    "application_token_created",
    "application_token_revoked",
    "domain_scope_created",
    "domain_scope_deleted",
    "application_access_granted",
    "application_access_revoked",
    "issuer_created",
    "issuer_updated",
    "issuer_disabled",
    "acme_account_created",
    "dns_provider_created",
    "dns_provider_updated",
    "dns_provider_credentials_replaced",
    "dns_provider_zone_added",
    "dns_provider_zone_removed",
    "dns_provider_zone_refresh_started",
    "dns_provider_zone_refreshed",
    "dns_zone_discovery_failed",
    "certificate_created",
    "certificate_issuance_started",
    "certificate_issuance_succeeded",
    "certificate_issuance_failed",
    "certificate_renewal_started",
    "certificate_renewal_succeeded",
    "certificate_renewal_failed",
    "certificate_key_rotation_started",
    "certificate_key_rotation_succeeded",
    "certificate_key_rotation_failed",
    "certificate_revoked",
    "certificate_revocation_retried",
    "certificate_revocation_failed",
    "certificate_deleted",
    "private_key_read",
    "server_self_certificate_synced"
  ].map((action) => [action, labelForColumn(action)]);
}

function localDateTimeInputValue(value: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function rfc3339FromLocalInput(value: string) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function formatDateTime(value: string) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
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

function labelForColumn(key: string) {
  const labels: Record<string, string> = {
    normalized_sans: "Domains",
    key_type: "Key type",
    issuer_name: "Issuer",
    application_name: "Application",
    current_user_role: "Your role",
    domain_scope_count: "Domain scopes",
    certificate_count: "Certificates",
    token_count: "Tokens",
    trusted_source_cidr_count: "Trusted CIDRs",
    system_kind: "System kind",
    expires_at: "Expires at",
    last_used_at: "Last used",
    created_at: "Created at",
    updated_at: "Updated at",
    last_login_at: "Last login",
    global_role: "Global role",
    oidc_linked: "OIDC",
    application_grant_count: "Grants",
    directory_url: "Directory URL",
    renewal_window_seconds: "Renewal window",
    zone_mode: "Zone mode",
    zone_refresh_status: "Refresh status",
    last_zone_refresh_at: "Last refresh",
    zone_name: "Zone",
    already_configured: "Configured",
    source_ip: "Source IP",
    target_type: "Target type",
    identity_type: "Identity type",
    not_after: "Not after",
    failure_code: "Failure"
  };
  return labels[key] || key.replaceAll("_", " ").replace(/^\w/, (c) => c.toUpperCase());
}

function kv(label: string, value: unknown) {
  return createElement("div", { className: "kv" }, createElement("span", null, label), createElement("strong", null, cell(value)));
}

function resourceMap(rows: any[]) {
  return new Map(rows.filter((row) => row?.id).map((row) => [row.id, row]));
}

function readinessCard(title: string, status: string, items: string[]) {
  return createElement("section", { className: "metric" },
    createElement("span", null, title),
    createElement("strong", null, status),
    createElement("div", null, items.filter(Boolean).slice(0, 5).map((item) => createElement("small", { key: item }, item)))
  );
}

function setupStatusFromCounts(activeIssuers: number, activeProviders: number, zones: number) {
  if (activeIssuers === 0) return "Needs issuer";
  if (activeProviders === 0) return "Needs DNS provider";
  if (zones === 0) return "Needs DNS zone";
  return "Ready";
}

function appLabel(app: any) {
  if (!app) return "";
  const display = app.display_name && app.display_name !== app.name ? ` - ${app.display_name}` : "";
  return `${app.name}${display}`;
}

function userLabel(user: any) {
  if (!user) return "";
  if (user.email && user.display_name && user.display_name !== user.email) return `${user.email} - ${user.display_name}`;
  return user.email || user.display_name || "";
}

function dnsProviderLabel(provider: any) {
  if (!provider) return "";
  return provider.name || "";
}

function certificateLabel(cert: any) {
  if (!cert) return "Certificate";
  const domains = cert.normalized_sans || cert.domains;
  if (Array.isArray(domains) && domains.length) return domains.join(", ");
  return "Certificate";
}

type AuditLabelMaps = {
  applications?: Map<string, any>;
  users?: Map<string, any>;
  certificates?: Map<string, any>;
  issuers?: Map<string, any>;
  providers?: Map<string, any>;
  application?: any;
};

function auditColumns(labels: AuditLabelMaps = {}): TableColumn[] {
  return [
    "created_at",
    { key: "identity", render: (event) => auditIdentityLabel(event, labels) },
    "action",
    { key: "target", render: (event) => auditTargetLabel(event, labels) },
    "result",
    "source_ip"
  ];
}

function auditMetadata(event: any): Record<string, any> {
  if (!event?.metadata) return {};
  if (typeof event.metadata === "string") {
    try {
      return JSON.parse(event.metadata);
    } catch {
      return {};
    }
  }
  return event.metadata;
}

function auditIdentityLabel(event: any, labels: AuditLabelMaps) {
  if (event.identity_type === "system") return "System";
  if (event.identity_type === "user") return userLabel(labels.users?.get(event.identity_id)) || "User";
  if (event.identity_type === "application") return appLabel(labels.applications?.get(event.identity_id)) || "Application";
  return labelForColumn(event.identity_type || "identity");
}

function auditTargetLabel(event: any, labels: AuditLabelMaps) {
  const metadata = auditMetadata(event);
  const scopedApp = labels.application || labels.applications?.get(event.scope_application_id || metadata.application_id);
  switch (event.target_type) {
    case "application":
      return appLabel(labels.applications?.get(event.target_id)) || metadata.name || "Application";
    case "application_token":
      return metadata.name ? `Token ${metadata.name}` : scopedApp ? `Token for ${appLabel(scopedApp)}` : "Application token";
    case "application_access": {
      const user = userLabel(labels.users?.get(metadata.user_id));
      const app = appLabel(scopedApp);
      return [user || "User grant", app].filter(Boolean).join(" on ");
    }
    case "certificate":
    case "certificate_version":
      return certificateLabel(labels.certificates?.get(event.scope_certificate_id || event.target_id)) || "Certificate";
    case "user":
      return userLabel(labels.users?.get(event.target_id)) || metadata.email || "User";
    case "issuer":
      return labels.issuers?.get(event.target_id)?.name || metadata.name || "Issuer";
    case "dns_provider":
      return dnsProviderLabel(labels.providers?.get(event.target_id || event.scope_dns_provider_id)) || metadata.name || "DNS provider";
    default:
      return event.target_type ? labelForColumn(event.target_type) : "Resource";
  }
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

function versionDownloadable(version: any) {
  return (version.status === "valid" || version.status === "revoked") && Boolean(version.material_etag);
}

async function downloadArchive(session: Session, id: string, setNotice: (s: string) => void, versionID?: string) {
  const rid = requestID();
  const path = versionID ? `/v1/certificates/${id}/versions/${versionID}/tls-archive` : `/v1/certificates/${id}/tls-archive`;
  let response = await fetch(path, { headers: { Authorization: `Bearer ${session.accessToken}`, Accept: "application/gzip", "X-Request-ID": rid }, cache: "no-store", redirect: "error" });
  if (response.status === 401 && await refreshSession(session)) {
    response = await fetch(path, { headers: { Authorization: `Bearer ${session.accessToken}`, Accept: "application/gzip", "X-Request-ID": rid }, cache: "no-store", redirect: "error" });
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
