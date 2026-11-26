// Access token refresh of the browser session, shared by the tabs that hold a
// copy of the same login session.
//
// The session is in sessionStorage, so each tab has its own copy. A duplicated
// tab starts with a copy of the session of the first tab, so both tabs hold the
// same access token. POST /v1/auth/refresh rotates the token, and the server
// revokes the whole login session when a rotated token is sent to it again
// (internal/auth RotateAccessTokenTx, revoked_reason=token_reuse). So after one
// tab refreshes, the other tabs must not send the old token. Rules:
//
// - Refreshes are serialized across the tabs of this origin: with Web Locks
//   (navigator.locks), or with a short lease in localStorage when Web Locks are
//   not available (old browsers, pages that are not a secure context).
// - The tab that refreshed sends the new token to the other tabs of the same
//   login session on a BroadcastChannel. The channel name contains a random ID
//   that only the sessionStorage of these tabs holds.
// - Each tab counts the refreshes of its login session (generation). Before a
//   tab refreshes, it checks if another tab has a newer generation: a shared
//   Web Lock that each tab holds for its generation, or the generation in the
//   localStorage lease. If so, the tab asks for the newer token and does not
//   send its own token. If no tab answers, the tab removes its copy of the
//   session (the user must log in again in this tab only).
// - localStorage never holds a token or the channel ID.
// - Logout is not shared: it works as before.

export type SyncedSession = {
  accessToken: string;
  accessIssuedAt?: string;
  accessExpiresAt?: string;
  sessionExpiresAt?: string;
  // Random ID of the login session. Tabs with a copy of the same login session
  // have the same ID. Visible in Web Lock names and in localStorage.
  syncId?: string;
  // Random ID of the BroadcastChannel that carries the tokens. Kept only in
  // sessionStorage.
  channelId?: string;
  // Number of refreshes of the login session.
  generation?: number;
};

type Tokens = Pick<SyncedSession, "accessToken" | "accessIssuedAt" | "accessExpiresAt" | "sessionExpiresAt">;

export type SessionStore<S extends SyncedSession> = {
  // The session in the sessionStorage of this tab.
  load(): S | undefined;
  save(session: S | undefined): void;
  // Called after this tab stored a newer token that another tab sent.
  adopted?(session: S): void;
};

export type LockManagerLike = {
  request(name: string, options: { mode: "exclusive" | "shared" }, callback: () => Promise<unknown>): Promise<unknown>;
  query(): Promise<{ held?: { name?: string }[] }>;
};

export type ChannelLike = {
  post(message: unknown): void;
  close(): void;
};

export type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

export type SessionSyncEnv = {
  // navigator.locks.
  locks?: LockManagerLike;
  // Opens a BroadcastChannel.
  openChannel?: (name: string, onMessage: (data: unknown) => void) => ChannelLike;
  // localStorage. Used only for the refresh lease when Web Locks are not available.
  sharedStorage?: StorageLike;
  randomID: () => string;
  peerReplyTimeoutMs?: number;
  leaseMs?: number;
  leaseSettleMs?: number;
  leasePollMs?: number;
};

export type RefreshOutcome<S extends SyncedSession> =
  // This tab rotated the token.
  | { status: "refreshed"; session: S }
  // This tab took the newer token that this tab or another tab got before.
  | { status: "adopted"; session: S }
  // The server rejected the refresh, or the session is not usable.
  | { status: "failed" }
  // Another tab rotated the token of this tab, and no tab sent the new token.
  | { status: "lost" };

export type RefreshSteps<S extends SyncedSession> = {
  // The session has an access token and it and the session are not expired.
  usable(session: S): boolean;
  // POST /v1/auth/refresh. Returns the session with the new access token, or
  // undefined when the server rejects the refresh.
  rotate(session: S): Promise<S | undefined>;
};

export type SessionSync<S extends SyncedSession> = {
  // Joins the tabs of the login session of this tab. Call it each time the
  // session of this tab changes (undefined: logged out).
  track(session: S | undefined): void;
  refresh(session: S, steps: RefreshSteps<S>): Promise<RefreshOutcome<S>>;
  close(): void;
};

type TokensMessage = { type: "tokens"; syncId: string; generation: number; tokens: Tokens };
type RequestMessage = { type: "request"; syncId: string; generation: number };
type Lease = { owner?: string; until?: number; syncId?: string; generation?: number };

const refreshLockName = "certhub.session.refresh";
const generationLockPrefix = "certhub.session.generation.";
const channelPrefix = "certhub.session.";
const leaseKey = "certhub.session.refresh-lease";

export function newSessionLineage(randomID: () => string): Required<Pick<SyncedSession, "syncId" | "channelId" | "generation">> {
  return { syncId: randomID(), channelId: randomID(), generation: 0 };
}

export function createSessionSync<S extends SyncedSession>(store: SessionStore<S>, env: SessionSyncEnv): SessionSync<S> {
  const peerReplyTimeoutMs = env.peerReplyTimeoutMs ?? 3_000;
  const leaseMs = env.leaseMs ?? 10_000;
  const leaseSettleMs = env.leaseSettleMs ?? 50;
  const leasePollMs = env.leasePollMs ?? 50;
  const tabID = env.randomID();
  let channel: { id: string; port: ChannelLike } | undefined;
  let presence: { name: string; granted: Promise<void>; release(): void } | undefined;
  const waiters = new Set<() => void>();

  function track(session: S | undefined) {
    if (!session?.syncId || !session.channelId) {
      closeChannel();
      releasePresence();
      return;
    }
    if (channel?.id !== session.channelId) {
      closeChannel();
      const id = session.channelId;
      try {
        const port = env.openChannel?.(channelPrefix + id, receive);
        if (port) channel = { id, port };
      } catch {
        channel = undefined;
      }
    }
    const name = `${generationLockPrefix}${session.syncId}.${generationOf(session)}`;
    if (env.locks && presence?.name !== name) {
      const previous = presence;
      presence = holdSharedLock(env.locks, name);
      previous?.release();
    }
  }

  function closeChannel() {
    channel?.port.close();
    channel = undefined;
  }

  function releasePresence() {
    presence?.release();
    presence = undefined;
  }

  function receive(data: unknown) {
    if (!data || typeof data !== "object") return;
    const message = data as { type?: unknown; syncId?: unknown; generation?: unknown; tokens?: unknown };
    const current = store.load();
    if (!current?.syncId || message.syncId !== current.syncId || typeof message.generation !== "number") return;
    if (message.type === "tokens" && message.generation > generationOf(current)) {
      const tokens = validTokens(message.tokens);
      if (!tokens) return;
      const next = { ...current, ...tokens, generation: message.generation };
      store.save(next);
      track(next);
      store.adopted?.(next);
      waiters.forEach((check) => check());
    } else if (message.type === "request" && generationOf(current) > message.generation) {
      announce(current);
    }
  }

  function announce(session: S) {
    if (!session.syncId) return;
    const message: TokensMessage = {
      type: "tokens",
      syncId: session.syncId,
      generation: generationOf(session),
      tokens: {
        accessToken: session.accessToken,
        accessIssuedAt: session.accessIssuedAt,
        accessExpiresAt: session.accessExpiresAt,
        sessionExpiresAt: session.sessionExpiresAt
      }
    };
    try {
      channel?.port.post(message);
    } catch {
      // The other tabs ask again before they refresh.
    }
  }

  // Highest generation of this login session that a tab holds.
  async function newestGeneration(session: S): Promise<number> {
    let newest = generationOf(session);
    if (env.locks) {
      try {
        const prefix = `${generationLockPrefix}${session.syncId}.`;
        const { held = [] } = await env.locks.query();
        for (const lock of held) {
          if (lock.name?.startsWith(prefix)) newest = Math.max(newest, Number(lock.name.slice(prefix.length)) || 0);
        }
      } catch {
        // Unknown: refresh as before.
      }
    } else if (env.sharedStorage) {
      const lease = readLease(env.sharedStorage);
      if (lease && lease.syncId === session.syncId && typeof lease.generation === "number") newest = Math.max(newest, lease.generation);
    }
    return newest;
  }

  // Asks the other tabs for a token newer than the token of session.
  function requestNewer(session: S): Promise<S | undefined> {
    const syncId = session.syncId;
    const generation = generationOf(session);
    return new Promise((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const finish = (result: S | undefined) => {
        if (timer !== undefined) clearTimeout(timer);
        waiters.delete(check);
        resolve(result);
      };
      const check = () => {
        const current = store.load();
        if (current?.syncId !== syncId) finish(undefined);
        else if (generationOf(current) > generation) finish(current);
      };
      waiters.add(check);
      check();
      if (!waiters.has(check)) return;
      if (!channel || !syncId) return finish(undefined);
      timer = setTimeout(() => finish(undefined), peerReplyTimeoutMs);
      const request: RequestMessage = { type: "request", syncId, generation };
      try {
        channel.port.post(request);
      } catch {
        finish(undefined);
      }
    });
  }

  async function exclusive<T>(fn: () => Promise<T>): Promise<T> {
    if (env.locks) {
      let started = false;
      try {
        return (await env.locks.request(refreshLockName, { mode: "exclusive" }, () => {
          started = true;
          return fn();
        })) as T;
      } catch (err) {
        if (started) throw err;
        // Web Locks are not usable here (for example a sandboxed page).
        return fn();
      }
    }
    if (env.sharedStorage) return withLease(env.sharedStorage, fn);
    return fn();
  }

  // Best-effort mutual exclusion when Web Locks are not available.
  async function withLease<T>(storage: StorageLike, fn: () => Promise<T>): Promise<T> {
    for (;;) {
      const lease = readLease(storage);
      if (!lease?.owner || lease.owner === tabID || (lease.until ?? 0) <= Date.now()) {
        if (!writeLease(storage, { ...lease, owner: tabID, until: Date.now() + leaseMs })) break;
        await sleep(leaseSettleMs);
        if (readLease(storage)?.owner === tabID) break;
      }
      await sleep(leasePollMs);
    }
    try {
      return await fn();
    } finally {
      const lease = readLease(storage);
      if (lease?.owner === tabID) writeLease(storage, { syncId: lease.syncId, generation: lease.generation });
    }
  }

  // Lets the other tabs see the new generation before the refresh lock is free.
  async function publishGeneration(session: S) {
    if (env.locks) {
      await presence?.granted;
    } else if (env.sharedStorage && session.syncId) {
      const lease = readLease(env.sharedStorage);
      if (lease?.owner === tabID) writeLease(env.sharedStorage, { ...lease, syncId: session.syncId, generation: generationOf(session) });
    }
  }

  return {
    track,
    close() {
      closeChannel();
      releasePresence();
      waiters.clear();
    },
    refresh(session, steps) {
      // The token to replace. Keep a copy: while this tab waits for the lock,
      // the caller can copy an adopted token into the session object
      // (app.ts copyLatestSession), and then that token would be rotated again.
      const tokenToReplace = session.accessToken;
      return exclusive(async (): Promise<RefreshOutcome<S>> => {
        // The stored session of this tab has the newest token and generation.
        const latest = store.load();
        const current = latest?.accessToken ? latest : session;
        // An earlier refresh of this tab, or another tab, replaced the token.
        if (current.accessToken !== tokenToReplace && steps.usable(current)) return { status: "adopted", session: current };
        if (!current.accessToken || !steps.usable(current)) return { status: "failed" };
        if (current.syncId && await newestGeneration(current) > generationOf(current)) {
          // Another tab rotated this token. Sending it again revokes the session.
          const newer = await requestNewer(current);
          if (!newer) return { status: "lost" };
          return steps.usable(newer) ? { status: "adopted", session: newer } : { status: "failed" };
        }
        const rotated = await steps.rotate(current);
        if (!rotated) return { status: "failed" };
        const next = { ...rotated, generation: generationOf(current) + 1 };
        store.save(next);
        track(next);
        await publishGeneration(next);
        announce(next);
        return { status: "refreshed", session: next };
      });
    }
  };
}

function generationOf(session: SyncedSession | undefined): number {
  return session?.generation ?? 0;
}

function validTokens(value: unknown): Tokens | undefined {
  if (!value || typeof value !== "object") return undefined;
  const tokens = value as Record<string, unknown>;
  if (typeof tokens.accessToken !== "string" || !tokens.accessToken) return undefined;
  const optional = (key: string) => typeof tokens[key] === "string" ? tokens[key] as string : undefined;
  return {
    accessToken: tokens.accessToken,
    accessIssuedAt: optional("accessIssuedAt"),
    accessExpiresAt: optional("accessExpiresAt"),
    sessionExpiresAt: optional("sessionExpiresAt")
  };
}

function holdSharedLock(locks: LockManagerLike, name: string) {
  let release = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  let markGranted = () => {};
  const granted = new Promise<void>((resolve) => (markGranted = resolve));
  try {
    locks.request(name, { mode: "shared" }, () => {
      markGranted();
      return held;
    }).catch(markGranted);
  } catch {
    markGranted();
  }
  return { name, granted, release };
}

function readLease(storage: StorageLike): Lease | undefined {
  try {
    const raw = storage.getItem(leaseKey);
    const lease = raw ? JSON.parse(raw) : undefined;
    return lease && typeof lease === "object" ? lease as Lease : undefined;
  } catch {
    return undefined;
  }
}

function writeLease(storage: StorageLike, lease: Lease): boolean {
  try {
    storage.setItem(leaseKey, JSON.stringify(lease));
    return true;
  } catch {
    return false;
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
