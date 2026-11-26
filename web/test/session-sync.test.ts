import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { createSessionSync, type LockManagerLike, type SessionSyncEnv } from "../src/session-sync.ts";

type TestSession = {
  accessToken: string;
  syncId?: string;
  channelId?: string;
  generation?: number;
};

// Refresh rules of internal/auth (RotateAccessTokenTx): only the current access
// token of an active session can be rotated. A rotated token that is sent again
// revokes the whole login session (revoked_reason=token_reuse).
class FakeAuthServer {
  private tokens = new Map<string, "active" | "rotated">();
  private count = 0;
  revoked = false;
  refreshBodies: string[] = [];

  login(): TestSession {
    return { accessToken: this.issue(), syncId: randomID(), channelId: randomID(), generation: 0 };
  }

  async refresh(token: string): Promise<string | undefined> {
    this.refreshBodies.push(token);
    await new Promise((resolve) => setTimeout(resolve, 5));
    const status = this.tokens.get(token);
    if (!status || this.revoked) return undefined;
    if (status !== "active") {
      this.revoked = true;
      return undefined;
    }
    this.tokens.set(token, "rotated");
    return this.issue();
  }

  accepts(token: string | undefined): boolean {
    return Boolean(token) && !this.revoked && this.tokens.get(token as string) === "active";
  }

  private issue() {
    const token = `cth_uat_v1_${this.count++}`;
    this.tokens.set(token, "active");
    return token;
  }
}

function randomID() {
  return randomBytes(16).toString("hex");
}

function memoryStorage() {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => void items.set(key, String(value)),
    removeItem: (key: string) => void items.delete(key)
  };
}

function browserEnv(overrides: Partial<SessionSyncEnv> = {}): SessionSyncEnv {
  return {
    locks: navigator.locks,
    openChannel: (name, onMessage) => {
      const channel = new BroadcastChannel(name);
      channel.onmessage = (event) => onMessage((event as MessageEvent).data);
      return { post: (message) => channel.postMessage(message), close: () => channel.close() };
    },
    randomID,
    peerReplyTimeoutMs: 200,
    ...overrides
  };
}

// One browser tab: its own sessionStorage (a copy for a duplicated tab) and its
// own JavaScript state. Tabs of one test share the origin (locks, channels).
// onAdopted runs when the tab stored a newer token from another tab.
function openTab(server: FakeAuthServer, env: SessionSyncEnv, copied?: TestSession, onAdopted?: (session: TestSession) => void) {
  let stored: TestSession | undefined = copied ? structuredClone(copied) : undefined;
  const adopted: TestSession[] = [];
  const sync = createSessionSync<TestSession>({
    load: () => stored && { ...stored },
    save: (session) => {
      stored = session && { ...session };
      sync.track(stored);
    },
    adopted: (session) => {
      adopted.push(session);
      onAdopted?.(session);
    }
  }, env);
  sync.track(stored);
  return {
    adopted,
    stored: () => stored,
    // inPlace: sync.refresh gets the session object of the caller, not a copy.
    refresh(session: TestSession | undefined = stored, { inPlace = false } = {}) {
      assert.ok(session);
      return sync.refresh(inPlace ? session : { ...session }, {
        usable: (current) => Boolean(current.accessToken),
        rotate: async (current) => {
          const token = await server.refresh(current.accessToken);
          return token ? { ...current, accessToken: token } : undefined;
        }
      });
    },
    logout() {
      stored = undefined;
      sync.track(undefined);
    },
    close: () => sync.close()
  };
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

test("duplicated tab: the second tab adopts the rotated token and does not send the old one", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv();
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    const first = await a.refresh();
    assert.equal(first.status, "refreshed");
    const second = await b.refresh(session);
    assert.deepEqual(server.refreshBodies, [session.accessToken], "refresh requests (access_token bodies)");
    assert.equal(server.revoked, false, "server revoked the session for token reuse");
    assert.equal(second.status, "adopted");
    assert.equal(b.stored()?.accessToken, a.stored()?.accessToken);
    assert.ok(server.accepts(b.stored()?.accessToken));
  } finally {
    a.close();
    b.close();
  }
});

test("duplicated tab: two tabs that refresh at the same moment send one refresh request", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv();
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    const results = await Promise.all([a.refresh(), b.refresh()]);
    assert.deepEqual(server.refreshBodies, [session.accessToken], "refresh requests (access_token bodies)");
    assert.equal(server.revoked, false, "server revoked the session for token reuse");
    assert.deepEqual(results.map((r) => r.status).sort(), ["adopted", "refreshed"]);
    assert.equal(a.stored()?.accessToken, b.stored()?.accessToken);
    assert.ok(server.accepts(a.stored()?.accessToken));
  } finally {
    a.close();
    b.close();
  }
});

test("duplicated tab: a tab that updates its waiting session in place adopts the token and does not refresh again", async () => {
  const server = new FakeAuthServer();
  // Tab A keeps the refresh lock for a short time after it sent the new token,
  // so the announcement arrives in tab B before tab B gets the lock.
  const locks: LockManagerLike = {
    request: (name, options, callback) => navigator.locks.request(name, options, async () => {
      const result = await callback();
      if (name === "certhub.session.refresh") await delay(30);
      return result;
    }),
    query: () => navigator.locks.query()
  };
  const session = server.login();
  const a = openTab(server, browserEnv({ locks }), session);
  // Tab B is like AppShell (app.ts): its refresh timer gives the session object
  // of the React state to the refresh, and the adoption listener copies the
  // announced token into that object in place (copyLatestSession).
  const held = structuredClone(session);
  const b = openTab(server, browserEnv(), session, (latest) => void Object.assign(held, latest));
  try {
    // The two tabs have the same expiry, so their refresh timers fire together.
    const results = await Promise.all([a.refresh(), b.refresh(held, { inPlace: true })]);
    assert.equal(b.adopted.length, 1, "tab B did not get the announcement while it waited for the lock");
    assert.deepEqual(server.refreshBodies, [session.accessToken], "refresh requests (access_token bodies)");
    assert.equal(server.revoked, false, "server revoked the session for token reuse");
    assert.deepEqual(results.map((r) => r.status), ["refreshed", "adopted"]);
    assert.equal(b.stored()?.accessToken, a.stored()?.accessToken);
    assert.equal(b.stored()?.generation, 1);
    assert.ok(server.accepts(b.stored()?.accessToken));
  } finally {
    a.close();
    b.close();
  }
});

test("duplicated tab: the other tab stores the rotated token when it is announced", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv();
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    await a.refresh();
    await delay(20);
    assert.equal(b.stored()?.accessToken, a.stored()?.accessToken);
    assert.equal(b.stored()?.generation, 1);
    assert.equal(b.adopted.length, 1);
    // Many refresh cycles alternate between the tabs without token reuse.
    for (let i = 0; i < 4; i++) {
      await (i % 2 ? a : b).refresh();
      await delay(20);
    }
    assert.equal(server.revoked, false);
    assert.equal(new Set(server.refreshBodies).size, server.refreshBodies.length, "a token was sent to refresh twice");
    assert.ok(server.accepts(a.stored()?.accessToken));
    assert.equal(a.stored()?.accessToken, b.stored()?.accessToken);
  } finally {
    a.close();
    b.close();
  }
});

test("duplicated tab: a tab that missed the announcement gets the newer token from a tab that has it", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv();
  const session = server.login();
  const a = openTab(server, env, session);
  const c = openTab(server, env, session);
  try {
    await a.refresh();
    await delay(20);
    a.close();
    // Duplicated from the old copy; it was not open when the new token was announced.
    const b = openTab(server, env, session);
    try {
      const result = await b.refresh(session);
      assert.equal(result.status, "adopted");
      assert.deepEqual(server.refreshBodies, [session.accessToken]);
      assert.equal(b.stored()?.accessToken, c.stored()?.accessToken);
      assert.ok(server.accepts(b.stored()?.accessToken));
    } finally {
      b.close();
    }
  } finally {
    c.close();
  }
});

test("duplicated tab: the announcement arrives after the refresh lock is free", async () => {
  const server = new FakeAuthServer();
  // BroadcastChannel and Web Locks do not order their messages between each other.
  const slow = browserEnv();
  const env = browserEnv({
    openChannel: (name, onMessage) => slow.openChannel!(name, (data) => void setTimeout(() => onMessage(data), 30))
  });
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    await a.refresh();
    assert.equal(b.stored()?.generation, 0, "announcement arrived early");
    const result = await b.refresh(session);
    assert.equal(result.status, "adopted");
    assert.deepEqual(server.refreshBodies, [session.accessToken]);
    assert.equal(server.revoked, false);
  } finally {
    a.close();
    b.close();
  }
});

test("without BroadcastChannel: a stale tab does not send the rotated token", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv({ openChannel: undefined });
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    assert.equal((await a.refresh()).status, "refreshed");
    assert.equal((await b.refresh(session)).status, "lost");
    assert.deepEqual(server.refreshBodies, [session.accessToken]);
    assert.equal(server.revoked, false);
    assert.ok(server.accepts(a.stored()?.accessToken));
  } finally {
    a.close();
    b.close();
  }
});

test("tabs of different login sessions do not share tokens", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv();
  const one = openTab(server, env, server.login());
  const two = openTab(server, env, server.login());
  try {
    const before = two.stored()?.accessToken;
    await one.refresh();
    await delay(20);
    assert.equal(two.stored()?.accessToken, before);
    assert.equal((await two.refresh()).status, "refreshed");
    assert.equal(server.revoked, false);
    assert.notEqual(one.stored()?.accessToken, two.stored()?.accessToken);
  } finally {
    one.close();
    two.close();
  }
});

test("logout in one tab does not change the session of the other tab (as before)", async () => {
  const server = new FakeAuthServer();
  const env = browserEnv();
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    a.logout();
    await delay(20);
    assert.equal(b.stored()?.accessToken, session.accessToken);
  } finally {
    a.close();
    b.close();
  }
});

test("single tab: one refresh request per refresh", async () => {
  const server = new FakeAuthServer();
  const tab = openTab(server, browserEnv(), server.login());
  try {
    for (let i = 0; i < 3; i++) assert.equal((await tab.refresh()).status, "refreshed");
    assert.equal(server.refreshBodies.length, 3);
    assert.equal(tab.stored()?.generation, 3);
    assert.ok(server.accepts(tab.stored()?.accessToken));
  } finally {
    tab.close();
  }
});

test("without Web Locks: a localStorage lease serializes refreshes and never holds a token", async () => {
  const server = new FakeAuthServer();
  const storage = memoryStorage();
  const env = browserEnv({ locks: undefined, sharedStorage: storage, leaseSettleMs: 5, leasePollMs: 5 });
  const session = server.login();
  const a = openTab(server, env, session);
  const b = openTab(server, env, session);
  try {
    await Promise.all([a.refresh(), b.refresh()]);
    await b.refresh(session);
    assert.deepEqual(server.refreshBodies, [session.accessToken]);
    assert.equal(server.revoked, false);
    assert.equal(a.stored()?.accessToken, b.stored()?.accessToken);
    for (const value of storage.items.values()) {
      assert.ok(!value.includes("cth_uat_v1_"), `localStorage holds a token: ${value}`);
    }
  } finally {
    a.close();
    b.close();
  }
});

test("without Web Locks: a stale tab with no tab to answer does not send the rotated token", async () => {
  const server = new FakeAuthServer();
  const storage = memoryStorage();
  const env = browserEnv({ locks: undefined, sharedStorage: storage, leaseSettleMs: 5, leasePollMs: 5 });
  const session = server.login();
  const a = openTab(server, env, session);
  await a.refresh();
  a.close();
  const b = openTab(server, env, session);
  try {
    const result = await b.refresh(session);
    assert.equal(result.status, "lost");
    assert.deepEqual(server.refreshBodies, [session.accessToken]);
    assert.equal(server.revoked, false, "server revoked the session for token reuse");
  } finally {
    b.close();
  }
});

test("without Web Locks, BroadcastChannel and localStorage: a single tab refreshes as before", async () => {
  const server = new FakeAuthServer();
  const tab = openTab(server, { randomID }, server.login());
  try {
    assert.equal((await tab.refresh()).status, "refreshed");
    assert.equal((await tab.refresh()).status, "refreshed");
    assert.equal(server.refreshBodies.length, 2);
  } finally {
    tab.close();
  }
});
