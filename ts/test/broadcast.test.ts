// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from "vitest";
import type { AuthEvent } from "../src/index.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  empty,
  FakeBroadcastHub,
  makeClient,
  memoryStorage,
  SENTINEL_EMAIL,
  SENTINEL_TOKEN,
  tokenResponse,
} from "./helpers.js";

const routes = {
  "POST /api/v1/auth/token": () => tokenResponse(),
  "POST /api/v1/auth/logout": () => empty(204),
};

function twoTabs() {
  const hub = new FakeBroadcastHub();
  const mem = memoryStorage();
  const tab1 = makeClient(routes, { broadcast: hub.factory, storage: mem.storage });
  const tab2 = makeClient(routes, { broadcast: hub.factory, storage: mem.storage });
  const events: AuthEvent[] = [];
  tab2.client.onChange((e) => events.push(e));
  return { hub, mem, tab1, tab2, events };
}

describe("broadcast", () => {
  afterEach(() => {
    localStorage.clear();
  });

  it("uses the channel name mmlabs-auth:<appKey>", () => {
    const { hub } = twoTabs();
    expect(hub.channels.map((c) => c.name)).toEqual([
      "mmlabs-auth:ricotdin",
      "mmlabs-auth:ricotdin",
    ]);
  });

  it('logout posts exactly {type:"logout", accountId} — no token, no email', async () => {
    const { hub, tab1 } = twoTabs();
    tab1.client.selectAccount(ACCOUNT_A);
    await tab1.client.getToken();
    hub.posted.length = 0;
    await tab1.client.logout({ accountId: ACCOUNT_A });
    expect(hub.posted).toEqual([{ type: "logout", accountId: ACCOUNT_A }]);
    const raw = JSON.stringify(hub.posted);
    expect(raw).not.toContain(SENTINEL_TOKEN);
    expect(raw).not.toContain(SENTINEL_EMAIL);
  });

  it("logout_all message has only {type}", async () => {
    const { hub, tab1 } = twoTabs();
    await tab1.client.logout({ all: true });
    expect(hub.posted).toEqual([{ type: "logout_all" }]);
  });

  it("receiving logout clears tokens (next getToken fetches)", async () => {
    const { tab1, tab2, events } = twoTabs();
    tab2.client.selectAccount(ACCOUNT_A);
    await tab2.client.getToken();
    events.length = 0;
    await tab1.client.logout({ accountId: ACCOUNT_A });
    expect(events).toEqual([{ type: "signed-out", accountId: ACCOUNT_A }]);
    await tab2.client.getToken({ accountId: ACCOUNT_A });
    expect(tab2.net.count("POST /api/v1/auth/token")).toBe(2);
  });

  it("receiving account_changed re-reads mm_account_id and emits account-changed", () => {
    const { tab1, tab2, events } = twoTabs();
    tab1.client.selectAccount(ACCOUNT_B);
    expect(events).toEqual([{ type: "account-changed", accountId: ACCOUNT_B }]);
    expect(tab2.client.getAccountId()).toBe(ACCOUNT_B);
  });

  it("malformed or unknown messages are ignored", () => {
    const { hub, events } = twoTabs();
    const channel = hub.channels[0];
    for (const data of [
      null,
      "logout",
      { type: "logout" },
      { type: "logout", accountId: "x" },
      { type: "logout", accountId: ACCOUNT_A, token: SENTINEL_TOKEN },
      { type: "logout_all", extra: 1 },
      { type: "something" },
      [{ type: "logout_all" }],
    ]) {
      channel?.postMessage(data);
    }
    expect(events).toEqual([]);
  });

  it("no BroadcastChannel → no throw", async () => {
    const original = globalThis.BroadcastChannel;
    // biome-ignore lint/suspicious/noExplicitAny: removing a global for the test
    (globalThis as any).BroadcastChannel = undefined;
    try {
      const { client } = makeClient(routes, { broadcast: true });
      client.selectAccount(ACCOUNT_A);
      await client.logout({ all: true });
      client.dispose();
    } finally {
      globalThis.BroadcastChannel = original;
    }
  });

  it("storage event on mm_account_id triggers account-changed (happy-dom)", () => {
    const { client } = makeClient(routes, { storage: localStorage, broadcast: true });
    const events: AuthEvent[] = [];
    client.onChange((e) => events.push(e));
    localStorage.setItem("mm_account_id", ACCOUNT_B);
    window.dispatchEvent(new StorageEvent("storage", { key: "other" }));
    window.dispatchEvent(new StorageEvent("storage", { key: "mm_account_id" }));
    expect(events).toEqual([{ type: "account-changed", accountId: ACCOUNT_B }]);
    client.dispose();
  });

  it("dispose closes the channel and removes listeners", () => {
    const hub = new FakeBroadcastHub();
    const { client } = makeClient(routes, { broadcast: hub.factory, storage: localStorage });
    const events: AuthEvent[] = [];
    client.onChange((e) => events.push(e));
    client.dispose();
    expect(hub.channels[0]?.closed).toBe(true);
    window.dispatchEvent(new StorageEvent("storage", { key: "mm_account_id" }));
    client.selectAccount(ACCOUNT_A);
    expect(events).toEqual([]);
  });
});
