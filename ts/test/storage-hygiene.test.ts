// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAuthClient } from "../src/index.js";
import {
  ACCOUNT_A,
  BASE,
  empty,
  fakeFetch,
  loginResponse,
  SENTINEL_EMAIL,
  SENTINEL_PASSWORD,
  SENTINEL_TOKEN,
  tokenResponse,
} from "./helpers.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function setup() {
  const net = fakeFetch({
    "POST /api/v1/auth/login": () => loginResponse(),
    "POST /api/v1/auth/token": () => tokenResponse(),
    "POST /api/v1/auth/logout": () => empty(204),
    "GET /api/notes": () => empty(200),
  });
  // Default storage (localStorage) and default broadcast: the real browser path.
  const client = createAuthClient({ baseUrl: BASE, appKey: "ricotdin", fetch: net.fetch });
  return { client, net };
}

describe("storage hygiene", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("full flow login → getToken → fetchWithToken → logout writes only mm_account_id (a UUID) to localStorage; nothing to sessionStorage, indexedDB.open, document.cookie", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const open = vi.fn();
    vi.stubGlobal("indexedDB", { open });
    const { client } = setup();
    await client.login({ email: SENTINEL_EMAIL, password: SENTINEL_PASSWORD });
    expect(localStorage.getItem("mm_account_id")).toBe(ACCOUNT_A);
    await client.getToken();
    await client.fetchWithToken("https://ricotdin.mmlabs.online/api/notes");
    await client.logout({ all: true });
    client.dispose();
    expect(setItem.mock.calls.length).toBeGreaterThan(0);
    for (const [key, value] of setItem.mock.calls) {
      expect(key).toBe("mm_account_id");
      expect(value).toMatch(UUID_RE);
    }
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.length).toBe(0);
    expect(open).not.toHaveBeenCalled();
    expect(document.cookie).toBe("");
    vi.unstubAllGlobals();
  });

  it("token not found in JSON.stringify(client), own keys of client, globalThis values, location", async () => {
    const { client } = setup();
    await client.login({ email: SENTINEL_EMAIL, password: SENTINEL_PASSWORD });
    expect(await client.getToken()).toBe(SENTINEL_TOKEN);
    expect(JSON.stringify(client)).not.toContain(SENTINEL_TOKEN);
    for (const key of Reflect.ownKeys(client)) {
      expect(String((client as unknown as Record<PropertyKey, unknown>)[key])).not.toContain(
        SENTINEL_TOKEN,
      );
    }
    for (const key of Object.getOwnPropertyNames(globalThis)) {
      let value: unknown;
      try {
        value = (globalThis as Record<string, unknown>)[key];
      } catch {
        continue;
      }
      if (typeof value === "string") expect(value).not.toContain(SENTINEL_TOKEN);
    }
    expect(location.href).not.toContain(SENTINEL_TOKEN);
    expect(JSON.stringify({ ...localStorage })).not.toContain(SENTINEL_TOKEN);
    client.dispose();
  });

  it("no console.* calls during any flow", async () => {
    const spies = (["log", "info", "warn", "error", "debug", "trace"] as const).map((m) =>
      vi.spyOn(console, m),
    );
    const net = fakeFetch({
      "POST /api/v1/auth/login": () => new Response("broken", { status: 500 }),
      "POST /api/v1/auth/token": () => tokenResponse(),
    });
    const client = createAuthClient({ baseUrl: BASE, appKey: "ricotdin", fetch: net.fetch });
    await client.login({ email: SENTINEL_EMAIL, password: SENTINEL_PASSWORD }).catch(() => {});
    client.selectAccount(ACCOUNT_A);
    await client.getToken();
    client.onChange(() => {
      throw new Error("listener failure");
    });
    client.clearAccount();
    client.dispose();
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it("password not retained after login", async () => {
    const { client } = setup();
    await client.login({ email: SENTINEL_EMAIL, password: SENTINEL_PASSWORD });
    expect(JSON.stringify(client)).not.toContain(SENTINEL_PASSWORD);
    for (const key of Reflect.ownKeys(client)) {
      expect(String((client as unknown as Record<PropertyKey, unknown>)[key])).not.toContain(
        SENTINEL_PASSWORD,
      );
    }
    expect(JSON.stringify({ ...localStorage })).not.toContain(SENTINEL_PASSWORD);
    client.dispose();
  });
});
