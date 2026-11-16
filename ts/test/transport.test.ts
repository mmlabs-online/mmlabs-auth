import { describe, expect, it } from "vitest";
import type { AuthClient } from "../src/index.js";
import { createTransport } from "../src/transport.js";
import {
  ACCOUNT_A,
  empty,
  json,
  loginResponse,
  makeClient,
  SENTINEL_EMAIL,
  SENTINEL_PASSWORD,
  tokenResponse,
} from "./helpers.js";

const routes = {
  "POST /api/v1/auth/signup": () =>
    json(201, { id: ACCOUNT_A, email: SENTINEL_EMAIL, email_verified: false, created_at: "x" }),
  "POST /api/v1/auth/login": () => loginResponse(),
  "POST /api/v1/auth/logout": () => empty(204),
  "POST /api/v1/auth/token": () => tokenResponse(),
  "GET /api/v1/auth/accounts": () => json(200, { items: [] }),
  "POST /api/v1/auth/apps/ricotdin/join": () => json(200, { status: "member" }),
  "POST /api/v1/auth/verify-email/resend": () => empty(202),
  "POST /api/v1/auth/password/forgot": () => empty(202),
  "POST /api/v1/auth/verify-email": () => empty(204),
  "POST /api/v1/auth/password/reset": () => empty(204),
};

const authCalls: Array<[string, string, (c: AuthClient) => Promise<unknown>]> = [
  [
    "signup",
    "POST /api/v1/auth/signup",
    (c) => c.signup({ email: SENTINEL_EMAIL, password: SENTINEL_PASSWORD, turnstileToken: "t" }),
  ],
  ["login", "POST /api/v1/auth/login", (c) => c.login({ email: "a@b.c", password: "p" })],
  ["logout", "POST /api/v1/auth/logout", (c) => c.logout({ all: true })],
  ["token", "POST /api/v1/auth/token", (c) => c.getToken({ accountId: ACCOUNT_A })],
  ["accounts", "GET /api/v1/auth/accounts", (c) => c.listAccounts()],
  ["join", "POST /api/v1/auth/apps/ricotdin/join", (c) => c.join(ACCOUNT_A)],
  ["resend", "POST /api/v1/auth/verify-email/resend", (c) => c.resendVerification(ACCOUNT_A)],
  [
    "forgot",
    "POST /api/v1/auth/password/forgot",
    (c) => c.forgotPassword({ email: "a@b.c", turnstileToken: "t" }),
  ],
];

describe("transport", () => {
  it.each(authCalls)(
    "auth endpoints send credentials include, X-MM-App and no-store (%s)",
    async (_n, key, call) => {
      const { client, net } = makeClient(routes);
      await call(client);
      expect(net.calls).toHaveLength(1);
      const [req] = net.calls;
      expect(`${req?.method} ${req?.path}`).toBe(key);
      expect(req?.url.startsWith("https://api.mmlabs.online/api/v1/auth/")).toBe(true);
      expect(req?.init.credentials).toBe("include");
      expect(req?.init.cache).toBe("no-store");
      expect(req?.headers.get("X-MM-App")).toBe("ricotdin");
      expect(req?.headers.get("Authorization")).toBeNull();
    },
  );

  it("verifyEmail and resetPassword send credentials omit and no X-MM-App", async () => {
    const { client, net } = makeClient(routes);
    await client.verifyEmail("t".repeat(43));
    await client.resetPassword({ token: "t".repeat(43), newPassword: SENTINEL_PASSWORD });
    for (const req of net.calls) {
      expect(req.init.credentials).toBe("omit");
      expect(req.headers.get("X-MM-App")).toBeNull();
      expect(req.headers.get("Content-Type")).toBe("application/json");
    }
    expect(net.calls.map((c) => c.path)).toEqual([
      "/api/v1/auth/verify-email",
      "/api/v1/auth/password/reset",
    ]);
  });

  it("authFetch refuses a path outside /api/v1/auth/", () => {
    const { net } = makeClient();
    const t = createTransport({
      baseUrl: "https://api.mmlabs.online",
      appKey: "ricotdin",
      fetch: net.fetch,
      now: () => 0,
    });
    expect(() => t.authFetch("/api/v1/organizations", "GET")).toThrow(TypeError);
    expect(() => t.authFetch("/.well-known/jwks.json", "GET")).toThrow(TypeError);
    expect(net.calls).toHaveLength(0);
  });

  it("authFetch refuses traversal out of /api/v1/auth/ (.., %2e, %2E)", () => {
    const { net } = makeClient();
    for (const baseUrl of ["https://api.mmlabs.online", "https://api.mmlabs.online/identity"]) {
      const t = createTransport({ baseUrl, appKey: "ricotdin", fetch: net.fetch, now: () => 0 });
      for (const path of [
        "/api/v1/auth/../orgs",
        "/api/v1/auth/../../.well-known/jwks.json",
        "/api/v1/auth/%2e%2e/orgs",
        "/api/v1/auth/%2E%2E/orgs",
        "/api/v1/auth/.%2e/orgs",
      ]) {
        expect(() => t.authFetch(path, "GET")).toThrow(TypeError);
      }
    }
    expect(net.calls).toHaveLength(0);
  });

  it("authFetch accepts an auth path under a baseUrl with a path prefix", async () => {
    const { net } = makeClient({
      "GET /identity/api/v1/auth/accounts": () => json(200, { items: [] }),
    });
    const t = createTransport({
      baseUrl: "https://api.mmlabs.online/identity",
      appKey: "ricotdin",
      fetch: net.fetch,
      now: () => 0,
    });
    expect((await t.authFetch("/api/v1/auth/accounts", "GET")).status).toBe(200);
    expect(net.calls[0]?.url).toBe("https://api.mmlabs.online/identity/api/v1/auth/accounts");
  });

  it("Content-Type is set only when there is a body", async () => {
    const { client, net } = makeClient(routes);
    await client.listAccounts();
    await client.getToken({ accountId: ACCOUNT_A });
    expect(net.calls[0]?.headers.get("Content-Type")).toBeNull();
    expect(net.calls[0]?.init.body).toBeUndefined();
    expect(net.calls[1]?.headers.get("Content-Type")).toBe("application/json");
  });

  it("baseUrl must be https", () => {
    expect(() => makeClient({}, { baseUrl: "http://api.mmlabs.online" })).toThrow(TypeError);
    expect(() => makeClient({}, { baseUrl: "not a url" })).toThrow(TypeError);
    expect(() => makeClient({}, { baseUrl: "https://u:p@api.mmlabs.online" })).toThrow(TypeError);
    expect(() => makeClient({}, { baseUrl: "https://api.mmlabs.online?x=1" })).toThrow(TypeError);
  });

  it("http://localhost is allowed only with allowInsecureLocalhost", async () => {
    expect(() => makeClient({}, { baseUrl: "http://localhost:8000" })).toThrow(TypeError);
    expect(() =>
      makeClient({}, { baseUrl: "http://evil.example:8000", allowInsecureLocalhost: true }),
    ).toThrow(TypeError);
    const { client, net } = makeClient(routes, {
      baseUrl: "http://localhost:8000",
      allowInsecureLocalhost: true,
    });
    await client.listAccounts();
    expect(net.calls[0]?.url).toBe("http://localhost:8000/api/v1/auth/accounts");
  });

  it("baseUrl with path/trailing slash is normalised", async () => {
    for (const [baseUrl, expected] of [
      ["https://api.mmlabs.online/", "https://api.mmlabs.online/api/v1/auth/accounts"],
      ["https://example.test/identity//", "https://example.test/identity/api/v1/auth/accounts"],
    ] as const) {
      const path = new URL(expected).pathname;
      const { client, net } = makeClient(
        { [`GET ${path}`]: () => json(200, { items: [] }) },
        { baseUrl },
      );
      await client.listAccounts();
      expect(net.calls[0]?.url).toBe(expected);
    }
  });

  it("rejects an invalid appKey", () => {
    expect(() => makeClient({}, { appKey: "Bad Key" })).toThrow(TypeError);
  });
});
