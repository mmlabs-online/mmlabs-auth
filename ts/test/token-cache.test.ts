import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthError, ConfigurationError, EmailUnverifiedError } from "../src/index.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  deferred,
  empty,
  envelope,
  makeClient,
  SENTINEL_TOKEN,
  tokenResponse,
} from "./helpers.js";

const TOKEN = "POST /api/v1/auth/token";

describe("token cache", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("getToken() defaults audience to appKey and sends {audience, account_id}", async () => {
    const { client, net } = makeClient({ [TOKEN]: () => tokenResponse() });
    client.selectAccount(ACCOUNT_A);
    expect(await client.getToken()).toBe(SENTINEL_TOKEN);
    expect(net.calls[0]?.body).toEqual({ audience: "ricotdin", account_id: ACCOUNT_A });
    expect(await client.getToken("ricotdin")).toBe(SENTINEL_TOKEN);
    expect(net.count(TOKEN)).toBe(1);
  });

  it("getToken with another audience rejects ConfigurationError audience_mismatch without fetch", async () => {
    const { client, net } = makeClient({ [TOKEN]: () => tokenResponse() });
    client.selectAccount(ACCOUNT_A);
    const error = await client.getToken("admin").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as AuthError).code).toBe("audience_mismatch");
    expect(net.calls).toHaveLength(0);
  });

  it("cached token reused until expires_in - skew", async () => {
    const { client, net, clock } = makeClient({ [TOKEN]: () => tokenResponse() });
    client.selectAccount(ACCOUNT_A);
    await client.getToken();
    clock.advance(839_999);
    await client.getToken();
    expect(net.count(TOKEN)).toBe(1);
  });

  it("refetch after skew (900 s → at 840 s; 100 s → at 80 s, skew = min(60 s, 20 %))", async () => {
    for (const [expiresIn, refetchAtMs] of [
      [900, 840_000],
      [100, 80_000],
    ] as const) {
      const { client, net, clock } = makeClient({ [TOKEN]: () => tokenResponse("t", expiresIn) });
      client.selectAccount(ACCOUNT_A);
      await client.getToken();
      clock.advance(refetchAtMs - 1);
      await client.getToken();
      expect(net.count(TOKEN)).toBe(1);
      clock.advance(1);
      await client.getToken();
      expect(net.count(TOKEN)).toBe(2);
    }
  });

  it("10 concurrent calls → 1 fetch, same token", async () => {
    const gate = deferred<Response>();
    const { client, net } = makeClient({ [TOKEN]: () => gate.promise });
    client.selectAccount(ACCOUNT_A);
    const calls = Array.from({ length: 10 }, () => client.getToken());
    gate.resolve(tokenResponse());
    expect(new Set(await Promise.all(calls))).toEqual(new Set([SENTINEL_TOKEN]));
    expect(net.count(TOKEN)).toBe(1);
  });

  it("concurrent failure rejects all callers and is not cached", async () => {
    const gate = deferred<Response>();
    const { client, net } = makeClient({
      [TOKEN]: [() => gate.promise, () => tokenResponse()],
    });
    client.selectAccount(ACCOUNT_A);
    const calls = Array.from({ length: 5 }, () => client.getToken().catch((e: unknown) => e));
    gate.resolve(envelope(403, "email_unverified"));
    for (const result of await Promise.all(calls)) {
      expect(result).toBeInstanceOf(EmailUnverifiedError);
    }
    expect(await client.getToken()).toBe(SENTINEL_TOKEN);
    expect(net.count(TOKEN)).toBe(2);
  });

  it("forceRefresh bypasses cache", async () => {
    const { client, net } = makeClient({
      [TOKEN]: [() => tokenResponse("one"), () => tokenResponse("two")],
    });
    client.selectAccount(ACCOUNT_A);
    expect(await client.getToken()).toBe("one");
    expect(await client.getToken({ forceRefresh: true })).toBe("two");
    expect(await client.getToken()).toBe("two");
    expect(net.count(TOKEN)).toBe(2);
  });

  it("per-account cache; selectAccount clears", async () => {
    const { client, net } = makeClient({
      [TOKEN]: (req) => tokenResponse(`token-${(req.body as { account_id: string }).account_id}`),
    });
    client.selectAccount(ACCOUNT_A);
    expect(await client.getToken()).toBe(`token-${ACCOUNT_A}`);
    expect(await client.getToken({ accountId: ACCOUNT_B })).toBe(`token-${ACCOUNT_B}`);
    expect(await client.getToken()).toBe(`token-${ACCOUNT_A}`);
    expect(net.count(TOKEN)).toBe(2);
    client.selectAccount(ACCOUNT_B);
    expect(await client.getToken()).toBe(`token-${ACCOUNT_B}`);
    expect(net.count(TOKEN)).toBe(3);
  });

  it("in-flight result rejected (account_changed), not returned or cached, after logout or account switch", async () => {
    for (const interrupt of ["logout", "switch"] as const) {
      const gate = deferred<Response>();
      const { client, net } = makeClient({
        [TOKEN]: [() => gate.promise, () => tokenResponse("after")],
        "POST /api/v1/auth/logout": () => empty(204),
      });
      client.selectAccount(ACCOUNT_A);
      const inflight = client.getToken();
      if (interrupt === "logout") await client.logout({ accountId: ACCOUNT_A });
      else client.selectAccount(ACCOUNT_B);
      gate.resolve(tokenResponse("before"));
      const error = await inflight.catch((e: unknown) => e);
      expect(error).toBeInstanceOf(AuthError);
      expect((error as AuthError).code).toBe("account_changed");
      expect((error as AuthError).status).toBe(0);
      expect(await client.getToken({ accountId: ACCOUNT_A })).toBe("after");
      expect(net.count(TOKEN)).toBe(2);
    }
  });

  it("in-flight result rejected for every waiting caller after logout of that account", async () => {
    const gate = deferred<Response>();
    const { client } = makeClient({
      [TOKEN]: () => gate.promise,
      "POST /api/v1/auth/logout": () => empty(204),
    });
    client.selectAccount(ACCOUNT_A);
    const calls = [client.getToken(), client.getToken({ accountId: ACCOUNT_A })];
    await client.logout({ accountId: ACCOUNT_A });
    gate.resolve(tokenResponse("before"));
    for (const result of await Promise.all(calls.map((c) => c.catch((e: unknown) => e)))) {
      expect((result as AuthError).code).toBe("account_changed");
    }
  });

  it("getToken({accountId}) rejects a non-UUID accountId with TypeError, no fetch", async () => {
    const { client, net } = makeClient({ [TOKEN]: () => tokenResponse() });
    for (const accountId of ["x", `${ACCOUNT_A}|ricotdin`, ""]) {
      await expect(client.getToken({ accountId })).rejects.toBeInstanceOf(TypeError);
    }
    expect(net.calls).toHaveLength(0);
  });

  it("no account selected → AuthError no_account_selected, no fetch", async () => {
    const { client, net } = makeClient({ [TOKEN]: () => tokenResponse() });
    const error = await client.getToken().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).code).toBe("no_account_selected");
    expect(net.calls).toHaveLength(0);
  });

  it("fresh token after verifyEmail", async () => {
    const { client, net } = makeClient({
      [TOKEN]: [() => envelope(403, "email_unverified"), () => tokenResponse("verified")],
      "POST /api/v1/auth/verify-email": () => empty(204),
    });
    client.selectAccount(ACCOUNT_A);
    await expect(client.getToken()).rejects.toBeInstanceOf(EmailUnverifiedError);
    await client.verifyEmail("v".repeat(43));
    expect(await client.getToken({ forceRefresh: true })).toBe("verified");
    expect(net.count(TOKEN)).toBe(2);
  });

  it("no timers are scheduled", async () => {
    vi.useFakeTimers();
    const { client } = makeClient({ [TOKEN]: () => tokenResponse() });
    client.selectAccount(ACCOUNT_A);
    await client.getToken();
    await client.getToken({ forceRefresh: true });
    expect(vi.getTimerCount()).toBe(0);
  });
});
