import { describe, expect, it } from "vitest";
import { RateLimitedError } from "../src/index.js";
import { ACCOUNT_A, envelope, makeClient, tokenResponse } from "./helpers.js";

const TOKEN = "POST /api/v1/auth/token";

function limited(retryAfter: string) {
  return () => envelope(429, "rate_limited", { retry_after: 1 }, { "Retry-After": retryAfter });
}

describe("429 handling", () => {
  it("429 → RateLimitedError; calls before Retry-After reject locally with no fetch", async () => {
    const { client, net, clock } = makeClient({ [TOKEN]: [limited("30"), () => tokenResponse()] });
    client.selectAccount(ACCOUNT_A);
    const first = await client.getToken().catch((e: unknown) => e);
    expect(first).toBeInstanceOf(RateLimitedError);
    expect((first as RateLimitedError).retryAfter).toBe(30);
    clock.advance(20_000);
    const local = await client.getToken({ forceRefresh: true }).catch((e: unknown) => e);
    expect(local).toBeInstanceOf(RateLimitedError);
    expect((local as RateLimitedError).retryAfter).toBe(10);
    expect(net.count(TOKEN)).toBe(1);
  });

  it("after Retry-After the next call fetches", async () => {
    const { client, net, clock } = makeClient({ [TOKEN]: [limited("30"), () => tokenResponse()] });
    client.selectAccount(ACCOUNT_A);
    await client.getToken().catch(() => undefined);
    clock.advance(30_000);
    expect(await client.getToken()).toBeTruthy();
    expect(net.count(TOKEN)).toBe(2);
  });

  it("HTTP-date Retry-After blocks until that date", async () => {
    const { client, net, clock } = makeClient();
    const until = new Date(clock.now() + 120_000).toUTCString();
    net.routes[TOKEN] = [limited(until), () => tokenResponse()];
    client.selectAccount(ACCOUNT_A);
    await client.getToken().catch(() => undefined);
    clock.advance(119_000);
    await expect(client.getToken()).rejects.toBeInstanceOf(RateLimitedError);
    expect(net.count(TOKEN)).toBe(1);
    clock.advance(1_000);
    await client.getToken();
    expect(net.count(TOKEN)).toBe(2);
  });

  it("Retry-After is clamped to [0, 900] s (huge, Infinity-sized, far-future date, past date)", async () => {
    const { clock } = makeClient();
    const cases: Array<[string, number]> = [
      ["901", 900],
      ["9".repeat(400), 900],
      [new Date(clock.now() + 86_400_000).toUTCString(), 900],
      [new Date(clock.now() - 60_000).toUTCString(), 0],
    ];
    for (const [header, expected] of cases) {
      const {
        client,
        net,
        clock: c,
      } = makeClient({
        [TOKEN]: [
          () => envelope(429, "rate_limited", null, { "Retry-After": header }),
          () => tokenResponse(),
        ],
      });
      client.selectAccount(ACCOUNT_A);
      const error = await client.getToken().catch((e: unknown) => e);
      expect((error as RateLimitedError).retryAfter).toBe(expected);
      c.advance(expected * 1000);
      expect(await client.getToken()).toBeTruthy();
      expect(net.count(TOKEN)).toBe(2);
    }
  });

  it("details.retry_after fallback is clamped to 900 s", async () => {
    const { client } = makeClient({
      [TOKEN]: () => envelope(429, "rate_limited", { retry_after: 1e9 }),
    });
    client.selectAccount(ACCOUNT_A);
    const error = await client.getToken().catch((e: unknown) => e);
    expect((error as RateLimitedError).retryAfter).toBe(900);
  });

  it("no automatic retry after 429", async () => {
    const { client, net } = makeClient({
      [TOKEN]: limited("1"),
      "GET /api/v1/auth/accounts": limited("1"),
    });
    client.selectAccount(ACCOUNT_A);
    await expect(client.getToken()).rejects.toBeInstanceOf(RateLimitedError);
    await expect(client.listAccounts()).rejects.toBeInstanceOf(RateLimitedError);
    await new Promise((r) => setTimeout(r, 20));
    expect(net.calls).toHaveLength(2);
  });
});
