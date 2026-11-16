import { describe, expect, it } from "vitest";
import { ACCOUNT_A, empty, makeClient, type Recorded, tokenResponse } from "./helpers.js";

const TOKEN = "POST /api/v1/auth/token";
const API = "https://ricotdin.mmlabs.online/api/notes";
const NOTES = "GET /api/notes";

function setup(notes: Array<() => Response>) {
  const ctx = makeClient({
    [TOKEN]: [() => tokenResponse("token-1"), () => tokenResponse("token-2")],
    [NOTES]: notes,
    "POST /api/notes": notes,
  });
  ctx.client.selectAccount(ACCOUNT_A);
  const backend = () => ctx.net.calls.filter((c) => !c.path.startsWith("/api/v1/auth/"));
  return { ...ctx, backend };
}

const auth = (r: Recorded | undefined) => r?.headers.get("Authorization");

describe("fetchWithToken", () => {
  it("fetchWithToken sends Bearer, credentials omit, no X-MM-App even when the caller passes include/X-MM-App", async () => {
    const { client, backend } = setup([() => empty(200)]);
    const resp = await client.fetchWithToken(API, {
      credentials: "include",
      headers: { "X-MM-App": "ricotdin", Accept: "application/json" },
    });
    expect(resp.status).toBe(200);
    const [req] = backend();
    expect(req?.init.credentials).toBe("omit");
    expect(req?.headers.get("X-MM-App")).toBeNull();
    expect(req?.headers.get("Accept")).toBe("application/json");
    expect(auth(req)).toBe("Bearer token-1");
  });

  it("uses the headers of a Request input and still omits cookies", async () => {
    const { client, backend } = setup([() => empty(200)]);
    await client.fetchWithToken(
      new Request(API, { headers: { "X-Trace": "1", "X-MM-App": "x" }, credentials: "include" }),
    );
    const [req] = backend();
    expect(req?.headers.get("X-Trace")).toBe("1");
    expect(req?.headers.get("X-MM-App")).toBeNull();
    expect(req?.init.credentials).toBe("omit");
  });

  it("401 triggers exactly one forced refresh and one retry", async () => {
    const { client, net, backend } = setup([() => empty(401), () => empty(200)]);
    const resp = await client.fetchWithToken(API);
    expect(resp.status).toBe(200);
    expect(net.count(TOKEN)).toBe(2);
    expect(backend().map(auth)).toEqual(["Bearer token-1", "Bearer token-2"]);
  });

  it("a second 401 is returned to the caller without another retry", async () => {
    const { client, net, backend } = setup([() => empty(401)]);
    const resp = await client.fetchWithToken(API);
    expect(resp.status).toBe(401);
    expect(backend()).toHaveLength(2);
    expect(net.count(TOKEN)).toBe(2);
  });

  it("forced refresh at most once per 30 s per audience", async () => {
    const { client, net, clock, backend } = setup([() => empty(401)]);
    await client.fetchWithToken(API);
    clock.advance(29_000);
    expect((await client.fetchWithToken(API)).status).toBe(401);
    expect(backend()).toHaveLength(3);
    expect(net.count(TOKEN)).toBe(2);
    clock.advance(1_000);
    await client.fetchWithToken(API);
    expect(backend()).toHaveLength(5);
    expect(net.count(TOKEN)).toBe(3);
  });

  it("403/500 are not retried", async () => {
    for (const status of [403, 500]) {
      const { client, net, backend } = setup([() => empty(status)]);
      expect((await client.fetchWithToken(API)).status).toBe(status);
      expect(backend()).toHaveLength(1);
      expect(net.count(TOKEN)).toBe(1);
    }
  });

  it("no retry when the body is a ReadableStream", async () => {
    const { client, net, backend } = setup([() => empty(401)]);
    const body = new ReadableStream({
      start(controller) {
        controller.close();
      },
    });
    const resp = await client.fetchWithToken(API, {
      method: "POST",
      body,
      duplex: "half",
    } as RequestInit);
    expect(resp.status).toBe(401);
    expect(backend()).toHaveLength(1);
    expect(net.count(TOKEN)).toBe(1);
  });
});
