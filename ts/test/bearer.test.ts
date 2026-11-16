import { describe, expect, it } from "vitest";
import { type AuthError, ConfigurationError } from "../src/index.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  BASE,
  deferred,
  empty,
  makeClient,
  type Recorded,
  tokenResponse,
} from "./helpers.js";

const TOKEN = "POST /api/v1/auth/token";
const APP_ORIGIN = "https://ricotdin.mmlabs.online";
const API = `${APP_ORIGIN}/api/notes`;
const NOTES = "GET /api/notes";

function setup(notes: Array<() => Response | Promise<Response>>, options = {}) {
  const ctx = makeClient(
    {
      [TOKEN]: [() => tokenResponse("token-1"), () => tokenResponse("token-2")],
      [NOTES]: notes,
      "POST /api/notes": notes,
    },
    { apiOrigins: [APP_ORIGIN], ...options },
  );
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

  it("401 retry uses the account the call started with; no retry if the selection changed", async () => {
    const gate = deferred<Response>();
    const { client, net, backend } = setup([() => gate.promise, () => empty(200)]);
    const pending = client.fetchWithToken(API);
    await new Promise((r) => setTimeout(r, 0));
    client.selectAccount(ACCOUNT_B);
    gate.resolve(empty(401));
    const resp = await pending;
    expect(resp.status).toBe(401);
    expect(backend()).toHaveLength(1);
    expect(net.calls.filter((c) => c.path === "/api/v1/auth/token").map((c) => c.body)).toEqual([
      { audience: "ricotdin", account_id: ACCOUNT_A },
    ]);
  });

  it("401 retry asks /token for the same account and returns the first response if it changes mid-refresh", async () => {
    const refresh = deferred<Response>();
    const ctx = makeClient(
      {
        [TOKEN]: [() => tokenResponse("token-1"), () => refresh.promise],
        [NOTES]: [() => empty(401), () => empty(200)],
      },
      { apiOrigins: [APP_ORIGIN] },
    );
    ctx.client.selectAccount(ACCOUNT_A);
    const pending = ctx.client.fetchWithToken(API);
    while (ctx.net.count(TOKEN) < 2) await new Promise((r) => setTimeout(r, 0));
    ctx.client.selectAccount(ACCOUNT_B);
    refresh.resolve(tokenResponse("token-for-A"));
    expect((await pending).status).toBe(401);
    const tokenCalls = ctx.net.calls.filter((c) => c.path === "/api/v1/auth/token");
    expect(tokenCalls.map((c) => (c.body as { account_id: string }).account_id)).toEqual([
      ACCOUNT_A,
      ACCOUNT_A,
    ]);
    expect(ctx.net.count(NOTES)).toBe(1);
  });

  describe("destination guard", () => {
    async function refused(input: RequestInfo | URL, options = {}) {
      const { client, net } = setup([() => empty(200)], options);
      const error = await client.fetchWithToken(input).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ConfigurationError);
      expect((error as AuthError).code).toBe("bearer_origin_not_allowed");
      expect((error as AuthError).status).toBe(0);
      expect(net.calls).toHaveLength(0);
    }

    it("cross-origin URL → bearer_origin_not_allowed before getToken/fetch", async () => {
      await refused("https://evil.example/api/notes");
      await refused(new URL("https://ricotdin.mmlabs.online.evil.example/api/notes"));
      await refused(new Request("https://evil.example/api/notes"));
    });

    it("http: URL → refused, even for an allowed host", async () => {
      await refused("http://ricotdin.mmlabs.online/api/notes", {
        apiOrigins: ["http://ricotdin.mmlabs.online"],
      });
      await refused("http://ricotdin.mmlabs.online/api/notes");
    });

    it("identity /api/v1/auth/* → refused even if its origin is allowed", async () => {
      for (const url of [
        `${BASE}/api/v1/auth/token`,
        `${BASE}/api/x/../v1/auth/token`,
        `${BASE}//api/v1/auth/accounts`,
        `${BASE}/API/V1/AUTH/token`,
        `${BASE}/api/v1/%61uth/token`,
      ]) {
        await refused(url, { apiOrigins: [APP_ORIGIN, BASE] });
      }
    });

    it("relative or unparsable URL without location → refused", async () => {
      await refused("/api/notes");
    });

    it("no apiOrigins and no location → refused", async () => {
      const { client, net } = makeClient({ [NOTES]: () => empty(200) });
      client.selectAccount(ACCOUNT_A);
      const error = await client.fetchWithToken(API).catch((e: unknown) => e);
      expect((error as AuthError).code).toBe("bearer_origin_not_allowed");
      expect(net.calls).toHaveLength(0);
    });

    it("allowed origin is called (other identity paths on an allowed origin too)", async () => {
      const { client, backend } = setup([() => empty(200)], {
        apiOrigins: [`${APP_ORIGIN}/ignored-path`],
      });
      expect((await client.fetchWithToken(API)).status).toBe(200);
      expect(auth(backend()[0])).toBe("Bearer token-1");
    });

    it("loopback http only with allowInsecureLocalhost", async () => {
      const local = "http://localhost:3000";
      await refused(`${local}/api/notes`, { apiOrigins: [local] });
      const { client, net } = makeClient(
        { [TOKEN]: () => tokenResponse(), [NOTES]: () => empty(200) },
        { apiOrigins: [local], allowInsecureLocalhost: true },
      );
      client.selectAccount(ACCOUNT_A);
      expect((await client.fetchWithToken(`${local}/api/notes`)).status).toBe(200);
      expect(net.count(NOTES)).toBe(1);
    });

    it("invalid apiOrigins entry → TypeError at construction", () => {
      expect(() => makeClient({}, { apiOrigins: ["not a url"] })).toThrow(TypeError);
    });
  });
});
