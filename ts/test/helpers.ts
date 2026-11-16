import { type AuthClient, createAuthClient } from "../src/index.js";
import type { AuthClientOptions, BroadcastLike, StorageLike } from "../src/types.js";

export const SENTINEL_PASSWORD = "Sentinel-Password-7f3a91";
export const SENTINEL_EMAIL = "sentinel.user.7f3a91@example.test";
export const SENTINEL_TOKEN = "sentinel-token-7f3a91.payload.signature";
export const BASE = "https://api.mmlabs.online";
export const ACCOUNT_A = "11111111-1111-4111-8111-111111111111";
export const ACCOUNT_B = "22222222-2222-4222-8222-222222222222";

export interface Recorded {
  url: string;
  path: string;
  method: string;
  init: RequestInit;
  headers: Headers;
  body: unknown;
}

export type Handler = (req: Recorded) => Response | Promise<Response>;

/** Routes keyed `"METHOD /path"`; an array is consumed in order (the last one repeats). */
export function fakeFetch(routes: Record<string, Handler | Handler[]> = {}) {
  const calls: Recorded[] = [];
  const impl = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = init.method ?? "GET";
    const path = new URL(url).pathname;
    const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
    const rec: Recorded = { url, path, method, init, headers: new Headers(init.headers), body };
    calls.push(rec);
    const route = routes[`${method} ${path}`];
    const handler = Array.isArray(route) ? (route.length > 1 ? route.shift() : route[0]) : route;
    if (handler === undefined) throw new Error(`unexpected request ${method} ${path}`);
    return handler(rec);
  };
  return {
    fetch: impl as typeof fetch,
    calls,
    routes,
    count: (key: string) => calls.filter((c) => `${c.method} ${c.path}` === key).length,
  };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export function empty(status: number, headers: Record<string, string> = {}) {
  return new Response(null, { status, headers });
}

/** An error envelope whose server message carries sentinels (it must never be kept). */
export function envelope(
  status: number,
  code: string,
  details: unknown = null,
  headers: Record<string, string> = {},
) {
  const message = `server says ${SENTINEL_EMAIL} ${SENTINEL_PASSWORD} ${SENTINEL_TOKEN}`;
  return json(status, { error: { code, message, details } }, headers);
}

export function tokenResponse(token = SENTINEL_TOKEN, expiresIn = 900, audience = "ricotdin") {
  return json(
    200,
    { access_token: token, token_type: "Bearer", expires_in: expiresIn, audience },
    { "Cache-Control": "no-store" },
  );
}

export function loginResponse(accountId = ACCOUNT_A) {
  return json(200, {
    account_id: accountId,
    user: {
      id: "33333333-3333-4333-8333-333333333333",
      email: SENTINEL_EMAIL,
      email_verified: true,
    },
  });
}

export function fakeClock(start = 1_700_000_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

export function memoryStorage(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  const writes: Array<[string, string]> = [];
  const storage: StorageLike = {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => {
      writes.push([k, v]);
      data.set(k, v);
    },
    removeItem: (k) => {
      data.delete(k);
    },
  };
  return { storage, data, writes };
}

export function throwingStorage(): StorageLike {
  const fail = () => {
    throw new DOMException("blocked", "SecurityError");
  };
  return { getItem: fail, setItem: fail, removeItem: fail };
}

/** Delivers synchronously to every other channel of the same name. */
export class FakeBroadcastHub {
  readonly posted: unknown[] = [];
  readonly channels: FakeChannel[] = [];
  readonly factory = (name: string): BroadcastLike => {
    const channel = new FakeChannel(name, this);
    this.channels.push(channel);
    return channel;
  };
}

export class FakeChannel implements BroadcastLike {
  closed = false;
  readonly listeners: Array<(event: MessageEvent) => void> = [];
  constructor(
    readonly name: string,
    readonly hub: FakeBroadcastHub,
  ) {}
  postMessage(message: unknown): void {
    this.hub.posted.push(message);
    for (const other of this.hub.channels) {
      if (other !== this && !other.closed && other.name === this.name) other.deliver(message);
    }
  }
  deliver(data: unknown): void {
    for (const l of this.listeners) l({ data } as MessageEvent);
  }
  addEventListener(_type: "message", listener: (event: MessageEvent) => void): void {
    this.listeners.push(listener);
  }
  close(): void {
    this.closed = true;
    this.listeners.length = 0;
  }
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

export function makeClient(
  routes: Record<string, Handler | Handler[]> = {},
  options: Partial<AuthClientOptions> = {},
) {
  const net = fakeFetch(routes);
  const clock = fakeClock();
  const mem = memoryStorage();
  const client: AuthClient = createAuthClient({
    baseUrl: BASE,
    appKey: "ricotdin",
    fetch: net.fetch,
    storage: mem.storage,
    now: clock.now,
    broadcast: false,
    ...options,
  });
  return { client, net, clock, mem };
}
