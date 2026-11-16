import { AuthError, mapError, NetworkError } from "./errors.js";

const AUTH_PREFIX = "/api/v1/auth/";
export const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Validates `baseUrl` (https, or loopback http when allowed) and drops a trailing slash. */
export function normaliseBaseUrl(raw: string, allowInsecureLocalhost: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError("mmlabs-auth: baseUrl is not a valid URL");
  }
  const insecureOk =
    allowInsecureLocalhost && url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (url.protocol !== "https:" && !insecureOk) {
    throw new TypeError("mmlabs-auth: baseUrl must use https");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new TypeError("mmlabs-auth: baseUrl must not carry credentials, a query or a fragment");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}

export interface TransportDeps {
  baseUrl: string;
  appKey: string;
  fetch: typeof fetch;
  now: () => number;
}

export interface Transport {
  /** Cookie-class call: `credentials:"include"`, `X-MM-App`, `cache:"no-store"`. */
  authFetch(path: string, method: "GET" | "POST", body?: unknown): Promise<Response>;
  /** Public call (verify-email, reset): `credentials:"omit"`, no `X-MM-App`. */
  publicFetch(path: string, body: unknown): Promise<Response>;
}

export async function readJson(resp: Response): Promise<unknown> {
  try {
    return await resp.json();
  } catch {
    throw unexpected(resp);
  }
}

export function unexpected(resp: Response): AuthError {
  return new AuthError("unexpected_response", resp.status, {
    requestId: resp.headers.get("X-Request-ID") ?? undefined,
  });
}

export function createTransport(deps: TransportDeps): Transport {
  const authRoot = new URL(deps.baseUrl + AUTH_PREFIX).pathname;

  /** Prefix check on the resolved pathname; dot segments (`..`, `%2e`) are refused outright. */
  function isAuthPath(path: string): boolean {
    if (!path.startsWith(AUTH_PREFIX) || /\.\.|%2e/i.test(path)) return false;
    try {
      return new URL(deps.baseUrl + path).pathname.startsWith(authRoot);
    } catch {
      return false;
    }
  }

  async function send(path: string, init: RequestInit): Promise<Response> {
    let resp: Response;
    try {
      resp = await deps.fetch(deps.baseUrl + path, init);
    } catch {
      throw new NetworkError("network_error", 0);
    }
    if (resp.ok) return resp;
    let body: unknown;
    try {
      body = JSON.parse(await resp.text());
    } catch {
      body = undefined;
    }
    throw mapError(resp.status, body, resp.headers, deps.now());
  }

  return {
    authFetch(path, method, body) {
      if (!isAuthPath(path)) {
        throw new TypeError("mmlabs-auth: authFetch only calls /api/v1/auth/*");
      }
      const headers: Record<string, string> = { "X-MM-App": deps.appKey };
      const init: RequestInit = { method, credentials: "include", cache: "no-store", headers };
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      return send(path, init);
    },
    publicFetch(path, body) {
      return send(path, {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    },
  };
}
