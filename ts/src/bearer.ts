import { AuthError, ConfigurationError } from "./errors.js";
import { LOOPBACK } from "./transport.js";

const FORCED_REFRESH_INTERVAL_MS = 30_000;
const AUTH_PATH = /\/api\/v1\/auth(\/|$)/i;

export interface BearerDeps {
  fetch: typeof fetch;
  now: () => number;
  /** Identity API base (normalised); Bearer is never sent under its `/api/v1/auth/`. */
  baseUrl: string;
  /** Origins that may receive the token; `undefined` = `[location.origin]` when it exists. */
  apiOrigins: readonly string[] | undefined;
  allowInsecureLocalhost: boolean;
  getAccountId(): string | null;
  getToken(accountId: string | null, forceRefresh: boolean): Promise<string>;
}

export type FetchWithToken = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Normalises `apiOrigins` entries to origins; throws `TypeError` on an invalid entry. */
export function normaliseOrigins(origins: readonly string[]): string[] {
  return origins.map((raw) => {
    try {
      return new URL(raw).origin;
    } catch {
      throw new TypeError("mmlabs-auth: apiOrigins entry is not a valid URL");
    }
  });
}

/** Decoded, slash-collapsed path check, as a server router would see it. */
function isAuthPath(pathname: string): boolean {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return true;
  }
  return AUTH_PATH.test(decoded.replace(/\/{2,}/g, "/"));
}

function currentLocation(): { href: string; origin: string } | undefined {
  const loc = (globalThis as { location?: { href?: unknown; origin?: unknown } }).location;
  return typeof loc?.href === "string" && typeof loc.origin === "string"
    ? { href: loc.href, origin: loc.origin }
    : undefined;
}

/**
 * Throws `ConfigurationError("bearer_origin_not_allowed")` unless the target is https (or
 * loopback http with the opt-in), its origin is allowed, and it is not an identity auth path.
 */
function assertDestination(deps: BearerDeps, input: RequestInfo | URL): void {
  const loc = currentLocation();
  const allowed = deps.apiOrigins ?? (loc === undefined ? [] : [loc.origin]);
  const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  let target: URL;
  try {
    target = new URL(raw, loc?.href);
  } catch {
    throw new ConfigurationError("bearer_origin_not_allowed", 0);
  }
  const insecureOk =
    deps.allowInsecureLocalhost && target.protocol === "http:" && LOOPBACK.has(target.hostname);
  const onIdentityAuth =
    target.origin === new URL(deps.baseUrl).origin && isAuthPath(target.pathname);
  if (
    (target.protocol !== "https:" && !insecureOk) ||
    !allowed.includes(target.origin) ||
    onIdentityAuth
  ) {
    throw new ConfigurationError("bearer_origin_not_allowed", 0);
  }
}

/**
 * Calls the app's own backend with `Authorization: Bearer`. Never sends cookies or `X-MM-App`.
 * Only allowed origins receive the token. The account is fixed when the call starts: on a
 * 401 it fetches a fresh token for that account and retries once, at most once per 30 s (one
 * audience per client), and skips the retry if the selected account has changed meanwhile.
 * The second response is returned whatever its status.
 */
export function createFetchWithToken(deps: BearerDeps): FetchWithToken {
  let lastForcedAt = Number.NEGATIVE_INFINITY;

  async function send(input: RequestInfo | URL, init: RequestInit, token: string) {
    const base = init.headers ?? (input instanceof Request ? input.headers : undefined);
    const headers = new Headers(base);
    headers.delete("X-MM-App");
    headers.set("Authorization", `Bearer ${token}`);
    return deps.fetch(input, { ...init, headers, credentials: "omit" });
  }

  return async (input, init = {}) => {
    assertDestination(deps, input);
    const accountId = deps.getAccountId();
    const first = await send(input, init, await deps.getToken(accountId, false));
    if (first.status !== 401) return first;
    const streamed =
      init.body instanceof ReadableStream || (input instanceof Request && input.body !== null);
    const now = deps.now();
    if (streamed || now - lastForcedAt < FORCED_REFRESH_INTERVAL_MS) return first;
    if (deps.getAccountId() !== accountId) return first;
    lastForcedAt = now;
    let token: string;
    try {
      token = await deps.getToken(accountId, true);
    } catch (error) {
      if (error instanceof AuthError && error.code === "account_changed") return first;
      throw error;
    }
    if (deps.getAccountId() !== accountId) return first;
    return send(input, init, token);
  };
}
