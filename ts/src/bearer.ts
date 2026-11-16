const FORCED_REFRESH_INTERVAL_MS = 30_000;

export interface BearerDeps {
  fetch: typeof fetch;
  now: () => number;
  getToken(forceRefresh: boolean): Promise<string>;
}

export type FetchWithToken = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * Calls the app's own backend with `Authorization: Bearer`. Never sends cookies or `X-MM-App`.
 * On a 401 it fetches a fresh token and retries once, at most once per 30 s (one audience
 * per client); the second response is returned whatever its status.
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
    const first = await send(input, init, await deps.getToken(false));
    if (first.status !== 401) return first;
    const streamed =
      init.body instanceof ReadableStream || (input instanceof Request && input.body !== null);
    const now = deps.now();
    if (streamed || now - lastForcedAt < FORCED_REFRESH_INTERVAL_MS) return first;
    lastForcedAt = now;
    return send(input, init, await deps.getToken(true));
  };
}
