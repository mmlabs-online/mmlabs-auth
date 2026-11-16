import { RateLimitedError } from "./errors.js";

export interface IssuedToken {
  token: string;
  expiresIn: number;
}

interface Entry {
  token: string;
  freshUntil: number;
}

/** Fresh while `now < receivedAt + expires_in - skew`, skew = min(60 s, 20 % of expires_in). */
export function freshUntil(receivedAt: number, expiresIn: number): number {
  const lifetime = expiresIn * 1000;
  return receivedAt + lifetime - Math.min(60_000, lifetime * 0.2);
}

/**
 * In-memory access tokens keyed by `account|audience`. One request per key at a time
 * (single-flight); a result that lands after logout or an account switch is handed to its
 * callers but not cached (generation check). No timers: refresh happens on the next call.
 */
export class TokenCache {
  readonly #now: () => number;
  readonly #tokens = new Map<string, Entry>();
  readonly #inflight = new Map<string, Promise<string>>();
  readonly #generation = new Map<string, number>();
  readonly #blockedUntil = new Map<string, number>();
  #epoch = 0;

  constructor(now: () => number) {
    this.#now = now;
  }

  get(
    accountId: string,
    audience: string,
    forceRefresh: boolean,
    fetcher: () => Promise<IssuedToken>,
  ): Promise<string> {
    const now = this.#now();
    const blockedUntil = this.#blockedUntil.get(audience) ?? 0;
    if (now < blockedUntil) {
      const retryAfter = Math.ceil((blockedUntil - now) / 1000);
      return Promise.reject(new RateLimitedError("rate_limited", 429, { retryAfter }));
    }
    const key = `${accountId}|${audience}`;
    const cached = this.#tokens.get(key);
    if (forceRefresh) this.#tokens.delete(key);
    else if (cached !== undefined && now < cached.freshUntil) return Promise.resolve(cached.token);

    const pending = this.#inflight.get(key);
    if (pending !== undefined) return pending;

    const stamp = this.#stamp(accountId);
    const request = this.#fetch(key, accountId, audience, stamp, fetcher).finally(() => {
      if (this.#inflight.get(key) === request) this.#inflight.delete(key);
    });
    this.#inflight.set(key, request);
    return request;
  }

  async #fetch(
    key: string,
    accountId: string,
    audience: string,
    stamp: string,
    fetcher: () => Promise<IssuedToken>,
  ): Promise<string> {
    try {
      const issued = await fetcher();
      if (this.#stamp(accountId) === stamp) {
        this.#tokens.set(key, {
          token: issued.token,
          freshUntil: freshUntil(this.#now(), issued.expiresIn),
        });
      }
      return issued.token;
    } catch (error) {
      if (error instanceof RateLimitedError) {
        this.#blockedUntil.set(audience, this.#now() + error.retryAfter * 1000);
      }
      throw error;
    }
  }

  clearAccount(accountId: string): void {
    this.#generation.set(accountId, (this.#generation.get(accountId) ?? 0) + 1);
    for (const map of [this.#tokens, this.#inflight]) {
      for (const key of map.keys()) if (key.startsWith(`${accountId}|`)) map.delete(key);
    }
  }

  clearAll(): void {
    this.#epoch += 1;
    this.#tokens.clear();
    this.#inflight.clear();
  }

  #stamp(accountId: string): string {
    return `${this.#epoch}.${this.#generation.get(accountId) ?? 0}`;
  }
}
