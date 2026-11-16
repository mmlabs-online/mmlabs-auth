import type { StorageLike } from "./types.js";

export const ACCOUNT_KEY = "mm_account_id";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export function defaultStorage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * This origin's chosen account (`mm_account_id`). A storage that throws (private mode,
 * blocked site data) is dropped for good and the value lives in memory.
 */
export class AccountStore {
  #storage: StorageLike | null;
  #memory: string | null = null;

  constructor(storage: StorageLike | null) {
    this.#storage = storage;
  }

  get(): string | null {
    if (this.#storage !== null) {
      try {
        const value = this.#storage.getItem(ACCOUNT_KEY);
        if (value === null || isUuid(value)) return value;
        this.#storage.removeItem(ACCOUNT_KEY);
        return null;
      } catch {
        this.#storage = null;
      }
    }
    return this.#memory;
  }

  set(accountId: string): void {
    this.#memory = accountId;
    this.#write((s) => s.setItem(ACCOUNT_KEY, accountId));
  }

  clear(): void {
    this.#memory = null;
    this.#write((s) => s.removeItem(ACCOUNT_KEY));
  }

  #write(op: (storage: StorageLike) => void): void {
    if (this.#storage === null) return;
    try {
      op(this.#storage);
    } catch {
      this.#storage = null;
    }
  }
}
