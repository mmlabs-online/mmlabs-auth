import { ACCOUNT_KEY, isUuid } from "./accounts.js";
import { isRecord } from "./errors.js";
import type { BroadcastFactory, BroadcastLike } from "./types.js";

/** Cross-tab messages. They never carry a token or an email. */
export type BroadcastMessage =
  | { type: "logout"; accountId: string }
  | { type: "logout_all" }
  | { type: "account_changed" };

export function parseMessage(data: unknown): BroadcastMessage | null {
  if (!isRecord(data)) return null;
  const size = Object.keys(data).length;
  if (size === 1 && (data.type === "logout_all" || data.type === "account_changed")) {
    return { type: data.type };
  }
  if (size === 2 && data.type === "logout" && isUuid(data.accountId)) {
    return { type: "logout", accountId: data.accountId };
  }
  return null;
}

export interface BroadcastHandlers {
  onMessage(message: BroadcastMessage): void;
  /** Another tab changed `mm_account_id` (the `storage` event fallback). */
  onAccountStorage(): void;
}

/**
 * `BroadcastChannel("mmlabs-auth:<appKey>")`, or the `storage` event when no channel exists;
 * no-op without either.
 */
export class Broadcast {
  readonly #channel: BroadcastLike | null = null;
  readonly #onStorage: ((event: Event) => void) | null = null;

  constructor(appKey: string, option: boolean | BroadcastFactory, handlers: BroadcastHandlers) {
    if (option === false) return;
    const factory =
      typeof option === "function"
        ? option
        : typeof BroadcastChannel === "function"
          ? (name: string) => new BroadcastChannel(name)
          : null;
    try {
      this.#channel = factory?.(`mmlabs-auth:${appKey}`) ?? null;
      this.#channel?.addEventListener("message", (event) => {
        const message = parseMessage(event.data);
        if (message !== null) handlers.onMessage(message);
      });
    } catch {
      this.#channel = null;
    }
    // Fallback only: with a channel, the same change would otherwise be handled twice.
    if (this.#channel === null && typeof globalThis.addEventListener === "function") {
      this.#onStorage = (event) => {
        if ((event as StorageEvent).key === ACCOUNT_KEY) handlers.onAccountStorage();
      };
      globalThis.addEventListener("storage", this.#onStorage);
    }
  }

  post(message: BroadcastMessage): void {
    try {
      this.#channel?.postMessage(message);
    } catch {
      // A closed or broken channel only loses cross-tab sync.
    }
  }

  close(): void {
    this.#channel?.close();
    if (this.#onStorage !== null) globalThis.removeEventListener("storage", this.#onStorage);
  }
}
