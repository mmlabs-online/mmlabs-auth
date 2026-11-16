/** The subset of `Storage` the client uses (only for `mm_account_id`). */
export type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** The subset of `BroadcastChannel` the client uses. */
export interface BroadcastLike {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: MessageEvent) => void): void;
  close(): void;
}

export type BroadcastFactory = (name: string) => BroadcastLike;

export interface AuthClientOptions {
  /** Identity API origin, e.g. `https://api.mmlabs.online`. Must be https. */
  baseUrl: string;
  /** This app's key (`X-MM-App`, token audience). */
  appKey: string;
  fetch?: typeof fetch;
  /** Where `mm_account_id` lives. Defaults to `localStorage`; `null` keeps it in memory. */
  storage?: StorageLike | null;
  now?: () => number;
  /** Cross-tab sync. `true` (default) uses `BroadcastChannel` when it exists. */
  broadcast?: boolean | BroadcastFactory;
  /** Allows `http://localhost` / `127.0.0.1` / `[::1]` for local development. */
  allowInsecureLocalhost?: boolean;
  /**
   * Origins `fetchWithToken` may send the Bearer token to (https, or loopback http with
   * `allowInsecureLocalhost`). Defaults to `[location.origin]`; required where there is no
   * `location`. The identity API's `/api/v1/auth/*` never receives it.
   */
  apiOrigins?: string[];
}

export interface Account {
  accountId: string;
  email: string;
  emailVerified: boolean;
  displayName: string | null;
}

export interface SignupResult {
  id: string;
  email: string;
  emailVerified: boolean;
  createdAt: string;
}

export interface LoginResult {
  accountId: string;
  user: { id: string; email: string; emailVerified: boolean };
}

export type LogoutTarget = { accountId: string } | { all: true };

export interface GetTokenOptions {
  accountId?: string;
  forceRefresh?: boolean;
}

/** `accountId` is the newly chosen account, or the one signed out (`null` = all). */
export type AuthEvent =
  | { type: "account-changed"; accountId: string | null }
  | { type: "signed-out"; accountId: string | null };
