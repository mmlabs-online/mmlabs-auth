import { AccountStore, defaultStorage, isUuid } from "./accounts.js";
import { createFetchWithToken, type FetchWithToken } from "./bearer.js";
import { Broadcast, type BroadcastMessage } from "./broadcast.js";
import {
  AuthError,
  ConfigurationError,
  EmailAlreadyVerifiedError,
  isRecord,
  SessionInvalidError,
} from "./errors.js";
import { TokenCache } from "./token-cache.js";
import {
  createTransport,
  normaliseBaseUrl,
  readJson,
  type Transport,
  unexpected,
} from "./transport.js";
import type {
  Account,
  AuthClientOptions,
  AuthEvent,
  GetTokenOptions,
  LoginResult,
  LogoutTarget,
  SignupResult,
} from "./types.js";

/** Same as the server's `APP_KEY_RE` (org-admin-api `app/modules/rbac/models.py`). */
const APP_KEY_RE = /^[a-z][a-z0-9-]{1,31}$/;

function str(value: unknown): value is string {
  return typeof value === "string";
}

function requireAccountId(accountId: unknown): string {
  if (!isUuid(accountId)) throw new TypeError("mmlabs-auth: accountId must be a UUID");
  return accountId;
}

export class AuthClient {
  readonly appKey: string;
  readonly #transport: Transport;
  readonly #now: () => number;
  readonly #store: AccountStore;
  readonly #tokens: TokenCache;
  readonly #broadcast: Broadcast;
  readonly #bearer: FetchWithToken;
  readonly #listeners = new Set<(event: AuthEvent) => void>();

  constructor(options: AuthClientOptions) {
    if (!APP_KEY_RE.test(options.appKey)) throw new TypeError("mmlabs-auth: invalid appKey");
    this.appKey = options.appKey;
    const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#now = options.now ?? Date.now;
    this.#transport = createTransport({
      baseUrl: normaliseBaseUrl(options.baseUrl, options.allowInsecureLocalhost === true),
      appKey: this.appKey,
      fetch: fetchImpl,
      now: this.#now,
    });
    this.#store = new AccountStore(
      options.storage === undefined ? defaultStorage() : options.storage,
    );
    this.#tokens = new TokenCache(this.#now);
    this.#bearer = createFetchWithToken({
      fetch: fetchImpl,
      now: this.#now,
      getToken: (forceRefresh) => this.getToken({ forceRefresh }),
    });
    this.#broadcast = new Broadcast(this.appKey, options.broadcast ?? true, {
      onMessage: (message) => this.#onBroadcast(message),
      onAccountStorage: () =>
        this.#emit({ type: "account-changed", accountId: this.getAccountId() }),
    });
  }

  async signup(input: {
    email: string;
    password: string;
    turnstileToken: string;
  }): Promise<SignupResult> {
    const resp = await this.#transport.authFetch("/api/v1/auth/signup", "POST", {
      email: input.email,
      password: input.password,
      turnstile_token: input.turnstileToken,
    });
    const body = await readJson(resp);
    if (!isRecord(body) || !str(body.id) || !str(body.email) || !str(body.created_at)) {
      throw unexpected(resp);
    }
    return {
      id: body.id,
      email: body.email,
      emailVerified: body.email_verified === true,
      createdAt: body.created_at,
    };
  }

  async login(input: {
    email: string;
    password: string;
    turnstileToken?: string;
  }): Promise<LoginResult> {
    const resp = await this.#transport.authFetch("/api/v1/auth/login", "POST", {
      email: input.email,
      password: input.password,
      ...(input.turnstileToken !== undefined && { turnstile_token: input.turnstileToken }),
    });
    const body = await readJson(resp);
    const user = isRecord(body) ? body.user : undefined;
    if (!isRecord(body) || !isUuid(body.account_id) || !isRecord(user)) throw unexpected(resp);
    if (!str(user.id) || !str(user.email)) throw unexpected(resp);
    this.selectAccount(body.account_id);
    return {
      accountId: body.account_id,
      user: { id: user.id, email: user.email, emailVerified: user.email_verified === true },
    };
  }

  async listAccounts(): Promise<Account[]> {
    const resp = await this.#transport.authFetch("/api/v1/auth/accounts", "GET");
    const body = await readJson(resp);
    const items = isRecord(body) ? body.items : undefined;
    if (!Array.isArray(items)) throw unexpected(resp);
    return items.map((item: unknown) => {
      if (!isRecord(item) || !isUuid(item.account_id) || !str(item.email)) throw unexpected(resp);
      return {
        accountId: item.account_id,
        email: item.email,
        emailVerified: item.email_verified === true,
        displayName: str(item.display_name) ? item.display_name : null,
      };
    });
  }

  getAccountId(): string | null {
    return this.#store.get();
  }

  /** Chooses the account for this origin (`mm_account_id`) and drops cached tokens. */
  selectAccount(accountId: string): void {
    this.#store.set(requireAccountId(accountId));
    this.#tokens.clearAll();
    this.#emit({ type: "account-changed", accountId });
    this.#broadcast.post({ type: "account_changed" });
  }

  clearAccount(): void {
    this.#store.clear();
    this.#tokens.clearAll();
    this.#emit({ type: "account-changed", accountId: null });
    this.#broadcast.post({ type: "account_changed" });
  }

  invalidateToken(): void {
    this.#tokens.clearAll();
  }

  /** This app's access token, from memory while fresh. `audience` must be the `appKey`. */
  getToken(options?: GetTokenOptions): Promise<string>;
  getToken(audience: string, options?: GetTokenOptions): Promise<string>;
  async getToken(arg?: string | GetTokenOptions, more: GetTokenOptions = {}): Promise<string> {
    const audience = typeof arg === "string" ? arg : this.appKey;
    const options = typeof arg === "object" ? arg : more;
    if (audience !== this.appKey) throw new ConfigurationError("audience_mismatch", 0);
    const accountId = options.accountId ?? this.getAccountId();
    if (accountId === null) throw new AuthError("no_account_selected", 0);
    try {
      return await this.#tokens.get(accountId, audience, options.forceRefresh === true, () =>
        this.#issue(audience, accountId),
      );
    } catch (error) {
      if (error instanceof SessionInvalidError) this.#tokens.clearAccount(accountId);
      throw error;
    }
  }

  fetchWithToken(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return this.#bearer(input, init);
  }

  /** Joins this app for `accountId`. Call it only from the user's "Continue as" click (D8). */
  async join(accountId: string): Promise<"member"> {
    const id = requireAccountId(accountId);
    const resp = await this.#transport.authFetch(`/api/v1/auth/apps/${this.appKey}/join`, "POST", {
      account_id: id,
    });
    const body = await readJson(resp);
    if (!isRecord(body) || body.status !== "member") throw unexpected(resp);
    return "member";
  }

  /** Clears local state first (fail safe), tells other tabs, then calls the API. */
  async logout(target: LogoutTarget): Promise<void> {
    let body: { all: true } | { account_id: string };
    if ("all" in target && target.all === true) {
      this.#tokens.clearAll();
      this.#store.clear();
      this.#broadcast.post({ type: "logout_all" });
      this.#emit({ type: "signed-out", accountId: null });
      body = { all: true };
    } else {
      const id = requireAccountId((target as { accountId: unknown }).accountId);
      this.#forget(id);
      this.#broadcast.post({ type: "logout", accountId: id });
      this.#emit({ type: "signed-out", accountId: id });
      body = { account_id: id };
    }
    await this.#transport.authFetch("/api/v1/auth/logout", "POST", body);
  }

  async resendVerification(accountId?: string): Promise<"sent" | "already_verified"> {
    const id = accountId ?? this.getAccountId();
    if (id === null) throw new AuthError("no_account_selected", 0);
    try {
      await this.#transport.authFetch("/api/v1/auth/verify-email/resend", "POST", {
        account_id: id,
      });
      return "sent";
    } catch (error) {
      if (error instanceof EmailAlreadyVerifiedError) return "already_verified";
      throw error;
    }
  }

  async forgotPassword(input: { email: string; turnstileToken: string }): Promise<void> {
    await this.#transport.authFetch("/api/v1/auth/password/forgot", "POST", {
      email: input.email,
      turnstile_token: input.turnstileToken,
    });
  }

  async verifyEmail(token: string): Promise<void> {
    await this.#transport.publicFetch("/api/v1/auth/verify-email", { token });
  }

  async resetPassword(input: { token: string; newPassword: string }): Promise<void> {
    await this.#transport.publicFetch("/api/v1/auth/password/reset", {
      token: input.token,
      new_password: input.newPassword,
    });
  }

  onChange(listener: (event: AuthEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  dispose(): void {
    this.#broadcast.close();
    this.#listeners.clear();
    this.#tokens.clearAll();
  }

  async #issue(audience: string, accountId: string): Promise<{ token: string; expiresIn: number }> {
    const resp = await this.#transport.authFetch("/api/v1/auth/token", "POST", {
      audience,
      account_id: accountId,
    });
    const body = await readJson(resp);
    if (!isRecord(body) || !str(body.access_token) || body.access_token === "") {
      throw unexpected(resp);
    }
    const expiresIn = body.expires_in;
    if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) {
      throw unexpected(resp);
    }
    return { token: body.access_token, expiresIn };
  }

  #forget(accountId: string): void {
    this.#tokens.clearAccount(accountId);
    if (this.#store.get() === accountId) this.#store.clear();
  }

  #onBroadcast(message: BroadcastMessage): void {
    if (message.type === "logout") {
      this.#forget(message.accountId);
      this.#emit({ type: "signed-out", accountId: message.accountId });
    } else if (message.type === "logout_all") {
      this.#tokens.clearAll();
      this.#store.clear();
      this.#emit({ type: "signed-out", accountId: null });
    } else {
      this.#tokens.clearAll();
      this.#emit({ type: "account-changed", accountId: this.getAccountId() });
    }
  }

  #emit(event: AuthEvent): void {
    for (const listener of [...this.#listeners]) {
      try {
        listener(event);
      } catch {
        // A failing listener must not break the client or the other listeners.
      }
    }
  }
}

export function createAuthClient(options: AuthClientOptions): AuthClient {
  return new AuthClient(options);
}
