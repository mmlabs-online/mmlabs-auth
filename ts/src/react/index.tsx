import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { AuthClient } from "../client.js";
import { SessionInvalidError } from "../errors.js";
import type { Account, GetTokenOptions, LoginResult, LogoutTarget } from "../types.js";

export type AuthStatus = "loading" | "signed-out" | "needs-account" | "ready" | "error";

export interface AuthState {
  status: AuthStatus;
  /** The device's signed-in accounts, from the last `listAccounts()`. */
  accounts: Account[];
  /** This app's chosen account; set only when `status === "ready"`. */
  accountId: string | null;
  /** The `listAccounts()` failure when `status === "error"`. */
  error: Error | null;
  selectAccount(accountId: string): void;
  login(input: Parameters<AuthClient["login"]>[0]): Promise<LoginResult>;
  logout(target: LogoutTarget): Promise<void>;
  reload(): Promise<void>;
}

/** Functions only: the token value never enters React state, context or props. */
export interface AccessToken {
  getToken(options?: GetTokenOptions): Promise<string>;
  fetchWithToken(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface JoinState {
  /** Joins this app for `accountId`. Call it only from the user's click (D8). Rethrows. */
  join(accountId: string): Promise<"member">;
  pending: boolean;
  error: Error | null;
}

type Snapshot = Pick<AuthState, "status" | "accounts" | "accountId" | "error">;

const ClientContext = createContext<AuthClient | null>(null);
const StateContext = createContext<AuthState | null>(null);

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error("mmlabs-auth: unexpected error");
}

/**
 * Lists the accounts on mount and after every `client.onChange` event (login, account choice,
 * logout, other tabs). Holds no auth logic: the status is derived from `listAccounts()`.
 */
export function AuthProvider({ client, children }: { client: AuthClient; children?: ReactNode }) {
  const [snapshot, setSnapshot] = useState<Snapshot>({
    status: "loading",
    accounts: [],
    accountId: null,
    error: null,
  });
  // Only the latest listAccounts() call may set state; unmount invalidates all of them.
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const n = ++seq.current;
    try {
      const accounts = await client.listAccounts();
      if (n !== seq.current) return;
      const stored = client.getAccountId();
      const listed = stored !== null && accounts.some((a) => a.accountId === stored);
      setSnapshot({
        status: accounts.length === 0 ? "signed-out" : listed ? "ready" : "needs-account",
        accounts,
        accountId: listed ? stored : null,
        error: null,
      });
    } catch (error) {
      if (n !== seq.current) return;
      const signedOut = error instanceof SessionInvalidError;
      setSnapshot({
        status: signedOut ? "signed-out" : "error",
        accounts: [],
        accountId: null,
        error: signedOut ? null : asError(error),
      });
    }
  }, [client]);

  useEffect(() => {
    const unsubscribe = client.onChange(() => {
      void reload();
    });
    void reload();
    return () => {
      unsubscribe();
      seq.current++;
    };
  }, [client, reload]);

  const selectAccount = useCallback((id: string) => client.selectAccount(id), [client]);
  const login = useCallback(
    (input: Parameters<AuthClient["login"]>[0]) => client.login(input),
    [client],
  );
  // Local state is cleared (and an event emitted) before the POST; list again once it is done.
  const logout = useCallback(
    async (target: LogoutTarget) => {
      try {
        await client.logout(target);
      } finally {
        void reload();
      }
    },
    [client, reload],
  );

  const state = useMemo<AuthState>(
    () => ({ ...snapshot, selectAccount, login, logout, reload }),
    [snapshot, selectAccount, login, logout, reload],
  );

  return (
    <ClientContext.Provider value={client}>
      <StateContext.Provider value={state}>{children}</StateContext.Provider>
    </ClientContext.Provider>
  );
}

function useClient(hook: string): AuthClient {
  const client = useContext(ClientContext);
  if (client === null) throw new Error(`mmlabs-auth: ${hook} must be used inside <AuthProvider>`);
  return client;
}

/** The provider's state and actions (the context value itself). */
export function useAuth(): AuthState {
  const state = useContext(StateContext);
  if (state === null) throw new Error("mmlabs-auth: useAuth must be used inside <AuthProvider>");
  return state;
}

/** Stable `getToken` / `fetchWithToken` callbacks. There is deliberately no `token` field. */
export function useAccessToken(): AccessToken {
  const client = useClient("useAccessToken");
  return useMemo(
    () => ({
      getToken: (options?: GetTokenOptions) => client.getToken(options),
      fetchWithToken: (input: RequestInfo | URL, init?: RequestInit) =>
        client.fetchWithToken(input, init),
    }),
    [client],
  );
}

/** An explicit join for the user's "Continue as" click. Never called by the library. */
export function useJoin(): JoinState {
  const client = useClient("useJoin");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const join = useCallback(
    async (accountId: string) => {
      setPending(true);
      setError(null);
      try {
        return await client.join(accountId);
      } catch (e) {
        setError(asError(e));
        throw e;
      } finally {
        setPending(false);
      }
    },
    [client],
  );
  return useMemo(() => ({ join, pending, error }), [join, pending, error]);
}
