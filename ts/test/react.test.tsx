// @vitest-environment happy-dom
import { act, cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type AuthClient, NetworkError, NotMemberError } from "../src/index.js";
import { AuthProvider, useAccessToken, useAuth, useJoin } from "../src/react/index.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  empty,
  envelope,
  FakeBroadcastHub,
  type Handler,
  json,
  loginResponse,
  makeClient,
  memoryStorage,
  SENTINEL_EMAIL,
  SENTINEL_PASSWORD,
  SENTINEL_TOKEN,
  tokenResponse,
} from "./helpers.js";

const API = "https://ricotdin.mmlabs.online";

function accounts(...ids: string[]) {
  return json(200, {
    items: ids.map((id) => ({
      account_id: id,
      email: SENTINEL_EMAIL,
      email_verified: true,
      display_name: null,
    })),
  });
}

function wrapperFor(client: AuthClient) {
  return ({ children }: { children: ReactNode }) => (
    <AuthProvider client={client}>{children}</AuthProvider>
  );
}

function setup(routes: Record<string, Handler | Handler[]>, stored: string | null = ACCOUNT_A) {
  const t = makeClient(
    { "POST /api/v1/auth/token": () => tokenResponse(), ...routes },
    { apiOrigins: [API] },
  );
  if (stored !== null) t.client.selectAccount(stored);
  return t;
}

/** Every string reachable from `value` (objects, arrays, errors); functions are skipped. */
function strings(value: unknown, seen = new Set<unknown>()): string[] {
  if (typeof value === "string") return [value];
  if (typeof value !== "object" || value === null || seen.has(value)) return [];
  seen.add(value);
  const keys = [...Object.getOwnPropertyNames(value), ...Object.getOwnPropertySymbols(value)];
  return keys.flatMap((k) => strings((value as Record<PropertyKey, unknown>)[k], seen));
}

/** Renders every hook result, as an app might while debugging. */
function Probe() {
  const auth = useAuth();
  const access = useAccessToken();
  const joining = useJoin();
  return (
    <div>
      <span data-testid="status">{auth.status}</span>
      <pre>{JSON.stringify({ auth, access, joining })}</pre>
      <button type="button" onClick={() => void access.getToken()}>
        token
      </button>
    </div>
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("AuthProvider / useAuth", () => {
  it("status loading → ready when the stored account is listed", async () => {
    const { client } = setup({ "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A) });
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current.status).toBe("ready"));
    expect(result.current.accountId).toBe(ACCOUNT_A);
    expect(result.current.accounts.map((a) => a.accountId)).toEqual([ACCOUNT_A]);
    expect(result.current.error).toBeNull();
  });

  it("signed-out on empty list or session_invalid", async () => {
    const empty1 = setup({ "GET /api/v1/auth/accounts": () => accounts() });
    const r1 = renderHook(() => useAuth(), { wrapper: wrapperFor(empty1.client) });
    await waitFor(() => expect(r1.result.current.status).toBe("signed-out"));
    expect(r1.result.current.accountId).toBeNull();

    const invalid = setup({
      "GET /api/v1/auth/accounts": () => envelope(401, "session_invalid"),
    });
    const r2 = renderHook(() => useAuth(), { wrapper: wrapperFor(invalid.client) });
    await waitFor(() => expect(r2.result.current.status).toBe("signed-out"));
    expect(r2.result.current.error).toBeNull();
    expect(r2.result.current.accounts).toEqual([]);
  });

  it("needs-account when accounts exist but none chosen", async () => {
    const none = setup({ "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A) }, null);
    const r1 = renderHook(() => useAuth(), { wrapper: wrapperFor(none.client) });
    await waitFor(() => expect(r1.result.current.status).toBe("needs-account"));
    expect(r1.result.current.accountId).toBeNull();

    // A stored account that is no longer signed in on this device counts as none chosen.
    const stale = setup({ "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_B) }, ACCOUNT_A);
    const r2 = renderHook(() => useAuth(), { wrapper: wrapperFor(stale.client) });
    await waitFor(() => expect(r2.result.current.status).toBe("needs-account"));
    expect(r2.result.current.accountId).toBeNull();
  });

  it("error status on NetworkError", async () => {
    const { client } = setup({
      "GET /api/v1/auth/accounts": () => {
        throw new TypeError("Failed to fetch");
      },
    });
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.status).toBe("error"));
    expect(result.current.error).toBeInstanceOf(NetworkError);
    expect(result.current.accountId).toBeNull();
  });

  it("selectAccount updates accountId and status", async () => {
    const { client } = setup(
      { "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A, ACCOUNT_B) },
      null,
    );
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.status).toBe("needs-account"));
    act(() => result.current.selectAccount(ACCOUNT_B));
    await waitFor(() => expect(result.current.status).toBe("ready"));
    expect(result.current.accountId).toBe(ACCOUNT_B);
    expect(client.getAccountId()).toBe(ACCOUNT_B);
  });

  it("login and logout update state", async () => {
    let signedIn: string[] = [];
    const { client, net } = setup(
      {
        "GET /api/v1/auth/accounts": () => accounts(...signedIn),
        "POST /api/v1/auth/login": () => {
          signedIn = [ACCOUNT_A];
          return loginResponse(ACCOUNT_A);
        },
        "POST /api/v1/auth/logout": () => {
          signedIn = [];
          return empty(204);
        },
      },
      null,
    );
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.status).toBe("signed-out"));

    await act(async () => {
      await result.current.login({ email: SENTINEL_EMAIL, password: SENTINEL_PASSWORD });
    });
    await waitFor(() => expect(result.current.status).toBe("ready"));
    expect(result.current.accountId).toBe(ACCOUNT_A);

    await act(async () => {
      await result.current.logout({ accountId: ACCOUNT_A });
    });
    await waitFor(() => expect(result.current.status).toBe("signed-out"));
    expect(result.current.accountId).toBeNull();
    // The last list call ran after the logout POST.
    const paths = net.calls.map((c) => `${c.method} ${c.path}`);
    expect(paths.lastIndexOf("GET /api/v1/auth/accounts")).toBeGreaterThan(
      paths.lastIndexOf("POST /api/v1/auth/logout"),
    );
  });

  it("another tab's broadcast re-renders", async () => {
    const hub = new FakeBroadcastHub();
    const shared = memoryStorage();
    const routes = { "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A, ACCOUNT_B) };
    const opts = { broadcast: hub.factory, storage: shared.storage };
    const tab1 = makeClient(routes, opts);
    const tab2 = makeClient(routes, opts);
    tab1.client.selectAccount(ACCOUNT_A);
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(tab2.client) });
    await waitFor(() => expect(result.current.accountId).toBe(ACCOUNT_A));
    act(() => tab1.client.selectAccount(ACCOUNT_B));
    await waitFor(() => expect(result.current.accountId).toBe(ACCOUNT_B));
    expect(result.current.status).toBe("ready");
  });

  it("hooks outside provider throw", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => renderHook(() => useAuth())).toThrow(/inside <AuthProvider>/);
    expect(() => renderHook(() => useAccessToken())).toThrow(/inside <AuthProvider>/);
    expect(() => renderHook(() => useJoin())).toThrow(/inside <AuthProvider>/);
  });

  it("unmount unsubscribes", async () => {
    const { client, net } = setup({ "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A) });
    const subscribe = client.onChange.bind(client);
    let unsubscribed = 0;
    vi.spyOn(client, "onChange").mockImplementation((listener) => {
      const off = subscribe(listener);
      return () => {
        unsubscribed++;
        return off();
      };
    });
    const { result, unmount } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.status).toBe("ready"));
    expect(unsubscribed).toBe(0);
    unmount();
    expect(unsubscribed).toBe(1);
    const before = net.count("GET /api/v1/auth/accounts");
    client.selectAccount(ACCOUNT_B);
    expect(net.count("GET /api/v1/auth/accounts")).toBe(before);
  });
});

describe("useAccessToken", () => {
  it("useAccessToken exposes getToken/fetchWithToken and no token value (JSON.stringify of the hook result and the context value)", async () => {
    const { client } = setup({
      "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A),
      "GET /api/notes": () => json(200, { ok: true }),
    });
    const { result } = renderHook(
      () => ({ auth: useAuth(), access: useAccessToken(), joining: useJoin() }),
      { wrapper: wrapperFor(client) },
    );
    await waitFor(() => expect(result.current.auth.status).toBe("ready"));
    const firstAccess = result.current.access;
    expect(Object.keys(firstAccess).sort()).toEqual(["fetchWithToken", "getToken"]);

    let token = "";
    await act(async () => {
      token = await result.current.access.getToken();
      await result.current.access.fetchWithToken(`${API}/api/notes`);
    });
    expect(token).toBe(SENTINEL_TOKEN);
    // Stable callbacks: fetching a token does not change the hook result.
    expect(result.current.access).toBe(firstAccess);

    // The context value (useAuth returns it unchanged), the client in context, and every hook.
    const values = [result.current.auth, client, result.current.access, result.current.joining];
    for (const value of values) {
      expect(JSON.stringify(value) ?? "").not.toContain(SENTINEL_TOKEN);
      for (const s of strings(value)) expect(s).not.toContain(SENTINEL_TOKEN);
    }
  });

  it("no token value appears in rendered output", async () => {
    const { client } = setup({ "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A) });
    const { container } = render(
      <AuthProvider client={client}>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status").textContent).toBe("ready"));
    await act(async () => {
      screen.getByText("token").click();
      await client.getToken(); // the same cached token the click fetched
    });
    expect(container.innerHTML).not.toContain(SENTINEL_TOKEN);
    expect(document.documentElement.outerHTML).not.toContain(SENTINEL_TOKEN);
  });

  it('admin-pan smoke: appKey "admin", getToken() requests audience admin', async () => {
    const { client, net } = makeClient(
      {
        "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A),
        "POST /api/v1/auth/token": () => tokenResponse(SENTINEL_TOKEN, 900, "admin"),
      },
      { appKey: "admin", apiOrigins: ["https://api.mmlabs.online"] },
    );
    client.selectAccount(ACCOUNT_A);
    const { result } = renderHook(() => ({ auth: useAuth(), access: useAccessToken() }), {
      wrapper: wrapperFor(client),
    });
    await waitFor(() => expect(result.current.auth.status).toBe("ready"));
    await act(async () => {
      await result.current.access.getToken();
    });
    const tokenCall = net.calls.find((c) => c.path === "/api/v1/auth/token");
    expect(tokenCall?.body).toEqual({ audience: "admin", account_id: ACCOUNT_A });
    expect(tokenCall?.headers.get("X-MM-App")).toBe("admin");
  });
});

describe("useJoin", () => {
  it("useJoin calls join only when invoked; NotMemberError surfaces via instanceof", async () => {
    let member = false;
    const { client, net } = setup({
      "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A),
      "POST /api/v1/auth/token": () =>
        member ? tokenResponse() : envelope(403, "not_member", { join_available: true }),
      "POST /api/v1/auth/apps/ricotdin/join": () => {
        member = true;
        return json(200, { status: "member" });
      },
    });
    const { result } = renderHook(() => ({ access: useAccessToken(), joining: useJoin() }), {
      wrapper: wrapperFor(client),
    });
    await waitFor(() => expect(net.count("GET /api/v1/auth/accounts")).toBe(1));

    let caught: unknown;
    await act(async () => {
      caught = await result.current.access.getToken().catch((e: unknown) => e);
    });
    expect(caught).toBeInstanceOf(NotMemberError);
    expect((caught as NotMemberError).joinAvailable).toBe(true);
    expect(net.count("POST /api/v1/auth/apps/ricotdin/join")).toBe(0);
    expect(result.current.joining.pending).toBe(false);

    // The user's click.
    let joined: Promise<"member"> | undefined;
    act(() => {
      joined = result.current.joining.join(ACCOUNT_A);
    });
    expect(result.current.joining.pending).toBe(true);
    await act(async () => {
      await joined;
    });
    expect(result.current.joining.pending).toBe(false);
    expect(result.current.joining.error).toBeNull();
    expect(net.count("POST /api/v1/auth/apps/ricotdin/join")).toBe(1);
    await act(async () => {
      expect(await result.current.access.getToken()).toBe(SENTINEL_TOKEN);
    });
  });

  it("join failure sets error and rethrows", async () => {
    const { client } = setup({
      "GET /api/v1/auth/accounts": () => accounts(ACCOUNT_A),
      "POST /api/v1/auth/apps/ricotdin/join": () => envelope(403, "join_closed"),
    });
    const { result } = renderHook(() => useJoin(), { wrapper: wrapperFor(client) });
    let caught: unknown;
    await act(async () => {
      caught = await result.current.join(ACCOUNT_A).catch((e: unknown) => e);
    });
    expect((caught as Error).name).toBe("JoinUnavailableError");
    expect(result.current.error).toBe(caught);
    expect(result.current.pending).toBe(false);
  });
});
