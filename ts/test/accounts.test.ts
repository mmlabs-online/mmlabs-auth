import { describe, expect, it } from "vitest";
import { SessionInvalidError } from "../src/index.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  deferred,
  empty,
  envelope,
  json,
  loginResponse,
  makeClient,
  memoryStorage,
  SENTINEL_EMAIL,
  throwingStorage,
  tokenResponse,
} from "./helpers.js";

describe("accounts", () => {
  it("login stores account_id as mm_account_id and returns LoginResult", async () => {
    const { client, mem } = makeClient({ "POST /api/v1/auth/login": () => loginResponse() });
    const result = await client.login({ email: SENTINEL_EMAIL, password: "pw" });
    expect(result).toEqual({
      accountId: ACCOUNT_A,
      user: {
        id: "33333333-3333-4333-8333-333333333333",
        email: SENTINEL_EMAIL,
        emailVerified: true,
      },
    });
    expect(mem.data.get("mm_account_id")).toBe(ACCOUNT_A);
    expect(client.getAccountId()).toBe(ACCOUNT_A);
  });

  it("listAccounts maps items", async () => {
    const { client } = makeClient({
      "GET /api/v1/auth/accounts": () =>
        json(200, {
          items: [
            { account_id: ACCOUNT_A, email: "a@x.test", email_verified: true, display_name: "A" },
            { account_id: ACCOUNT_B, email: "b@x.test", email_verified: false, display_name: null },
          ],
        }),
    });
    expect(await client.listAccounts()).toEqual([
      { accountId: ACCOUNT_A, email: "a@x.test", emailVerified: true, displayName: "A" },
      { accountId: ACCOUNT_B, email: "b@x.test", emailVerified: false, displayName: null },
    ]);
  });

  it("selectAccount rejects a non-UUID", () => {
    const { client, mem } = makeClient();
    expect(() => client.selectAccount("../../etc")).toThrow(TypeError);
    expect(() => client.selectAccount("")).toThrow(TypeError);
    expect(mem.writes).toEqual([]);
  });

  it("invalid stored mm_account_id is dropped and removed on read", () => {
    const mem = memoryStorage({ mm_account_id: "<script>" });
    const { client } = makeClient({}, { storage: mem.storage });
    expect(client.getAccountId()).toBeNull();
    expect(mem.data.has("mm_account_id")).toBe(false);
  });

  it("throwing storage falls back to memory without throwing", () => {
    const { client } = makeClient({}, { storage: throwingStorage() });
    expect(client.getAccountId()).toBeNull();
    client.selectAccount(ACCOUNT_A);
    expect(client.getAccountId()).toBe(ACCOUNT_A);
    client.clearAccount();
    expect(client.getAccountId()).toBeNull();
  });

  it("storage: null uses memory", () => {
    const { client } = makeClient({}, { storage: null });
    client.selectAccount(ACCOUNT_B);
    expect(client.getAccountId()).toBe(ACCOUNT_B);
  });

  it("logout({accountId: current}) clears mm_account_id; another account leaves it", async () => {
    const { client, mem } = makeClient({ "POST /api/v1/auth/logout": () => empty(204) });
    client.selectAccount(ACCOUNT_A);
    await client.logout({ accountId: ACCOUNT_B });
    expect(mem.data.get("mm_account_id")).toBe(ACCOUNT_A);
    await client.logout({ accountId: ACCOUNT_A });
    expect(mem.data.has("mm_account_id")).toBe(false);
  });

  it("logout({all:true}) clears mm_account_id and all tokens", async () => {
    const { client, net, mem } = makeClient({
      "POST /api/v1/auth/logout": () => empty(204),
      "POST /api/v1/auth/token": () => tokenResponse(),
    });
    client.selectAccount(ACCOUNT_A);
    await client.getToken();
    await client.getToken({ accountId: ACCOUNT_B });
    await client.logout({ all: true });
    expect(mem.data.has("mm_account_id")).toBe(false);
    await client.getToken({ accountId: ACCOUNT_B });
    expect(net.count("POST /api/v1/auth/token")).toBe(3);
  });

  it("logout body is {account_id} XOR {all:true}", async () => {
    const { client, net } = makeClient({ "POST /api/v1/auth/logout": () => empty(204) });
    await client.logout({ accountId: ACCOUNT_A });
    await client.logout({ all: true });
    expect(net.calls.map((c) => c.body)).toEqual([{ account_id: ACCOUNT_A }, { all: true }]);
    await expect(client.logout({ accountId: "nope" })).rejects.toThrow(TypeError);
  });

  it("logout clears cached tokens synchronously before the request resolves", async () => {
    const gate = deferred<Response>();
    const { client, net } = makeClient({
      "POST /api/v1/auth/token": () => tokenResponse(),
      "POST /api/v1/auth/logout": () => gate.promise,
    });
    client.selectAccount(ACCOUNT_A);
    await client.getToken();
    const pending = client.logout({ accountId: ACCOUNT_A });
    expect(client.getAccountId()).toBeNull();
    await client.getToken({ accountId: ACCOUNT_A });
    expect(net.count("POST /api/v1/auth/token")).toBe(2);
    gate.resolve(empty(204));
    await pending;
  });

  it("session_invalid from getToken clears that account's tokens but keeps mm_account_id", async () => {
    const { client, net, mem } = makeClient({
      "POST /api/v1/auth/token": [
        () => tokenResponse("first-token"),
        () => envelope(401, "session_invalid"),
        () => tokenResponse("second-token"),
      ],
    });
    client.selectAccount(ACCOUNT_A);
    expect(await client.getToken()).toBe("first-token");
    await expect(client.getToken({ forceRefresh: true })).rejects.toBeInstanceOf(
      SessionInvalidError,
    );
    expect(mem.data.get("mm_account_id")).toBe(ACCOUNT_A);
    expect(await client.getToken()).toBe("second-token");
    expect(net.count("POST /api/v1/auth/token")).toBe(3);
  });
});
