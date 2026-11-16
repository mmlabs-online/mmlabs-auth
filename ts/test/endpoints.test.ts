import { describe, expect, it } from "vitest";
import { EmailTakenError, NotMemberError } from "../src/index.js";
import {
  ACCOUNT_A,
  empty,
  envelope,
  json,
  loginResponse,
  makeClient,
  SENTINEL_EMAIL,
  SENTINEL_PASSWORD,
} from "./helpers.js";

describe("endpoints", () => {
  it("signup sends {email,password,turnstile_token} and returns SignupResult", async () => {
    const { client, net } = makeClient({
      "POST /api/v1/auth/signup": () =>
        json(201, {
          id: ACCOUNT_A,
          email: SENTINEL_EMAIL,
          email_verified: false,
          created_at: "2026-11-16T10:00:00Z",
        }),
    });
    const result = await client.signup({
      email: SENTINEL_EMAIL,
      password: SENTINEL_PASSWORD,
      turnstileToken: "ts",
    });
    expect(net.calls[0]?.body).toEqual({
      email: SENTINEL_EMAIL,
      password: SENTINEL_PASSWORD,
      turnstile_token: "ts",
    });
    expect(result).toEqual({
      id: ACCOUNT_A,
      email: SENTINEL_EMAIL,
      emailVerified: false,
      createdAt: "2026-11-16T10:00:00Z",
    });
    expect(client.getAccountId()).toBeNull();
  });

  it("signup maps 409 email_taken", async () => {
    const { client } = makeClient({
      "POST /api/v1/auth/signup": () => envelope(409, "email_taken"),
    });
    await expect(
      client.signup({ email: "a@b.c", password: "p", turnstileToken: "t" }),
    ).rejects.toBeInstanceOf(EmailTakenError);
  });

  it("login with and without turnstileToken", async () => {
    const { client, net } = makeClient({ "POST /api/v1/auth/login": () => loginResponse() });
    await client.login({ email: "a@b.c", password: "p" });
    await client.login({ email: "a@b.c", password: "p", turnstileToken: "ts" });
    expect(net.calls.map((c) => c.body)).toEqual([
      { email: "a@b.c", password: "p" },
      { email: "a@b.c", password: "p", turnstile_token: "ts" },
    ]);
  });

  it("join(accountId) POSTs /api/v1/auth/apps/<appKey>/join {account_id}", async () => {
    const { client, net } = makeClient({
      "POST /api/v1/auth/apps/ricotdin/join": () => json(200, { status: "member" }),
    });
    expect(await client.join(ACCOUNT_A)).toBe("member");
    expect(net.calls[0]?.body).toEqual({ account_id: ACCOUNT_A });
  });

  it("join without accountId throws (runtime and type)", async () => {
    const { client, net } = makeClient();
    // @ts-expect-error accountId is required
    await expect(client.join()).rejects.toThrow(TypeError);
    await expect(client.join("not-a-uuid")).rejects.toThrow(TypeError);
    expect(net.calls).toHaveLength(0);
  });

  it("not_member from getToken never triggers a join request", async () => {
    const { client, net } = makeClient({
      "POST /api/v1/auth/token": () => envelope(403, "not_member", { join_available: true }),
    });
    client.selectAccount(ACCOUNT_A);
    const error = await client.getToken().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NotMemberError);
    expect((error as NotMemberError).joinAvailable).toBe(true);
    await new Promise((r) => setTimeout(r, 10));
    expect(net.calls.map((c) => c.path)).toEqual(["/api/v1/auth/token"]);
  });

  it('resendVerification 202 → "sent"; 409 email_already_verified → "already_verified"', async () => {
    const { client, net } = makeClient({
      "POST /api/v1/auth/verify-email/resend": [
        () => empty(202),
        () => envelope(409, "email_already_verified"),
      ],
    });
    client.selectAccount(ACCOUNT_A);
    expect(await client.resendVerification()).toBe("sent");
    expect(await client.resendVerification(ACCOUNT_A)).toBe("already_verified");
    expect(net.calls.map((c) => c.body)).toEqual([
      { account_id: ACCOUNT_A },
      { account_id: ACCOUNT_A },
    ]);
  });

  it("forgotPassword 202 sends X-MM-App + include", async () => {
    const { client, net } = makeClient({ "POST /api/v1/auth/password/forgot": () => empty(202) });
    await client.forgotPassword({ email: SENTINEL_EMAIL, turnstileToken: "ts" });
    const [req] = net.calls;
    expect(req?.body).toEqual({ email: SENTINEL_EMAIL, turnstile_token: "ts" });
    expect(req?.headers.get("X-MM-App")).toBe("ricotdin");
    expect(req?.init.credentials).toBe("include");
  });

  it("resetPassword 204 sends {token,new_password}, omit", async () => {
    const { client, net } = makeClient({ "POST /api/v1/auth/password/reset": () => empty(204) });
    await client.resetPassword({ token: "r".repeat(43), newPassword: SENTINEL_PASSWORD });
    const [req] = net.calls;
    expect(req?.body).toEqual({ token: "r".repeat(43), new_password: SENTINEL_PASSWORD });
    expect(req?.init.credentials).toBe("omit");
    expect(req?.headers.get("X-MM-App")).toBeNull();
  });

  it("verifyEmail 204", async () => {
    const { client, net } = makeClient({ "POST /api/v1/auth/verify-email": () => empty(204) });
    await expect(client.verifyEmail("v".repeat(43))).resolves.toBeUndefined();
    expect(net.calls[0]?.body).toEqual({ token: "v".repeat(43) });
    expect(net.calls[0]?.init.credentials).toBe("omit");
  });
});
