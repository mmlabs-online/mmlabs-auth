import { describe, expect, it } from "vitest";
import contract from "../../contract/error-codes.json" with { type: "json" };
import { mapError } from "../src/errors.js";
import * as lib from "../src/index.js";
import {
  envelope,
  makeClient,
  SENTINEL_EMAIL,
  SENTINEL_PASSWORD,
  SENTINEL_TOKEN,
} from "./helpers.js";

const NOW = Date.parse("2026-11-16T10:00:00Z");

async function errorFrom(resp: Response): Promise<lib.AuthError> {
  const body: unknown = await resp.json();
  return mapError(resp.status, body, resp.headers, NOW);
}

function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("error mapping", () => {
  it.each(Object.entries(contract.codes))(
    "every typed code in contract/error-codes.json maps to its class and status (%s)",
    async (code, entry) => {
      const error = await errorFrom(envelope(entry.status, code));
      const ErrorClass = (lib as unknown as Record<string, new (...a: never[]) => unknown>)[
        entry.class
      ];
      expect(ErrorClass).toBeTypeOf("function");
      expect(error).toBeInstanceOf(ErrorClass);
      expect(error).toBeInstanceOf(lib.AuthError);
      expect(error.constructor.name).toBe(entry.class);
      expect(error.name).toBe(entry.class);
      expect(error.code).toBe(code);
      expect(error.status).toBe(entry.status);
      expect(error.message).toBe(`mmlabs-auth: ${code}`);
    },
  );

  it("unknown code maps to generic AuthError with the raw code", async () => {
    const error = await errorFrom(envelope(400, "something_new"));
    expect(error.constructor).toBe(lib.AuthError);
    expect(error.code).toBe("something_new");
    expect(error.status).toBe(400);
  });

  it("RateLimitedError.retryAfter from Retry-After seconds", async () => {
    const error = await errorFrom(
      envelope(429, "rate_limited", { retry_after: 99 }, { "Retry-After": "17" }),
    );
    expect(error).toBeInstanceOf(lib.RateLimitedError);
    expect((error as lib.RateLimitedError).retryAfter).toBe(17);
  });

  it("RateLimitedError.retryAfter from Retry-After HTTP-date", async () => {
    const at = new Date(NOW + 42_000).toUTCString();
    const error = await errorFrom(envelope(429, "rate_limited", null, { "Retry-After": at }));
    expect((error as lib.RateLimitedError).retryAfter).toBe(42);
  });

  it("RateLimitedError.retryAfter falls back to details.retry_after, then 5", async () => {
    const fromDetails = await errorFrom(envelope(429, "rate_limited", { retry_after: 33 }));
    expect((fromDetails as lib.RateLimitedError).retryAfter).toBe(33);
    const garbage = await errorFrom(
      envelope(429, "rate_limited", { retry_after: "soon" }, { "Retry-After": "later" }),
    );
    expect((garbage as lib.RateLimitedError).retryAfter).toBe(5);
  });

  it("NotMemberError.joinAvailable", async () => {
    const yes = await errorFrom(envelope(403, "not_member", { join_available: true }));
    const no = await errorFrom(envelope(403, "not_member", { join_available: false }));
    const missing = await errorFrom(envelope(403, "not_member"));
    expect((yes as lib.NotMemberError).joinAvailable).toBe(true);
    expect((no as lib.NotMemberError).joinAvailable).toBe(false);
    expect((missing as lib.NotMemberError).joinAvailable).toBe(false);
  });

  it("WeakPasswordError.reasons", async () => {
    const error = await errorFrom(
      envelope(422, "weak_password", { reasons: ["too_short", 7, "too_common"] }),
    );
    expect((error as lib.WeakPasswordError).reasons).toEqual(["too_short", "too_common"]);
  });

  it("ValidationError keeps only type/loc", async () => {
    const error = await errorFrom(
      envelope(422, "validation_error", [
        { type: "missing", loc: ["body", "email"], msg: SENTINEL_EMAIL, input: SENTINEL_PASSWORD },
      ]),
    );
    expect((error as lib.ValidationError).issues).toEqual([
      { type: "missing", loc: ["body", "email"] },
    ]);
    expect(JSON.stringify(error)).not.toContain(SENTINEL_EMAIL);
  });

  it("requestId from X-Request-ID", async () => {
    const error = await errorFrom(envelope(403, "not_member", null, { "X-Request-ID": "req-123" }));
    expect(error.requestId).toBe("req-123");
  });

  it("fetch TypeError → NetworkError", async () => {
    const { client } = makeClient(
      {},
      {
        fetch: async () => {
          throw new TypeError("Failed to fetch");
        },
      },
    );
    const error = await rejection(client.listAccounts());
    expect(error).toBeInstanceOf(lib.NetworkError);
    expect((error as lib.AuthError).code).toBe("network_error");
    expect((error as lib.AuthError).status).toBe(0);
  });

  it("non-JSON or non-envelope body → AuthError unexpected_response", async () => {
    const cases = [
      () => new Response("<html>bad gateway</html>", { status: 502 }),
      () => new Response(JSON.stringify({ detail: "x" }), { status: 400 }),
      () => new Response("not json", { status: 200 }),
      () => new Response(JSON.stringify({ items: "nope" }), { status: 200 }),
    ];
    for (const handler of cases) {
      const { client } = makeClient({ "GET /api/v1/auth/accounts": handler });
      const error = await rejection(client.listAccounts());
      expect(error).toBeInstanceOf(lib.AuthError);
      expect((error as lib.AuthError).code).toBe("unexpected_response");
    }
  });

  it("JSON.stringify/String/message of every error contain no sentinel token, email or password", async () => {
    const codes = [...Object.keys(contract.codes), "something_new"];
    for (const code of codes) {
      const { client } = makeClient({
        "POST /api/v1/auth/login": () =>
          envelope(422, code, {
            reasons: ["too_short"],
            join_available: SENTINEL_TOKEN,
            retry_after: 1,
          }),
      });
      const error = await rejection(
        client.login({
          email: SENTINEL_EMAIL,
          password: SENTINEL_PASSWORD,
          turnstileToken: SENTINEL_TOKEN,
        }),
      );
      const views = [JSON.stringify(error), String(error), (error as Error).message];
      for (const view of views) {
        for (const sentinel of [SENTINEL_TOKEN, SENTINEL_EMAIL, SENTINEL_PASSWORD]) {
          expect(view).not.toContain(sentinel);
        }
      }
    }
  });
});
