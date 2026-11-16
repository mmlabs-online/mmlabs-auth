import { describe, expect, it } from "vitest";
import example from "../../contract/token-response.example.json" with { type: "json" };
import { ACCOUNT_A, json, makeClient } from "./helpers.js";

describe("contract", () => {
  it("contract token-response example is accepted by getToken", async () => {
    const { client, net } = makeClient(
      { "POST /api/v1/auth/token": () => json(example.status, example.body, example.headers) },
      { appKey: example.body.audience },
    );
    client.selectAccount(ACCOUNT_A);
    expect(await client.getToken()).toBe(example.body.access_token);
    expect(net.calls[0]?.body).toEqual({ audience: example.body.audience, account_id: ACCOUNT_A });
  });
});
