import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiRequest, authorizedHeaders } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("authorizedHeaders", () => {
  it("adds a trimmed Bearer token without discarding content type", () => {
    const headers = authorizedHeaders("  operator-secret  ", {
      "Content-Type": "application/json",
    });
    expect(headers.get("Authorization")).toBe("Bearer operator-secret");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("does not send an empty credential", () => {
    expect(authorizedHeaders("   ").has("Authorization")).toBe(false);
  });
});

describe("apiRequest", () => {
  it("returns typed JSON for a successful response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"ok":true}')));
    await expect(apiRequest<{ ok: boolean }>("/status", "token")).resolves.toEqual({ ok: true });
  });

  it("surfaces the stable API detail on failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response('{"detail":"operator_authentication_required"}', {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    await expect(apiRequest("/protected", "wrong-token")).rejects.toEqual(
      new ApiError(401, "operator_authentication_required"),
    );
  });
});
