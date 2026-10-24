import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, request } from "../api/client";

function mockFetch(response: Response | Error) {
  const fn = vi.fn(async () => {
    if (response instanceof Error) throw response;
    return response;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

describe("API client", () => {
  it("returns parsed JSON on success", async () => {
    mockFetch(new Response(JSON.stringify({ ok: 1 }), { status: 200 }));
    await expect(request<{ ok: number }>("/x")).resolves.toEqual({ ok: 1 });
  });

  it("surfaces the backend's error code and safe message", async () => {
    mockFetch(
      new Response(JSON.stringify({ error: { code: "rpc_not_configured", message: "No RPC.", details: {} } }), {
        status: 503,
      }),
    );
    const error = await request("/x").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("rpc_not_configured");
    expect((error as ApiError).status).toBe(503);
  });

  it("maps a non-JSON failure to a generic error", async () => {
    mockFetch(new Response("<html>bad gateway</html>", { status: 502 }));
    const error = (await request("/x").catch((e: unknown) => e)) as ApiError;
    expect(error.code).toBe("unexpected_response");
    expect(error.message).not.toContain("<html>");
  });

  it("maps network failures", async () => {
    mockFetch(new TypeError("Failed to fetch"));
    const error = (await request("/x").catch((e: unknown) => e)) as ApiError;
    expect(error.code).toBe("network_error");
  });

  it("sends JSON bodies to same-origin, encoded paths", async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({}), { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    await api.scanApprovals("0x" + "a".repeat(40), { lookback_blocks: 5 });
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`/api/v1/wallets/0x${"a".repeat(40)}/approvals/scan`);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ lookback_blocks: 5 }));
    await api.finding("../../etc");
    expect((fetch.mock.calls[1] as unknown as [string])[0]).toBe("/api/v1/findings/..%2F..%2Fetc");
  });
});
