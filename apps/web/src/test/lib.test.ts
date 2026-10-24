import { describe, expect, it } from "vitest";

import { parseScanOptions } from "../components/ScanForm";
import { explorerBlockUrl, explorerTxUrl, safeExternalUrl } from "../lib/explorer";
import { formatReading, formatUtc, looksLikeAddress } from "../lib/format";

const HASH = "0x" + "ab".repeat(32);

describe("explorer links", () => {
  it("builds links only from validated values", () => {
    expect(explorerTxUrl(1, HASH)).toBe(`https://etherscan.io/tx/${HASH}`);
    expect(explorerTxUrl(11155111, HASH)).toBe(`https://sepolia.etherscan.io/tx/${HASH}`);
    expect(explorerTxUrl(1, "0xabc")).toBeNull();
    expect(explorerTxUrl(1, `${HASH}?x=<script>`)).toBeNull();
    expect(explorerTxUrl(56, HASH)).toBeNull(); // unknown chain
    expect(explorerBlockUrl(1, -1)).toBeNull();
  });

  it.each([
    "javascript:alert(1)",
    "http://etherscan.io/tx/1",
    "https://etherscan.io.evil.example/tx/1",
    "https://user:pass@etherscan.io/tx/1",
    "data:text/html,<script>alert(1)</script>",
    "not a url",
  ])("rejects unsafe external URL %s", (url) => {
    expect(safeExternalUrl(url)).toBeNull();
  });

  it("accepts known explorer URLs", () => {
    expect(safeExternalUrl("https://etherscan.io/block/1")).toBe("https://etherscan.io/block/1");
  });
});

describe("formatting", () => {
  it("shows unknown readings explicitly, never as zero", () => {
    expect(formatReading({ status: "unknown", raw: null, formatted: null, unknown_reason: "call_reverted" }, "TKN")).toBe(
      "Unknown (Call reverted)",
    );
    expect(formatReading({ status: "known", raw: "5", formatted: null, unknown_reason: null }, null)).toBe("5 base units");
    expect(formatReading({ status: "known", raw: "1500", formatted: "1.5", unknown_reason: null }, "TKN")).toBe("1.5 TKN");
  });

  it("formats times in explicit UTC", () => {
    expect(formatUtc("2026-01-02T03:04:05+00:00")).toBe("2026-01-02 03:04:05 UTC");
  });

  it("checks address shape", () => {
    expect(looksLikeAddress("0x" + "a".repeat(40))).toBe(true);
    expect(looksLikeAddress("0x" + "a".repeat(39))).toBe(false);
    expect(looksLikeAddress("vitalik.eth")).toBe(false);
  });
});

describe("scan options", () => {
  it("parses lookback and token lists", () => {
    const token = "0x" + "1".repeat(40);
    expect(parseScanOptions("500", `${token}, ${token}\n`)).toEqual({
      options: { lookback_blocks: 500, tokens: [token, token] },
    });
    expect(parseScanOptions("", "")).toEqual({ options: {} });
  });

  it.each([
    ["-1", ""],
    ["1.5", ""],
    ["abc", ""],
    ["", "0x123"],
  ])("rejects lookback=%s tokens=%s", (lookback, tokens) => {
    expect(parseScanOptions(lookback, tokens).error).toBeTruthy();
  });
});
