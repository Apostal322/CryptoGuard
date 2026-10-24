import type { Confidence, Reading, Severity } from "../api/types";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** Shape check only; the backend validates the EIP-55 checksum authoritatively. */
export function looksLikeAddress(value: string): boolean {
  return ADDRESS.test(value.trim());
}

/** Explicit UTC, never the viewer's local zone, so times match the chain and the API. */
export function formatUtc(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

export function formatReading(reading: Reading, symbol: string | null): string {
  if (reading.status === "unknown") return `Unknown (${humanize(reading.unknown_reason ?? "unavailable")})`;
  if (reading.formatted !== null) return `${reading.formatted} ${symbol ?? ""}`.trim();
  return `${reading.raw} base units`;
}

export function humanize(code: string): string {
  const text = code.replace(/[_:]/g, " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  informational: "Informational",
  review_recommended: "Review recommended",
  elevated_risk: "Elevated risk",
  critical_evidence: "Critical evidence",
  unknown: "Unknown",
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical_evidence: 0,
  elevated_risk: 1,
  unknown: 2,
  review_recommended: 3,
  informational: 4,
};

export const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};
