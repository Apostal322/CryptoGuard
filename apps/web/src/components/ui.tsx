import type { ReactNode } from "react";

import type { ApiError } from "../api/client";
import type { Confidence, Severity } from "../api/types";
import { explorerTxUrl, safeExternalUrl } from "../lib/explorer";
import { CONFIDENCE_LABEL, SEVERITY_LABEL } from "../lib/format";

// All text below is rendered through React, which escapes it. Nothing uses
// dangerouslySetInnerHTML: token symbols, labels and explanations are untrusted strings.

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-line bg-surface p-5">
      {(title || actions) && (
        <header className="mb-4 flex flex-wrap items-center justify-between gap-3">
          {title && <h2 className="text-base font-semibold tracking-tight">{title}</h2>}
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

type Tone = "neutral" | "info" | "ok" | "review" | "elevated" | "critical" | "simulated";

const TONES: Record<Tone, string> = {
  neutral: "border-line text-muted",
  info: "border-info/40 text-info",
  ok: "border-ok/40 text-ok",
  review: "border-review/50 text-review",
  elevated: "border-elevated/50 text-elevated",
  critical: "border-critical/60 text-critical",
  simulated: "border-simulated/50 text-simulated",
};

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${TONES[tone]}`}
    >
      {children}
    </span>
  );
}

const SEVERITY_TONE: Record<Severity, Tone> = {
  informational: "info",
  review_recommended: "review",
  elevated_risk: "elevated",
  critical_evidence: "critical",
  unknown: "neutral",
};

/** Severity and confidence are always shown together and never merged into one score. */
export function SeverityBadges({ severity, confidence }: { severity: Severity; confidence: Confidence }) {
  return (
    <span className="inline-flex flex-wrap gap-1.5">
      <Badge tone={SEVERITY_TONE[severity]}>{SEVERITY_LABEL[severity]}</Badge>
      <Badge>{CONFIDENCE_LABEL[confidence]}</Badge>
    </span>
  );
}

export function SimulatedBadge({ simulated }: { simulated: boolean }) {
  return simulated ? (
    <Badge tone="simulated" title="Fictional demo fixture, not Ethereum state">
      Simulated
    </Badge>
  ) : (
    <Badge tone="ok" title="Read from the configured Ethereum RPC provider">
      Real data
    </Badge>
  );
}

const CALLOUT: Record<"info" | "warn" | "error", string> = {
  info: "border-info/30 bg-info/5",
  warn: "border-review/40 bg-review/5",
  error: "border-critical/50 bg-critical/5",
};

export function Callout({ tone = "info", title, children }: { tone?: "info" | "warn" | "error"; title?: string; children: ReactNode }) {
  return (
    <div role={tone === "error" ? "alert" : "note"} className={`rounded-lg border px-4 py-3 text-sm ${CALLOUT[tone]}`}>
      {title && <p className="mb-1 font-medium">{title}</p>}
      <div className="text-muted">{children}</div>
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p role="status" aria-live="polite" className="flex items-center gap-2 text-sm text-muted">
      <span className="size-3 animate-pulse rounded-full bg-accent/70" aria-hidden />
      {label}
    </p>
  );
}

export function ErrorView({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <Callout tone="error" title="Request failed">
      <p>{error.message}</p>
      <p className="mt-1 font-mono text-xs text-faint">code: {error.code}</p>
      {onRetry && (
        <Button className="mt-3" onClick={onRetry}>
          Retry
        </Button>
      )}
    </Callout>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-dashed border-line px-4 py-6 text-center text-sm text-muted">{children}</p>;
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "secondary",
  type = "button",
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary";
  type?: "button" | "submit";
  className?: string;
}) {
  const style =
    variant === "primary"
      ? "bg-accent text-bg hover:bg-accent/90"
      : "border border-line bg-surface-2 text-ink hover:border-faint";
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${style} ${className}`}
    >
      {children}
    </button>
  );
}

export function KeyValues({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(9rem,max-content)_1fr]">
      {items.map(([key, value], index) => (
        <div key={index} className="contents">
          <dt className="text-muted">{key}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ExternalLink({ href, children }: { href: string | null; children: ReactNode }) {
  const safe = safeExternalUrl(href);
  if (!safe) return <>{children}</>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-2 hover:underline">
      {children}
      <span className="sr-only"> (opens block explorer)</span>
    </a>
  );
}

/** A full address, never shortened: shortened addresses are what poisoning exploits. */
export function Address({ value, label }: { value: string; label?: string | null }) {
  return (
    <span className="inline-flex min-w-0 flex-wrap items-baseline gap-x-2">
      <code className="break-all font-mono text-[0.8125rem]">{value}</code>
      {label && <span className="text-xs text-muted">{label}</span>}
    </span>
  );
}

export function TxLink({ chainId, hash, simulated }: { chainId: number; hash: string | null; simulated: boolean }) {
  if (!hash) return <span className="text-muted">none</span>;
  const code = <code className="break-all font-mono text-xs">{hash}</code>;
  return simulated ? code : <ExternalLink href={explorerTxUrl(chainId, hash)}>{code}</ExternalLink>;
}

export function Limitations({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <details className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-sm">
      <summary className="cursor-pointer font-medium">What this does not show ({items.length})</summary>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-muted">
        {items.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
    </details>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="font-medium">{label}</span>
      {children}
      {hint && <span className="text-xs text-faint">{hint}</span>}
    </label>
  );
}

export const inputClass =
  "w-full rounded-lg border border-line bg-bg px-3 py-2 font-mono text-sm text-ink placeholder:text-faint focus:border-accent";
