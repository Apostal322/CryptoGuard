import { useState, type FormEvent } from "react";

import { looksLikeAddress } from "../lib/format";
import { Button, Field, inputClass } from "./ui";

export interface ScanOptions {
  lookback_blocks?: number;
  tokens?: string[];
}

export function parseScanOptions(lookback: string, tokens: string): { options?: ScanOptions; error?: string } {
  const options: ScanOptions = {};
  if (lookback.trim()) {
    const value = Number(lookback.trim());
    if (!Number.isSafeInteger(value) || value < 1) return { error: "Lookback must be a positive whole number of blocks." };
    options.lookback_blocks = value;
  }
  const list = tokens.split(/[\s,]+/).filter(Boolean);
  const bad = list.find((token) => !looksLikeAddress(token));
  if (bad) return { error: "Each token must be a full 0x-prefixed contract address." };
  if (list.length > 25) return { error: "At most 25 token contracts can be scanned at once." };
  if (list.length) options.tokens = list;
  return { options };
}

export function ScanForm({
  submitLabel,
  busy,
  onSubmit,
  showLookback = true,
  tokenHint = "Optional. Some free RPC providers only allow scans of named token contracts.",
}: {
  submitLabel: string;
  busy: boolean;
  onSubmit: (options: ScanOptions) => void;
  showLookback?: boolean;
  tokenHint?: string;
}) {
  const [lookback, setLookback] = useState("");
  const [tokens, setTokens] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const parsed = parseScanOptions(showLookback ? lookback : "", tokens);
    setError(parsed.error ?? null);
    if (parsed.options) onSubmit(parsed.options);
  };

  return (
    <form onSubmit={submit} className="grid gap-3 sm:grid-cols-[12rem_1fr_auto] sm:items-end" noValidate>
      {showLookback && (
        <Field label="Lookback (blocks)" hint="Server default if empty.">
          <input
            className={inputClass}
            inputMode="numeric"
            value={lookback}
            onChange={(event) => setLookback(event.target.value)}
            placeholder="10000"
          />
        </Field>
      )}
      <Field label="Token contracts" hint={tokenHint}>
        <input
          className={inputClass}
          value={tokens}
          onChange={(event) => setTokens(event.target.value)}
          placeholder="0x…, 0x…"
          spellCheck={false}
        />
      </Field>
      <Button type="submit" variant="primary" disabled={busy}>
        {busy ? "Scanning…" : submitLabel}
      </Button>
      {error && <p className="text-sm text-critical sm:col-span-3">{error}</p>}
    </form>
  );
}
