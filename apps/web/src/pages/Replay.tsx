import { useState, type ReactNode } from "react";

import { ApiError, api } from "../api/client";
import type { ReplayCaseView, ReplayResult, ReplayVisibilityResult } from "../api/types";
import {
  Address,
  Badge,
  Button,
  Callout,
  Card,
  Empty,
  ErrorView,
  KeyValues,
  Limitations,
  Loading,
  SeverityBadges,
  TxLink,
} from "../components/ui";
import { safeCuratedUrl } from "../lib/explorer";
import { humanize } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { AffixAddress } from "./wallet/PoisoningPanel";

const OUTCOME: Record<ReplayVisibilityResult["outcome"], { label: string; tone: "ok" | "review" | "critical" }> = {
  early_warning: { label: "Early warning", tone: "ok" },
  post_incident_only: { label: "Post-incident classification only", tone: "review" },
  not_detected: { label: "Not detected", tone: "critical" },
};

/** Shared leading/trailing characters, to highlight how the lookalike imitates the original. */
function affix(a: string, b: string): [number, number] {
  const x = a.slice(2).toLowerCase();
  const y = b.slice(2).toLowerCase();
  let prefix = 0;
  while (prefix < 40 && x[prefix] === y[prefix]) prefix++;
  let suffix = 0;
  while (suffix < 40 - prefix && x[39 - suffix] === y[39 - suffix]) suffix++;
  return [prefix, suffix];
}

function VisibilityCard({ result, chainId }: { result: ReplayVisibilityResult; chainId: number }) {
  const outcome = OUTCOME[result.outcome];
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-line bg-surface-2 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={outcome.tone}>{outcome.label}</Badge>
        <span className="font-mono text-xs text-muted">{result.visibility}</span>
      </div>
      <p className="text-sm text-muted">{result.description}</p>
      <p className="text-sm">{result.explanation}</p>
      {result.first_warning && (
        <KeyValues
          items={[
            ["First warning", `block ${result.first_warning.block_number.toLocaleString("en-US")} (${result.first_warning.rule_id})`],
            ["Assessment", <SeverityBadges key="s" severity={result.first_warning.severity} confidence={result.first_warning.confidence} />],
            [
              "Lead time",
              `${result.lead_time_blocks} blocks` +
                (result.lead_time_seconds !== null ? ` (about ${Math.round(result.lead_time_seconds / 60)} minutes)` : ""),
            ],
            ["Signals", result.first_warning.signals.map(humanize).join(", ")],
          ]}
        />
      )}
      {result.at_harm_block && (
        <p className="text-xs text-muted">
          Once the harmful transfer is visible: {result.at_harm_block.rule_id} ({humanize(result.at_harm_block.severity)},{" "}
          {result.at_harm_block.confidence} confidence). This is post-incident, not early detection.
        </p>
      )}
      <p className="text-xs text-faint">
        {result.checkpoints_evaluated} point-in-time checkpoints · {result.other_addresses_flagged_before_harm} other
        address(es) flagged before the harm (unlabelled) · chain {chainId}
      </p>
    </div>
  );
}

function ResultView({ result, chainId }: { result: ReplayResult; chainId: number }) {
  const failed = result.leakage_checks.filter((c) => !c.passed);
  return (
    <div className="flex flex-col gap-4">
      {failed.length > 0 && (
        <Callout tone="error" title="Leakage check failed">
          The result is not trustworthy: {failed.map((c) => c.check).join(", ")}.
        </Callout>
      )}
      <div className="grid gap-3 lg:grid-cols-2">
        {result.results.map((r) => (
          <VisibilityCard key={r.visibility} result={r} chainId={chainId} />
        ))}
      </div>
      <div>
        <h3 className="mb-2 text-sm font-semibold">Temporal leakage checks</h3>
        <ul className="flex flex-col gap-1.5 text-sm">
          {result.leakage_checks.map((c) => (
            <li key={c.check} className="flex flex-wrap gap-2">
              <Badge tone={c.passed ? "ok" : "critical"}>{c.passed ? "Pass" : "Fail"}</Badge>
              <span className="font-mono text-xs">{c.check}</span>
              <span className="text-muted">{c.detail}</span>
            </li>
          ))}
        </ul>
      </div>
      <p className="text-xs text-faint">
        Detector {result.detector_version}, ruleset {result.ruleset_version} · fixture{" "}
        <code className="break-all">{result.fixture_sha256}</code> ({result.transfers_in_fixture} transfers,{" "}
        {result.wallet_transactions_in_fixture} wallet transactions; recorded with {result.recorded_with} using{" "}
        {result.rpc_requests_when_recorded} requests) · replay {result.runtime_ms} ms, peak {result.peak_memory_kib} KiB,{" "}
        {result.rpc_requests_during_replay} RPC requests
      </p>
      <Limitations items={result.limitations} />
    </div>
  );
}

function CaseCard({ item }: { item: ReplayCaseView }) {
  const m = item.manifest;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [prefix, suffix] = m.intended_recipient ? affix(m.harm.recipient, m.intended_recipient) : [0, 0];

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.replayRun(m.case_id));
    } catch (cause) {
      setError(cause instanceof ApiError ? cause : null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={m.title} actions={<Badge>{humanize(m.category)}</Badge>}>
      <div className="flex flex-col gap-4">
        <p className="text-sm">{m.summary}</p>
        <KeyValues
          items={[
            ["Victim", <Address key="v" value={m.victim} />],
            ...(m.intended_recipient
              ? ([["Intended recipient", <AffixAddress key="i" address={m.intended_recipient} prefix={prefix} suffix={suffix} />]] as [string, ReactNode][])
              : []),
            ["Funds went to", <AffixAddress key="r" address={m.harm.recipient} prefix={prefix} suffix={suffix} />],
            ["Harmful transaction", <span key="h">block {m.harm.block_number.toLocaleString("en-US")} · <TxLink chainId={m.chain_id} hash={m.harm.transaction_hash} simulated={false} /></span>],
            ["What happened", m.harm.description],
            ["Replay window", `blocks ${m.evaluation.from_block.toLocaleString("en-US")}–${m.evaluation.to_block.toLocaleString("en-US")}. ${m.evaluation.rationale}`],
            ["First public report", m.first_public_report],
          ]}
        />
        <details className="rounded-lg border border-line px-4 py-3 text-sm">
          <summary className="cursor-pointer font-medium">Ground truth: sources and on-chain verification</summary>
          <ul className="mt-2 flex flex-col gap-2">
            {m.public_sources.map((s) => {
              const url = safeCuratedUrl(s.url);
              return (
                <li key={s.url}>
                  {url ? (
                    <a className="text-accent hover:underline" href={url} target="_blank" rel="noopener noreferrer">
                      {s.publisher}: {s.title}
                    </a>
                  ) : (
                    `${s.publisher}: ${s.title}`
                  )}
                  <span className="block text-xs text-muted">
                    Used for: {s.used_for} (accessed {s.accessed})
                  </span>
                </li>
              );
            })}
          </ul>
          <ul className="mt-3 list-disc space-y-1 pl-5 text-muted">
            {m.onchain_verification.map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ul>
        </details>
        <Limitations items={m.ground_truth_limitations} />
        {item.recorded ? (
          <Button variant="primary" className="self-start" onClick={run} disabled={busy}>
            {busy ? "Replaying…" : result ? "Replay again" : "Run replay"}
          </Button>
        ) : (
          <Callout tone="warn">No fixture recorded yet; run `cryptoguard replay record {m.case_id}`.</Callout>
        )}
        {error && <ErrorView error={error} />}
        {result && <ResultView result={result} chainId={m.chain_id} />}
      </div>
    </Card>
  );
}

export function Replay() {
  const cases = useAsync(() => api.replayCases(), []);
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Incident replay</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">
          Could CryptoGuard have warned before a known harmful transaction, using only what was on
          chain at the time? Each case replays recorded mainnet data offline, block by block,
          with the incident's ground truth used only for scoring. These are case studies, not
          detection-rate benchmarks.
        </p>
      </div>
      {cases.loading && <Loading />}
      {cases.error && <ErrorView error={cases.error} onRetry={cases.run} />}
      {cases.data && cases.data.items.length === 0 && <Empty>No replay cases are packaged.</Empty>}
      {cases.data?.items.map((item) => (
        <CaseCard key={item.manifest.case_id} item={item} />
      ))}
    </div>
  );
}
