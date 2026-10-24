import { api } from "../api/client";
import { useStatus } from "../app/status";
import { Badge, Card, ErrorView, KeyValues, Loading } from "../components/ui";
import { SEVERITY_LABEL } from "../lib/format";
import { useAsync } from "../lib/useAsync";

export function Settings() {
  const status = useStatus();
  const rules = useAsync(() => api.rules(), []);
  const s = status.data;
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
      <p className="-mt-4 text-sm text-muted">
        Configuration lives on the server (environment variables or <code>.env</code>), never in the
        browser. This page shows it read-only.
      </p>

      <Card title="RPC and monitoring">
        {status.loading && !s && <Loading />}
        {status.error && <ErrorView error={status.error} onRetry={status.run} />}
        {s && (
          <KeyValues
            items={[
              ["Mode", s.mode === "demo" ? "Demo (simulated fixtures)" : "Real (Ethereum RPC)"],
              ["RPC endpoint", s.rpc_configured ? `${s.provider} (path and credentials hidden)` : "Not configured (CRYPTOGUARD_RPC_URL)"],
              ["Chain", `${s.chain_name} (id ${s.chain_id})`],
              ["Monitoring", "On request: each snapshot is taken when you ask (Timeline tab). No background schedule yet."],
              ["Confirmations", "Snapshots are taken a configurable number of blocks behind the head (CRYPTOGUARD_SNAPSHOT_CONFIRMATIONS)."],
              ["API version", s.version],
            ]}
          />
        )}
      </Card>

      <Card title="Privacy and data retention">
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
          <li>No accounts, cookies, analytics or third-party scripts.</li>
          <li>Addresses you analyze are sent to the configured RPC provider, and nowhere else.</li>
          <li>Observations, snapshots, findings and transfers are stored locally until you delete them.</li>
          <li>
            Delete everything with <code className="font-mono">cryptoguard purge --yes</code>, or one
            wallet with <code className="font-mono">--address 0x…</code>.
          </li>
        </ul>
      </Card>

      <Card title={rules.data ? `Rules (${rules.data.ruleset_id} ${rules.data.version})` : "Rules"}>
        {rules.loading && <Loading />}
        {rules.error && <ErrorView error={rules.error} onRetry={rules.run} />}
        {rules.data && (
          <>
            <p className="mb-3 text-sm text-muted">
              Severities: {rules.data.severities.map((sev) => SEVERITY_LABEL[sev]).join(", ")}. Each
              finding also carries a separate confidence level.
            </p>
            <ul className="divide-y divide-line">
              {rules.data.rules.map((rule) => (
                <li key={rule.rule_id} className="flex flex-col gap-1 py-3 sm:flex-row sm:gap-4">
                  <span className="flex shrink-0 items-start gap-2 sm:w-56">
                    <Badge>{rule.rule_id}</Badge>
                    <span className="text-xs text-muted">{rule.category.replace(/_/g, " ")}</span>
                  </span>
                  <span className="text-sm">{rule.description}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>
    </div>
  );
}
