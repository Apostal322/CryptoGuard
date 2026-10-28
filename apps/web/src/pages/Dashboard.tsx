import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import { useStatus } from "../app/status";
import { Address, Badge, Button, Card, ErrorView, Field, KeyValues, Loading, inputClass } from "../components/ui";
import { formatUtc, looksLikeAddress } from "../lib/format";
import { useAsync } from "../lib/useAsync";

function WalletSearch() {
  const navigate = useNavigate();
  const [value, setValue] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const address = value.trim();
    if (!looksLikeAddress(address)) {
      setProblem("Enter a full 0x-prefixed address of 40 hexadecimal characters.");
      return;
    }
    setProblem(null);
    navigate(`/wallet/${address}`);
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-3" noValidate>
      <Field
        label="Public Ethereum address"
        hint="Only public data is read. Never enter a private key or seed phrase anywhere."
      >
        <input
          className={inputClass}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="0x…"
          spellCheck={false}
          autoComplete="off"
          aria-invalid={problem ? true : undefined}
          aria-describedby={problem ? "address-problem" : undefined}
        />
      </Field>
      {problem && (
        <p id="address-problem" className="text-sm text-critical">
          {problem}
        </p>
      )}
      <div>
        <Button type="submit" variant="primary">
          Analyze address
        </Button>
      </div>
    </form>
  );
}

function StatusPanel() {
  const { data, error, loading, run } = useStatus();
  if (loading && !data) return <Loading label="Checking the API and RPC provider…" />;
  if (error) return <ErrorView error={error} onRetry={run} />;
  if (!data) return null;
  const verified =
    data.mode === "demo" ? (
      <Badge tone="simulated">Simulated, no RPC</Badge>
    ) : data.chain_verified === true ? (
      <Badge tone="ok">Verified via eth_chainId</Badge>
    ) : data.chain_verified === false ? (
      <Badge tone="critical">Chain mismatch</Badge>
    ) : (
      <Badge>Not verified</Badge>
    );
  return (
    <KeyValues
      items={[
        ["Mode", data.mode === "demo" ? <Badge tone="simulated">Demo (simulated)</Badge> : <Badge tone="ok">Real</Badge>],
        ["Chain", <span key="c">{data.chain_name} (id {data.chain_id}) {verified}</span>],
        ["Provider", data.provider ?? <span className="text-muted">not configured</span>],
        ["Head block", data.head_block?.toLocaleString("en-US") ?? <span className="text-muted">unknown</span>],
        [
          "RPC requests",
          data.rpc_metrics
            ? `${data.rpc_metrics.requests} sent, ${data.rpc_metrics.failures} failed, ${data.rpc_metrics.retries} retried (since API start)`
            : <span className="text-muted">n/a</span>,
        ],
        ["Checked", <span key="t">{formatUtc(data.checked_at)} <Button onClick={run}>Refresh</Button></span>],
      ]}
    />
  );
}

function DemoAddresses() {
  const { data, error, loading } = useAsync(() => api.demoAddresses(), []);
  if (loading) return <Loading />;
  if (error) return <ErrorView error={error} />;
  if (!data) return null;
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">{data.notice}</p>
      <ul className="divide-y divide-line">
        {data.addresses.map((entry) => (
          <li key={entry.address} className="flex flex-col gap-1 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium">{entry.label}</p>
              <p className="text-xs text-muted">{entry.description}</p>
              <Address value={entry.address} />
            </div>
            <Link className="text-sm text-accent hover:underline" to={`/wallet/${entry.address}`}>
              Open
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Dashboard() {
  const { data } = useStatus();
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Wallet security, with the evidence</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">
          CryptoGuard reads public Ethereum state and shows what is observably true, the block it
          comes from, and what it does not cover. Warnings are evidence-based heuristics, not proof
          of fraud.
        </p>
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Analyze a wallet">
          <WalletSearch />
        </Card>
        <Card title="Monitoring status">
          <StatusPanel />
        </Card>
      </div>
      {data?.mode === "demo" && (
        <Card title="Demo fixtures">
          <DemoAddresses />
        </Card>
      )}
      <Card title="How monitoring works">
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
          <li>Snapshots are taken on request; changes are located between two snapshot blocks.</li>
          <li>Only the scanned block ranges are covered; each result states its coverage.</li>
          <li>
            ERC-20 approvals and transfers are analyzed, and so is native ETH the wallet itself sends. Native ETH it
            receives, internal transfers and NFT approvals are not visible.
          </li>
          <li>No warning is not the same as safe: only the observed data is checked.</li>
        </ul>
      </Card>
    </div>
  );
}
