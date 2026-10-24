import { api } from "../../api/client";
import type { AddressInspection, CodeKind } from "../../api/types";
import {
  Address,
  Badge,
  Button,
  Callout,
  Card,
  ErrorView,
  ExternalLink,
  KeyValues,
  Limitations,
  Loading,
  SimulatedBadge,
} from "../../components/ui";
import { formatUtc } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

const CODE_LABEL: Record<CodeKind, string> = {
  no_code: "No code (EOA without delegation, or undeployed address)",
  eip7702_delegation: "EIP-7702 delegation",
  contract: "Contract",
  malformed_delegation_prefix: "Malformed EIP-7702 indicator",
};

function Inspection({ data }: { data: AddressInspection }) {
  const { block, account_code: code } = data;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Current observed state" actions={<SimulatedBadge simulated={data.simulated} />}>
        <KeyValues
          items={[
            [
              "Chain",
              `${data.chain_name} (id ${data.chain_id}${data.chain_verified ? ", verified via eth_chainId" : ", not verified: simulated"})`,
            ],
            [
              "Block",
              <span key="b" className="flex flex-wrap items-center gap-2">
                <ExternalLink href={data.explorer?.block ?? null}>#{block.number.toLocaleString("en-US")}</ExternalLink>
                <Badge tone={block.finality === "finalized" ? "ok" : "review"}>
                  {block.finality.replace("_", " ")}
                </Badge>
              </span>,
            ],
            ["Block hash", <code key="h" className="break-all font-mono text-xs">{block.hash}</code>],
            ["Block time", formatUtc(block.timestamp)],
            [
              "Native balance",
              <span key="n">
                {data.native_balance.formatted} {data.native_balance.symbol}{" "}
                <span className="font-mono text-xs text-muted">({data.native_balance.wei} wei)</span>
              </span>,
            ],
            ["Account code", `${CODE_LABEL[code.kind]} · ${code.code_size} bytes`],
            ["Observed", formatUtc(data.observed_at)],
            ["Coverage", data.coverage],
          ]}
        />
        <p className="mt-4 text-sm text-muted">{code.explanation}</p>
      </Card>

      {code.delegation && (
        <Card title="EIP-7702 delegation">
          <KeyValues
            items={[
              ["Delegates to", <Address key="t" value={code.delegation.target} />],
              ["Target code", `${CODE_LABEL[code.delegation.target_code_kind]} · ${code.delegation.target_code_size} bytes`],
            ]}
          />
          <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted">
            {code.delegation.notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        </Card>
      )}

      <Limitations items={data.limitations} />
    </div>
  );
}

export function OverviewPanel({ address }: { address: string }) {
  const { data, error, loading, run } = useAsync(() => api.analyze(address), [address]);
  if (loading) return <Loading label="Reading chain state at the latest block…" />;
  if (error) return <ErrorView error={error} onRetry={run} />;
  if (!data) return null;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <Button onClick={run}>Re-read at latest block</Button>
      </div>
      {data.persistence === "failed" && (
        <Callout tone="warn">The observation was read but could not be stored locally.</Callout>
      )}
      <Inspection data={data.inspection} />
    </div>
  );
}
