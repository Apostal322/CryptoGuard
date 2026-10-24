// Block-explorer links are built only from validated values and an allow-listed host.
// URLs coming from the API are re-checked against the same allow-list before rendering.

const EXPLORERS: Record<number, string> = {
  1: "https://etherscan.io",
  11155111: "https://sepolia.etherscan.io",
};

const TX_HASH = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export function explorerTxUrl(chainId: number, txHash: string | null | undefined): string | null {
  const base = EXPLORERS[chainId];
  if (!base || !txHash || !TX_HASH.test(txHash)) return null;
  return `${base}/tx/${txHash.toLowerCase()}`;
}

export function explorerAddressUrl(chainId: number, address: string): string | null {
  const base = EXPLORERS[chainId];
  if (!base || !ADDRESS.test(address)) return null;
  return `${base}/address/${address}`;
}

export function explorerBlockUrl(chainId: number, block: number): string | null {
  const base = EXPLORERS[chainId];
  if (!base || !Number.isSafeInteger(block) || block < 0) return null;
  return `${base}/block/${block}`;
}

/**
 * For curated, code-reviewed links (replay case sources) only — never for chain data:
 * any https URL without embedded credentials.
 */
export function safeCuratedUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password ? parsed.toString() : null;
  } catch {
    return null;
  }
}

/** Returns the URL only if it is https and points at a known explorer host. */
export function safeExternalUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const allowed = Object.values(EXPLORERS).some((base) => new URL(base).host === parsed.host);
  return parsed.protocol === "https:" && allowed && !parsed.username && !parsed.password
    ? parsed.toString()
    : null;
}
