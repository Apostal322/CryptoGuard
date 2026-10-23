# Security

## Security boundaries

- **Read-only.** CryptoGuard never asks for private keys, seed phrases, passwords or
  signatures. The provider exposes no `eth_sendRawTransaction`, signing or approval/revocation
  method; `eth_call` is used only for local, read-only execution.
- **RPC endpoint is operator configuration.** It comes from the environment only. The API
  rejects unknown request fields, so a client cannot point the server at another URL (SSRF).
  Only `https` is accepted, except `http` for `localhost`/`127.0.0.1`/`::1`.
- **Secrets stay out of output.** The RPC URL is shown as `scheme://host[:port]/…`. Log
  records are scrubbed of the URL and its path/query/userinfo; httpx request logging is
  silenced. Exceptions raised from transport errors drop the underlying cause (which can embed
  the URL).
- **Untrusted chain data.** Every RPC value is shape- and size-checked; malformed data raises
  `rpc_invalid_response` instead of being guessed. Provider error text is never echoed to API
  clients. Token `symbol()` output is decoded with strict length bounds, stripped of markup
  characters and truncated, and is always labelled untrusted. Responses are JSON only (`Content-Security-Policy: default-src 'none'`,
  `nosniff`), and validation errors do not echo input.
- **Chain verification.** `eth_chainId` must match the configured chain before any state read.
- **Resource limits.** Request timeouts, bounded retries (with capped `Retry-After`), bounded
  RPC concurrency, a response-size cap, bounded `eth_getLogs` block ranges, a request-body
  limit (POST requires `Content-Length`), and per-client rate limiting with bounded memory.
- **CORS** is restricted to configured origins; wildcards are rejected; no credentials.

## Threat model (summary)

| Threat | Current mitigation | Residual risk |
|---|---|---|
| Malicious contract/token metadata | Not rendered yet; all output is JSON; values validated | UI (Phase 5) must escape everything |
| RPC provider lies or fails | Chain-id check, strict parsing, reorg re-check, explicit errors | A malicious provider can still report false state; cross-provider checks are future work |
| Supply-chain compromise | Small dependency set, `uv.lock`, Dependabot | Upstream compromise of a pinned package |
| Data poisoning (future ML/intel feeds) | No external intel ingested yet | Must be addressed with provenance in later phases |
| Alert spoofing | No alerting yet | Alerts must carry evidence references |
| Sensitive log leakage | Redacting formatter, httpx logging silenced | Third-party libraries logging at DEBUG |
| Misleading risk scores | No scores; outputs are observed facts with limitations | Future rule engine must keep severity ≠ confidence |
| Denial of service | Rate limit, body limit, RPC budgets and timeouts | Single-process limiter only |
| False positives / negatives | No detectors yet; every result lists what was not checked | Later detectors need evaluation (EVALUATION.md) |

## Privacy

Watched-address history can link a person to wallets. Data is stored locally (`data/`,
git-ignored); `cryptoguard purge --yes` deletes it. Inspected addresses are sent to the
configured RPC provider and nowhere else. There are no accounts or analytics.

## Supported environments

Local, single-user use on Windows, macOS and Linux with Python 3.12. CryptoGuard has not had
an independent security review and must not be relied on as a sole safeguard for funds.

## Reporting a vulnerability

Please open a private GitHub security advisory on the repository rather than a public issue.
Include reproduction steps and the affected version. Never include private keys or seed
phrases in a report.
