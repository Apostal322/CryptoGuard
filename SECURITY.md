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
- **Web UI.** No `dangerouslySetInnerHTML`; untrusted chain metadata renders as text. External
  links only go to allow-listed block explorers over https, with `rel="noopener noreferrer"`,
  and are never generated for simulated data. Production builds carry a strict
  Content-Security-Policy (`default-src 'self'`, no inline scripts, no third-party origins).
  The browser never receives or sends RPC URLs or credentials. Addresses are identified in
  full, because shortened addresses are what poisoning exploits; a shortened form appears only
  in poisoning titles, to illustrate how a wallet would display the lookalike.
- **Local, single-user API.** There is no authentication: anyone who can reach the API can
  take snapshots or acknowledge findings. Bind to `127.0.0.1` (the default) and do not expose
  it to a network without an authenticating reverse proxy. CORS is not authentication.
- **Browser attacks on the local API.** The API answers only to `CRYPTOGUARD_ALLOWED_HOSTS`
  (default `127.0.0.1`, `localhost`, `::1`), which defeats DNS rebinding. POSTs must be
  `application/json` (cross-site "simple" requests are refused with 415) and a present
  `Origin` must be a configured CORS origin or the API's own origin (403 otherwise).
- **Concurrency.** Snapshots (per wallet) and campaign runs are single-flight across threads,
  processes and restarts through database leases with fencing; a conflicting request gets
  409 and a run that loses its lease cannot write results.

## Threat model (summary)

| Threat | Current mitigation | Residual risk |
|---|---|---|
| Malicious contract/token metadata | Validated and length-bounded; rendered as text only (no HTML injection); `symbol()` labelled untrusted | Misleading but well-formed names (e.g. a fake "USDT") still display; labels are never safety verdicts |
| Forged Transfer logs (fake tokens, `transferFrom(victim, x, 0)`) | Transfer logs are never treated as asset movement; the transaction signer is read separately; the poisoning detector requires similarity plus context | A forged log can still create an informational finding |
| Campaign pollution (attacker links an innocent wallet) | Campaign links only through planting-side entities, never through the targeted wallet; popular contracts and hub signers never merge; chained groups labelled tentative | A link says "shared infrastructure", which a shared service could also produce |
| RPC provider lies or fails | Chain-id check, strict parsing, reorg re-check, explicit errors; missing history is reported, never read as "nothing happened" | A malicious provider can still report false state; cross-provider checks are future work |
| Historical leakage in evaluations | Manifests never feed detectors; point-in-time re-extraction; tests for every leakage path found | Evaluations cover few cases and cannot estimate rates |
| Supply-chain compromise | Small dependency set, `uv.lock` / `package-lock.json`, Dependabot, pip-audit and npm audit in CI | Upstream compromise of a pinned package |
| Data poisoning (intel feeds, ML) | No external threat feed or ML model is ingested | Must be addressed with provenance if added |
| Sensitive log leakage | Redacting formatter, httpx logging silenced | Third-party libraries logging at DEBUG |
| Misleading risk scores | No global score; severity and confidence are separate; experimental analyses never change findings | Users may still over-read "elevated risk" |
| Denial of service | Rate limit, body limit, RPC budgets and timeouts, bounded graphs and campaign runs (one at a time) | Single-process limiter only |
| False positives / negatives | Every result lists what was not checked; evaluation in EVALUATION.md | 4 incident cases; no rate estimate is possible |

## Privacy

Watched-address history can link a person to wallets. Data is stored locally (`data/`,
git-ignored); `cryptoguard purge --yes` deletes it, including stored transfer history and any
campaign run that mentions the wallet. Inspected addresses are sent to the configured RPC
provider and nowhere else. `cryptoguard campaigns expand` additionally sends the planting
signers, lookalikes and token contracts it investigates to that provider (never the
victims' private data, which CryptoGuard does not have). There are no accounts or analytics.

## Supported environments

Local, single-user use on Windows, macOS and Linux with Python 3.12. Only Windows 11 was run
locally; Linux is covered by the CI matrix definition, which has not run yet because the
repository has no remote. CryptoGuard has not had an independent security review and must not
be relied on as a sole safeguard for funds.

## Release review (0.1.0, 2026-10-28)

Performed by the development process itself, not independently:

- Code scan for dangerous constructs (dynamic evaluation, shell execution, unsafe
  deserialization, raw SQL, signing or broadcasting methods, unescaped HTML): none found.
- Tracked files scanned for credentials: only test placeholders; recorded fixtures name only
  the keyless public endpoint used.
- Dependencies: `pip-audit` on all 39 locked Python packages and `npm audit` on the frontend
  lockfile reported no known vulnerabilities on 2026-10-28.
- New endpoints: inputs validated (checksummed addresses, id pattern, bounded pagination and
  graph sizes); campaign runs are single-flight; experimental features are off by default.

Phase 10 release validation (2026-10-28) fixed CSRF and DNS-rebinding exposure of the local
API, cross-process single-flight, concurrent-snapshot failures and the handling of reverted
ETH payments; see [RELEASE_AUDIT.md](RELEASE_AUDIT.md) for the register.

## Reporting a vulnerability

Please open a private GitHub security advisory on the repository rather than a public issue.
Include reproduction steps and the affected version. Never include private keys or seed
phrases in a report.
