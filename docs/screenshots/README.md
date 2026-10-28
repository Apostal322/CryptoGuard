# Screenshots

Rendered by the browser E2E suite (`apps/web/e2e/layout.spec.ts`, refreshed with
`CRYPTOGUARD_SCREENSHOTS=1 npm run e2e`) from the production frontend build talking to the
real API. The API's RPC endpoint is the deterministic **fictional** test chain of
`tests/e2e/server.py`, which is why the app shows "Real data" (real mode, real code path)
while every address, transaction and block is made up. Each image carries a banner saying
so. None of these screens is live Ethereum analysis.

Captured on Windows at `744150a`. Later fixes changed only how the header and long finding
titles wrap on narrow or wide-font screens (CHANGELOG, "GitHub CI and cross-platform
validation"); at the captured sizes the screens look the same apart from slightly tighter
navigation-link spacing on the 375 px dashboard.

| File | Shows |
|---|---|
| `wallet-overview.png` | Point-in-time inspection of a wallet |
| `security-finding.png` | A CG-POI-003 finding with its evidence and history |
| `security-timeline.png` | Three snapshots: baseline, poisoning warning, escalation (warning superseded) |
| `campaign-investigation.png` | Experimental related-activity context (shadow mode) with evidence |
| `mobile-dashboard.png` | The dashboard at 375 px |
