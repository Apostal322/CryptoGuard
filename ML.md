# Machine learning (experimental, shadow mode only)

CryptoGuard has an optional ML subsystem (`src/cryptoguard/ml/`, the `ml` extra). It
classifies an Ethereum **transaction** as part of a phishing operation or not, using
features that were knowable when the transaction executed. It is trained and evaluated on
independently labelled public data, compared with trivial and rule baselines on identical
held-out rows, and integrated **only in shadow mode**: scores are returned for review and
monitored for drift, and they never create, change or resolve findings.

Generated results: [ML_EVALUATION.md](ML_EVALUATION.md). This page is the data card,
method and decision log.

## Data card

### Sources (pinned)

| Source | Content (verified) | License | Use |
|---|---|---|---|
| [PTXPhish](https://github.com/HypoopyH/PTXPhish) @ `18efed8f` (Chen et al., NDSS 2025) | 18,555 unique transaction hashes in 13 subtypes: 4,998 phishing (ice phishing 2,569; NFT order 609; address poisoning 226; payable function 1,594) and 13,557 benign ("KOL" 9,572, "Developer" 3,985). Labels reviewed by two security experts. **No addresses, values or timestamps.** | none published | training and evaluation labels; data fetched locally, never redistributed |
| [Poison-Hunter](https://github.com/DS2L/Poison-Hunter) @ `74ff6f7d` (Guan & Li, CCS 2024) | 5,890 phishing addresses (Etherscan and Forta labels), 1,154 *popular* benign addresses, 150 sample transfers | none published | data card only |
| [Forta labelled-datasets](https://github.com/forta-network/labelled-datasets) @ `40a9c2f2` | Etherscan `phish-hack`, `exploit`, `heist` address labels, last updated January 2023 | MIT | data card only |

`cryptoguard ml fetch-sources` downloads the files at those commits into `data/external/`
(git-ignored) and refuses any file whose SHA-256 differs from the pinned value
(`ml/sources.py`).

### Label quality findings

- PTXPhish holds 4,998 phishing hashes where the paper states 5,000 ("Wallet function": 806
  in the sheet, 808 in the README). No hash appears twice or in two categories.
- Many labelled phishing transactions are the **attacker's** (for ice phishing, the
  `transferFrom` that drains the victim), not the victim's approval. The task is therefore
  "is this transaction part of a phishing operation", not "is the approval I am about to
  sign malicious".
- The benign class consists of transactions by prominent accounts ("KOL") and developers. It
  is not a random sample of Ethereum users. Benign transactions span blocks 3.2M to 20.4M
  (2017–2024); phishing ones only 15.0M to 18.5M (2022–2023).
- Poison-Hunter's benign addresses are popular accounts, separable from phishing addresses
  by popularity alone; its 150-row sample CSV is column-shifted (two more fields per row
  than header names). Not used for training.
- Forta's files contain 7,233 duplicate addresses across and within files; Forta and
  Poison-Hunter share no address, and Etherscan labels underlie both.
- None of the ~13,000 labelled phishing addresses and none of the 18,555 PTXPhish
  transactions appears in CryptoGuard's recorded replay fixtures (2,396 addresses), so
  CryptoGuard's own detectors cannot be evaluated on these labels.

### Chain data (collected once, budgeted)

`ml sample` draws a deterministic stratified sample (seed 20261029): all 226 address-poisoning
transactions, 1,125 other phishing transactions and 1,350 benign ones (2,701 total).
`ml collect` reads, per transaction, the transaction, its receipt, the sender's nonce and the
target's code **at the previous block**, from `eth.drpc.org`, under a hard cap of 12,000
requests that counts every attempt including retries and is written after every
transaction. Result: 2,527 transactions collected, 174 skipped by the budget guard, none
missing on chain; 11,953 requests charged in total. One collection run was interrupted
before it could record its count; it was charged a conservative upper estimate (recorded in
the ledger file). Chain data stays local (`data/ml/chain/`).

## Method

**Features** (`ml/features.py`, 40, pure Python, shared by training and scoring): value,
gas, fee type, calldata size, known function families by selector (approve, permit, operator
grant, transfer, delegated transfer, multicall, Seaport, proxy upgrade), contract-creation
and target code properties (code size, EIP-7702 delegation, vanity zero runs), sender's prior
transaction count, receipt status and gas ratio, log structure (Transfer, Approval and
ApprovalForAll counts, zero-value and delegated transfers, recipients, unlimited approvals)
and the largest lookalike affix among the transaction's parties. Deliberately **not**
features: block number or time (the classes come from different eras) and raw addresses or
hashes.

**Study window and splits** (`ml/splits.py`):

1. Only blocks where both classes occur (15,030,659 to 18,928,566).
2. Time order: train is the earliest 60%, validation the next 20%, test the last 20%; no
   block is shared.
3. Account purge: a validation or test row that shares any account (sender, target,
   spender, recipient) with an earlier split is dropped, except accounts in a curated
   registry of public infrastructure (major tokens, DEX routers, marketplaces, Permit2).
   This removed 199 validation and 176 test rows that would otherwise have leaked.

**Models** (`ml/train.py`): majority and stratified dummies; two rules (a hand-written
"phishing-shaped call" heuristic and a transaction-level proxy of CryptoGuard's signals);
logistic regression, random forest and LightGBM, each on all features and without the three
identity-like features (`no_identity`). Hyperparameters, threshold (F1 on validation),
feature set and the selected model are chosen on validation by log loss; test is scored once.
Every run is appended to `data/ml/runs/ledger.jsonl` with git SHA, package versions, the
dataset manifest hash, configuration and metrics.

**Promotion gate**: on validation, close at least half of the AP gap between the best
non-learned baseline and 1.0; on test, the model's 95% AP interval must lie above the best
baseline's test AP. Only a gated run can be promoted (`ml promote`).

## Results (run `20261029T055343Z-41bb2f56`, code `e9b49f1`)

| Model (test: 129 phishing, 43 benign) | Test AP [95% CI] | ROC-AUC | Recall | False-positive rate [95% CI] |
|---|---|---|---|---|
| Majority | 0.750 | 0.500 | 1.000 | 1.000 |
| Rule: phishing-shaped call | 0.845 [0.797, 0.891] | 0.694 | 0.411 | 0.023 [0.000, 0.077] |
| Rule: CryptoGuard-signal proxy | 0.750 | 0.500 | 0.047 | 0.047 |
| **LightGBM (selected)** | **0.999** [0.996, 1.000] | 0.995 | 0.977 | 0.163 [0.056, 0.273] |
| LightGBM without identity features | 0.991 | 0.976 | 0.977 | 0.209 |
| Logistic regression | 0.978 | 0.951 | 0.891 | 0.047 [0.000, 0.116] |

Full table, intervals, per-family recall, importance and errors: [ML_EVALUATION.md](ML_EVALUATION.md).

**What this does and does not show.** On held-out, later, account-disjoint transactions the
learned models rank phishing-operation transactions far better than any rule. The result
holds without the identity-like features. The model relies mostly on transaction *shape*:
delegated `transferFrom` calls (permutation importance 0.30), log count, proxy upgrades,
vanity-mined targets and target code size. The CryptoGuard-signal proxy is at chance
because those signals (unlimited approvals, zero-value transfers) describe wallet exposure
and are common in benign traffic too; CryptoGuard's detectors are wallet-centric and need
wallet history that this dataset lacks, so they could not be run on it.

**Failure modes.**

- The false-positive rate is about 16% on prominent accounts' transactions, measured on
  only 43 benign rows. On ordinary traffic, where phishing is far rarer than the 75% of this
  test set, most alerts would be false. This is why the model stays in shadow mode.
- **Plain token transfers are the blind spot.** 5 of the 7 test false positives and 2 of the 3
  missed phishing transactions (address poisoning) have the same shape: one `transfer()`
  call, one Transfer log, no ETH value. By transaction shape alone, a poisoning transfer and
  an ordinary payment look the same. Telling them apart needs the wallet's history (does
  the recipient imitate an earlier counterparty?), which is exactly what CryptoGuard's
  wallet-centric poisoning detector checks: the two are complementary, not substitutes.
- The other 2 false positives call vanity-mined contracts (10 and 14 leading or trailing
  zero nibbles), a property the model learned from phishing contracts.
- The third miss is a fake-token transfer whose receipt holds no logs at all.

## Shadow mode

```powershell
uv sync --extra ml
uv run cryptoguard ml fetch-sources                         # labels (hash-verified)
uv run cryptoguard ml sample                                # deterministic sample
uv run cryptoguard ml collect --rpc-url <archive-capable RPC>  # budgeted, resumable
uv run cryptoguard ml build                                 # validated table, splits, manifest
uv run cryptoguard ml train                                 # ledger, model card, ML_EVALUATION.md
uv run cryptoguard ml promote data/ml/runs/<run-id>         # refused unless the gate passed
uv run cryptoguard ml score <tx-hash> --rpc-url <RPC>       # one shadow score (4 RPC calls)
uv run cryptoguard ml monitor                               # feature drift (PSI) of scored txs
```

With `CRYPTOGUARD_ML_SHADOW=shadow`, the API offers `POST /api/v1/ml/transactions/score`
(`{"tx_hash"}`; the RPC endpoint is the operator's, never the request's) and
`GET /api/v1/ml/status` (promoted run, gate, drift). With the default `off` both answer 409
`feature_disabled`; without the extra or a promoted model, 503 `ml_unavailable`. Scores are
logged to `data/ml/shadow_scores.jsonl` for drift monitoring and are never stored as
findings. The promoted model is a pickle; it is loaded only from the local registry and only
if its SHA-256 matches its model card.

A full training run (10 model configurations after a 36-candidate search, bootstrap
intervals, permutation importance) took 34–44 s on a 4-core CPU with a peak of 197 MiB
(`scripts/peak_memory.py ml train`). It is deterministic: a repeated run gave identical
metrics for every model and a byte-identical model file. No GPU and no graph neural
network: gradient boosting on tabular features already ranks near the ceiling here, and the
data has no graph beyond each transaction's own parties.

## Decision log (changes made after seeing data)

These choices were revised during development; each revision was made before the final run
and is kept in the run ledger.

1. **Study window.** Added after the first data showed the classes come from different eras.
2. **Hub rule.** The first rule exempted accounts used by 10+ distinct senders. A leakage test
   showed that a scam contract called by many victims would be exempted, letting its later
   victims reach the test split. Replaced by a curated registry; over-linking only costs rows.
3. **Promotion gate.** The first gate ("+0.05 AP over the best baseline") could not be met when
   that baseline already exceeded 0.95 (seen on a partial-data dry run). Replaced by "close
   half of the remaining gap".
4. **Selection metric.** AP saturates near 1.0 here, so model selection and permutation
   importance use log loss.

## Limitations

- One labelled source, with a benign class of prominent accounts; precision on real traffic
  is unknown and likely low.
- Small evaluation splits after the window and purge; intervals are wide.
- Receipt-based features describe executed transactions; warning before signing would need
  transaction simulation (not implemented).
- Live scoring costs 4 RPC requests per transaction and needs historical state.
- Not independently reviewed.
