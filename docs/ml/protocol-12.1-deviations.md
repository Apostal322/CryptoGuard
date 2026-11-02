# Phase 12.1 protocol: deviations and implementation fixes

The protocol is frozen at commit `999794a` (`docs/ml/protocol-12.1.md`) and is not edited.
This file records every change made after freezing. All entries below were written
**before the study was run**: no outcome, metric or feature value of the real episodes had
been computed when they were committed. The primary hypotheses, metrics, split, groups,
tests and decision rule are unchanged.

## F1. Protected wallets entered the cross-victim graph (defect, fixed)

Protocol section 3 says that no event of the frozen cohorts' wallets enters any
computation. The study removed those wallets as *episodes*, but the graph index (G1, G2,
G3) still counted their archive rows: a protected wallet could be a "prior victim" of a
candidate lookalike.

**Fix:** `GraphIndex(exclude=...)`. Rows where either party is a protected wallet never
become an edge. The study passes the 91 protected wallets to every graph it builds:
- the primary graph;
- the `graph_drop_50` robustness graph;
- the cut graphs of the leakage control.

A test covers planted, paid and same-tx edges.

## F2. Archive pass rewrote its indexes on every batch (defect, fixed)

The first graph-context pass ran for about two hours and had covered 32% of the archive
when its process ended with the session. About 420k target rows had been stored by then.
The cause was the three secondary indexes, maintained during random-key inserts:
- every 20k-row commit journalled most index pages;
- the scan had written about 5 GB for a 200 MB file, on a shared, saturated disk.

**Fix:** the scanner now creates the indexes once, after the load. The finished schema is
identical, and a test checks that the indexes exist.

The partial file was not used: the archive is not block-ordered (88,845 order inversions
in the stored prefix), so it was not a clean time prefix. The pass was re-run from the
start with the same target manifest.

## D1. Entity and campaign overlap with the frozen items (added analysis)

The protocol excludes the frozen cohorts' *wallets*. A study episode can still share an
attacker entity with a frozen item.

An episode **overlaps** if any of the following holds:
- one of its candidates, or a planting counterparty, is a frozen item's wallet or address
  under review;
- one of its planting transactions is a frozen item's transaction;
- it shares a protocol linkage group with an episode that overlaps directly.

All of these are read from the blinded reviewer sheets only.

**Added:**
- the count of overlapping episodes per split;
- the four primary tests repeated without overlapping test episodes, as a **sensitivity**
  analysis (Holm over the same four);
- the exploratory learned model is fitted on development episodes **without** overlapping
  ones, so no fitted parameter is shaped by an entity under human review.

The confirmatory result remains the pre-registered test on all eligible test episodes. If
the two disagree on any decision, the report says so and does not choose between them.

## D2. Coverage-symmetry audit (added check)

Protocol section 4 states that the new pass covers paid and rival lookalikes alike. This
is now verified, not assumed. For paid and rival candidates separately, the audit
reports:
- the share targeted by the manifest;
- the share of their planting rows present in the graph database;
- the share of their planting transactions targeted;
- the median number of archive rows observed at the cutoff;
- the share the old subset would have covered.

It also checks that the graph database was built from this exact manifest (by hash). If
the audit fails, every G feature result is reported as invalid.

## Unchanged

- Eligibility and the 1,068 episodes.
- The features B0–B3, T0–T4, G1–G3 and NC, and their missingness rules.
- The methods, including H_fixed's components.
- The metrics, the linkage groups, the temporal split, the bootstrap and permutation
  settings, the seed, Holm over P-H1, P-H2, P-H3 and P-H5, and the decision margin.
- The frozen cohorts' files, hashes and packages: read only, never modified.
