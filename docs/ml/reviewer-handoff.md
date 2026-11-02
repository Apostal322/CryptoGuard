# Reviewer handoff (maintainer)

Materials for recruiting two independent human reviewers. Nothing here has been sent. No
reviewer has been contacted, has agreed or exists yet. Only the maintainer contacts
reviewers; no tool or AI assistant sends anything.

## 1. Invitation (ready to send; adjust the greeting, promise nothing not yet decided)

> **Subject: Independent review of Ethereum transactions (address-poisoning research)**
>
> I am looking for an independent reviewer for a small research study on Ethereum
> address poisoning: attackers planting look-alike addresses in a wallet's history.
> You would judge about 95 historical transactions, plus 10 training cases, using a
> local review page on your own computer and, if you wish, a public block explorer.
>
> What it involves:
> - installing `uv` and running a small local Python tool that I send you as a zip file;
> - working independently, without discussing items with the other reviewer until both
>   of you have submitted;
> - recording, for each item, a decision, your reasons and what you saw.
>
> The data come from a licensed research dataset and must stay on your computer. They are
> not to be shared or published.
>
> My rough estimate is about 9 hours in total, which you can split over several sessions.
> This is an assumption, not a measured time. There is no payment.
>
> Would you be willing?

## 2. Eligibility

- Comfortable reading Ethereum transactions, token transfers and logs on a block explorer.
- Understands ERC-20 `transfer`/`transferFrom`, zero-value transfers and token contracts.
- Did not build the samples or see their answer keys. The maintainer and any AI assistant
  involved are not eligible.
- Two *different people*. Two sessions of one person, or of an AI model, do not count.

## 3. Workload (assumption, not measured)

| Part | Items | Decisions (2 reviewers) | Assumed minutes per item | Hours per reviewer |
|---|---|---|---|---|
| Training | 10 | 20 | 5 | about 1 |
| Cohort `review-sample/1` | 60 | 120 | 5 | about 5 |
| Cohort `hard-negative-candidates/1` | 35 | 70 | 5 | about 3 |
| **Total** | 105 | 210 (190 real) | | **about 9** |

The 5 minutes per item comes from no pilot. Replace it with the median time of the
training cases once a reviewer has done them.

## 4. Data handling

**Decide before sending.** The packets are derived from Tsuchiya et al. data under
CC BY-NC-ND 4.0, whose "NoDerivatives" term restricts sharing adapted material. Sending
it privately to two reviewers for non-commercial research may be acceptable, but that is
your judgement or the dataset authors' to make, not this tool's. Asking the authors is the
safe route. This is not legal advice.

- Packages contain addresses derived from CC BY-NC-ND 4.0 research data. Keep them on the
  reviewer's computer, use them only for this review, and delete them afterwards if asked.
- Return only `annotations/submission.json`.
- Do not post screenshots or item details anywhere.

## 5. Independence

- One package and one store per reviewer, on separate computers or user accounts where
  possible. On a shared computer, independence is procedural.
- The reviewers do not see each other's decisions, the answer keys, the manifests or any
  model output before both have finalized.
- After finalization nothing can be edited. Changes need a protocol amendment.

## 6. Maintainer checklist

1. `cryptoguard ml review verify` and `cryptoguard ml review verify --cohort
   hard-negative-candidates/1`: all hashes match.
2. Check the evidence packets are in place. If either command below says they are missing,
   rebuild them:
   - `cryptoguard ml review build-evidence`
   - `cryptoguard ml review build-evidence --cohort hard-negative-candidates/1`

   The printed hashes must equal the registered ones (`review_sample.COHORTS`).
3. Build one kit per pseudonym (`A`, `B`) from a clean tree. A pseudonym is not tied to
   a person until its kit is sent; give `A` to whoever agrees first.

   ```bash
   uv run python scripts/make_reviewer_kit.py --reviewer A
   ```

   This writes `data/ml/poisoning/outbox/reviewer-A.zip` and a maintainer-only
   `reviewer-A.record.json`. The kit holds three folders (`training`, `set-1` =
   `review-sample/1`, `set-2` = `hard-negative-candidates/1`), the guide, a setup README
   and the review tool's code without the reports, tests or research docs. The script
   refuses to finish if any check fails (registered hashes, no key or manifest, no
   source words in the real folders). The neutral folder names and the code-only copy keep
   the cohort descriptions out of the reviewers' sight.
4. Send each reviewer only their own zip, privately (not a public link). Write the date
   into `sent` in the record file.
5. When a submission arrives, run
   `cryptoguard ml review check-submission <file> [--cohort …]` and fix nothing by hand
   (`set-1` needs no `--cohort`; `set-2` needs `--cohort hard-negative-candidates/1`). A
   problem goes back to the reviewer.
6. With both finalized: run `cryptoguard ml review agreement --submission A --submission B
   [--cohort …]`. It needs no key.
7. Only then: `cryptoguard ml review unblind …` per cohort. Report aggregates. Keep the
   per-item files local.

## 7. Optional, needs your approval: closing the signer gap

The packets lack signers for 85 items, receipts for all 95 and metadata for 28 tokens.
No local source has them. A request of about 292 calls (cap 365) to a provider with
historical state would close these gaps (ML_EVIDENCE_COMPLETION.md §19). It is not needed
to start the review, and nothing is collected without your explicit approval of a cap and
a provider.
