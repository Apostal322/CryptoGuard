# Reviewer guide: CryptoGuard poisoning review

Thank you for reviewing. You will judge 60 Ethereum transactions, independently. Please do
not discuss items with the other reviewer until you have both submitted.

## Setup (once)

1. Get your personal review folder from the maintainer. It contains `reviewer_sheet.jsonl`
   and `reviewer.json`, and nothing else is needed.
2. From the CryptoGuard repository, with Python 3.12 and `uv`, run:

   ```bash
   uv run cryptoguard ml review serve --package <your folder>
   ```

3. Your browser opens the review page. If it does not, open the exact address the command
   prints. That address contains a session key, so do not share it.
4. Your work is saved in `<your folder>/annotations/` on every Save. You can close the
   window and run the command again at any time to continue.

The page runs only on your computer (127.0.0.1). Nothing is uploaded.

## What you decide

For each item: **was this transaction an address-poisoning attempt against the wallet?**
A poisoning attempt plants a look-alike address in the wallet's history, so the owner
later copies it by mistake.

Use only evidence up to the item's block (the observation cutoff). Whether money was lost
later does not decide whether this was an attempt.

| Key | Decision | Use when |
|---|---|---|
| 1 | Confirmed poisoning attempt | the address under review imitates a real earlier counterparty of the wallet, and you found no legitimate relationship |
| 2 | Likely poisoning attempt | the pattern fits, but one element cannot be checked |
| 3 | Confirmed legitimate interaction | you found evidence of a genuine relationship |
| 4 | Insufficient evidence | the data does not allow a decision; this is a valid answer |
| 5 | Conflicting evidence | observations point both ways |

## Checklist per item

1. **Planting transfer.** Open the transaction. Did it move a token, or record a zero-value
   transfer, between the wallet and the address under review?
2. **Earlier counterparty.** In the wallet's history *before the block*, find an address it
   really dealt with that shares the first and last characters of the address under
   review. Paste it in. The page counts the matching characters.
3. **Token and value.** Is it a widely used token or an imitation contract? Is the value
   zero, dust or ordinary?
4. **Initiator.** Did the wallet send it, or a third party (for example through
   `transferFrom`)?
5. **Legitimate explanation.** Could the address be the wallet's own, or a known partner's?

For each check, say what you found: observed / looked for and absent / data not available
/ not looked at / not applicable / contradictory. "Not available" is not evidence against
an attempt.

Some folders show items titled **"Candidate for independent security review"**. They may
also show:
- a coverage note: how much of the wallet's history was recorded;
- an expandable table of the wallet's recorded activity before the cutoff.

Judge them exactly like any other item. Any of the five decisions may be right, including
"Confirmed poisoning attempt". The table is a convenience: it shows only what was
recorded, so check an explorer when the note says history is missing.

## Be honest about what you saw

Block explorers show later activity and sometimes labels such as "Phishing". That is fine.
Just record it:
- whether you used an explorer;
- whether you viewed activity after the cutoff block;
- whether you saw a third-party label;
- whether you saw any source label, payoff record or model output.

These answers are not judged.

## Keyboard

| Key | Action |
|---|---|
| 1–5 | choose a decision |
| Ctrl+S | save |
| `[` and `]` | previous and next item |

The numbered buttons show which items are saved.

## Problems

- **A transaction cannot be found anywhere:** do not guess. Tell the maintainer, who can
  replace the item. Do not ask for a replacement because an item is hard; use
  "Insufficient evidence" instead.
- **Save fails:** your input is kept as a draft in the browser. Fix the message shown, or
  restart the command, and save again.

## Finishing

When all items are saved, press **Finalize submission**. After that, nothing can be
changed. Send `<your folder>/annotations/submission.json` to the maintainer.
