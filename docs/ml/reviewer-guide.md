# Reviewer guide: CryptoGuard poisoning review

Thank you for reviewing. You will judge Ethereum transactions independently: two folders,
60 and 35 items. Please do not discuss items with the other reviewer until you have both
submitted.

## Before the real items: training (about an hour)

Start with the training folder. It holds ten invented cases with the same panels as the
real items. Read `training_notes.md` in that folder *after* trying them. Training answers
are never used as data, and the real items are never used for practice.

## Setup (once per folder)

1. Get your personal review folders from the maintainer. Each contains
   `reviewer_sheet.jsonl`, `reviewer.json` and usually `evidence_packets.jsonl`, and
   nothing else is needed.
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

## The offline evidence panel

Most items show an **Offline evidence** panel. It lists what this computer's recorded data
show *before the cutoff block*:
- the candidate transfer;
- who signed it (when known);
- the token;
- the wallet's earlier transfers;
- for some items, how often the address appeared with other wallets.

Read the coloured notes:
- **"Only rows a research dataset kept"**: ordinary activity is missing. Absence of a
  payment there does not mean the wallet never paid anyone.
- **"No earlier rows of this wallet are available locally"**: use a block explorer, up to
  the cutoff block.
- **"Token not on the reviewed list"**: unknown, not necessarily fake.

The panel never tells you the answer and computes no similarity. Find the earlier
counterparty yourself and paste it into the form.

## Reasons and citations

For a confirmed decision, tick at least one reason. Paste the transaction hashes or
addresses you relied on into **Evidence cited**, one per line.

## Be honest about what you saw

Block explorers show later activity and sometimes labels such as "Phishing". That is fine.
Just record it:
- whether you used an explorer;
- whether you viewed activity after the cutoff block;
- whether you saw a third-party label;
- whether you saw any source label, payoff record or model output.

You will also be asked:
- whether you saw a later payment from the wallet to this address;
- whether a third-party label influenced you;
- whether you used the offline panel.

These answers are not judged, and an item is never removed because of them.

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
