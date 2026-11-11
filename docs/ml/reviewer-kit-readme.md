# Your review kit

This kit is personal to you. Please do not pass it on.

## What is in it

| Folder or file | What it is |
|---|---|
| `README.md` | this page |
| `reviewer-guide.md` | how to decide, what to record and what to do if something goes wrong |
| `cryptoguard/` | the local review tool |
| `training/` | 10 invented practice cases |
| `set-1/` | the first real set |
| `set-2/` | the second real set |

## Setup (once)

1. Install `uv`: <https://docs.astral.sh/uv/getting-started/installation/>. It fetches
   Python 3.12 itself on first use, together with the tool's dependencies from PyPI.
2. Open a terminal in the `cryptoguard` folder of this kit.

## Reviewing

Do the folders in this order: `training`, then `set-1`, then `set-2`. For each folder, run
the command below from the `cryptoguard` folder (`training` shown):

```bash
uv run --no-dev cryptoguard ml review serve --package ../training
```

The first run takes a minute or two while `uv` sets things up.

The review page opens in your browser. Read `reviewer-guide.md` before the first real
item, and read `training/training_notes.md` only after trying the practice cases.

Each folder has a **Finalize submission** button. After finalizing, the folder can no
longer be changed.

## Working independently

- Work alone. Please don't discuss items with the other reviewer until you have both
  finalized.
- Use only this kit, the guide and, if you wish, a public block explorer.
- Please don't look up this project's other documents or code comments about how the
  items were chosen. They could influence your judgement.
- If you see something by accident, carry on and record it in the item's questions. That
  is not a problem.

## Returning your work

Send the maintainer these three files, and nothing else:
- `training/annotations/submission.json`
- `set-1/annotations/submission.json`
- `set-2/annotations/submission.json`

Please don't send screenshots or item details.

## Data

The items come from research datasets whose licences forbid redistribution. Please:
- keep the kit on your own computer;
- use it only for this review;
- don't post item details anywhere;
- delete the kit afterwards if the maintainer asks.
