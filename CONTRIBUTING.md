# Contributing

## Setup

```powershell
uv sync                     # includes the dev group (NumPy/SciPy for the analytics tests)
uv run pytest
uv run ruff check . ; uv run ruff format --check . ; uv run mypy src
cd apps/web; npm ci; npm run typecheck; npm test; npm run build
```

Regenerate the evaluation reports after changing a detector, the replay fixtures or the
campaign code (both are generated; never edit them by hand):

```powershell
uv run cryptoguard replay run --analytics --write-report EVALUATION.md
uv run cryptoguard campaigns evaluate --write-report CAMPAIGN_EVALUATION.md
```

Apart from timestamps and timings, regenerated reports must match the committed ones;
`tests/unit/test_evaluation_regression.py` pins the headline results.

Optional: `uvx pre-commit install` to run the same checks before each commit.

## Rules

- Read-only only: no signing, broadcasting, approvals or revocations, ever.
- Never commit secrets, `.env`, local databases or downloaded datasets.
- Token amounts are integers; display formatting uses `core.units.format_units`.
- Don't fabricate chain data. If a value can't be obtained, raise or mark it unknown.
- New detectors document their rules and false-positive considerations in
  `DETECTION_METHODS.md` and ship with benign and malicious fixtures.
- Every fixed bug gets a regression test where practical. Mocks isolate the network; they
  must not replace the behaviour under test (see `tests/fakenode.py`).
- Tests that hit a real network are marked `live` and are excluded by default.
- Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
