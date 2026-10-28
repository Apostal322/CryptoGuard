"""Command-line interface.

cryptoguard inspect <address> [--demo] [--json] [--no-store]
cryptoguard approvals <address> [--lookback N | --from-block N] [--token T]... [--demo]
                      [--json] [--no-store]
cryptoguard status [--demo]
cryptoguard demo-addresses
cryptoguard serve [--host 127.0.0.1] [--port 8000] [--demo]
cryptoguard purge [--address <address>] --yes
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

from pydantic import SecretStr, ValidationError

from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import get_chain
from cryptoguard.core.config import Settings, secret_fragments
from cryptoguard.core.errors import CryptoGuardError
from cryptoguard.core.hexutil import parse_hash32
from cryptoguard.core.logging import configure_logging
from cryptoguard.risk.lifecycle import OPEN_STATUSES
from cryptoguard.services.approvals import (
    AllowanceLevel,
    ApprovalScanReport,
    Reading,
    ScanLimits,
    scan_approvals,
)
from cryptoguard.services.demo import DEMO_ACCOUNTS
from cryptoguard.services.inspection import AddressInspection, inspect_address
from cryptoguard.services.poisoning import PoisoningReport, scan_poisoning
from cryptoguard.services.providers import build_provider, require_provider
from cryptoguard.services.snapshots import DetectionOptions, SnapshotOutcome, take_snapshot


def _load_settings(demo: bool) -> Settings:
    settings = Settings()
    if demo:
        settings = settings.model_copy(update={"mode": "demo"})
    secrets = secret_fragments(settings.rpc_url.get_secret_value()) if settings.rpc_url else []
    configure_logging(settings.log_level, as_json=settings.log_json, secrets=secrets)
    return settings


def _render(inspection: AddressInspection) -> str:
    block = inspection.block
    code = inspection.account_code
    lines: list[str] = []
    if inspection.simulated:
        lines.append("*** SIMULATED DEMO DATA — fictional fixtures, not Ethereum state ***")
    else:
        lines.append(f"Real data via RPC provider {inspection.provider}")
    lines += [
        f"Address:   {inspection.address}",
        f"Chain:     {inspection.chain_name} (chain id {inspection.chain_id}, verified via "
        "eth_chainId)",
        f"Block:     #{block.number} {block.hash}",
        f"           {block.timestamp.isoformat()} ({block.finality.replace('_', ' ')}; "
        f"head #{block.head_block_number})",
        f"Balance:   {inspection.native_balance.formatted} {inspection.native_balance.symbol} "
        f"({inspection.native_balance.wei} wei)",
        f"Code:      {code.kind.value} ({code.code_size} bytes, hash {code.code_hash})",
    ]
    if code.delegation is not None:
        d = code.delegation
        lines.append(
            f"Delegates: {d.target} "
            f"(target: {d.target_code_kind.value}, {d.target_code_size} bytes)"
        )
        lines += [f"           - {note}" for note in d.notes]
    lines.append(f"Meaning:   {code.explanation}")
    lines.append(f"Coverage:  {inspection.coverage}")
    lines.append("Limitations:")
    lines += [f"  - {item}" for item in inspection.limitations]
    if inspection.explorer is not None:
        lines.append(f"Explorer:  {inspection.explorer.address}")
    return "\n".join(lines)


async def _inspect(settings: Settings, address: str, *, store: bool) -> AddressInspection:
    provider = require_provider(build_provider(settings))
    try:
        inspection = await inspect_address(provider, address, chain=get_chain(settings.chain_id))
    finally:
        await provider.aclose()
    if store:
        from cryptoguard.database.repository import open_repository

        open_repository(settings.database_url).save_inspection(inspection)
    return inspection


def _amount(reading: Reading, symbol: str) -> str:
    if reading.status == "unknown":
        return f"unknown ({reading.unknown_reason})"
    if reading.formatted is None:
        return f"{reading.raw} base units"
    return f"{reading.formatted} {symbol}"


def _render_approvals(report: ApprovalScanReport) -> str:
    lines: list[str] = []
    if report.simulated:
        lines.append("*** SIMULATED DEMO DATA — fictional fixtures, not Ethereum state ***")
    else:
        lines.append(f"Real data via RPC provider {report.provider}")
    lines += [
        f"Owner:     {report.owner}",
        f"Chain:     {report.chain_name} (chain id {report.chain_id})",
        f"State at:  block #{report.block_number} {report.block_hash} "
        f"({report.block_timestamp.isoformat()})",
        f"Coverage:  {report.coverage.description}",
        f"Found:     {report.pairs_discovered} token/spender pair(s) from "
        f"{report.log_counts.erc20_approvals} ERC-20 Approval log(s); "
        f"{report.log_counts.erc721_shaped_approvals} NFT-shaped log(s) not analyzed",
    ]
    active = [a for a in report.approvals if a.active is not False]
    inactive = len(report.approvals) - len(active)
    for entry in active:
        symbol = entry.token.symbol or "?"
        label = f" [{entry.spender.label}]" if entry.spender.label else ""
        lines += [
            "",
            f"  Token     {entry.token.address} ({symbol}, untrusted symbol)",
            f"  Spender   {entry.spender.address}{label} ({entry.spender.code_kind.value})",
            f"  Allowance {entry.allowance_level.value}: "
            + (
                "max uint256"
                if entry.allowance_level is AllowanceLevel.UNLIMITED
                else _amount(entry.current_allowance, symbol)
            ),
            f"  Balance   {_amount(entry.owner_balance, symbol)}",
            f"  Exposure  ≤ {_amount(entry.exposure_upper_bound, symbol)}",
            f"  Last set  block #{entry.latest_event.block_number}, "
            f"tx {entry.latest_event.transaction_hash}",
        ]
        lines += [f"  ! {s.code} ({s.evidence_class}): {s.explanation}" for s in entry.signals]
    if inactive:
        lines += ["", f"  {inactive} pair(s) have a current allowance of 0 (not shown)."]
    lines += ["", "Limitations:"] + [f"  - {item}" for item in report.limitations]
    return "\n".join(lines)


async def _approvals(
    settings: Settings,
    address: str,
    *,
    lookback: int | None,
    from_block: int | None,
    tokens: list[str] | None,
    store: bool,
) -> ApprovalScanReport:
    provider = require_provider(build_provider(settings))
    try:
        scan = await scan_approvals(
            provider,
            address,
            chain=get_chain(settings.chain_id),
            limits=ScanLimits.from_settings(settings),
            from_block=from_block,
            lookback_blocks=lookback,
            tokens=tokens,
        )
    finally:
        await provider.aclose()
    if store:
        from cryptoguard.database.repository import open_repository

        open_repository(settings.database_url).save_approval_scan(scan.report, scan.events)
    return scan.report


def _render_snapshot(outcome: SnapshotOutcome) -> str:
    lines = ["*** SIMULATED DEMO DATA ***"] if outcome.simulated else []
    since = f"since block {outcome.previous_block}" if outcome.previous_block is not None else ""
    lines += [
        f"Snapshot #{outcome.snapshot_id} of {outcome.owner} at block {outcome.block_number} "
        f"({outcome.block_timestamp.isoformat()}, {outcome.lag_blocks} blocks behind head) "
        + ("[baseline]" if outcome.is_baseline else since),
        f"Coverage: {outcome.coverage.description}",
    ]
    if not outcome.created:
        lines.append("(already recorded; nothing re-read)")
    if outcome.changes:
        lines.append("Changes:")
        for change in outcome.changes:
            cause = change.cause.transaction_hash or "state comparison"
            lines.append(f"  - {change.explanation} Cause: {cause}.")
            lines.append(f"    Why it matters: {change.why_it_matters}")
    elif not outcome.is_baseline:
        lines.append("Changes: none observed.")
    if outcome.finding_events:
        lines.append("Findings:")
        for event in outcome.finding_events:
            lines.append(
                f"  - [{event.severity}/{event.confidence}] {event.title}: "
                f"{event.from_status or '-'} -> {event.to_status} ({event.reason})"
            )
    if outcome.findings_not_reverified:
        lines.append(
            f"{outcome.findings_not_reverified} open finding(s) could not be re-verified and "
            "were left unchanged."
        )
    lines += [f"Note: {note}" for note in outcome.notes]
    return "\n".join(lines)


async def _snapshot(
    settings: Settings,
    address: str,
    *,
    block: int | None,
    tokens: list[str] | None,
    lookback: int | None,
) -> SnapshotOutcome:
    from cryptoguard.database.repository import open_repository

    provider = require_provider(build_provider(settings))
    try:
        return await take_snapshot(
            provider,
            open_repository(settings.database_url),
            address,
            chain=get_chain(settings.chain_id),
            limits=ScanLimits.from_settings(settings),
            confirmations=settings.snapshot_confirmations,
            block=block,
            tokens=tokens,
            lookback_blocks=lookback,
            options=DetectionOptions.from_settings(settings),
        )
    finally:
        await provider.aclose()


async def _poisoning(
    settings: Settings, address: str, *, lookback: int | None, tokens: list[str] | None
) -> PoisoningReport:
    provider = require_provider(build_provider(settings))
    try:
        return await scan_poisoning(
            provider,
            address,
            chain=get_chain(settings.chain_id),
            limits=ScanLimits.from_settings(settings),
            options=DetectionOptions.from_settings(settings),
            lookback_blocks=lookback,
            tokens=tokens,
        )
    finally:
        await provider.aclose()


def _render_poisoning(report: PoisoningReport) -> str:
    lines = ["*** SIMULATED DEMO DATA ***"] if report.simulated else []
    lines += [
        f"Address-poisoning scan of {report.owner} at block {report.block_number}: "
        f"{report.transfers_analyzed} ERC-20 transfer(s) analyzed, {len(report.cases)} case(s).",
    ]
    for case in report.cases:
        lines += [
            "",
            f"  [{case.severity.value}/{case.confidence.value}] {case.rule_id}",
            f"  Suspect:   {case.suspect}",
            f"  Imitates:  {case.reference} (first used block {case.reference_first_used_block}"
            + ("" if case.reference_confirmed else ", signer unverified")
            + ")",
            f"  Match:     first {case.prefix_match} / last {case.suffix_match} hex chars "
            f"({case.displayed_as}); random odds {case.random_match_odds}",
        ]
        for signal in case.signals:
            tx = f" tx {signal.transaction_hash}" if signal.transaction_hash else ""
            lines.append(f"    - {signal.code}: {signal.description}{tx}")
        lines.append(f"  Action:    {case.recommended_action}")
    lines += ["", "Limitations:"] + [f"  - {item}" for item in report.limitations]
    return "\n".join(lines)


def _print_timeline(settings: Settings, address: str, limit: int) -> None:
    from cryptoguard.database.repository import open_repository

    rows, total = open_repository(settings.database_url).timeline(
        settings.chain_id, to_checksum_address(address), limit=limit, offset=0
    )
    print(f"{total} snapshot(s); newest first.")
    for row in rows:
        s = row.snapshot
        tag = " [SIMULATED]" if s.data_source == "demo_fixture" else ""
        kind = "baseline" if s.is_baseline else f"since block {row.previous_block}"
        print(f"\n#{s.id} block {s.block_number} {s.block_timestamp.isoformat()} ({kind}){tag}")
        for change in s.changes:
            print(f"  change: {change['explanation']}")
        for event in row.finding_events:
            print(f"  finding: {event.title} {event.from_status or '-'} -> {event.to_status}")


def _print_findings(settings: Settings, address: str, show_all: bool) -> None:
    from cryptoguard.database.repository import open_repository

    statuses = None if show_all else [s.value for s in OPEN_STATUSES]
    findings = open_repository(settings.database_url).list_findings(
        settings.chain_id, to_checksum_address(address), statuses
    )
    print(f"{len(findings)} finding(s).")
    for f in findings:
        tag = " [SIMULATED]" if f.data_source == "demo_fixture" else ""
        print(
            f"\n{f.fingerprint}{tag}\n  {f.rule_id} [{f.severity}/{f.confidence}] {f.status}: "
            f"{f.title}\n  {f.explanation}\n  first seen block {f.first_seen_block}, "
            f"last seen block {f.last_seen_block}"
        )


def _replay_command(args: argparse.Namespace, settings: Settings) -> int:
    from pathlib import Path

    from cryptoguard.blockchain.provider import build_rpc_provider
    from cryptoguard.core.config import validate_rpc_url
    from cryptoguard.replay.engine import replay
    from cryptoguard.replay.models import case_directory, load_cases
    from cryptoguard.replay.record import record_fixture
    from cryptoguard.replay.report import render_markdown

    cases = load_cases()
    if args.replay_command == "list":
        for case in cases:
            status = f"fixture {case.fixture_sha256[:12]}…" if case.fixture_sha256 else "no fixture"
            print(f"{case.manifest.case_id}  [{status}]  {case.manifest.title}")
        return 0

    if args.replay_command == "record":
        manifest = next((c.manifest for c in cases if c.manifest.case_id == args.case_id), None)
        if manifest is None:
            print(f"error: unknown case {args.case_id}", file=sys.stderr)
            return 1
        record_settings = settings.model_copy(
            update={
                "rpc_url": SecretStr(validate_rpc_url(args.rpc_url)),
                "chain_id": manifest.chain_id,
                "rpc_max_concurrency": 2,
            }
        )

        async def run_recording() -> str:
            provider = build_rpc_provider(record_settings)
            try:
                fixture = await record_fixture(provider, manifest, chunk_blocks=args.chunk_blocks)
            finally:
                await provider.aclose()
            path = case_directory(manifest.case_id) / "fixture.json"
            path.write_bytes(fixture.canonical_bytes() + b"\n")
            return (
                f"Recorded {len(fixture.transfers)} transfers and "
                f"{len(fixture.wallet_transactions)} wallet transactions "
                f"({fixture.rpc_requests} RPC requests) to {path}"
            )

        print(asyncio.run(run_recording()))
        return 0

    if args.replay_command in ("sample-background", "record-background"):
        return _background_command(args, settings)

    selected = [
        c for c in cases if c.fixture and (not args.case_id or c.manifest.case_id == args.case_id)
    ]
    if not selected:
        print("error: no recorded case matches", file=sys.stderr)
        return 1
    results = [replay(c.manifest, c.fixture) for c in selected if c.fixture]
    analytics_md = ""
    if args.analytics:
        from cryptoguard.replay.analytics_eval import Subject, render_analytics, run_evaluation
        from cryptoguard.replay.background import load_background

        subjects = [
            Subject(
                c.manifest.case_id,
                "positive",
                c.fixture,
                c.manifest.harm.block_number,
                c.manifest.harm.recipient,
            )
            for c in selected
            if c.fixture
        ] + [
            Subject(b.manifest.case_id, "background", b.fixture)
            for b in load_background()
            if b.fixture and not args.case_id
        ]
        unrecorded = [b.manifest.case_id for b in load_background() if b.fixture is None]
        evaluation = run_evaluation(
            subjects,
            scaling=not args.no_scaling,
            notes=[
                f"Background wallet(s) {', '.join(unrecorded)} were sampled but could not be "
                "recorded (the provider rejected a block read); they are excluded, not replaced."
            ]
            if unrecorded and not args.case_id
            else [],
        )
        analytics_md = render_analytics(evaluation)
        if args.analytics_json:
            Path(args.analytics_json).write_text(
                evaluation.model_dump_json(indent=1), encoding="utf-8"
            )
        if not args.write_report:
            print(analytics_md)
    if args.write_report:
        report = render_markdown(results)
        if analytics_md:
            report = report.rstrip("\n") + "\n\n" + analytics_md
        Path(args.write_report).write_text(report, encoding="utf-8")
        print(f"Wrote {args.write_report}")
    if args.json:
        print(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
    else:
        for r in results:
            print(f"{r.case_id}: harm at block {r.harm_block}")
            for v in r.results:
                print(f"  {v.visibility.value}: {v.outcome} — {v.explanation}")
            for check in r.leakage_checks:
                print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.check}")
    return 0


def _background_command(args: argparse.Namespace, settings: Settings) -> int:
    from datetime import UTC, datetime

    from cryptoguard.blockchain.provider import build_rpc_provider
    from cryptoguard.core.config import validate_rpc_url
    from cryptoguard.replay.background import (
        background_root,
        load_background,
        sample_background,
        write_manifest,
    )
    from cryptoguard.replay.record import record_window

    rpc_settings = settings.model_copy(
        update={"rpc_url": SecretStr(validate_rpc_url(args.rpc_url)), "rpc_max_concurrency": 2}
    )

    async def sample() -> str:
        provider = build_rpc_provider(rpc_settings)
        try:
            chosen, log = await sample_background(
                provider,
                seed=args.seed,
                count=args.count,
                block_range=(args.from_block, args.to_block),
                window_blocks=args.window_blocks,
                max_nonce_delta=args.max_nonce_delta,
                created_at=datetime.now(UTC),
            )
        finally:
            await provider.aclose()
        for manifest in chosen:
            write_manifest(manifest)
        (background_root() / f"SELECTION-{args.seed}.json").write_text(
            log.model_dump_json(indent=1) + "\n"
        )
        return f"Selected {len(chosen)} wallets, excluded {len(log.excluded)} draws."

    async def record() -> str:
        lines = []
        pending = [c for c in load_background() if c.fixture is None][: args.limit]
        for case in pending:
            m = case.manifest
            provider = build_rpc_provider(rpc_settings.model_copy(update={"chain_id": m.chain_id}))
            try:
                fixture = await record_window(
                    provider,
                    case_id=m.case_id,
                    chain_id=m.chain_id,
                    wallet=m.wallet,
                    start=m.from_block,
                    end=m.to_block,
                    chunk_blocks=args.chunk_blocks,
                    all_timestamps=False,
                    max_wallet_transactions=200,
                )
            except Exception as exc:  # report and continue with the next wallet
                lines.append(f"{m.case_id}: FAILED ({type(exc).__name__}: {exc})")
                continue
            finally:
                await provider.aclose()
            path = background_root() / m.case_id / "fixture.json"
            path.write_bytes(fixture.canonical_bytes() + b"\n")
            lines.append(
                f"{m.case_id}: {len(fixture.transfers)} transfers, "
                f"{len(fixture.wallet_transactions)} wallet txs, {fixture.rpc_requests} requests"
            )
        return "\n".join(lines) or "Nothing to record."

    print(asyncio.run(sample() if args.replay_command == "sample-background" else record()))
    return 0


def _campaign_command(args: argparse.Namespace, settings: Settings) -> int:
    from datetime import UTC, datetime
    from pathlib import Path

    from cryptoguard.campaigns import dataset

    if args.campaign_command in ("analyze", "expand"):
        return _campaign_product_command(args, settings)
    if args.campaign_command == "evaluate":
        from cryptoguard.campaigns.evaluate import render_report, run_campaign_evaluation

        evaluation = run_campaign_evaluation()
        if args.json:
            Path(args.json).write_text(evaluation.model_dump_json(indent=1), encoding="utf-8")
        report = render_report(evaluation)
        if args.write_report:
            Path(args.write_report).write_text(report, encoding="utf-8")
            print(f"Wrote {args.write_report}")
        else:
            print(report)
        return 0

    from cryptoguard.blockchain.provider import build_rpc_provider
    from cryptoguard.campaigns.expansion import (
        ExpansionBudget,
        ExpansionResult,
        TaskOutcome,
        expand,
    )
    from cryptoguard.core.config import validate_rpc_url

    subjects = dataset.fixture_attempts()
    attempts = [a for s in subjects for a in s.attempts]
    cutoff = max(s.cutoff_block for s in subjects)
    budget = ExpansionBudget(max_requests=args.max_requests, max_seconds=args.max_seconds)
    path = dataset.expansion_path()
    previous = dataset.load_expansion(path)
    completed: dict[str, TaskOutcome] = {}
    if previous is not None and previous[0].cutoff_block == cutoff:
        completed = {o.task.task_id: o for o in previous[0].outcomes if o.status == "complete"}
    rpc_settings = settings.model_copy(
        update={"rpc_url": SecretStr(validate_rpc_url(args.rpc_url)), "rpc_max_concurrency": 2}
    )

    async def run() -> str:
        provider = build_rpc_provider(rpc_settings)
        done: list[TaskOutcome] = []
        try:
            header = await provider.get_block(cutoff)
            meta = {
                "recorded_at": datetime.now(UTC).isoformat(),
                "recorded_with": provider.endpoint_display,
                "cutoff_block_hash": header.hash,
                "seed_attempts": sorted(a.attempt_id for a in attempts),
                "subjects": {s.subject_id: s.fixture_sha256 for s in subjects},
            }

            def checkpoint(outcome: TaskOutcome) -> None:  # safe interruption: save as we go
                done.append(outcome)
                partial = ExpansionResult(
                    "campaign-expansion/1",
                    1,
                    cutoff,
                    budget,
                    [*completed.values(), *done],
                    0,
                    0.0,
                    "interrupted",
                )
                dataset.save_expansion(path, partial, meta)

            result = await expand(
                provider,
                attempts,
                chain_id=1,
                cutoff_block=cutoff,
                budget=budget,
                completed=completed,
                on_task=checkpoint,
            )
            dataset.save_expansion(path, result, meta)
        finally:
            await provider.aclose()
        verified = len(result.attempts())
        return (
            f"{len(result.outcomes)} tasks, {result.requests} requests, {result.seconds:.0f}s, "
            f"{len(result.candidates)} candidates ({verified} verified attempts), "
            f"stopped: {result.stopped}. Wrote {path}"
        )

    print(asyncio.run(run()))
    return 0


def _campaign_product_command(args: argparse.Namespace, settings: Settings) -> int:
    from cryptoguard.blockchain.provider import DataSource
    from cryptoguard.campaigns.expansion import (
        ExpansionBudget,
        TaskOutcome,
        expand,
        outcome_to_dict,
    )
    from cryptoguard.database.campaigns import CampaignStore
    from cryptoguard.database.repository import open_repository
    from cryptoguard.services.campaigns import collect_attempts, require_enabled, run_analysis

    require_enabled(settings)
    repo = open_repository(settings.database_url)
    source: DataSource = "demo_fixture" if settings.mode == "demo" else "rpc"
    if args.campaign_command == "analyze":
        info = run_analysis(repo, chain_id=settings.chain_id, data_source=source, settings=settings)
        print(info.model_dump_json(indent=2))
        return 0

    provider = build_provider(settings)
    if provider is None or source != "rpc":
        print("error: expansion needs a configured RPC provider in real mode", file=sys.stderr)
        return 1
    store = CampaignStore(repo)
    attempts, cutoff, _, _ = collect_attempts(
        repo,
        chain_id=settings.chain_id,
        data_source=source,
        history_limit=settings.transfer_history_limit,
    )
    from cryptoguard.campaigns.expansion import outcome_from_dict

    completed = {
        o.task.task_id: o
        for o in (outcome_from_dict(p) for p in store.load_tasks(settings.chain_id, source))
        if o.status == "complete"
    }

    def save(outcome: TaskOutcome) -> None:
        store.save_task(
            chain_id=settings.chain_id,
            data_source=source,
            task_id=outcome.task.task_id,
            kind=outcome.task.kind,
            entity=outcome.task.key,
            seed_block=outcome.task.seed_block,
            status=outcome.status,
            payload=outcome_to_dict(outcome),
        )

    async def run() -> str:
        try:
            result = await expand(
                provider,
                attempts,
                chain_id=settings.chain_id,
                cutoff_block=cutoff,
                budget=ExpansionBudget(
                    max_requests=args.max_requests or settings.campaign_expansion_max_requests
                ),
                completed=completed,
                on_task=save,
            )
        finally:
            await provider.aclose()
        return json.dumps(result.coverage(), indent=2)

    print(asyncio.run(run()))
    return 0


async def _status(settings: Settings) -> dict[str, object]:
    provider = build_provider(settings)
    result: dict[str, object] = {
        "mode": settings.mode,
        "chain_id": settings.chain_id,
        "rpc_configured": settings.rpc_url is not None,
        "provider": provider.endpoint_display if provider else None,
    }
    if provider is None:
        return result
    try:
        result["verified_chain_id"] = await provider.verify_chain()
        result["head_block"] = await provider.block_number()
    finally:
        await provider.aclose()
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cryptoguard", description="CryptoGuard — read-only Ethereum wallet security analysis."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="inspect an address at the current block")
    p_inspect.add_argument("address")
    p_inspect.add_argument("--demo", action="store_true", help="use simulated demo fixtures")
    p_inspect.add_argument("--json", action="store_true", help="print JSON")
    p_inspect.add_argument("--no-store", action="store_true", help="do not save the observation")

    p_approvals = sub.add_parser(
        "approvals", help="discover ERC-20 approvals in a block window and verify allowances"
    )
    p_approvals.add_argument("address")
    p_approvals.add_argument("--lookback", type=int, help="number of recent blocks to scan")
    p_approvals.add_argument("--from-block", type=int, help="scan from this block to the head")
    p_approvals.add_argument(
        "--token",
        action="append",
        dest="tokens",
        help="limit discovery to this token contract (repeatable)",
    )
    p_approvals.add_argument("--demo", action="store_true", help="use simulated demo fixtures")
    p_approvals.add_argument("--json", action="store_true", help="print JSON")
    p_approvals.add_argument("--no-store", action="store_true", help="do not save the scan")

    p_snapshot = sub.add_parser("snapshot", help="record a security snapshot on the timeline")
    p_snapshot.add_argument("address")
    p_snapshot.add_argument(
        "--block", type=int, help="snapshot block (default: head - confirmations)"
    )
    p_snapshot.add_argument("--token", action="append", dest="tokens", help="token scope")
    p_snapshot.add_argument("--lookback", type=int, help="discovery window for the first snapshot")
    p_snapshot.add_argument("--demo", action="store_true")
    p_snapshot.add_argument("--json", action="store_true")

    p_poison = sub.add_parser("poisoning", help="one-off address-poisoning scan (not stored)")
    p_poison.add_argument("address")
    p_poison.add_argument("--lookback", type=int, help="number of recent blocks to scan")
    p_poison.add_argument("--token", action="append", dest="tokens", help="token scope")
    p_poison.add_argument("--demo", action="store_true")
    p_poison.add_argument("--json", action="store_true")

    p_timeline = sub.add_parser("timeline", help="show stored snapshots and their changes")
    p_timeline.add_argument("address")
    p_timeline.add_argument("--limit", type=int, default=20)
    p_timeline.add_argument("--demo", action="store_true")

    p_findings = sub.add_parser("findings", help="list stored findings (open by default)")
    p_findings.add_argument("address")
    p_findings.add_argument("--all", action="store_true", help="include resolved/superseded")
    p_findings.add_argument("--demo", action="store_true")

    p_graph = sub.add_parser("graph", help="show the stored relationship graph of a wallet")
    p_graph.add_argument("address")
    p_graph.add_argument("--max-nodes", type=int, default=60)
    p_graph.add_argument("--include-inactive", action="store_true")
    p_graph.add_argument("--demo", action="store_true")
    p_graph.add_argument("--json", action="store_true")

    p_replay = sub.add_parser("replay", help="historical incident replay")
    replay_sub = p_replay.add_subparsers(dest="replay_command", required=True)
    replay_sub.add_parser("list", help="list packaged incident cases")
    p_record = replay_sub.add_parser("record", help="record a case fixture from an archive RPC")
    p_record.add_argument("case_id")
    p_record.add_argument(
        "--rpc-url", required=True, help="RPC endpoint with historical logs and state"
    )
    p_record.add_argument("--chunk-blocks", type=int, default=100)
    p_sample = replay_sub.add_parser(
        "sample-background", help="draw unlabelled background wallets (seeded) from an RPC"
    )
    p_sample.add_argument("--rpc-url", required=True)
    p_sample.add_argument("--seed", type=int, required=True)
    p_sample.add_argument("--count", type=int, default=10)
    p_sample.add_argument("--from-block", type=int, required=True)
    p_sample.add_argument("--to-block", type=int, required=True)
    p_sample.add_argument("--window-blocks", type=int, default=21_601)
    p_sample.add_argument("--max-nonce-delta", type=int, default=100)
    p_bg = replay_sub.add_parser(
        "record-background", help="record fixtures for background wallets that have none"
    )
    p_bg.add_argument("--rpc-url", required=True)
    p_bg.add_argument("--chunk-blocks", type=int, default=1_000)
    p_bg.add_argument("--limit", type=int, default=None, help="record at most this many")
    p_run = replay_sub.add_parser("run", help="replay recorded cases offline")
    p_run.add_argument("case_id", nargs="?", help="one case (default: all recorded cases)")
    p_run.add_argument("--json", action="store_true")
    p_run.add_argument("--write-report", metavar="PATH", help="write the markdown report here")
    p_run.add_argument(
        "--analytics",
        action="store_true",
        help="also evaluate the experimental analyses (needs the analytics extra)",
    )
    p_run.add_argument("--no-scaling", action="store_true", help="skip the synthetic benchmark")
    p_run.add_argument("--analytics-json", metavar="PATH", help="write raw evaluation JSON here")

    p_camp = sub.add_parser("campaigns", help="cross-wallet poisoning campaigns (experimental)")
    camp_sub = p_camp.add_subparsers(dest="campaign_command", required=True)
    p_rec = camp_sub.add_parser(
        "record-expansion",
        help="record a bounded expansion around the replay fixtures' attempts (resumable)",
    )
    p_rec.add_argument("--rpc-url", required=True, help="RPC with historical logs and state")
    p_rec.add_argument("--max-requests", type=int, default=2_500)
    p_rec.add_argument("--max-seconds", type=float, default=1_200)
    camp_sub.add_parser(
        "analyze", help="cluster stored poisoning attempts of monitored wallets (shadow mode)"
    )
    p_expand = camp_sub.add_parser(
        "expand", help="budgeted expansion around stored attempts via the configured RPC"
    )
    p_expand.add_argument("--max-requests", type=int, default=None)
    p_eval = camp_sub.add_parser("evaluate", help="evaluate campaign clustering offline")
    p_eval.add_argument("--write-report", metavar="PATH")
    p_eval.add_argument("--json", metavar="PATH", help="write raw evaluation JSON here")

    p_ack = sub.add_parser("ack", help="acknowledge a finding by id")
    p_ack.add_argument("finding_id")

    p_status = sub.add_parser("status", help="check configuration and provider connectivity")
    p_status.add_argument("--demo", action="store_true")

    sub.add_parser("demo-addresses", help="list fictional demo fixture addresses")

    p_serve = sub.add_parser("serve", help="run the HTTP API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--demo", action="store_true")

    p_purge = sub.add_parser("purge", help="delete locally stored observations")
    p_purge.add_argument("--address", help="only this address")
    p_purge.add_argument("--yes", action="store_true", help="confirm deletion")

    args = parser.parse_args(argv)

    try:
        if args.command == "demo-addresses":
            print("Fictional demo fixtures (not Ethereum state):")
            for account in DEMO_ACCOUNTS:
                print(f"  {account.address}  {account.label}: {account.description}")
            return 0

        settings = _load_settings(getattr(args, "demo", False))

        if args.command == "inspect":
            inspection = asyncio.run(_inspect(settings, args.address, store=not args.no_store))
            if args.json:
                print(inspection.model_dump_json(indent=2))
            else:
                print(_render(inspection))
            return 0

        if args.command == "approvals":
            report = asyncio.run(
                _approvals(
                    settings,
                    args.address,
                    lookback=args.lookback,
                    from_block=args.from_block,
                    tokens=args.tokens,
                    store=not args.no_store,
                )
            )
            print(report.model_dump_json(indent=2) if args.json else _render_approvals(report))
            return 0

        if args.command == "snapshot":
            outcome = asyncio.run(
                _snapshot(
                    settings,
                    args.address,
                    block=args.block,
                    tokens=args.tokens,
                    lookback=args.lookback,
                )
            )
            print(outcome.model_dump_json(indent=2) if args.json else _render_snapshot(outcome))
            return 0

        if args.command == "poisoning":
            poison_report = asyncio.run(
                _poisoning(settings, args.address, lookback=args.lookback, tokens=args.tokens)
            )
            print(
                poison_report.model_dump_json(indent=2)
                if args.json
                else _render_poisoning(poison_report)
            )
            return 0

        if args.command == "timeline":
            _print_timeline(settings, args.address, args.limit)
            return 0

        if args.command == "findings":
            _print_findings(settings, args.address, args.all)
            return 0

        if args.command == "graph":
            from cryptoguard.database.repository import open_repository
            from cryptoguard.services.graph import wallet_graph

            graph = wallet_graph(
                open_repository(settings.database_url),
                args.address,
                chain_id=settings.chain_id,
                data_source="demo_fixture" if settings.mode == "demo" else "rpc",
                options=DetectionOptions.from_settings(settings),
                max_nodes=args.max_nodes,
                include_inactive=args.include_inactive,
            )
            if args.json:
                print(graph.model_dump_json(indent=2))
                return 0
            print(
                f"Graph of {graph.wallet} at snapshot block {graph.snapshot_block}: "
                f"{len(graph.nodes)} nodes, {len(graph.edges)} edges"
                + (" [SIMULATED]" if graph.simulated else "")
            )
            for e in graph.edges:
                tag = "" if e.evidence_class == "observed_fact" else " (inferred)"
                print(f"  {e.type}{tag}: {e.source} -> {e.target}\n    {e.explanation}")
            for item in graph.limitations:
                print(f"  - {item}")
            return 0

        if args.command == "replay":
            return _replay_command(args, settings)
        if args.command == "campaigns":
            return _campaign_command(args, settings)

        if args.command == "ack":
            from cryptoguard.database.repository import open_repository
            from cryptoguard.risk.lifecycle import InvalidTransitionError

            try:
                finding = open_repository(settings.database_url).acknowledge_finding(
                    parse_hash32(args.finding_id)
                )
            except (InvalidTransitionError, ValueError) as exc:
                print(f"error [invalid_transition]: {exc}", file=sys.stderr)
                return 1
            if finding is None:
                print("error [finding_not_found]: no finding with this id", file=sys.stderr)
                return 1
            print(f"Acknowledged: {finding.title}")
            return 0

        if args.command == "status":
            print(json.dumps(asyncio.run(_status(settings)), indent=2))
            return 0

        if args.command == "serve":
            import uvicorn

            from cryptoguard.api.app import create_app

            uvicorn.run(create_app(settings), host=args.host, port=args.port, log_config=None)
            return 0

        if args.command == "purge":
            if not args.yes:
                print("Refusing to delete without --yes.", file=sys.stderr)
                return 2
            from cryptoguard.database.repository import open_repository

            address = to_checksum_address(args.address) if args.address else None
            deleted = open_repository(settings.database_url).purge(address)
            print(f"Deleted {deleted} stored observation(s).")
            return 0
    except CryptoGuardError as exc:
        print(f"error [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors())
        print(f"error [configuration_error]: invalid settings: {fields}", file=sys.stderr)
        return 1
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
