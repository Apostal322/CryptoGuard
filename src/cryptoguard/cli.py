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

from pydantic import ValidationError

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
