"""Command-line interface.

cryptoguard inspect <address> [--demo] [--json] [--no-store]
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
from cryptoguard.core.logging import configure_logging
from cryptoguard.services.demo import DEMO_ACCOUNTS
from cryptoguard.services.inspection import AddressInspection, inspect_address
from cryptoguard.services.providers import build_provider, require_provider


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
