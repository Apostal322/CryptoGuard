"""Smoke-test an installed CryptoGuard wheel, outside the source tree.

    python scripts/smoke_install.py --venv /tmp/cg-venv            # core install
    python scripts/smoke_install.py --venv /tmp/cg-venv --analytics  # with the extra

Runs everything from an empty temporary directory with the venv's own interpreter, so the
repository can never be imported by accident. Standard library only. Checks the import
location, the CLI, the offline replay (headline leads), the demo-mode API (startup, health,
status, host and content-type checks) and the experimental-analysis state: "unavailable"
without numpy/scipy, computed with them (plus both offline evaluations).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# Same expectations as tests/unit/test_evaluation_regression.py (lead with wallet txs).
EXPECTED_LEADS = {
    "wbtc-1155-poisoning-2024-05-03": 367,
    "eth-140-poisoning-2025-08-14": 42,
    "usdt-50m-poisoning-2025-12-19": 113,
    "eth-4556-poisoning-2026-01-30": 13_057,
}
DEMO_WALLET = "0x5Ea834F1e27E7AB750Bdd34CaCD2E28213De4c98"
REPO = Path(__file__).resolve().parent.parent


def step(msg: str) -> None:
    print(f"==> {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"FAILED: {msg}", flush=True)
    sys.exit(1)


def run(cmd: list[str], cwd: Path, env: dict[str, str], timeout: float = 300) -> str:
    proc = subprocess.run(  # noqa: S603 (our own fixed commands)
        cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode != 0:
        print(proc.stdout[-4000:], proc.stderr[-4000:], sep="\n")
        fail(f"{' '.join(cmd[:4])} exited {proc.returncode}")
    return proc.stdout


def request(url: str, method: str = "GET", body: bytes | None = None, **headers: str) -> int:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        # Generous: a snapshot also runs the shadow analysis (up to 30 s) when it is enabled.
        with urllib.request.urlopen(req, timeout=90) as resp:  # noqa: S310 (local only)
            return int(resp.status)
    except urllib.error.HTTPError as err:
        return err.code


def listening(url: str) -> bool:
    try:
        return request(url) == 200
    except urllib.error.URLError as err:
        if isinstance(err.reason, ConnectionError):  # not accepting connections yet
            return False
        raise
    except ConnectionError:
        return False


def get_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (local only)
        return json.loads(resp.read())


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--analytics", action="store_true", help="the extra is installed")
    args = parser.parse_args()

    bindir = args.venv / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    cli = shutil.which("cryptoguard", path=str(bindir))
    if not python.exists() or cli is None:
        fail(f"no python or cryptoguard entry point in {bindir}")
    assert cli is not None

    work = Path(tempfile.mkdtemp(prefix="cg-smoke-"))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CRYPTOGUARD_", "PYTHON"))}
    env["CRYPTOGUARD_DATABASE_URL"] = f"sqlite:///{(work / 'smoke.db').as_posix()}"
    try:
        step("import location")
        where = run(
            [str(python), "-I", "-c", "import cryptoguard; print(cryptoguard.__file__)"], work, env
        ).strip()
        if Path(where).resolve().is_relative_to(REPO):
            fail(f"imported from the source tree: {where}")
        print(where)
        has_numpy = (
            run(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import importlib.util as u; print(bool(u.find_spec('numpy')))",
                ],
                work,
                env,
            ).strip()
            == "True"
        )
        if has_numpy != args.analytics:
            fail(f"numpy installed={has_numpy}, expected {args.analytics}")

        step("cli")
        run([cli, "--help"], work, env)
        run([cli, "replay", "list"], work, env)

        step("offline replay (headline leads)")
        cases = json.loads(run([cli, "replay", "run", "--json"], work, env))
        leads = {
            c["case_id"]: r["lead_time_blocks"]
            for c in cases
            for r in c["results"]
            if r["visibility"] == "erc20_plus_wallet_transactions"
        }
        if leads != EXPECTED_LEADS:
            fail(f"replay leads changed: {leads}")
        print(leads)

        if args.analytics:
            step("analytics evaluation (offline)")
            run(
                [
                    cli,
                    "replay",
                    "run",
                    "--analytics",
                    "--no-scaling",
                    "--write-report",
                    str(work / "EVALUATION.md"),
                ],
                work,
                env,
                timeout=900,
            )
            step("campaign evaluation (offline)")
            run(
                [
                    cli,
                    "campaigns",
                    "evaluate",
                    "--write-report",
                    str(work / "CAMPAIGN_EVALUATION.md"),
                ],
                work,
                env,
                timeout=900,
            )

        step("demo-mode API")
        port = free_port()
        base = f"http://127.0.0.1:{port}/api/v1"
        server_env = dict(env, CRYPTOGUARD_ANALYSIS_GRAPH="shadow", CRYPTOGUARD_LOG_LEVEL="WARNING")
        log = (work / "server.log").open("w")
        server = subprocess.Popen(  # noqa: S603
            [cli, "serve", "--demo", "--port", str(port)],
            cwd=work,
            env=server_env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            started = time.monotonic()
            while not listening(f"{base}/health"):
                if server.poll() is not None or time.monotonic() - started > 120:
                    log.close()
                    print((work / "server.log").read_text()[-4000:])
                    fail("API did not become healthy")
                time.sleep(0.5)
            print(f"healthy after {time.monotonic() - started:.1f} s")
            if request(f"{base}/status") != 200:
                fail("status endpoint")
            if request(f"{base}/health", Host="evil.example") != 400:
                fail("foreign Host header was not refused")
            code = request(
                f"{base}/campaigns/runs", "POST", b"{}", **{"Content-Type": "text/plain"}
            )
            if code != 415:
                fail(f"text/plain POST gave {code}, expected 415")
            snap_started = time.monotonic()
            snap = request(
                f"{base}/wallets/{DEMO_WALLET}/snapshots",
                "POST",
                b"{}",
                **{"Content-Type": "application/json"},
            )
            if snap != 200:
                fail(f"demo snapshot gave {snap}")
            print(f"demo snapshot in {time.monotonic() - snap_started:.1f} s")
            analysis = get_json(f"{base}/wallets/{DEMO_WALLET}/analysis")
            assert isinstance(analysis, dict)
            network = analysis["network"]["status"]
            expected = {"ok", "insufficient_data"} if args.analytics else {"unavailable"}
            if network not in expected:
                fail(f"analysis network status {network!r}, expected one of {expected}")
            print(f"analysis network section: {network}")
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
            log.close()
        step("OK")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
