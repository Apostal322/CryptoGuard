"""Phase 11.7: evidence completeness semantics, review-server hardening, an independent
reference for the candidate generator, exact FPR bounds, the experiment spec, research
verification and an end-to-end synthetic review workflow.

Synthetic data only. The synthetic reviewers below are software fixtures, not people.
"""

from __future__ import annotations

import http.client
import json
import random
import threading
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import candidates as cand
from cryptoguard.ml import evidence as ev
from cryptoguard.ml import experiment_spec as spec
from cryptoguard.ml import power
from cryptoguard.ml import review_sample as rs
from cryptoguard.ml import unblind as ub
from cryptoguard.ml.annotation import AnnotationError
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.ml.review_server import ReviewApp, serve
from cryptoguard.ml.submissions import agreement_report, check_submission
from tests.review_fixtures import ATTEMPT_FIELDS, INSUFFICIENT_FIELDS, fields, frozen
from tests.unit.test_ml_poisoning import FAKE, FRIEND, LOOKALIKE, USDT, WALLET, fixture, transfer
from tests.unit.test_ml_validation_readiness import ITEM, archive_db, arow, base_rows

STRANGER = "0x" + "3c" * 20

# --- evidence completeness semantics ------------------------------------------------------


def test_same_block_rows_of_unknown_order_are_counted_not_dropped(tmp_path: Path) -> None:
    rows = [*base_rows(), (7, 1_000, "0xother", USDT, WALLET, STRANGER, 0, 1.0, 1.0, 1, None, 4, 4)]
    (p,) = ev.build([ITEM], archive_dbs=[archive_db(tmp_path / "a.sqlite", rows)], fixtures=[])
    assert p["wallet_history"]["same_block_rows_order_unknown"] == 1
    assert "same_block_order_unknown" in p["coverage"]["statuses"]
    assert all(r["transaction"] != "0xother" for r in p["wallet_history"]["shown"])


def test_absence_is_read_differently_under_each_coverage(tmp_path: Path) -> None:
    """'No earlier interaction' must not read as 'unfamiliar' when history is partial."""
    complete = ev.packet(ITEM, rows=[], source="recorded_window", window=(0, 2_000))
    partial = ev.packet(ITEM, rows=[], source="archive", window=None)
    nothing = ev.packet(ITEM, rows=[], source=None, window=None)
    texts = {p["address_relationship"]["interpretation"] for p in (complete, partial, nothing)}
    assert len(texts) == 3
    assert "complete recorded window" in complete["address_relationship"]["interpretation"]
    assert "ordinary activity is missing" in partial["address_relationship"]["interpretation"]
    assert "unknown" in nothing["address_relationship"]["interpretation"]
    assert "partial_history" in partial["coverage"]["statuses"]
    assert "insufficient_evidence" in nothing["coverage"]["statuses"]


def test_duplicate_rows_across_sources_count_once(tmp_path: Path) -> None:
    a = archive_db(tmp_path / "a.sqlite", base_rows())
    b = archive_db(tmp_path / "b.sqlite", base_rows())
    (one,) = ev.build([ITEM], archive_dbs=[a], fixtures=[])
    (two,) = ev.build([ITEM], archive_dbs=[a, b], fixtures=[])
    assert one == two


def test_future_graph_edges_never_change_a_packet(tmp_path: Path) -> None:
    later = [arow(9, 1_200, "0xlate", LOOKALIKE, "0x" + "77" * 20, 0.0, flags=2)]
    (a,) = ev.build(
        [ITEM], archive_dbs=[archive_db(tmp_path / "a.sqlite", base_rows())], fixtures=[]
    )
    (b,) = ev.build(
        [ITEM], archive_dbs=[archive_db(tmp_path / "b.sqlite", [*base_rows(), *later])], fixtures=[]
    )
    assert a["graph_context"] == b["graph_context"]


# --- review server hardening -------------------------------------------------------------------


@pytest.fixture
def server(tmp_path: Path):
    from cryptoguard.ml import training

    app = ReviewApp(training.make_package("A", tmp_path / "t"))
    with app.store:
        httpd, _ = serve(app)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            yield app, httpd.server_address[1]
        finally:
            httpd.shutdown()
            httpd.server_close()


def raw(port: int, method: str, path: str, headers: dict[str, str], body: bytes = b"") -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders(body or None)
    status = conn.getresponse().status
    conn.close()
    return status


def test_foreign_origin_and_bad_lengths_are_refused(server) -> None:
    app, port = server
    base = {"Host": f"127.0.0.1:{port}", "X-Review-Token": app.token}
    assert raw(port, "GET", "/api/state", base) == 200
    assert raw(port, "GET", "/api/state", base | {"Origin": "https://evil.example"}) == 421
    assert raw(port, "GET", "/api/state", base | {"Origin": f"http://127.0.0.1:{port}"}) == 200
    post = base | {"Content-Type": "application/json"}
    assert raw(port, "POST", "/api/save", post | {"Content-Length": "-1"}) == 400
    assert raw(port, "POST", "/api/save", post | {"Content-Length": "abc"}) == 400


# --- candidate generator: an independent reference ---------------------------------------------


def _ref_affix(a: str, b: str) -> tuple[int, int]:
    """Matched leading and trailing hex characters, written from the rule's definition."""
    x, y = a.lower()[2:], b.lower()[2:]
    lead = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), min(len(x), len(y)))
    trail = next(
        (i for i in range(min(len(x), len(y))) if x[-1 - i] != y[-1 - i]), min(len(x), len(y))
    )
    return lead, trail


def _reference(fx: Any) -> list[tuple[str, frozenset[str]]]:
    """candidates/2 from its documented rules only (no code shared with the generator)."""
    w = fx.wallet.lower()
    ts = sorted(fx.transfers, key=lambda t: (t.block_number, t.transaction_index, t.log_index))
    chosen_pos: list[tuple[tuple[int, int, int], str]] = []
    for t in fx.transfers:
        if t.sender.lower() == w and t.tx_sender is not None and t.tx_sender.lower() == w:
            chosen_pos.append(
                ((t.block_number, t.transaction_index, t.log_index), t.recipient.lower())
            )
    for t in fx.wallet_transactions:
        if t.to and int(t.value):
            chosen_pos.append(((t.block_number, t.transaction_index, -1), t.to.lower()))
    out = []
    for t in ts:
        incoming, outgoing = t.recipient.lower() == w, t.sender.lower() == w
        if not (incoming or outgoing):
            continue
        pos = (t.block_number, t.transaction_index, t.log_index)
        party = (t.sender if incoming else t.recipient).lower()
        matched = False
        for p, k in chosen_pos:
            if p < pos and k != party:
                lead, trail = _ref_affix(party, k)
                matched |= lead + trail >= 6 and trail >= 3
        value, token = int(t.value), t.token.lower()
        signed = None if t.tx_sender is None else t.tx_sender.lower() == w
        m = set()
        if incoming and value == 0:
            m.add("zero_value_in")
        if outgoing and signed is False:
            m.add("spoofed_out")
        if incoming and matched:
            m.add("lookalike_in")
            if token not in TRUSTED_TOKENS:
                m.add("untrusted_token_in")
        if incoming and token in cand.STABLECOINS and 0 < value <= 10_000:
            m.add("dust_in")
        if m:
            out.append((t.transaction_hash, frozenset(m)))
    return out


def test_generator_matches_an_independent_reference() -> None:
    rng = random.Random(11)
    shared_suffix = ["0xd29" + rng.choice("0123456789abcdef") * 33 + "d7d5" for _ in range(6)]
    parties = [FRIEND, LOOKALIKE, STRANGER, *shared_suffix, FRIEND.upper().replace("0X", "0x")]
    for _ in range(40):
        ts = []
        for i in range(20):
            b = rng.randrange(100, 900)
            if rng.random() < 0.4:
                ts.append(
                    transfer(
                        b,
                        WALLET,
                        rng.choice(parties),
                        rng.choice([0, 7, 10**9]),
                        tx_sender=rng.choice([WALLET, None, STRANGER]),
                        idx=i,
                    )
                )
            else:
                ts.append(
                    transfer(
                        b,
                        rng.choice(parties),
                        WALLET,
                        rng.choice([0, 7, 10**9]),
                        token=rng.choice([USDT, FAKE]),
                        idx=i,
                    )
                )
        fx = fixture(ts, [])
        got = [(c.event.planting_tx, frozenset(c.methods)) for c in cand.generate(fx)]
        assert got == _reference(fx)


def test_malformed_counterparties_never_crash_or_match() -> None:
    fx = fixture(
        [
            transfer(500, WALLET, FRIEND, 1, tx_sender=WALLET, idx=1),
            transfer(900, "0xd296", WALLET, 5_000_000_000, idx=1),
        ],
        [],
    )
    assert "lookalike_in" not in {m for c in cand.generate(fx) for m in c.methods}


# --- exact FPR bounds and the experiment spec ---------------------------------------------------


def test_exact_bounds_match_closed_forms() -> None:
    for n in (30, 35, 50, 100, 300):
        assert power.clopper_pearson_upper(0, n) == pytest.approx(1 - 0.05 ** (1 / n), abs=1e-6)
        p = power.clopper_pearson_upper(1, n)  # P(X <= 1) = 0.05 at the bound
        assert (1 - p) ** n + n * p * (1 - p) ** (n - 1) == pytest.approx(0.05, abs=1e-6)
    rows = {(r["negatives"], r["design_effect"]): r for r in power.bound_table()}
    assert (
        rows[(100, 2.0)]["upper_0_flagged_cp_one_sided"]
        == rows[(50, 1.0)]["upper_0_flagged_cp_one_sided"]
    )  # clustering halves the information


def test_spec_has_a_source_proxy_free_ablation_and_exports() -> None:
    clean = spec.FEATURE_GROUPS["combined_without_source_proxies"]
    assert not set(clean) & set(spec.SOURCE_PROXIES)
    assert set(clean) < set(spec.FEATURE_GROUPS["combined"])
    exported = json.loads(spec.spec_json())
    assert exported["status"] == "inactive"
    assert "fairness" in exported
    assert "low_fpr_claim" in exported["label_count_stages"]


def test_research_verification_reports_missing_inputs_without_fetching(tmp_path: Path) -> None:
    from cryptoguard.ml.verify_research import verify

    report = verify(tmp_path / "data", tmp_path / "ml", hash_archive=False)
    statuses = {c["check"]: c["status"] for c in report["checks"]}
    assert statuses["source address_poisoning_ethereum.sql.gz"] == "MISSING"
    assert report["summary"]["FAIL"] == 0
    assert report["rpc_requests"] == 0


def test_a_corrupted_lease_database_is_not_reported_as_busy(tmp_path: Path) -> None:
    from sqlalchemy.exc import DatabaseError

    from cryptoguard.database.history import HistoryRepository
    from cryptoguard.database.leases import LeaseBusyError, LeaseStore
    from cryptoguard.database.repository import create_db_engine

    path = tmp_path / "bad.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    store = LeaseStore(HistoryRepository(create_db_engine(f"sqlite:///{path.as_posix()}")))
    with pytest.raises(DatabaseError) as err:
        store.acquire("k", 30)
    assert not isinstance(err.value, LeaseBusyError)


# --- end-to-end synthetic review workflow --------------------------------------------------------


def _http_save(
    app: ReviewApp, port: int, item: dict[str, Any], base: dict[str, Any], revision: int = 0
) -> int:
    body = json.dumps(
        {
            "fields": fields(item["item"], item["victim_event_id"], base),
            "expected_revision": revision,
        }
    ).encode()
    headers = {
        "Host": f"127.0.0.1:{port}",
        "X-Review-Token": app.token,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    return raw(port, "POST", "/api/save", headers, body)


def test_end_to_end_synthetic_workflow_with_failures(tmp_path: Path, monkeypatch) -> None:
    _, sample, manifest = frozen(tmp_path, monkeypatch)
    work = tmp_path / "work"
    pkg_a = ub.make_package(sample, work, "A", tmp_path / "pa")

    def session(pkg: Path):
        app = ReviewApp(pkg)
        app.store.__enter__()
        httpd, _ = serve(app)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return app, httpd

    def stop(app: ReviewApp, httpd: Any) -> None:
        httpd.shutdown()
        httpd.server_close()
        app.store.__exit__()

    items = rs.read_sheet(sample / rs.SHEET)
    app, httpd = session(pkg_a)
    port = httpd.server_address[1]
    assert _http_save(app, port, items[0], ATTEMPT_FIELDS) == 200
    old_token = app.token
    stop(app, httpd)  # the server restarts: a new session token, saved work kept

    (pkg_a / "annotations" / "annotations.log.jsonl.tmp").write_bytes(b"{half")  # torn save
    app, httpd = session(pkg_a)
    port = httpd.server_address[1]
    stale = {"Host": f"127.0.0.1:{port}", "X-Review-Token": old_token}
    assert raw(port, "GET", "/api/state", stale) == 403
    assert len(app.state()["decisions"]) == 1
    for it in items[1:]:
        assert _http_save(app, port, it, ATTEMPT_FIELDS) == 200
    app.finalize()
    stop(app, httpd)
    sub_a = pkg_a / "annotations" / "submission.json"

    assert check_submission(sub_a, sample, cohort=rs.SAMPLE_VERSION) == []
    with pytest.raises(KeyError):
        check_submission(sub_a, sample, cohort="no-such-cohort/1")
    with pytest.raises(ub.UnblindingRefused):
        ub.unblind(sample, work, [sub_a])  # premature: one reviewer

    pkg_b = ub.make_package(sample, work, "B", tmp_path / "pb")
    app, httpd = session(pkg_b)
    port = httpd.server_address[1]
    for i, it in enumerate(items):
        assert _http_save(app, port, it, INSUFFICIENT_FIELDS if i < 5 else ATTEMPT_FIELDS) == 200
    app.finalize()
    stop(app, httpd)
    sub_b = pkg_b / "annotations" / "submission.json"

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_bytes(sub_b.read_bytes()[:-40])
    assert check_submission(corrupt, sample, cohort=rs.SAMPLE_VERSION)
    with pytest.raises(AnnotationError):
        agreement_report([sub_a, corrupt], sample, cohort=rs.SAMPLE_VERSION)

    agree = agreement_report([sub_a, sub_b], sample, cohort=rs.SAMPLE_VERSION)
    assert agree["binary"]["disagreements"] == 5
    report = ub.unblind(sample, work, [sub_a, sub_b])
    assert report["items_reviewed_by_all"] == len(manifest["selected"])
    assert report["primary_all_reviewers_attempt"]["overall"]["positives"] == len(items) - 5
    log = (work / ub.ACCESS_LOG).read_text(encoding="utf-8").splitlines()
    assert len(log) == 1  # exactly one opening of the key, by the successful unblind
