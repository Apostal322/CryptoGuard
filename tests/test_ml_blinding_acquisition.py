"""Protocol 12.9: reviewer-blinding exposure levels, review-task leakage, declarations,
incident eligibility, pilot selection, collection preparation and the approval gate.
Synthetic only; every expectation follows from a definition in the protocol."""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from cryptoguard.ml import benchmark_contract as bc
from cryptoguard.ml import benchmark_eval as be
from cryptoguard.ml import incident_acquisition as ia
from cryptoguard.ml import reliability_study as rs
from cryptoguard.ml import review_blinding as rb

ROOT = Path(__file__).resolve().parents[1]
A1, A2, A3, A4 = ("0x" + c * 40 for c in "1234")
T1, T2 = ("0x" + c * 64 for c in "ab")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(cwd), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.invalid")
    git(tmp_path, "config", "user.name", "t")
    git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def commit(root: Path, files: dict[str, str], message: str, date: str) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(root), "commit", "-q", "-m", message],  # noqa: S607
        check=True,
        env={
            **__import__("os").environ,
            "GIT_AUTHOR_DATE": f"{date}T12:00:00",
            "GIT_COMMITTER_DATE": f"{date}T12:00:00",
        },
    )


# --- Part I: exposure levels ----------------------------------------------------------------


def test_artifact_roles() -> None:
    k = rb.artifact_kind
    assert k("src/cryptoguard/replay/cases/x/manifest.json") == "incident_manifest"
    assert k("docs/ml/incident-benchmark/cases/x/manifest.json") == "incident_manifest"
    assert k("docs/ml/incident-benchmark/stage2-candidates.json") == "incident_registry"
    assert k("src/cryptoguard/replay/cases/x/fixture.json") == "incident_fixture"
    assert k("src/cryptoguard/replay/campaign_cases/expansion.json") == "campaign_expansion"
    assert k("src/cryptoguard/replay/background_cases/bg/fixture.json") == "neutral"
    assert k("tests/test_x.py") == "neutral"
    manifest = {
        "victim": A1,
        "intended_recipient": A2,
        "harm": {"recipient": A3, "transaction_hash": T1},
    }
    assert rb.json_roles("incident_manifest", manifest) == {
        A1: "context", A2: "context", A3: "outcome", T1: "outcome"
    }  # fmt: skip
    registry = {"candidates": [{"identifiers": {"victim": A1, "lookalike": A3, "harm_tx": T1,
                                                "etherscan_filter_fadd": A4}}]}  # fmt: skip
    assert rb.json_roles("incident_registry", registry) == {
        A1: "context", A3: "outcome", T1: "outcome", A4: "outcome"
    }  # fmt: skip
    assert rb.line_role("incident_registry", f'  "harm_tx": "{T1}",') == "outcome"
    assert rb.line_role("incident_manifest", f'  "recipient": "{A3}",') == "outcome"
    assert rb.line_role("incident_manifest", f'  "victim": "{A1}",') == "context"
    assert rb.line_role("neutral", f'  "harm_tx": "{T1}",') == "neutral"


def item(**kw: object) -> rb.Item:
    base: dict[str, object] = dict(
        cohort="hard-negative-candidates/1", item=1, provenance="recorded_window",
        core=frozenset({A1, A2, T1}), context=frozenset({A4}), sheet_sha256="s" * 64,
    )  # fmt: skip
    return rb.Item(**(base | kw))  # type: ignore[arg-type]


def occ(path: str, role: str, channel: str = "head") -> rb.Occurrence:
    return rb.Occurrence(path, rb.artifact_kind(path), role, channel, "2026-10-28")


@pytest.mark.parametrize(
    ("role", "level"), [("outcome", "R3"), ("context", "R2"), ("neutral", "R1")]
)
def test_levels_follow_the_strongest_role(role: str, level: str) -> None:
    a = rb.assess(item(), {A1: [occ("f.json", role)]}, {}, {})
    assert (a.repo_level, a.external_level, a.combined) == (level, "R0", level)
    assert a.disposition == rb.DISPOSITION[level]


def test_partial_only_is_unknown_and_nothing_is_r0() -> None:
    assert rb.assess(item(), {}, {}, {A2: ["notes.md"]}).repo_level == "RU"
    assert rb.assess(item(), {}, {}, {}).repo_level == "R0"


def test_external_provenance_and_context_counterparties() -> None:
    a = rb.assess(item(provenance="archive_payoff_linked"), {}, {}, {})
    assert (a.repo_level, a.external_level, a.combined) == ("R0", "R3", "R3")
    b = rb.assess(item(provenance="archive_uncategorized"), {}, {}, {})
    assert b.combined == "R2"
    # a context counterparty in an outcome role exposes the item; the core-only view does not
    c = rb.assess(item(), {A4: [occ("src/cryptoguard/replay/cases/x/manifest.json", "outcome")]},
                  {}, {})  # fmt: skip
    assert (c.repo_level, c.repo_level_core_only) == ("R3", "R0")


def test_r4_is_never_inferred_from_r3() -> None:
    every = [
        rb.assess(item(provenance=p), {A1: [occ("f.json", r)]}, {}, {})
        for p in rb.EXTERNAL_LEVEL
        for r in ("outcome", "context", "neutral")
    ]
    assert all(a.combined != "R4" for a in every)


def test_history_channel_dates_and_roles(tmp_path: Path) -> None:
    root = repo(tmp_path)
    reg = "docs/ml/incident-benchmark/candidates.json"
    body = json.dumps({"candidates": [{"identifiers": {"lookalike": A3}}]}, indent=1)
    commit(root, {reg: body, "notes.md": f"see {A2[:12]}... later"}, "add", "2026-10-24")
    commit(root, {reg: "{}"}, "drop", "2026-11-05")
    idents = frozenset({A3, A2})
    hist = rb.scan_history(root, idents)
    o = hist[A3][reg]
    assert (o.role, o.first_date, o.channel) == ("outcome", "2026-10-24", "history")
    assert rb.scan_head(root, idents) == {}  # gone at HEAD, still public through history
    a = rb.assess(item(core=frozenset({A3})), {}, hist, {})
    assert a.repo_level == "R3"
    assert a.occurrences[0]["channel"] == "history"
    assert rb.scan_partial(root, idents) == {A2: ["notes.md"]}


# --- Part I: review tasks and declarations ---------------------------------------------------

ROW = {
    "schema_version": "review-sheet/2", "item": 7, "chain_id": 1, "wallet": A1,
    "address_under_review": A2, "transaction": T1, "block": 100,
    "context": [{"block": "99", "counterparty": A4, "direction": "in", "value": "1",
                 "label": "x"}],
    "coverage_note": "No wallet history is included: use a block explorer, up to the block above.",
    "description": "Candidate for independent security review",
    "subtype": "fake_token", "source_label": "payoff",
}  # fmt: skip


def test_payload_is_whitelisted_and_clean() -> None:
    p = rb.task_payload(ROW)
    assert set(p) == {"item", "chain_id", "wallet", "address_under_review", "transaction",
                      "block", "context", "coverage_note"}  # fmt: skip
    assert set(p["context"][0]) == {"block", "counterparty", "direction", "value"}
    leaks = (
        {"subtype": "x"},
        {"model_score": 0.9},
        {"nested": {"verdict": "x"}},
        {"note": "confirmed poisoning victim"},
        {"items": ["looks like a scam"]},
    )
    for leak in leaks:
        with pytest.raises(rb.PayloadLeakError) as e:
            rb.assert_payload_clean(leak)
        assert "poison" not in str(e.value)
        assert "scam" not in str(e.value)


def test_task_ids_are_opaque_and_r4_is_not_a_task_level() -> None:
    t = rb.build_task(ROW, sheet_sha256="a" * 64, evidence_version="evidence-packets/2",
                      evidence_sha256="e" * 64, exposure_level="R2")  # fmt: skip
    assert t.task_id == rb.task_id("a" * 64, 7)
    assert len(t.task_id) == 20
    assert "hard" not in t.task_id
    assert t.task_id != rb.task_id("a" * 64, 8)
    with pytest.raises(ValueError, match="R4"):
        rb.build_task(ROW, sheet_sha256="a" * 64, evidence_version="v", evidence_sha256="e",
                      exposure_level="R4")  # fmt: skip


def declaration(task: str = "t1", rid: str = "rev-a", **kw: str) -> rb.ReviewerDeclaration:
    base = dict(reviewer_id=rid, task_id=task, prior_familiarity="no",
                external_sources_consulted="no", repository_consulted="no",
                model_output_seen="no", declared_at="2026-11-12")  # fmt: skip
    return rb.ReviewerDeclaration(**(base | kw))


def test_declarations_are_never_defaulted() -> None:
    assert rb.review_exposure("R3", None)["level"] == "RU"
    assert rb.review_exposure("R3", declaration())["level"] == "R3"
    assert rb.review_exposure("R3", declaration(external_sources_consulted="yes"))["level"] == "R4"
    assert rb.review_exposure("R3", declaration(prior_familiarity="yes"))["level"] == "R4"
    assert rb.review_exposure("R2", declaration(repository_consulted="yes"))["level"] == "R2"
    assert rb.review_exposure("R1", declaration(prior_familiarity="unknown"))["level"] == "RU"
    seen = rb.review_exposure("R1", declaration(model_output_seen="yes"))
    assert (seen["level"], seen["model_output_seen"]) == ("R1", "yes")  # reported apart
    with pytest.raises(ValidationError):
        declaration(prior_familiarity="maybe")
    with pytest.raises(ValidationError):
        declaration(rid="name with spaces")


def test_adjudication_needs_two_declared_reviews_on_the_same_evidence() -> None:
    t = rb.build_task(ROW, sheet_sha256="a" * 64, evidence_version="v", evidence_sha256="e" * 64,
                      exposure_level="R1")  # fmt: skip
    a = rb.SubmittedReview("rev-a", "insufficient_evidence", "e" * 64, declaration(t.task_id))
    b = rb.SubmittedReview("rev-b", "insufficient_evidence", "e" * 64,
                           declaration(t.task_id, "rev-b"))  # fmt: skip
    assert rb.adjudication_readiness(t, [a])["ready"] is False
    ok = rb.adjudication_readiness(t, [a, b])
    assert ok["ready"]
    assert ok["confirmatory"]
    assert not rb.adjudication_readiness(t, [a, rb.SubmittedReview("rev-b", "x", "e" * 64, None)])[
        "ready"
    ]
    elsewhere = rb.SubmittedReview("rev-b", "x", "f" * 64, b.declaration)
    assert not rb.adjudication_readiness(t, [a, elsewhere])["ready"]
    other = rb.SubmittedReview("rev-b", "x", "e" * 64, declaration("another", "rev-b"))
    assert not rb.adjudication_readiness(t, [a, other])["ready"]
    t3 = t.model_copy(update={"exposure_level": "R3"})
    assert rb.adjudication_readiness(t3, [a, b])["confirmatory"] is False


def test_guidance_screen() -> None:
    doc = (ROOT / "docs/ml/reviewer-blinding-protocol.md").read_text(encoding="utf-8")
    section = doc.split("<!-- reviewer-guidance:start -->")[1].split(
        "<!-- reviewer-guidance:end -->"
    )[0]
    assert rb.guidance_findings(section) == {}
    for field in ("prior_familiarity", "external_sources_consulted", "repository_consulted",
                  "model_output_seen"):  # fmt: skip
        assert field in section
    assert rb.guidance_findings("Most of these were confirmed victims (payoff).")


@pytest.mark.skipif(
    not (ROOT / "data/ml/poisoning/review_sample/reviewer_sheet.jsonl").is_file(),
    reason="frozen cohorts are local research data",
)
def test_frozen_cohorts_are_unchanged() -> None:
    before = rb.verify_cohorts(ROOT / "data/ml/poisoning")
    rb.load_items(ROOT / "data/ml/poisoning")
    assert rb.verify_cohorts(ROOT / "data/ml/poisoning") == before


# --- Part II: leads and eligibility ----------------------------------------------------------


def lead(lead_id: str = "L1", **kw: object) -> ia.Lead:
    ids = {
        "victim": ia.Identifier(status="verbatim", value=A1),
        "harm_tx": ia.Identifier(status="verbatim", value=T1),
        "lookalike": ia.Identifier(status="truncated", value="0x3333…3333"),
    }
    base: dict[str, object] = dict(
        lead_id=lead_id, origin="new:test", chain_stated="ethereum", identifiers=ids,
        sources=(ia.LeadSource(publisher="p", url="https://example.invalid", date="2026",
                               read=True),),
    )  # fmt: skip
    return ia.Lead(**(base | kw))  # type: ignore[arg-type]


def test_identifiers_are_verbatim_or_marked_truncated() -> None:
    with pytest.raises(ValidationError):
        ia.Identifier(status="verbatim", value="0x1234...abcd")  # never completed
    with pytest.raises(ValidationError):
        ia.Identifier(status="truncated", value=A1)  # a full value is not truncated
    with pytest.raises(ValidationError):
        ia.Identifier(status="truncated", value="0x1234abcd")  # no ellipsis kept
    with pytest.raises(ValidationError):
        ia.Identifier(status="absent", value=A1)
    assert ia.Identifier(status="truncated", value="0x5a5a5a5a…").status == "truncated"


def ids(**over: ia.Identifier) -> dict[str, ia.Identifier]:
    return dict(lead().identifiers) | over


@pytest.mark.parametrize(
    ("kw", "dev", "status"),
    [
        ({}, {"victim": ["archive_databases"]}, "DEVELOPMENT_ONLY"),
        ({"chain_stated": "other", "chain_name": "Base"}, {}, "REJECTED"),
        ({"identifiers": {"victim": ia.Identifier(status="absent")}}, {}, "REJECTED"),
        ({"conflicts": ("date differs",)}, {}, "NEEDS_IDENTIFIER_VERIFICATION"),
        ({"identifiers": ids(victim=ia.Identifier(status="truncated", value="0x5b5b...5b5b"))},
         {}, "NEEDS_IDENTIFIER_VERIFICATION"),
        ({"identifiers": ids(harm_tx=ia.Identifier(status="absent"))}, {},
         "NEEDS_IDENTIFIER_VERIFICATION"),
        ({"chain_stated": "unstated"}, {}, "NEEDS_IDENTIFIER_VERIFICATION"),
        ({"campaign_notes": ("same crew as a development case",)}, {}, "NEEDS_CAMPAIGN_REVIEW"),
        ({"mechanism_claimed": "erc1155"}, {}, "UNSUPPORTED_MECHANISM"),
        ({"harm_claimed": False}, {}, "NOT_EVALUABLE"),
        ({}, {}, ia.READY),
    ],
)  # fmt: skip
def test_eligibility_rule_order(kw: dict, dev: dict, status: str) -> None:
    got, reasons = ia.classify(lead(**kw), dev)
    assert got == status
    assert not any(re.search(r"0x[0-9a-f]{8}", r) for r in reasons)  # no identifier in reasons


def test_shared_attacker_identifiers_need_a_cluster() -> None:
    a = lead("La", identifiers=ids(lookalike=ia.Identifier(status="verbatim", value=A3)))
    b = lead("Lb", identifiers=ids(victim=ia.Identifier(status="verbatim", value=A4),
                                   harm_tx=ia.Identifier(status="verbatim", value=T2),
                                   lookalike=ia.Identifier(status="verbatim",
                                                           value=A3)))  # fmt: skip
    assert ia.shared_attacker_identifiers([a, b]) == {"La": ["Lb"], "Lb": ["La"]}
    assert ia.classify(a, {}, shared=["Lb"])[0] == "NEEDS_CAMPAIGN_REVIEW"
    assert ia.classify(a, {}, shared=["Lb"], same_cluster=["Lb"])[0] == ia.READY
    out = ia.classify_all([a, b], {})
    assert out["La"]["cluster"] == out["Lb"]["cluster"] == "La"
    assert ia.select_pilot(out) == [min(["La", "Lb"], key=ia.pilot_rank)]  # one per cluster


def test_pilot_selection_ignores_size_and_is_capped() -> None:
    leads = [
        lead(f"L{i:02d}", amount=f"{i} USDT",
             identifiers=ids(victim=ia.Identifier(status="verbatim", value="0x" + f"{i:040x}"),
                             harm_tx=ia.Identifier(status="verbatim", value="0x" + f"{i:064x}")))
        for i in range(1, 15)
    ]  # fmt: skip
    chosen = ia.select_pilot(ia.classify_all(leads, {}))
    assert len(chosen) == ia.PILOT_CAP
    assert chosen == sorted((x.lead_id for x in leads), key=ia.pilot_rank)[:10]
    bigger = [x.model_copy(update={"amount": "1,000,000 USDT"}) for x in leads]
    assert ia.select_pilot(ia.classify_all(bigger, {})) == chosen


def test_hint_clusters_join_narrative_duplicates() -> None:
    a = lead("La", cluster_hint="h")
    other = ids(
        victim=ia.Identifier(status="verbatim", value=A4),
        harm_tx=ia.Identifier(status="verbatim", value=T2),
    )
    b = lead("Lb", cluster_hint="h", identifiers=other)
    assert ia.clusters([a, b]) == {"La": "La", "Lb": "La"}


def test_development_overlap_search(tmp_path: Path) -> None:
    root, poison = tmp_path, tmp_path / "data/ml/poisoning"
    fx = root / "src/cryptoguard/replay/cases/c1/fixture.json"
    fx.parent.mkdir(parents=True)
    fx.write_text(json.dumps({"wallet": A1.upper().replace("0X", "0x")}), encoding="utf-8")
    poison.mkdir(parents=True)
    con = sqlite3.connect(poison / "archive_subset.sqlite")
    con.execute("CREATE TABLE transfers (tx TEXT, sender TEXT, receiver TEXT, value REAL)")
    con.execute("INSERT INTO transfers VALUES (?, ?, ?, 1.0)", (T1, A2, A3))
    con.commit()
    con.close()
    (poison / "unblinding_key.jsonl").write_text(json.dumps({"x": A4}), encoding="utf-8")
    probe = lead(identifiers={
        "victim": ia.Identifier(status="verbatim", value=A1),
        "harm_tx": ia.Identifier(status="verbatim", value=T1),
        "intended": ia.Identifier(status="verbatim", value=A4),
    })  # fmt: skip
    hits, searched = ia.development_hits([probe], root, poison)
    assert hits["L1"] == {
        "victim": ["recorded_fixtures_and_manifests"],
        "harm_tx": ["archive_databases"],
    }  # the unblinding key is never read
    assert searched["archive_databases"] == 1
    assert ia.classify(probe, hits["L1"])[0] == "DEVELOPMENT_ONLY"


# --- Part II: collection preparation and approval -------------------------------------------


def test_jobs_carry_only_collector_fields() -> None:
    jobs = ia.collection_jobs([lead()])
    anchor, record = jobs
    assert isinstance(anchor, ia.AnchorJob)
    assert isinstance(record, ia.RecordJob)
    assert anchor.max_requests == 5
    assert record.max_requests == 2_500
    req = ia.record_request(record, 24_000_000)
    assert req.model_dump() == {
        "chain_id": 1, "wallet": A1, "from_block": 24_000_000 - 21_600, "to_block": 24_000_000,
        "observation": 2, "max_requests": 2_500,
    }  # fmt: skip
    with pytest.raises(ValidationError):
        bc.CollectorRequest(**req.model_dump(), harm_tx=T1)  # type: ignore[call-arg]
    assert "harm" not in json.dumps(record.model_dump())


def test_budget() -> None:
    b = ia.budget(10)
    assert (b["per_window_cap"], b["total_cap"], b["jobs"]) == (2_505, 25_050, 20)
    assert b["estimates"]["high"]["requests"] == 10 * (1 + 1_433)
    assert b["estimates"]["high"]["with_retry_reserve"] == round(10 * 1_434 * 1.2)
    assert ia.budget(0)["total_cap"] == 0


def approval(m: dict, **kw: object) -> ia.ApprovalRecord:
    sha = ia.manifest_sha256(m)
    base: dict[str, object] = dict(
        manifest_sha256=sha, per_window_cap=m["per_window_cap"], total_cap=m["total_cap"],
        approver_statement=f"I approve manifest {sha[:12]} with a total cap of "
        f"{m['total_cap']:,} requests.",
        approved_at="2026-11-12",
    )  # fmt: skip
    return ia.ApprovalRecord(**(base | kw))  # type: ignore[arg-type]


def test_approval_is_specific_and_never_inferred() -> None:
    m = ia.manifest([lead()], git="abc")
    ia.check_approval(approval(m), m)  # exact approval passes
    with pytest.raises(ia.ApprovalError, match="planning only"):
        ia.check_approval(None, m)
    for bad in (
        approval(m, approver_statement="continue"),
        approval(m, approver_statement="Go ahead with the recording."),
        approval(m, manifest_sha256="0" * 64),
        approval(m, per_window_cap=5_000),
        approval(m, total_cap=6_000),
        approval(m, approver_statement=f"approve {ia.manifest_sha256(m)[:12]} up to 2,000"),
    ):
        with pytest.raises(ia.ApprovalError):
            ia.check_approval(bad, m)
    # an approval for one manifest is not reusable for another
    second = lead("L2", identifiers=ids(victim=ia.Identifier(status="verbatim", value=A4)))
    m2 = ia.manifest([lead(), second], git="abc")
    with pytest.raises(ia.ApprovalError):
        ia.check_approval(approval(m), m2)
    empty = ia.manifest([], git="abc")
    with pytest.raises(ia.ApprovalError, match="nothing to approve"):
        ia.check_approval(approval(empty), empty)


def test_stop_rules() -> None:
    base = dict(selected=10, provider_failures=0, recorded=10, mechanism_eligible=8,
                discordant_top5=3, cluster_sizes={f"c{i}": 1 for i in range(10)},
                leakage_failures=[], missing_categories=[])  # fmt: skip
    assert not any(r["triggered"] for r in ia.pilot_stop_rules(base))

    def fired(**kw: object) -> list[str]:
        return [r["rule"] for r in ia.pilot_stop_rules(base | kw) if r["triggered"]]

    assert fired(provider_failures=4) == ["S1"]
    assert fired(mechanism_eligible=4) == ["S2"]
    assert (
        fired(recorded=6, mechanism_eligible=3, cluster_sizes={f"c{i}": 1 for i in range(6)}) == []
    )
    assert fired(discordant_top5=1) == ["S3"]
    assert fired(cluster_sizes={"c0": 6, "c1": 4}) == ["S4"]
    assert fired(leakage_failures=["x"]) == ["S5"]
    assert fired(missing_categories=["native_dust"]) == ["S6"]


def test_no_network_code() -> None:
    for mod in (ia, rb):
        src = Path(mod.__file__).read_text(encoding="utf-8")  # type: ignore[arg-type]
        imports = "\n".join(
            line for line in src.splitlines() if re.match(r"\s*(from|import) ", line)
        )
        for banned in ("requests", "httpx", "urllib", "socket", "aiohttp", "web3", "replay.record",
                       "ml.fetch", "ml.collect", "rpc"):  # fmt: skip
            assert banned not in imports, (mod.__name__, banned)


def test_commitments_are_salted_and_registry_is_identifier_free(tmp_path: Path) -> None:
    x = lead()
    salts = ia.load_salts(tmp_path / "s.json", [x])
    assert ia.load_salts(tmp_path / "s.json", [x]) == salts  # created once
    c = ia.commitments(x, salts["L1"])
    assert c == ia.commitments(x, salts["L1"]) != ia.commitments(x, "other-salt")
    assert set(c) == {"victim", "harm_tx"}  # verbatim identifiers only
    reg = ia.public_registry([x], ia.classify_all([x], {}), salts, {})
    text = json.dumps(reg)
    assert A1 not in text
    assert T1 not in text
    assert "0x3333" not in text
    for leak in (f"x {A1}", "0x5a5a5a5a…", "0x5b5b...5b5b"):
        with pytest.raises(ia.AcquisitionError):
            ia.assert_no_identifiers(leak)


def test_public_phase_12_9_files_carry_no_identifiers() -> None:
    for rel in ("docs/ml/incident-benchmark/acquisition-12.9.json",
                "docs/ml/reviewer-blinding-protocol.md", "docs/ml/protocol-12.9.md",
                "ML_INDEPENDENT_INCIDENT_ACQUISITION.md"):  # fmt: skip
        ia.assert_no_identifiers((ROOT / rel).read_text(encoding="utf-8"))
    out = git(ROOT, "check-ignore", "data/ml/research/phase12.9/leads.local.json")
    assert out.strip()


# --- T5g reference-group exposure ------------------------------------------------------------


def test_reference_group_exposure() -> None:
    fx = rs.wallet_fixture(
        transfers=[], native=[(rs.lookalike(1), 1, 2_000, True)],
        wallet_txs=[(rs.lookalike(1), 10**18, 5_000)],
    )  # fmt: skip
    c = bc.BenchmarkCase(
        case_id="g", chain_id=1, victim=fx.wallet, from_block=fx.from_block, to_block=fx.to_block,
        cutoff=(5_000, 0), cutoff_rule="x", observation_schema="observation/2",
        source=bc.CaseSource(publisher="s", url="synthetic://"), cluster_id="g",
        population="synthetic",
    )  # fmt: skip
    p = be.predict(c, fx)
    assert set(p.buckets) == set(p.candidates)
    o = bc.Outcome(case_id="g", verified=True, paid_address=rs.lookalike(1),
                   intended_recipient=p.buckets[rs.lookalike(1)])  # fmt: skip
    g = be.reference_group_exposure(p, o)
    assert g is not None
    assert g["B0"]["1"] is True
    assert be.reference_group_exposure(p, o.model_copy(update={"intended_recipient": A4})) == {
        m: {str(k): False for k in be.K_GRID} for m in be.ORDERS
    }
    assert be.reference_group_exposure(p, o.model_copy(update={"intended_recipient": None})) is None


# --- protocol 12.9 D3 additions -------------------------------------------------------------


def test_identity_cases() -> None:
    truncated_tx = ids(harm_tx=ia.Identifier(status="truncated", value="0x5c5c5c5c...5c5c"))
    assert ia.classify(lead(identifiers=truncated_tx), {})[0] == "NEEDS_IDENTIFIER_VERIFICATION"
    # an identifier whose role the page does not state never stands in for the victim
    unassigned = {
        "unassigned_address": ia.Identifier(status="verbatim", value=A1),
        "harm_tx": ia.Identifier(status="verbatim", value=T1),
    }
    status, reasons = ia.classify(lead(identifiers=unassigned), {})
    assert (status, reasons) == ("NEEDS_IDENTIFIER_VERIFICATION", ["victim absent"])
    # a missing intended recipient does not block recording (T5g is then not assessable)
    no_intended = lead()
    assert "intended" not in no_intended.identifiers
    assert ia.classify(no_intended, {})[0] == ia.READY


def test_duplicate_reports_share_a_cluster() -> None:
    a = lead("La")
    same_tx = lead("Lb", identifiers=ids(victim=ia.Identifier(status="verbatim", value=A4)))
    same_victim = lead("Lc", identifiers=ids(harm_tx=ia.Identifier(status="verbatim", value=T2)))
    cl = ia.clusters([a, same_tx, same_victim])
    assert set(cl.values()) == {"La"}
    assert len(ia.select_pilot(ia.classify_all([a, same_tx, same_victim], {}))) == 1


def test_no_runner_no_retries_and_no_mapping_in_public_output() -> None:
    names = {n for n in dir(ia) if callable(getattr(ia, n))}
    assert not {n for n in names if re.search(r"(?i)^(run|execute|launch|submit|record_all)", n)}
    job_fields = set(ia.AnchorJob.model_fields) | set(ia.RecordJob.model_fields)
    assert not {f for f in job_fields if "retry" in f or "retries" in f}
    a = rb.assess(item(), {A1: [occ("src/cryptoguard/replay/cases/x/manifest.json", "outcome")]},
                  {}, {})  # fmt: skip
    public = json.dumps(rb.summarize([a]))
    assert "manifest.json" not in public
    assert '"item"' not in public
    assert A1 not in public
    for rel in ("data/ml/research/phase12.9/blinding/item_exposure.local.jsonl",
                "data/ml/research/phase12.9/commitment-salts.local.json"):  # fmt: skip
        assert git(ROOT, "check-ignore", rel).strip()


def test_group_exposure_is_reported_apart_from_address_exposure() -> None:
    r = {
        "eligible": True, "mechanism_eligible": True, "T1_assessable": True, "T1_observed": True,
        "T2_generated": True, "cluster_id": "c", "failure": "ranked_below_k",
        "T3_rank": {m: 7 for m in be.ORDERS},
        "T4_exposed": {m: {str(k): k >= 7 for k in be.K_GRID} for m in be.ORDERS},
        "T5g_reference_group_exposed": {m: {str(k): True for k in be.K_GRID} for m in be.ORDERS},
        "T5_mechanism_identified": None, "fidelity": {"records": 1, "resolved_pre_cutoff": 1},
        "burden": {"candidates": 9, "wallet_days": 3.0, "evidence_records": 9, "summary_bytes": 1},
        "candidates": 9,
    }  # fmt: skip
    agg = be.aggregate([r, r | {"T5g_reference_group_exposed": None}])
    assert agg["end_to_end_topk"]["B0"][1]["value"] == 0.0
    assert agg["reference_group_exposure"]["B0"][1] == {"value": 1.0, "numerator": 1,
                                                         "denominator": 1}  # fmt: skip
    assert agg["reference_group_not_assessable"] == 1
