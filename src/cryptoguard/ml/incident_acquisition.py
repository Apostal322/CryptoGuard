"""Phase 12.9 independent incident acquisition (protocol 12.9, Part II). Offline only.

A *lead* is a publicly described incident with whatever identifiers its sources give. This
module checks those identifiers, finds overlaps with every development artifact, groups
related leads, assigns one eligibility status per lead (first matching rule wins), selects a
pilot, and prepares - but never runs - the collection jobs and their budget.

Two safety properties hold by construction:

* **No network.** Nothing here imports an HTTP, RPC or socket client. Collection jobs are
  data; a recorder that could run them is not called, and no batch runner exists.
* **No identifier is published.** Lead identifiers live in a git-ignored local vault. The
  public registry carries source citations, statuses and *salted* SHA-256 commitments, so it
  neither repeats the identifiers nor lets anyone test a guessed address against it.

Approval is a separate record (``ApprovalRecord``) bound to the manifest's hash and caps;
``check_approval`` refuses anything else, including general encouragement.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from cryptoguard.ml import benchmark_contract as bc

STUDY_VERSION = "incident-acquisition/1"
LEADS_VERSION = "incident-leads-local/1"
REGISTRY_VERSION = "incident-acquisition-registry/1"
MANIFEST_VERSION = "collection-manifest/1"
VAULT = Path("data/ml/research/phase12.9/leads.local.json")
SALTS = Path("data/ml/research/phase12.9/commitment-salts.local.json")
PUBLIC_REGISTRY = Path("docs/ml/incident-benchmark/acquisition-12.9.json")

PILOT_SEED = "cg-12.9-pilot|"
PILOT_CAP = 10
ANCHOR_CAP = 5
RECORD_CAP = 2_500
WINDOW_BLOCKS = 21_600
# Measured on the recorded 21,600-block windows (Stage 1 and Stage 2a ledgers).
ESTIMATES = {"low": 475, "typical": 1_299, "high": 1_433}
ANCHOR_ESTIMATE = 1
RETRY_RESERVE = 0.20
ARCHIVE_LAST_DATE = "2024-06-30"

READY = "READY_FOR_BLIND_RECORDING"
STATUSES = (
    "DEVELOPMENT_ONLY",
    "REJECTED",
    "NEEDS_IDENTIFIER_VERIFICATION",
    "NEEDS_CAMPAIGN_REVIEW",
    "UNSUPPORTED_MECHANISM",
    "NOT_EVALUABLE",
    READY,
)
UNSUPPORTED = frozenset({"internal_transfer", "erc1155", "zero_value_native"})
REQUIRED_FOR_READY = ("victim", "harm_tx")

_FULL = re.compile(r"^0x(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_TRUNC = re.compile(r"(…|\.\.\.)")
_HEX_IN_TEXT = re.compile(r"0x[0-9a-fA-F]{8,}")
GENERIC_APPROVALS = frozenset(
    {"continue", "ok", "okay", "yes", "go", "go ahead", "proceed", "approved", "do it", "sure"}
)


class AcquisitionError(ValueError):
    """The lead vault or a lead is malformed."""


class ApprovalError(PermissionError):
    """No valid approval for the collection manifest."""


# --- leads ----------------------------------------------------------------------------------


class Identifier(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["verbatim", "truncated", "absent"]
    value: str | None = None
    where: Literal["text", "hyperlink"] | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Identifier:
        if self.status == "absent":
            if self.value is not None:
                raise ValueError("an absent identifier has no value")
        elif self.value is None:
            raise ValueError(f"a {self.status} identifier needs its value as shown")
        elif self.status == "verbatim" and not _FULL.match(self.value):
            raise ValueError("a verbatim identifier must be a full address or hash")
        elif self.status == "truncated" and (
            _FULL.match(self.value) or not _TRUNC.search(self.value)
        ):
            raise ValueError("a truncated identifier keeps its ellipsis and is never completed")
        return self


class LeadSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    publisher: str
    url: str
    date: str
    read: bool  # False: seen only in search results, not read in full


class Lead(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    lead_id: str
    origin: str
    sources: tuple[LeadSource, ...]
    chain_stated: Literal["ethereum", "other", "unstated"]
    chain_name: str | None = None
    event_date: str | None = None
    amount: str | None = None
    mechanism_claimed: str = "unknown"
    harm_claimed: bool = True
    identifiers: dict[str, Identifier]
    conflicts: tuple[str, ...] = ()
    campaign_notes: tuple[str, ...] = ()
    cluster_hint: str | None = None
    notes: tuple[str, ...] = ()

    def verbatim(self) -> dict[str, str]:
        return {
            r: i.value.lower()
            for r, i in self.identifiers.items()
            if i.status == "verbatim" and i.value
        }

    def statuses(self) -> dict[str, str]:
        return {r: i.status for r, i in sorted(self.identifiers.items())}

    def has_identifier(self) -> bool:
        return any(i.status != "absent" for i in self.identifiers.values())


def load_vault(path: Path) -> tuple[list[Lead], dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != LEADS_VERSION:
        raise AcquisitionError(f"{path}: unexpected schema {raw.get('schema_version')!r}")
    leads = [Lead.model_validate(x) for x in raw["leads"]]
    ids = [x.lead_id for x in leads]
    if len(set(ids)) != len(ids):
        raise AcquisitionError("duplicate lead ids")
    meta = {k: v for k, v in raw.items() if k != "leads"}
    return leads, meta


def identifier_problems(lead: Lead) -> list[str]:
    """Internal consistency: one value in two roles, or a role contradiction."""
    seen: dict[str, str] = {}
    out: list[str] = []
    for role, value in sorted(lead.verbatim().items()):
        if value in seen:
            out.append(f"same identifier in roles {seen[value]} and {role}")
        seen[value] = role
    v = lead.verbatim()
    if "victim" in v and v["victim"] in {v.get("lookalike"), v.get("intended")}:
        out.append("victim equals a counterparty role")
    return out


# --- commitments ----------------------------------------------------------------------------


def load_salts(path: Path, leads: Sequence[Lead], *, create: bool = True) -> dict[str, str]:
    """One secret 128-bit salt per lead, generated once and kept locally. A salted commitment
    binds the recorded identifier without letting anyone test a guessed one."""
    salts: dict[str, str] = {}
    if path.is_file():
        salts = json.loads(path.read_text(encoding="utf-8"))
    missing = [x.lead_id for x in leads if x.lead_id not in salts]
    if missing and create:
        for lead_id in missing:
            salts[lead_id] = secrets.token_hex(16)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(salts, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    elif missing:
        raise AcquisitionError(f"no salt for {len(missing)} lead(s)")
    return salts


def commitment(salt: str, role: str, value: str) -> str:
    return hashlib.sha256(f"{salt}|{role}|{value.lower()}".encode()).hexdigest()


def commitments(lead: Lead, salt: str) -> dict[str, str]:
    return {r: commitment(salt, r, v) for r, v in sorted(lead.verbatim().items())}


# --- development overlap ---------------------------------------------------------------------

TRACKED_DEVELOPMENT = (
    "src/cryptoguard/replay/cases",
    "src/cryptoguard/replay/background_cases",
    "src/cryptoguard/replay/campaign_cases",
    "docs/ml/incident-benchmark/cases",
)
REGISTRIES = (
    Path("docs/ml/incident-benchmark/candidates.json"),
    Path("docs/ml/incident-benchmark/stage2-candidates.json"),
)
TEXT_SUFFIXES = (".json", ".jsonl", ".md", ".csv", ".txt")
SQLITE_COLUMNS = frozenset(
    {
        "sender",
        "receiver",
        "tx",
        "intended",
        "victim",
        "lookalike",
        "address",
        "counterparty",
        "wallet",
        "transaction_hash",
        "planting_tx",
        "imitated",
    }
)


def _is_key_file(path: Path) -> bool:
    return "unblinding" in path.name or path.name.endswith(".zip")


def _scan_text_file(path: Path, needles: frozenset[str], chunk: int = 1 << 24) -> set[str]:
    """Lower-cased substring search, streamed in chunks with an overlap, so a large file is
    never held in memory."""
    found: set[str] = set()
    tail = ""
    width = max((len(n) for n in needles), default=0)
    with path.open(encoding="utf-8", errors="replace") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            text = (tail + block).lower()
            found |= {n for n in needles if n not in found and n in text}
            tail = text[-width:] if width else ""
            if len(found) == len(needles):
                break
    return found


def _scan_sqlite(path: Path, needles: frozenset[str]) -> set[str]:
    """Exact matches in address- and hash-like columns, read only. The local databases store
    lower-case hex (checked in Phase 12.9), so an indexed column is searched by its index."""
    found: set[str] = set()
    variants = sorted(needles)
    marks = ",".join("?" * len(variants))
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
            for c in cols:
                if c.lower() not in SQLITE_COLUMNS:
                    continue
                q = f'SELECT DISTINCT "{c}" FROM "{t}" WHERE "{c}" IN ({marks})'  # noqa: S608
                found |= {str(r[0]).lower() for r in con.execute(q, variants)}
    finally:
        con.close()
    return found


def development_registry_entries(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(development entries, lead entries) of the committed registries. An entry is
    development when it has a recorded fixture or a case directory."""
    dev: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    for reg in REGISTRIES:
        path = root / reg
        if not path.is_file():
            continue
        for c in json.loads(path.read_text(encoding="utf-8"))["candidates"]:
            recorded = (
                bool(c.get("fixture_case_id"))
                or (root / "docs/ml/incident-benchmark/cases" / c["case_id"]).exists()
            )
            (dev if recorded else leads).append(c)
    return dev, leads


def development_sources(root: Path, poisoning_dir: Path) -> dict[str, list[Path]]:
    """Every development artifact, by class (protocol 12.9 section 8, rule 1)."""
    research = root / "data/ml/research"
    out: dict[str, list[Path]] = {
        "recorded_fixtures_and_manifests": [],
        "campaign_expansion": [],
        "archive_episodes": [],
        "archive_rows": [],
        "review_packets": [],
        "frozen_cohort_sheets": [],
        "reviewer_kits": [],
        "local_research_outputs": [],
        "archive_databases": [],
    }
    for base in TRACKED_DEVELOPMENT:
        for p in sorted((root / base).rglob("*.json")):
            key = (
                "campaign_expansion"
                if "campaign_cases" in p.parts
                else ("recorded_fixtures_and_manifests")
            )
            out[key].append(p)
    episodes = research / "phase12.5/episodes.jsonl"
    if episodes.is_file():
        out["archive_episodes"].append(episodes)
    for p in sorted(poisoning_dir.rglob("*")):
        if not p.is_file() or _is_key_file(p):
            continue
        rel = p.relative_to(poisoning_dir).as_posix()
        if p.suffix == ".sqlite":
            out["archive_databases"].append(p)
        elif p.suffix not in TEXT_SUFFIXES:
            continue
        elif p.name == "reviewer_sheet.jsonl" and not rel.startswith("outbox"):
            out["frozen_cohort_sheets"].append(p)
        elif rel.startswith("outbox"):
            out["reviewer_kits"].append(p)
        elif "review_packets" in p.name or "/evidence/" in f"/{rel}" or rel.startswith("review"):
            out["review_packets"].append(p)
        elif p.name.endswith("rows.jsonl"):
            out["archive_rows"].append(p)
        else:
            out["local_research_outputs"].append(p)
    for p in sorted(research.rglob("*")):
        if (
            p.is_file()
            and p.suffix in TEXT_SUFFIXES
            and "phase12.9" not in p.parts
            and p != episodes
            and not _is_key_file(p)
        ):
            out["local_research_outputs"].append(p)
    return out


def development_hits(
    leads: Sequence[Lead], root: Path, poisoning_dir: Path
) -> tuple[dict[str, dict[str, list[str]]], dict[str, int]]:
    """Per lead: role -> the development source classes containing that verbatim identifier.
    Also returns how many files of each class were searched."""
    needles = frozenset(v for x in leads for v in x.verbatim().values())
    hits: dict[str, set[str]] = {n: set() for n in needles}
    searched: dict[str, int] = {}
    if needles:
        for klass, paths in development_sources(root, poisoning_dir).items():
            searched[klass] = len(paths)
            for p in paths:
                try:
                    found = (
                        _scan_sqlite(p, needles)
                        if p.suffix == ".sqlite"
                        else _scan_text_file(p, needles)
                    )
                except (OSError, sqlite3.Error):
                    continue
                for n in found:
                    hits[n].add(klass)
        dev_entries, _ = development_registry_entries(root)
        dev_values = {
            str(v).lower()
            for c in dev_entries
            for v in (c.get("identifiers") or {}).values()
            if isinstance(v, str)
        }
        searched["development_registry_entries"] = len(dev_entries)
        for n in needles & dev_values:
            hits[n].add("development_registry_entries")
    out = {
        x.lead_id: {r: sorted(hits[v]) for r, v in sorted(x.verbatim().items()) if hits[v]}
        for x in leads
    }
    return out, searched


# --- clusters and eligibility ----------------------------------------------------------------


def clusters(leads: Sequence[Lead]) -> dict[str, str]:
    """Lead id -> cluster id (the smallest lead id in its group). Leads join when they share
    a verbatim identifier in any role or carry the same cluster hint."""
    parent = {x.lead_id: x.lead_id for x in leads}

    def find(a: str) -> str:
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    owner: dict[str, str] = {}
    for x in leads:
        keys = [f"id:{v}" for v in x.verbatim().values()]
        if x.cluster_hint:
            keys.append(f"hint:{x.cluster_hint}")
        for k in keys:
            if k in owner:
                union(owner[k], x.lead_id)
            else:
                owner[k] = x.lead_id
    return {x.lead_id: find(x.lead_id) for x in leads}


def shared_attacker_identifiers(leads: Sequence[Lead]) -> dict[str, list[str]]:
    """Lead id -> other leads sharing a lookalike, post-harm or unassigned identifier."""
    by_value: dict[str, set[str]] = {}
    for x in leads:
        for role, v in x.verbatim().items():
            if role.startswith(("lookalike", "post_harm", "unassigned")):
                by_value.setdefault(v, set()).add(x.lead_id)
    out: dict[str, set[str]] = {}
    for ids in by_value.values():
        for a in ids:
            out.setdefault(a, set()).update(ids - {a})
    return {k: sorted(v) for k, v in out.items() if v}


def classify(
    lead: Lead,
    dev: Mapping[str, Sequence[str]],
    *,
    shared: Sequence[str] = (),
    same_cluster: Iterable[str] = (),
) -> tuple[str, list[str]]:
    """Protocol 12.9 section 8: the first matching rule wins. Returns (status, reasons);
    reasons never contain an identifier."""
    if dev:
        roles = ", ".join(sorted(dev))
        return "DEVELOPMENT_ONLY", [f"identifier ({roles}) found in a development artifact"]
    if lead.chain_stated == "other":
        return "REJECTED", [f"not Ethereum mainnet ({lead.chain_name or 'other chain'})"]
    if not lead.has_identifier():
        return "REJECTED", ["no identifier in any source read"]
    problems = identifier_problems(lead)
    if lead.conflicts or problems:
        return "NEEDS_IDENTIFIER_VERIFICATION", [
            *(f"conflicting: {c}" for c in lead.conflicts),
            *problems,
        ]
    status = lead.statuses()
    missing = [r for r in REQUIRED_FOR_READY if status.get(r, "absent") != "verbatim"]
    if missing:
        return "NEEDS_IDENTIFIER_VERIFICATION", [f"{r} {status.get(r, 'absent')}" for r in missing]
    if lead.chain_stated != "ethereum":
        return "NEEDS_IDENTIFIER_VERIFICATION", ["chain not stated by any source read"]
    unclustered = sorted(set(shared) - set(same_cluster))
    if lead.campaign_notes or unclustered:
        return "NEEDS_CAMPAIGN_REVIEW", [
            *lead.campaign_notes,
            *(f"shares an attacker identifier with {o}" for o in unclustered),
        ]
    if lead.mechanism_claimed in UNSUPPORTED:
        return "UNSUPPORTED_MECHANISM", [f"{lead.mechanism_claimed} is not observable"]
    if not lead.harm_claimed:
        return "NOT_EVALUABLE", ["no harmful transfer claimed"]
    return READY, []


def classify_all(
    leads: Sequence[Lead], dev_hits: Mapping[str, Mapping[str, Sequence[str]]]
) -> dict[str, dict[str, Any]]:
    cl = clusters(leads)
    shared = shared_attacker_identifiers(leads)
    out: dict[str, dict[str, Any]] = {}
    for x in leads:
        mates = [o for o, c in cl.items() if c == cl[x.lead_id] and o != x.lead_id]
        status, reasons = classify(
            x, dev_hits.get(x.lead_id, {}), shared=shared.get(x.lead_id, ()), same_cluster=mates
        )
        out[x.lead_id] = {"status": status, "reasons": reasons, "cluster": cl[x.lead_id]}
    return out


# --- pilot, jobs and budget ------------------------------------------------------------------


def pilot_rank(lead_id: str) -> str:
    return hashlib.sha256((PILOT_SEED + lead_id).encode()).hexdigest()


def select_pilot(classified: Mapping[str, Mapping[str, Any]], cap: int = PILOT_CAP) -> list[str]:
    """Every READY lead, at most one per cluster, in hash order, capped. Detectability, loss
    size and ease of recording are never inputs."""
    ready = sorted((x for x, v in classified.items() if v["status"] == READY), key=pilot_rank)
    taken: set[str] = set()
    out: list[str] = []
    for lead_id in ready:
        c = classified[lead_id]["cluster"]
        if c in taken:
            continue
        taken.add(c)
        out.append(lead_id)
        if len(out) == cap:
            break
    return out


class AnchorJob(BaseModel):
    """One receipt read of the harmful transaction. Its output to the collector is the block
    number only; the receipt goes to the outcome vault."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str
    lead_id: str
    kind: Literal["anchor"] = "anchor"
    chain_id: Literal[1] = 1
    transaction: str
    expected_sender: str
    max_requests: int = ANCHOR_CAP


class RecordJob(BaseModel):
    """A Phase 12.8 collector request, completed from the anchor's block number."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str
    lead_id: str
    kind: Literal["record"] = "record"
    depends_on: str
    chain_id: Literal[1] = 1
    wallet: str
    window_blocks: int = WINDOW_BLOCKS
    observation: Literal[2] = 2
    max_requests: int = RECORD_CAP


def collection_jobs(selected: Sequence[Lead]) -> list[AnchorJob | RecordJob]:
    jobs: list[AnchorJob | RecordJob] = []
    for x in selected:
        v = x.verbatim()
        anchor = AnchorJob(
            job_id=f"{x.lead_id}:anchor",
            lead_id=x.lead_id,
            transaction=v["harm_tx"],
            expected_sender=v["victim"],
        )
        jobs += [
            anchor,
            RecordJob(
                job_id=f"{x.lead_id}:record",
                lead_id=x.lead_id,
                depends_on=anchor.job_id,
                wallet=v["victim"],
            ),
        ]
    return jobs


def record_request(job: RecordJob, harm_block: int) -> bc.CollectorRequest:
    """The collector request once the anchor has produced the harmful block H: the window
    ends at H and no outcome field can be passed."""
    if harm_block <= job.window_blocks:
        raise ValueError("implausible harmful block")
    return bc.CollectorRequest(
        chain_id=job.chain_id,
        wallet=job.wallet,
        from_block=harm_block - job.window_blocks,
        to_block=harm_block,
        observation=job.observation,
        max_requests=job.max_requests,
    )


def budget(n_leads: int) -> dict[str, Any]:
    """Hard caps and planning estimates for ``n_leads`` selected leads."""
    per_window = ANCHOR_CAP + RECORD_CAP
    est = {
        k: {
            "requests": n_leads * (ANCHOR_ESTIMATE + v),
            "with_retry_reserve": round(n_leads * (ANCHOR_ESTIMATE + v) * (1 + RETRY_RESERVE)),
        }
        for k, v in ESTIMATES.items()
    }
    return {
        "leads": n_leads,
        "jobs": 2 * n_leads,
        "anchor_cap": ANCHOR_CAP,
        "record_cap": RECORD_CAP,
        "per_window_cap": per_window,
        "total_cap": n_leads * per_window,
        "estimates": est,
        "basis": "measured 21,600-block observation/1 and /2 recordings (475 / 1,299 / 1,433)",
        "wallet_activity": "unknown without RPC",
    }


def manifest(selected: Sequence[Lead], git: str | None) -> dict[str, Any]:
    jobs = collection_jobs(selected)
    b = budget(len(selected))
    return {
        "schema_version": MANIFEST_VERSION,
        "protocol": "protocol-12.9",
        "code_revision": git,
        "status": "planning only: not approved, not executed",
        "jobs": [j.model_dump() for j in jobs],
        "per_window_cap": b["per_window_cap"],
        "total_cap": b["total_cap"],
        "budget": b,
    }


def manifest_bytes(m: Mapping[str, Any]) -> bytes:
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode()


def manifest_sha256(m: Mapping[str, Any]) -> str:
    return hashlib.sha256(manifest_bytes(m)).hexdigest()


# --- approval gate ---------------------------------------------------------------------------


class ApprovalRecord(BaseModel):
    """The user's specific approval, quoted from chat. Never inferred from configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_sha256: str
    per_window_cap: int
    total_cap: int
    approver_statement: str
    approved_at: str


def _mentions(statement: str, number: int) -> bool:
    digits = re.sub(r"(?<=\d)[,\s_](?=\d{3}\b)", "", statement)
    return re.search(rf"(?<!\d){number}(?!\d)", digits) is not None


def check_approval(record: ApprovalRecord | None, m: Mapping[str, Any]) -> None:
    """Raise ``ApprovalError`` unless ``record`` approves exactly this manifest and caps."""
    if record is None:
        raise ApprovalError("no approval record: the manifest is planning only")
    if not m.get("jobs"):
        raise ApprovalError("the manifest has no jobs: there is nothing to approve")
    problems = []
    sha = manifest_sha256(m)
    if record.manifest_sha256 != sha:
        problems.append("manifest hash differs")
    if record.per_window_cap != m["per_window_cap"]:
        problems.append("per-window cap differs")
    if record.total_cap != m["total_cap"]:
        problems.append("total cap differs")
    text = record.approver_statement.strip()
    if text.lower().strip(" .!") in GENERIC_APPROVALS:
        problems.append("general encouragement is not approval of a specific cap")
    if not _mentions(text, m["total_cap"]):
        problems.append("the statement does not state the total cap")
    if sha[:12] not in text.lower():
        problems.append("the statement does not name the manifest (first 12 hex characters)")
    if problems:
        raise ApprovalError("; ".join(problems))


# --- pilot stop rules ------------------------------------------------------------------------


def pilot_stop_rules(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Protocol 12.9 section 13, in order, on a recorded pilot's summary: ``selected``,
    ``provider_failures``, ``recorded``, ``mechanism_eligible``, ``discordant_top5``,
    ``cluster_sizes`` (cluster -> recorded incidents), ``leakage_failures`` (case ids),
    ``missing_categories``."""
    selected = int(summary["selected"])
    recorded = int(summary["recorded"])
    out: list[dict[str, Any]] = []
    failures = int(summary["provider_failures"])
    out.append(
        {
            "rule": "S1",
            "triggered": selected > 0 and failures / selected > 0.30,
            "action": "stop and report",
        }
    )
    eligible = int(summary["mechanism_eligible"])
    out.append(
        {
            "rule": "S2",
            "triggered": eligible < min(5, -(-recorded // 2)) if recorded else True,
            "action": "pause broader collection",
        }
    )
    out.append(
        {
            "rule": "S3",
            "triggered": int(summary["discordant_top5"]) < 2,
            "action": "no powered comparison on current assumptions",
        }
    )
    sizes: Mapping[str, int] = summary.get("cluster_sizes", {})
    biggest = max(sizes.values(), default=0)
    out.append(
        {
            "rule": "S4",
            "triggered": recorded > 0 and biggest > recorded / 2,
            "action": "effective sample size is the cluster count",
            "effective_n": len(sizes),
        }
    )
    leaks = list(summary.get("leakage_failures", ()))
    out.append(
        {
            "rule": "S5",
            "triggered": bool(leaks),
            "action": "exclude from confirmatory metrics",
            "excluded": len(leaks),
        }
    )
    out.append(
        {
            "rule": "S6",
            "triggered": bool(summary.get("missing_categories")),
            "action": "report every missing mechanism category",
            "missing": sorted(summary.get("missing_categories", ())),
        }
    )
    return out


# --- public registry -------------------------------------------------------------------------


def public_registry(
    leads: Sequence[Lead],
    classified: Mapping[str, Mapping[str, Any]],
    salts: Mapping[str, str],
    meta: Mapping[str, Any],
) -> dict[str, Any]:
    """Citations, statuses and salted commitments only. No identifier, truncated or full."""
    rows = []
    for x in sorted(leads, key=lambda x: x.lead_id):
        c = classified[x.lead_id]
        rows.append(
            {
                "lead_id": x.lead_id,
                "origin": x.origin,
                "sources": [s.model_dump() for s in x.sources],
                "chain_stated": x.chain_stated,
                "chain_name": x.chain_name,
                "event_date": x.event_date,
                "amount": x.amount,
                "mechanism_claimed": x.mechanism_claimed,
                "identifier_status": x.statuses(),
                "commitments": commitments(x, salts[x.lead_id]),
                "status": c["status"],
                "reasons": c["reasons"],
                "cluster": c["cluster"],
                "conflicts": list(x.conflicts),
                "campaign_notes": list(x.campaign_notes),
            }
        )
    disc = meta.get("discovery", {})
    reg = {
        "schema_version": REGISTRY_VERSION,
        "protocol": "protocol-12.9",
        "discovery": {
            k: disc.get(k)
            for k in ("date", "searches", "page_reads", "budget", "explorer_or_rpc_requests")
        },
        "commitment": "sha256(salt|role|lower-case identifier); one secret salt per lead, kept "
        "locally and disclosed only at unblinding",
        "development_duplicates": [
            {"case": d["case"], "sources_seen": len(d.get("seen_in", []))}
            for d in meta.get("development_duplicates", [])
        ],
        "leads": rows,
    }
    assert_no_identifiers(json.dumps(reg))
    return reg


def assert_no_identifiers(text: str) -> None:
    """A public artifact must not carry an address or hash, even a truncated one."""
    if _HEX_IN_TEXT.search(text) or re.search(r"0x[0-9a-fA-F]{2,}\s*(…|\.\.\.)", text):
        raise AcquisitionError("an identifier would be published")


# --- study ----------------------------------------------------------------------------------


def selection_bias(
    leads: Sequence[Lead], classified: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    def by(fn: Any) -> dict[str, dict[str, int]]:
        out: dict[str, Counter[str]] = {}
        for x in leads:
            out.setdefault(str(fn(x)), Counter())[classified[x.lead_id]["status"]] += 1
        return {k: dict(sorted(v.items())) for k, v in sorted(out.items())}

    return {
        "by_origin": by(lambda x: x.origin.split(":")[0]),
        "by_any_source_read": by(lambda x: any(s.read for s in x.sources)),
        "by_chain_stated": by(lambda x: x.chain_stated),
        "by_victim_status": by(lambda x: x.statuses().get("victim", "absent")),
        "by_harm_tx_status": by(lambda x: x.statuses().get("harm_tx", "absent")),
        "within_archive_period": by(
            lambda x: bool(x.event_date) and str(x.event_date)[:10] <= ARCHIVE_LAST_DATE
        ),
    }


def main(
    root: Path,
    poisoning_dir: Path,
    out: Path,
    *,
    vault: Path | None = None,
    write_public: bool = False,
    git: str | None = None,
) -> dict[str, Any]:
    vault = vault or root / VAULT
    leads, meta = load_vault(vault)
    salts = load_salts(root / SALTS, leads)
    dev, searched = development_hits(leads, root, poisoning_dir)
    classified = classify_all(leads, dev)
    pilot_ids = select_pilot(classified)
    by_id = {x.lead_id: x for x in leads}
    m = manifest([by_id[i] for i in pilot_ids], git)
    out.mkdir(parents=True, exist_ok=True)
    local = {
        "study": STUDY_VERSION,
        "classified": classified,
        "development_hits": dev,  # roles and source classes only; identifiers stay in the vault
        "pilot": pilot_ids,
    }
    (out / "acquisition.local.json").write_text(
        json.dumps(local, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "collection-manifest.local.json").write_bytes(manifest_bytes(m) + b"\n")
    registry = public_registry(leads, classified, salts, meta)
    if write_public:
        # bytes, so the tracked file has LF endings on every platform
        (root / PUBLIC_REGISTRY).write_bytes(
            (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode()
        )
    statuses = Counter(v["status"] for v in classified.values())
    return {
        "study": STUDY_VERSION,
        "protocol": "protocol-12.9",
        "rpc_requests": 0,
        "leads": len(leads),
        "new_leads": sum(x.origin.startswith("new") for x in leads),
        "statuses": {s: statuses.get(s, 0) for s in STATUSES},
        "clusters": len(set(v["cluster"] for v in classified.values())),
        "development_overlap_leads": sum(bool(v) for v in dev.values()),
        "development_files_searched": searched,
        "pilot_selected": len(pilot_ids),
        "manifest_sha256": manifest_sha256(m),
        "manifest_jobs": len(m["jobs"]),
        "budget": m["budget"],
        "selection_bias": selection_bias(leads, classified),
        "discovery": meta.get("discovery", {}),
    }
