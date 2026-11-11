"""Local review app: blinding, token and host checks, durable saves and finalization.

The server runs on 127.0.0.1 with a synthetic frozen sample. Every response is searched for
values that only the unblinding key holds.
"""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.review_server import ReviewApp, serve
from cryptoguard.ml.unblind import make_package
from tests.review_fixtures import INSUFFICIENT_FIELDS, fields, frozen


@pytest.fixture
def running(tmp_path: Path, monkeypatch) -> Iterator[dict[str, Any]]:
    _, sample, _ = frozen(tmp_path, monkeypatch)
    pkg = make_package(sample, tmp_path / "work", "A", tmp_path / "pkg-A")
    app = ReviewApp(pkg)
    with app.store:
        httpd, url = serve(app)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        base = url.split("/#")[0]
        try:
            yield {"base": base, "token": app.token, "sample": sample, "pkg": pkg, "app": app}
        finally:
            httpd.shutdown()
            httpd.server_close()


def call(
    env: dict[str, Any],
    path: str,
    body: Any = None,
    *,
    token: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, dict[str, str]]:
    h = {"X-Review-Token": env["token"] if token is None else token, **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(env["base"] + path, data=data, headers=h)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=10) as res:  # noqa: S310 - loopback test
            raw = res.read()
            return res.status, _parse(raw, res.headers), dict(res.headers)
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}"), dict(err.headers)


def _parse(raw: bytes, headers: Any) -> Any:
    return json.loads(raw) if "json" in headers.get("Content-Type", "") else raw.decode()


def hidden_values(sample: Path) -> set[str]:
    """Strings only the key holds: imitated addresses, payoffs, rivals, subtypes, labels."""
    out: set[str] = set()
    for line in (sample / rs.KEY).read_text(encoding="utf-8").splitlines():
        p = json.loads(line)["packet"]
        out |= {p["imitated"], *p["competing_lookalikes"], *p["source_labels"]}
        out |= {x.split()[0] for x in p["payment_evidence"]}
        out.add(p["evidence_summary"])
    return out


def test_package_holds_only_the_blinded_sheet(running: dict[str, Any]) -> None:
    files = {p.name for p in running["pkg"].iterdir()}
    assert files == {rs.SHEET, "reviewer.json", "annotations"}
    assert (running["pkg"] / rs.SHEET).read_bytes() == (running["sample"] / rs.SHEET).read_bytes()


def test_no_response_contains_hidden_answers(running: dict[str, Any]) -> None:
    hidden = hidden_values(running["sample"])
    subtypes = ("fake_token", "spoofed_transfer_from", "zero_value", "dust")
    bodies = []
    for path in ("/", "/app.js", "/app.css"):
        _, body, _ = call(running, path)
        bodies.append(body)
    static = "\n".join(bodies)
    bodies = []
    for path in ("/api/state", "/nope"):
        _, body, _ = call(running, path)
        bodies.append(json.dumps(body))
    status, saved, _ = call(running, "/api/save", {"fields": fields(1, _event(running, 1))})
    assert status == 200
    bodies.append(json.dumps(saved))
    _, bad, _ = call(running, "/api/save", {"fields": fields(1, "0" * 16)})
    bodies.append(json.dumps(bad))  # error messages too
    api = "\n".join(bodies)
    leaked = [h for h in hidden if h and h in api + static]
    assert leaked == []
    assert not any(s in api for s in subtypes)
    assert not re.search(r"0x[0-9a-fA-F]{40}", static)  # static files carry no addresses


def _event(env: dict[str, Any], item: int) -> str:
    state = env["app"].state()
    return next(i["victim_event_id"] for i in state["items"] if i["item"] == item)


def test_api_needs_the_session_token_and_a_loopback_host(running: dict[str, Any]) -> None:
    assert call(running, "/api/state", token="")[0] == 403
    assert call(running, "/api/state", token="guess")[0] == 403
    body = {"fields": fields(1, _event(running, 1))}
    assert call(running, "/api/save", body, token="")[0] == 403
    assert call(running, "/api/state", headers={"Host": "evil.example:80"})[0] == 421
    assert call(running, "/", headers={"Host": "evil.example"})[0] == 421


def test_security_headers_and_request_limits(running: dict[str, Any]) -> None:
    _, _, headers = call(running, "/")
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    plain = {"Content-Type": "text/plain"}
    assert call(running, "/api/save", {"fields": {}}, headers=plain)[0] == 415
    big = {"fields": {"notes": "x" * 70_000}}
    assert call(running, "/api/save", big)[0] == 413
    assert call(running, "/api/save", [1, 2])[0] == 400


def test_save_resume_and_finalize_over_http(running: dict[str, Any]) -> None:
    state = call(running, "/api/state")[1]
    assert state["reviewer"] == "A"
    assert state["decisions"] == {}
    for it in state["items"]:
        status, res, _ = call(
            running,
            "/api/save",
            {"fields": fields(it["item"], it["victim_event_id"]), "expected_revision": 0},
        )
        assert status == 200, res
    # A stale client is told to reload instead of overwriting.
    first = state["items"][0]
    stale = {
        "fields": fields(first["item"], first["victim_event_id"], INSUFFICIENT_FIELDS),
        "expected_revision": 0,
    }
    assert call(running, "/api/save", stale)[0] == 400
    resumed = ReviewApp(running["pkg"]).state()  # what a restarted server would serve
    assert len(resumed["decisions"]) == len(state["items"])
    status, fin, _ = call(running, "/api/finalize", {})
    assert status == 200
    assert len(fin["content_sha256"]) == 64
    stale["expected_revision"] = 1
    status, err, _ = call(running, "/api/save", stale)
    assert status == 400
    assert "finalized" in err["error"]
    assert (running["pkg"] / "annotations" / "submission.json").exists()


def test_invalid_decisions_get_a_useful_error(running: dict[str, Any]) -> None:
    f = {**fields(1, _event(running, 1)), "prior_counterparty_address": None}
    status, err, _ = call(running, "/api/save", {"fields": f})
    assert status == 400
    assert "imitated earlier counterparty" in err["error"]


def test_a_second_server_cannot_open_the_same_store(running: dict[str, Any]) -> None:
    from cryptoguard.ml.annotation import AnnotationError

    other = ReviewApp(running["pkg"])
    with pytest.raises(AnnotationError, match="another review session"), other.store:
        pass


def test_a_tampered_sheet_will_not_be_served(running: dict[str, Any]) -> None:
    from cryptoguard.ml.review_server import PackageError

    sheet = running["pkg"] / rs.SHEET
    sheet.write_bytes(sheet.read_bytes() + b"\n")
    with pytest.raises(PackageError, match="frozen sheet"):
        ReviewApp(running["pkg"])
