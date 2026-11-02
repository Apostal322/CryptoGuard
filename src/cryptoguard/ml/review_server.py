"""Local review app for one reviewer (``cryptoguard ml review serve``). Standard library
only, loopback only, and kept apart from the CryptoGuard API, so no research data reaches
the production service.

Blinding is enforced on the server.
- The server reads only the reviewer package: the blinded sheet, the reviewer's own store
  and any blinded replacement lines.
- It cannot read the unblinding key, the manifest or another reviewer's files, because
  none of them is in the package.
- Static files carry no data.

Local web safety:
- every API call needs a per-session token sent in a custom header, which a cross-site
  page cannot send without a CORS preflight that is never granted;
- a Host check stops DNS rebinding;
- a strict CSP is set, and the page renders text only (no ``innerHTML``).
"""

from __future__ import annotations

import hmac
import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from threading import Lock
from typing import Any

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.annotation import (
    PROTOCOL,
    AnnotationError,
    ReviewerStore,
)

PACKAGE_INFO = "reviewer.json"
REPLACEMENT_SHEET = "replacement_sheet.jsonl"
STORE_DIR = "annotations"
MAX_BODY = 64 * 1024
STATIC = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/app.css": ("app.css", "text/css")}  # fmt: skip
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SHEET_FIELDS = ("item", "victim_event_id", "chain_id", "wallet", "address_under_review",
                "transaction", "block")  # fmt: skip
OPTIONAL_FIELDS = ("description", "coverage_note", "context")  # sheet v2 (later cohorts)


def _view(r: dict[str, Any]) -> dict[str, Any]:
    """The reviewer's view of one sheet line: required fields plus whitelisted extras."""
    return {k: r[k] for k in SHEET_FIELDS} | {k: r[k] for k in OPTIONAL_FIELDS if k in r}


class PackageError(ValueError):
    pass


def load_package(package: Path, expected_sheet_sha256: str | None = None) -> dict[str, Any]:
    """Verify the package and return its reviewer, sample hashes and active items. The
    cohort is found by the sheet's hash among the committed cohorts (``rs.COHORTS``)."""
    info = json.loads((package / PACKAGE_INFO).read_text(encoding="utf-8"))
    sheet_path = package / rs.SHEET
    got = rs.file_sha256(sheet_path)
    known = expected_sheet_sha256 == got if expected_sheet_sha256 else rs.cohort_for_sheet(got)
    if got != info["sheet_sha256"] or not known:
        raise PackageError(f"{sheet_path}: sha256 {got} is not a frozen sheet")
    items = {r["item"]: _view(r) for r in rs.read_sheet(sheet_path)}
    replaced: list[int] = []
    rep_path = package / REPLACEMENT_SHEET
    if rep_path.exists():
        for line in rep_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["replaces_item"] not in items or r["item"] in items:
                raise PackageError(f"{rep_path}: bad replacement for item {r['replaces_item']}")
            del items[r["replaces_item"]]
            replaced.append(r["replaces_item"])
            items[r["item"]] = _view(r)
    return {
        "reviewer": info["reviewer"],
        "selection_sha256": info["selection_sha256"],
        "sheet_sha256": got,
        "items": dict(sorted(items.items())),
        "replaced_items": sorted(replaced),
    }


class ReviewApp:
    def __init__(self, package: Path, expected_sheet_sha256: str | None = None) -> None:
        self.pkg = load_package(package, expected_sheet_sha256)
        ids = {i: v["victim_event_id"] for i, v in self.pkg["items"].items()}
        self.store = ReviewerStore(package / STORE_DIR, self.pkg["reviewer"], ids)
        self.token = secrets.token_urlsafe(24)
        self.lock = Lock()

    def state(self) -> dict[str, Any]:
        latest = self.store.latest()
        return {
            "reviewer": self.pkg["reviewer"],
            "protocol": PROTOCOL,
            "sample": self.pkg["selection_sha256"][:12],
            "finalized": self.store.finalized,
            "items": list(self.pkg["items"].values()),
            "replaced_items": self.pkg["replaced_items"],
            "decisions": {str(i): a.model_dump(mode="json") for i, a in latest.items()},
        }

    def save(self, body: dict[str, Any]) -> dict[str, Any]:
        fields = body.get("fields")
        if not isinstance(fields, dict):
            raise AnnotationError("missing fields")
        with self.lock:
            a = self.store.save(fields, expected_revision=body.get("expected_revision"))
        return {"saved": a.model_dump(mode="json")}

    def finalize(self) -> dict[str, Any]:
        with self.lock:
            sub = self.store.finalize(
                {
                    "selection_sha256": self.pkg["selection_sha256"],
                    "sheet_sha256": self.pkg["sheet_sha256"],
                }
            )
        return {"content_sha256": sub.content_sha256, "finalized_at": sub.finalized_at}


def make_handler(app: ReviewApp, port_ref: list[int]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "cryptoguard-review"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            pass  # no request logging: paths and bodies stay off the console

        def _headers(self, status: int, ctype: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _json(self, status: int, obj: Any) -> None:
            data = json.dumps(obj).encode()
            self._headers(status, "application/json", len(data))
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            port = port_ref[0]
            return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _authorized(self) -> bool:
            token = self.headers.get("X-Review-Token", "")
            return hmac.compare_digest(token.encode(), app.token.encode())

        def do_GET(self) -> None:
            if not self._host_ok():
                return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "bad host"})
            path = self.path.split("?", 1)[0]
            if path in STATIC:
                name, ctype = STATIC[path]
                data = resources.files("cryptoguard.ml.review_app").joinpath(name).read_bytes()
                self._headers(HTTPStatus.OK, ctype, len(data))
                return self.wfile.write(data)  # type: ignore[return-value]
            if path == "/api/state":
                if not self._authorized():
                    return self._json(HTTPStatus.FORBIDDEN, {"error": "missing or bad token"})
                return self._json(HTTPStatus.OK, app.state())
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._host_ok():
                return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "bad host"})
            if not self._authorized():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "missing or bad token"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "JSON only"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise AnnotationError("body must be a JSON object")
                if self.path == "/api/save":
                    return self._json(HTTPStatus.OK, app.save(body))
                if self.path == "/api/finalize":
                    return self._json(HTTPStatus.OK, app.finalize())
            except (AnnotationError, json.JSONDecodeError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except OSError as exc:  # disk full, permissions: the log on disk is unchanged
                return self._json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"save failed, nothing was written: {exc.strerror or exc}"},
                )
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    return Handler


def serve(app: ReviewApp, port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Bind to 127.0.0.1 and return the server and the URL (token in the fragment, which
    browsers never send to the server or in a Referer)."""
    port_ref = [0]
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port_ref))
    port_ref[0] = httpd.server_address[1]
    return httpd, f"http://127.0.0.1:{port_ref[0]}/#token={app.token}"
