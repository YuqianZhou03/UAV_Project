"""Serve the interactive dashboard over HTTP (avoids file:// fetch blocks).

Usage from repo root:
  python dashboard/serve.py

Chinese UI: http://127.0.0.1:8765/
English UI: http://127.0.0.1:8765/en/

API (same origin): GET /api/uav-workflow?mode=auto|attack|normal&seed=optional_int
Runs ``uav_workflow_sim.run_uav_workflow`` (real tensors + APC). Omit ``seed`` for a fresh random sample each call.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import traceback
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

PORT = int(os.environ.get("DASHBOARD_PORT", "8765"))


class _ReuseThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/api/uav-workflow":
            qs = parse_qs(parsed.query or "")
            mode = (qs.get("mode") or ["auto"])[0]
            seed_raw = (qs.get("seed") or [None])[0]
            seed_val = None
            if seed_raw not in (None, ""):
                try:
                    seed_val = int(str(seed_raw).strip())
                except ValueError:
                    seed_val = None
            try:
                from uav_workflow_sim import run_uav_workflow

                out = run_uav_workflow(mode=str(mode), seed=seed_val)
            except Exception as e:  # noqa: BLE001 — surface to UI
                out = {
                    "ok": False,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
            body = json.dumps(out, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, fmt: str, *args: object) -> None:
        if self.path.startswith("/api/"):
            return
        super().log_message(fmt, *args)


def main() -> None:
    os.chdir(ROOT)
    with _ReuseThreadingTCPServer(("127.0.0.1", PORT), DashboardHandler) as httpd:
        print(f"Chinese UI: http://127.0.0.1:{PORT}/")
        print(f"English UI: http://127.0.0.1:{PORT}/en/")
        print(f"Workflow API: http://127.0.0.1:{PORT}/api/uav-workflow?mode=auto")
        print(f"(cwd={ROOT})  Ctrl+C to stop.")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
