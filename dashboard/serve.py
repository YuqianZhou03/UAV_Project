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
import socket
import socketserver
import subprocess
import sys
import traceback
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

PORT = int(os.environ.get("DASHBOARD_PORT", "8765"))
_CTRL: dict[str, object] = {"server_pid": None, "client_pids": []}


def _ps_q(s: str) -> str:
    return str(s).replace("'", "''")


def _python_path() -> str:
    venv_py = REPO / ".venv" / "Scripts" / "python.exe"
    if venv_py.is_file():
        return str(venv_py)
    return sys.executable


def _port_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=0.35):
            return True
    except OSError:
        return False


def _spawn_terminal(
    title: str, py_args: list[str], env_vars: dict[str, str] | None = None
) -> int:
    py = _python_path()
    args = " ".join([f"'{_ps_q(a)}'" for a in py_args])
    env_cmd = ""
    if isinstance(env_vars, dict) and env_vars:
        env_cmd = " ".join([f"$env:{k} = '{_ps_q(v)}';" for k, v in env_vars.items()])
    ps = (
        f"{env_cmd}"
        f"$Host.UI.RawUI.WindowTitle = '{_ps_q(title)}'; "
        f"Set-Location -LiteralPath '{_ps_q(str(REPO))}'; "
        f"& '{_ps_q(py)}' {args}"
    )
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    p = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", ps],
        creationflags=flags,
    )
    return int(p.pid)


def _clients_running() -> bool:
    pids = _CTRL.get("client_pids")
    if not isinstance(pids, list) or len(pids) != 3:
        return False
    alive: list[int] = []
    for pid in pids:
        if not isinstance(pid, int) or pid <= 0:
            continue
        try:
            os.kill(int(pid), 0)
            alive.append(int(pid))
        except ProcessLookupError:
            continue
        except PermissionError:
            alive.append(int(pid))
    _CTRL["client_pids"] = alive
    return len(alive) == 3


def _kill_pid(pid: int | None) -> None:
    if not isinstance(pid, int) or pid <= 0:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        pass


def _kill_listeners_on_port(port: int) -> None:
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
    except Exception:
        return
    pids: set[int] = set()
    needle = f":{int(port)}"
    for ln in out.splitlines():
        s = ln.strip()
        if "LISTENING" not in s:
            continue
        if needle not in s:
            continue
        parts = s.split()
        if not parts:
            continue
        try:
            pids.add(int(parts[-1]))
        except Exception:
            continue
    for pid in pids:
        _kill_pid(pid)


def _reset_runtime() -> None:
    _kill_pid(_CTRL.get("server_pid") if isinstance(_CTRL.get("server_pid"), int) else None)
    pids = _CTRL.get("client_pids")
    if isinstance(pids, list):
        for pid in pids:
            _kill_pid(pid if isinstance(pid, int) else None)
    _kill_listeners_on_port(8080)
    _CTRL["server_pid"] = None
    _CTRL["client_pids"] = []


def _step_server(pid: int | None) -> dict:
    return {
        "id": "server_config",
        "title_zh": "① 服务器向三机下发 fit 配置",
        "title_en": "① Server broadcasts fit config to 3 UAVs",
        "body_zh": "服务器终端已启动，等待后续三机连接后下发 fit 参数。",
        "body_en": "Server terminal started. Waiting for UAV clients before fit config broadcast.",
        "kv": {"server_pid": pid, "grpc_addr": "127.0.0.1:8080"},
    }


def _step_clients(pids: list[int]) -> dict:
    return {
        "id": "local_traffic",
        "title_zh": "② 三机并行：各自生成流量窗口并运行本地 IDS",
        "title_en": "② Three UAVs: parallel synthetic traffic + local IDS",
        "body_zh": "三架无人机终端已启动，准备接收服务器参数并参与训练/推理。",
        "body_en": "Three UAV client terminals started and ready for training/inference.",
        "kv": {"client_pids": pids, "edge_uav_count": 3},
    }


def _control_action(action: str, mode: str, seed_val: int | None) -> dict:
    action = (action or "").strip().lower()
    if action == "status":
        return {
            "ok": True,
            "action": "status",
            "server_started": bool(_port_listening(8080)),
            "clients_started": bool(_clients_running()),
        }

    if action == "start_server":
        _reset_runtime()
        # Keep dashboard demo runtime isolated: do not overwrite the main
        # checkpoint used by workflow inference (`fl_global_last.pt`).
        pid = _spawn_terminal(
            "FL-SERVER",
            ["server.py"],
            env_vars={
                "FL_CHECKPOINT_FILE": "fl_runtime_last.pt",
                "FL_TRUST_CHECKPOINT_FILE": "trustnet_runtime_last.pt",
            },
        )
        _CTRL["server_pid"] = pid
        return {
            "ok": True,
            "action": action,
            "message": "已重置旧流程并启动新服务器终端。",
            "phase_step": _step_server(pid),
        }

    if action == "start_clients":
        pids: list[int] = []
        if _clients_running():
            pids = [int(x) for x in _CTRL["client_pids"]]  # type: ignore[index]
            return {
                "ok": True,
                "action": action,
                "message": "三架无人机终端已在运行。",
                "phase_step": _step_clients(pids),
            }
        for i in range(3):
            pids.append(_spawn_terminal(f"FL-CLIENT-{i}", ["client.py", str(i)]))
        _CTRL["client_pids"] = pids
        return {
            "ok": True,
            "action": action,
            "message": "三架无人机终端已启动。",
            "phase_step": _step_clients(pids),
        }

    if action == "start_training":
        from uav_workflow_sim import run_uav_workflow

        out = run_uav_workflow(mode=str(mode), seed=seed_val)
        srv_pid = _CTRL.get("server_pid")
        out["action"] = action
        out["control"] = {
            "server_started": bool(_port_listening(8080) or (isinstance(srv_pid, int) and srv_pid > 0)),
            "clients_started": bool(_clients_running()),
            "server_pid": srv_pid,
            "client_pids": _CTRL.get("client_pids"),
        }
        return out

    return {"ok": False, "error": f"Unknown action: {action}"}


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
        if path == "/api/fl-control":
            qs = parse_qs(parsed.query or "")
            action = (qs.get("action") or ["status"])[0]
            mode = (qs.get("mode") or ["auto"])[0]
            seed_raw = (qs.get("seed") or [None])[0]
            seed_val = None
            if seed_raw not in (None, ""):
                try:
                    seed_val = int(str(seed_raw).strip())
                except ValueError:
                    seed_val = None
            try:
                out = _control_action(str(action), str(mode), seed_val)
            except Exception as e:  # noqa: BLE001
                out = {"ok": False, "error": str(e), "traceback": traceback.format_exc()}
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
