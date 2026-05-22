"""Start Flower server then three clients; exit when server finishes (all FL rounds done)."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    env = os.environ.copy()
    env.setdefault("FL_NUM_ROUNDS", "3")
    startup_delay = float(env.get("FL_HEADLESS_STARTUP_DELAY", "18"))
    log = Path(env.get("FL_RUN_LOG", str(ROOT / "_last_fl_run.log")))
    if not log.is_absolute():
        log = ROOT / log
    server = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    time.sleep(startup_delay)
    clients: list[subprocess.Popen] = []
    for i in range(3):
        clients.append(
            subprocess.Popen(
                [sys.executable, "client.py", str(i)],
                cwd=ROOT,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        time.sleep(0.4)
    out, _ = server.communicate()
    if out:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(out, encoding="utf-8", errors="replace")
        print(out[-8000:] if len(out) > 8000 else out)
    for c in clients:
        c.terminate()
        try:
            c.wait(timeout=5)
        except subprocess.TimeoutExpired:
            c.kill()
    sys.exit(server.returncode or 0)


if __name__ == "__main__":
    main()
