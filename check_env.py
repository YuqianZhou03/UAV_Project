"""Preflight checks for the UAV federated IDS demo.

Run this before training or demonstrations:

    python check_env.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATA_DIR = (ROOT / os.environ.get("UAV_SWARM_DIR", "data/swarm_processed")).resolve()
CHECKPOINT_DIR = ROOT / "checkpoints"

REQUIRED_MODULES = {
    "flwr": "Flower federated learning runtime",
    "numpy": "array/tensor storage",
    "pandas": "CSV preprocessing",
    "sklearn": "preprocessing and metrics",
    "torch": "CNN-LSTM and TrustNet models",
    "yaml": "APC YAML configuration",
}


def _module_ok(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _port_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) != 0


def _check_modules() -> list[str]:
    errors: list[str] = []
    for module, purpose in REQUIRED_MODULES.items():
        if _module_ok(module):
            print(f"[OK] Python module {module:<8} - {purpose}")
        else:
            errors.append(f"Missing Python module: {module} ({purpose})")
            print(f"[MISSING] Python module {module:<8} - {purpose}")
    return errors


def _check_data() -> list[str]:
    errors: list[str] = []
    meta_path = DATA_DIR / "meta.json"
    test_path = DATA_DIR / "test.npz"
    train_paths = [DATA_DIR / f"train_split_{i}.npz" for i in range(9)]

    if not meta_path.is_file():
        errors.append(f"Missing {meta_path}")
        print(f"[MISSING] {meta_path}")
        return errors

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    holdout = float(meta.get("packet_holdout_frac", -1.0))
    print(
        "[OK] dataset meta "
        f"classes={meta.get('num_classes')} features={meta.get('n_features')} "
        f"window={meta.get('window')} train_windows={meta.get('train_window_total')}"
    )
    if abs(holdout - 0.20) <= 1e-9:
        print("[OK] dataset split target: 80% train / 20% test")
    else:
        print(
            "[WARN] dataset split is not the current 80/20 target "
            f"(packet_holdout_frac={holdout}). Rebuild with: "
            "python preprocess_swarm_federated.py && python enrich_swarm_telemetry.py"
        )

    for path in [test_path, *train_paths]:
        if path.is_file():
            print(f"[OK] data file {path.relative_to(ROOT)}")
        else:
            errors.append(f"Missing {path}")
            print(f"[MISSING] {path.relative_to(ROOT)}")
    return errors


def _check_ports() -> list[str]:
    errors: list[str] = []
    for port, label in [(8080, "Flower server"), (8765, "dashboard")]:
        if _port_free(port):
            print(f"[OK] port {port} free for {label}")
        else:
            errors.append(f"Port {port} is already in use ({label})")
            print(f"[BUSY] port {port} already in use ({label})")
    return errors


def _check_optional_artifacts() -> None:
    last = CHECKPOINT_DIR / "fl_global_last.pt"
    if last.is_file():
        print(f"[OK] optional checkpoint exists: {last.relative_to(ROOT)}")
    else:
        print("[INFO] no FL checkpoint yet; it will be created after a complete server run")


def main() -> int:
    print(f"UAV FL-IDS environment check: {ROOT}")
    errors: list[str] = []
    errors.extend(_check_modules())
    errors.extend(_check_data())
    errors.extend(_check_ports())
    _check_optional_artifacts()

    if errors:
        print("\nEnvironment check failed:")
        for err in errors:
            print(f"  - {err}")
        print("\nInstall dependencies with: python -m pip install -r requirements.txt")
        print("Regenerate data with: python preprocess_swarm_federated.py && python enrich_swarm_telemetry.py")
        return 1

    print("\nEnvironment check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
