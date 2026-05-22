"""Run an RL ablation for the federated UAV IDS workflow.

The script can run three comparable variants:
1. no_apc: plain FedAvg-style baseline, no APC noise/frequency/participation control.
2. no_rl: APC receives a fixed trust score baseline.
3. with_rl: APC receives TrustNet scores from ``FLTrustRLBridge``.

Each run writes its live-round payload and server log under
``outputs/rl_ablation/<timestamp>/``. A compact comparison is saved as both JSON
and Markdown.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
LIVE_ROUNDS = ROOT / "dashboard" / "data" / "live_rounds.json"


def _check_dependencies() -> None:
    required = {
        "flwr": "flwr",
        "numpy": "numpy",
        "sklearn": "scikit-learn",
        "torch": "torch",
        "yaml": "PyYAML",
    }
    missing = [pkg for module, pkg in required.items() if importlib.util.find_spec(module) is None]
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(
            f"Missing Python dependencies: {joined}. Run `python -m pip install -r requirements.txt` first."
        )


def _fmt_float(value: Any, digits: int = 6) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _variant_metrics(payload: dict[str, Any], variant: str, duration_sec: float) -> dict[str, Any]:
    rounds = payload.get("rounds") or []
    if not rounds:
        raise RuntimeError(f"{variant}: no rounds found in {LIVE_ROUNDS}")
    final = max(rounds, key=lambda r: int(r.get("id", 0)))
    centralized = final.get("centralized") or {}
    rl_apc = final.get("rl_apc") or {}
    aggregation = final.get("aggregation") or {}
    policy = rl_apc.get("next_policy") or {}
    shares = [
        float((r.get("aggregation") or {}).get("malicious_weight_share", 0.0) or 0.0)
        for r in rounds
    ]
    trust_rows = [r.get("rl_apc", {}).get("trust_scores_0_100", []) for r in rounds]
    final_trust = trust_rows[-1] if trust_rows else []
    malicious_trust = float(final_trust[2]) if len(final_trust) > 2 else 0.0
    clean_trust = (
        float((float(final_trust[0]) + float(final_trust[1])) / 2.0)
        if len(final_trust) > 1
        else 0.0
    )
    return {
        "variant": variant,
        "round": int(final.get("id", 0)),
        "accuracy": float(centralized.get("accuracy", 0.0)),
        "loss": float(centralized.get("loss", 0.0)),
        "precision_macro": float(centralized.get("precision_macro", 0.0)),
        "recall_macro": float(centralized.get("recall_macro", 0.0)),
        "trust_mean": float(rl_apc.get("trust_mean", 0.0)),
        "threat_level": float(rl_apc.get("threat_level", 0.0)),
        "next_participate": int(policy.get("participate", 1)),
        "next_noise_scale": float(policy.get("noise_scale", 0.0)),
        "next_freq_n": int(policy.get("freq_n", 1)),
        "next_epsilon": float(policy.get("epsilon", 0.0)),
        "next_delta": float(policy.get("delta", 0.0)),
        "next_clip_norm": float(policy.get("clip_norm", 0.0)),
        "accepted_clients": int(aggregation.get("accepted_clients", 0) or 0),
        "malicious_weight_share": float(aggregation.get("malicious_weight_share", 0.0) or 0.0),
        "mean_malicious_weight_share": float(sum(shares) / len(shares)) if shares else 0.0,
        "max_malicious_weight_share": float(max(shares)) if shares else 0.0,
        "final_clean_trust_mean": clean_trust,
        "final_malicious_trust": malicious_trust,
        "aggregation_mode": str(aggregation.get("mode", "")),
        "duration_sec": float(duration_sec),
        "per_uav_next_policy": rl_apc.get("next_policy_per_uav") or {},
        "aggregation": aggregation,
    }


def _run_variant(
    *,
    name: str,
    apc_enabled: bool,
    rl_enabled: bool,
    out_dir: Path,
    rounds: int,
    seed: int,
    scenario: str,
    fixed_trust_score: float,
    local_epochs: int,
    batch_size: int,
    swarm_dir: str | None,
    startup_delay: float,
    timeout_sec: int,
) -> dict[str, Any]:
    variant_dir = out_dir / name
    variant_dir.mkdir(parents=True, exist_ok=True)
    server_log = variant_dir / "server.log"

    env = os.environ.copy()
    env.update(
        {
            "FL_NUM_ROUNDS": str(rounds),
            "FL_APC_ENABLED": "1" if apc_enabled else "0",
            "FL_RL_ENABLED": "1" if rl_enabled else "0",
            "FL_RL_FIXED_TRUST_SCORE": str(fixed_trust_score),
            "FL_SWARM_SCENARIO": scenario,
            "FL_LOCAL_EPOCHS": str(local_epochs),
            "FL_LOCAL_BATCH_SIZE": str(batch_size),
            "FL_SEED": str(seed),
            "PYTHONHASHSEED": str(seed),
            "FL_RUN_LOG": str(server_log),
            "FL_CHECKPOINT_FILE": f"fl_global_{name}.pt",
            "FL_TRUST_CHECKPOINT_FILE": f"trustnet_{name}_{scenario}.pt",
            "FL_TRUST_RESUME": "0",
            "FL_HEADLESS_STARTUP_DELAY": str(startup_delay),
        }
    )
    if swarm_dir:
        env["UAV_SWARM_DIR"] = swarm_dir

    cmd = [sys.executable, "_run_fl_headless.py"]
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        (variant_dir / "runner_stdout.log").write_text(stdout, encoding="utf-8", errors="replace")
        (variant_dir / "runner_stderr.log").write_text(stderr, encoding="utf-8", errors="replace")
        raise RuntimeError(f"{name}: timed out after {timeout_sec}s") from exc

    duration = time.perf_counter() - started
    (variant_dir / "runner_stdout.log").write_text(proc.stdout, encoding="utf-8", errors="replace")
    (variant_dir / "runner_stderr.log").write_text(proc.stderr, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"{name}: FL run failed with exit code {proc.returncode}")

    if not LIVE_ROUNDS.is_file():
        raise RuntimeError(f"{name}: missing {LIVE_ROUNDS}")
    live_copy = variant_dir / "live_rounds.json"
    shutil.copy2(LIVE_ROUNDS, live_copy)
    payload = json.loads(live_copy.read_text(encoding="utf-8"))
    metrics = _variant_metrics(payload, name, duration)
    metrics["server_log"] = str(server_log)
    metrics["live_rounds"] = str(live_copy)
    return metrics


def _comparison(no_rl: dict[str, Any], with_rl: dict[str, Any]) -> dict[str, Any]:
    metric_keys = [
        "accuracy",
        "loss",
        "precision_macro",
        "recall_macro",
        "trust_mean",
        "threat_level",
        "next_noise_scale",
        "next_freq_n",
        "accepted_clients",
        "malicious_weight_share",
        "mean_malicious_weight_share",
        "max_malicious_weight_share",
        "final_clean_trust_mean",
        "final_malicious_trust",
    ]
    deltas: dict[str, float] = {}
    for key in metric_keys:
        deltas[key] = float(with_rl[key]) - float(no_rl[key])
    return {"no_rl": no_rl, "with_rl": with_rl, "delta_with_rl_minus_no_rl": deltas}


def _compare_many(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    baseline_name = "no_rl" if "no_rl" in results else next(iter(results))
    baseline = results[baseline_name]
    metric_keys = [
        "accuracy",
        "loss",
        "precision_macro",
        "recall_macro",
        "trust_mean",
        "threat_level",
        "next_noise_scale",
        "next_freq_n",
        "accepted_clients",
        "malicious_weight_share",
        "mean_malicious_weight_share",
        "max_malicious_weight_share",
        "final_clean_trust_mean",
        "final_malicious_trust",
    ]
    deltas: dict[str, dict[str, float]] = {}
    for name, metrics in results.items():
        deltas[name] = {
            key: float(metrics[key]) - float(baseline[key])
            for key in metric_keys
        }
    return {
        "baseline": baseline_name,
        "variants": results,
        "delta_minus_baseline": deltas,
    }


def _write_markdown(path: Path, comparison: dict[str, Any]) -> None:
    variants = comparison["variants"]
    deltas = comparison["delta_minus_baseline"]
    names = list(variants.keys())
    rows = [
        "accuracy",
        "loss",
        "precision_macro",
        "recall_macro",
        "trust_mean",
        "threat_level",
        "next_noise_scale",
        "next_freq_n",
        "accepted_clients",
        "malicious_weight_share",
        "mean_malicious_weight_share",
        "max_malicious_weight_share",
        "final_clean_trust_mean",
        "final_malicious_trust",
    ]
    lines = [
        "# RL Ablation Comparison",
        "",
        f"Baseline for deltas: `{comparison['baseline']}`",
        "",
        "| Metric | " + " | ".join(names) + " |",
        "|---" + "|---:" * len(names) + "|",
    ]
    for metric in rows:
        lines.append("| " + metric + " | " + " | ".join(_fmt_float(variants[n][metric]) for n in names) + " |")
    lines.extend(["", "## Delta vs baseline", "", "| Metric | " + " | ".join(names) + " |", "|---" + "|---:" * len(names) + "|"])
    for metric in rows:
        lines.append("| " + metric + " | " + " | ".join(_fmt_float(deltas[n][metric]) for n in names) + " |")
    lines.extend(["", "## Artifacts", ""])
    for name in names:
        lines.append(f"- {name} log: `{variants[name]['server_log']}`")
        lines.append(f"- {name} live rounds: `{variants[name]['live_rounds']}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run no-RL vs with-RL FL ablation.")
    parser.add_argument("--rounds", type=int, default=int(os.environ.get("FL_NUM_ROUNDS", "15")))
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument(
        "--scenario",
        choices=["iid", "non_iid", "malicious", "dropout", "low_resource"],
        default=os.environ.get("FL_SWARM_SCENARIO", "iid"),
    )
    parser.add_argument(
        "--variants",
        default="no_apc,no_rl,with_rl",
        help="Comma-separated subset of: no_apc,no_rl,with_rl",
    )
    parser.add_argument("--fixed-trust-score", type=float, default=70.0)
    parser.add_argument("--local-epochs", type=int, default=int(os.environ.get("FL_LOCAL_EPOCHS", "2")))
    parser.add_argument("--batch-size", type=int, default=int(os.environ.get("FL_LOCAL_BATCH_SIZE", "32")))
    parser.add_argument("--swarm-dir", default=os.environ.get("UAV_SWARM_DIR"))
    parser.add_argument("--startup-delay", type=float, default=18.0)
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "outputs" / "rl_ablation" / datetime.now().strftime("%Y%m%d_%H%M%S"),
    )
    args = parser.parse_args()

    _check_dependencies()

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    requested = [v.strip() for v in args.variants.split(",") if v.strip()]
    valid = {
        "no_apc": {"apc_enabled": False, "rl_enabled": False},
        "no_rl": {"apc_enabled": True, "rl_enabled": False},
        "with_rl": {"apc_enabled": True, "rl_enabled": True},
    }
    unknown = [v for v in requested if v not in valid]
    if unknown:
        raise RuntimeError(f"Unknown variants: {', '.join(unknown)}")

    print(f"[ablation] output: {out_dir}")
    print(f"[ablation] scenario: {args.scenario}")
    results: dict[str, dict[str, Any]] = {}
    for name in requested:
        cfg = valid[name]
        print(f"[ablation] running {name}...")
        results[name] = _run_variant(
            name=name,
            apc_enabled=bool(cfg["apc_enabled"]),
            rl_enabled=bool(cfg["rl_enabled"]),
            out_dir=out_dir,
            rounds=args.rounds,
            seed=args.seed,
            scenario=args.scenario,
            fixed_trust_score=args.fixed_trust_score,
            local_epochs=args.local_epochs,
            batch_size=args.batch_size,
            swarm_dir=args.swarm_dir,
            startup_delay=args.startup_delay,
            timeout_sec=args.timeout_sec,
        )

    comparison = _compare_many(results)
    json_path = out_dir / "comparison.json"
    md_path = out_dir / "comparison.md"
    json_path.write_text(json.dumps(comparison, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_markdown(md_path, comparison)

    print("\nMetric                 " + "  ".join(f"{name:>10}" for name in requested))
    print("-" * (23 + 12 * len(requested)))
    for key in ["accuracy", "loss", "precision_macro", "recall_macro", "trust_mean", "next_noise_scale", "next_freq_n", "accepted_clients", "malicious_weight_share", "mean_malicious_weight_share", "final_clean_trust_mean", "final_malicious_trust"]:
        print(f"{key:<22} " + "  ".join(f"{_fmt_float(results[name][key]):>10}" for name in requested))
    print(f"\n[ablation] wrote {json_path}")
    print(f"[ablation] wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
