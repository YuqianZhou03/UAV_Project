"""Write per-round FL metrics for the static dashboard (dashboard/data/live_rounds.json).

The browser loads rounds.json for layout/theatres/glossary, then replaces the ``rounds``
array with ``live_rounds.json`` when present and non-empty so the UI matches the
latest server.py run on this machine.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from swarm_fl_data import NUM_CLIENTS, split_index_for_round_client

_LIVE = Path(__file__).resolve().parent / "dashboard" / "data" / "live_rounds.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def reset_live_dashboard() -> None:
    """Call when starting a new Flower server so the UI shows only this session."""
    _LIVE.parent.mkdir(parents=True, exist_ok=True)
    _LIVE.write_text(
        json.dumps({"generated_at": _utc_now(), "rounds": []}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def append_live_round(
    *,
    server_round: int,
    scenario: dict[str, Any],
    loss: float,
    metrics: dict[str, Any],
    test_windows: int,
    telemetry_pooled: dict[str, float] | None,
    fit_rows: list[dict[str, Any]],
    eval_acc: dict[int, float],
    trust_scores_0_100: list[float],
    trust_mean: float,
    threat_level: float,
    mission_criticality: float,
    resource_availability: float,
    next_policy: dict[str, Any],
    per_uav_next_policy: dict[int, dict[str, float]] | None = None,
    aggregation: dict[str, Any] | None = None,
) -> None:
    """Append or replace one round card (id == server_round)."""
    fit_clients: list[dict[str, Any]] = []
    for cid in range(NUM_CLIENTS):
        row = next((r for r in fit_rows if int(r.get("client_id", -1)) == cid), {})
        n_ex = int(row.get("num_examples", 0) or 0)
        bat = row.get("battery_soc_mean")
        cpu = row.get("cpu_util_mean")
        fit_clients.append(
            {
                "slot": f"UAV-{cid}",
                "split_index": split_index_for_round_client(server_round, cid),
                "num_examples": n_ex,
                "battery_mean": float(bat) if bat is not None else None,
                "cpu_mean": float(cpu) if cpu is not None else None,
                "local_eval_accuracy": float(eval_acc.get(cid, 0.0)),
                "local_epochs": float(row.get("local_epochs", 0.0) or 0.0),
                "batch_size": int(row.get("batch_size", 0) or 0),
            }
        )

    record: dict[str, Any] = {
        "id": int(server_round),
        "label": f"Round {server_round} — live (this run)",
        "phase": "post_round_eval",
        "scenario": {
            "region": scenario["region"],
            "place": scenario["place"],
            "gps_wgs84": scenario["gps_wgs84"],
            "training_scene": scenario["training_scene"],
        },
        "centralized": {
            "accuracy": float(metrics.get("accuracy", 0.0)),
            "loss": float(loss),
            "precision_macro": float(metrics.get("precision_macro", 0.0)),
            "recall_macro": float(metrics.get("recall_macro", 0.0)),
            "test_windows": int(test_windows),
        },
        "telemetry_pooled": telemetry_pooled
        or {"battery_soc_mean": None, "cpu_util_mean": None},
        "rl_apc": {
            "trust_scores_0_100": [float(x) for x in trust_scores_0_100],
            "trust_mean": float(trust_mean),
            "threat_level": float(threat_level),
            "mission_criticality": float(mission_criticality),
                "resource_availability": float(resource_availability),
                "epsilon": float(next_policy.get("epsilon", 1.0 / max(float(next_policy.get("noise_scale", 0.65)), 1e-6))),
                "delta": float(next_policy.get("delta", 1e-5)),
                "clip_norm": float(next_policy.get("clip_norm", 1.0)),
                "next_policy": {
                    "participate": int(next_policy.get("participate", 1)),
                    "noise_scale": float(next_policy.get("noise_scale", 0.65)),
                    "freq_n": int(next_policy.get("freq_n", 1)),
                    "update_frequency": int(next_policy.get("freq_n", 1)),
                    "epsilon": float(next_policy.get("epsilon", 1.0 / max(float(next_policy.get("noise_scale", 0.65)), 1e-6))),
                    "delta": float(next_policy.get("delta", 1e-5)),
                    "clip_norm": float(next_policy.get("clip_norm", 1.0)),
                },
            },
        "fit_clients": fit_clients,
        "aggregation": aggregation or {},
    }
    if per_uav_next_policy:
        record["rl_apc"]["next_policy_per_uav"] = {
            str(k): {
                "participate": int(v["participate"]),
                "noise_scale": float(v["noise_scale"]),
                "freq_n": int(round(float(v["freq_n"]))),
                "update_frequency": int(round(float(v["freq_n"]))),
                "epsilon": float(v.get("epsilon", 1.0 / max(float(v["noise_scale"]), 1e-6))),
                "delta": float(v.get("delta", 1e-5)),
                "clip_norm": float(v.get("clip_norm", 1.0)),
            }
            for k, v in per_uav_next_policy.items()
        }

    _LIVE.parent.mkdir(parents=True, exist_ok=True)
    if _LIVE.is_file():
        data = json.loads(_LIVE.read_text(encoding="utf-8"))
    else:
        data = {"generated_at": _utc_now(), "rounds": []}
    rounds: list[dict[str, Any]] = [r for r in data.get("rounds", []) if int(r.get("id", -1)) != int(server_round)]
    rounds.append(record)
    rounds.sort(key=lambda r: int(r.get("id", 0)))
    data["rounds"] = rounds
    data["generated_at"] = _utc_now()
    _LIVE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
