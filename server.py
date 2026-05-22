import json
import os
import random
from pathlib import Path
from typing import Any

import numpy as np
import flwr as fl
import torch
import torch.nn as nn
from flwr.common import FitIns
from flwr.common import ndarrays_to_parameters, parameters_to_ndarrays
from sklearn.metrics import precision_recall_fscore_support

from model import CnnLstmIDS, set_model_parameters
from scenario_config import (
    TELEM_BATTERY_IDX,
    TELEM_CPU_IDX,
    format_scenario_block,
    scenario_for_round,
)
from apc_module import AdaptivePrivacyController
from RL_module import FLTrustRLBridge, build_client_states, client_threat_level
from RL_module.core import ACTION_NAMES, STATE_NAMES
from swarm_fl_data import NUM_CLIENTS, SWARM_DIR, load_global_test, load_meta

import dashboard_live

# Must match ServerConfig(num_rounds=...). After the final centralized eval, global weights are saved.
SERVER_NUM_ROUNDS = int(os.environ.get("FL_NUM_ROUNDS", "3"))
CHECKPOINT_DIR = Path(os.environ.get("FL_CHECKPOINT_DIR", "checkpoints"))
CHECKPOINT_LAST = CHECKPOINT_DIR / os.environ.get("FL_CHECKPOINT_FILE", "fl_global_last.pt")
RL_ENABLED = os.environ.get("FL_RL_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
APC_ENABLED = os.environ.get("FL_APC_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
RL_FIXED_TRUST_SCORE = float(os.environ.get("FL_RL_FIXED_TRUST_SCORE", "70.0"))
TRUST_CHECKPOINT = CHECKPOINT_DIR / os.environ.get("FL_TRUST_CHECKPOINT_FILE", "trustnet_last.pt")
DP_DELTA = float(os.environ.get("FL_DP_DELTA", "1e-5"))
DELTA_CLIP_NORM = float(os.environ.get("FL_DELTA_CLIP_NORM", "1.0"))


def _seed_from_env() -> None:
    raw = os.environ.get("FL_SEED")
    if not raw:
        return
    seed = int(raw)
    random.seed(seed)
    np.random.seed(seed % (2**32 - 1))
    torch.manual_seed(seed)


_seed_from_env()


def _eval_config(server_round: int) -> dict[str, float]:
    return {"server_round": float(server_round)}


X_te, y_te, NUM_CLASSES, N_FEATURES = load_global_test()
X_test = torch.tensor(X_te, dtype=torch.float32)
y_test = torch.tensor(y_te, dtype=torch.long)


def _fmt_pct_ratio(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x * 100:.2f}%"


def _fmt_pct_0_100(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x:.2f}%"


def _telemetry_summary_from_tensor(x: torch.Tensor) -> dict[str, float] | None:
    """Mean battery (%) and CPU (%) over test windows if telemetry channels exist."""
    if x.dim() != 3 or x.size(-1) <= TELEM_CPU_IDX:
        return None
    bat = float(x[:, :, TELEM_BATTERY_IDX].mean().item())
    cpu = float(x[:, :, TELEM_CPU_IDX].mean().item())
    return {"battery_soc_mean": bat, "cpu_util_mean": cpu}


def make_evaluate_fn(post_hooks: list, num_rounds: int):
    def evaluate(server_round, parameters, config):
        net = CnnLstmIDS(n_features=N_FEATURES, num_classes=NUM_CLASSES)
        set_model_parameters(net, parameters)

        net.eval()
        criterion = nn.CrossEntropyLoss()

        with torch.no_grad():
            logits = net(X_test)
            loss = criterion(logits, y_test).item()
            _, predicted = torch.max(logits.data, 1)

        y_true = y_test.cpu().numpy()
        y_pred = predicted.cpu().numpy()
        prec, rec, _, _ = precision_recall_fscore_support(
            y_true, y_pred, average="macro", zero_division=0
        )
        total = y_test.size(0)
        correct = (predicted == y_test).sum().item()
        accuracy = correct / total if total else 0.0

        sc = scenario_for_round(server_round)
        telem = _telemetry_summary_from_tensor(X_test)

        payload = {
            "phase": "centralized_eval",
            "server_round": int(server_round),
            "scenario": {
                "region": sc["region"],
                "place": sc["place"],
                "latitude_deg": sc["latitude_deg"],
                "longitude_deg": sc["longitude_deg"],
                "gps_wgs84": sc["gps_wgs84"],
                "training_scene": sc["training_scene"],
            },
            "test": {
                "windows": int(total),
                "path": str(SWARM_DIR / "test.npz"),
                "accuracy": accuracy,
                "loss": loss,
                "precision_macro": float(prec),
                "recall_macro": float(rec),
            },
        }
        if telem:
            payload["test_pooled_telemetry_mean"] = telem
            payload["test_pooled_telemetry_mean_fmt"] = {
                "battery_soc_mean": _fmt_pct_0_100(telem["battery_soc_mean"]),
                "cpu_util_mean": _fmt_pct_0_100(telem["cpu_util_mean"]),
            }
        payload["test_fmt"] = {
            "accuracy": _fmt_pct_ratio(accuracy),
            "precision_macro": _fmt_pct_ratio(float(prec)),
            "recall_macro": _fmt_pct_ratio(float(rec)),
        }

        print("\n" + "=" * 56)
        print(format_scenario_block(sc, title=f"[SERVER] round {server_round} — eval theatre"))
        print("-" * 56)
        print(
            "[SERVER] eval summary: "
            f"acc={_fmt_pct_ratio(accuracy)}  "
            f"precision_macro={_fmt_pct_ratio(float(prec))}  "
            f"recall_macro={_fmt_pct_ratio(float(rec))}  "
            f"loss={loss:.4f}"
        )
        if telem:
            print(
                "[SERVER] pooled telemetry mean: "
                f"battery={_fmt_pct_0_100(telem['battery_soc_mean'])}  "
                f"CPU={_fmt_pct_0_100(telem['cpu_util_mean'])}"
            )
        print("-" * 56)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("=" * 56 + "\n")

        metrics_out: dict[str, Any] = {
            "accuracy": accuracy,
            "precision_macro": float(prec),
            "recall_macro": float(rec),
        }
        if telem:
            metrics_out["battery_soc_mean"] = telem["battery_soc_mean"]
            metrics_out["cpu_util_mean"] = telem["cpu_util_mean"]
        for h in post_hooks:
            h(server_round, loss, metrics_out)

        if int(server_round) == int(num_rounds):
            CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
            meta = load_meta()
            payload_ckpt = {
                "state_dict": {k: v.detach().cpu() for k, v in net.state_dict().items()},
                "n_features": int(N_FEATURES),
                "num_classes": int(NUM_CLASSES),
                "saved_after_server_round": int(server_round),
                "label_names": list(meta.get("label_names", [])),
                "label_to_id": dict(meta.get("label_to_id", {})),
            }
            torch.save(payload_ckpt, CHECKPOINT_LAST)
            print(f"\n[SERVER] Saved global FL model for cross-domain eval -> {CHECKPOINT_LAST.resolve()}\n")

        return loss, metrics_out

    return evaluate


class LoggingFedAvg(fl.server.strategy.FedAvg):
    """FedAvg with structured console logs after each fit aggregation."""

    def aggregate_fit(self, server_round, results, failures):
        sc = scenario_for_round(server_round)
        rows: list[dict[str, Any]] = []
        for item in results or []:
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            cp, fit_res = item
            cid = getattr(cp, "cid", "?")
            metrics = getattr(fit_res, "metrics", None) or {}
            n_ex = int(getattr(fit_res, "num_examples", 0) or 0)
            rows.append(
                {
                    "client_id": cid,
                    "num_examples": n_ex,
                    "battery_soc_mean": metrics.get("battery_soc_mean"),
                    "cpu_util_mean": metrics.get("cpu_util_mean"),
                    "resource_availability": metrics.get("resource_availability"),
                    "latency_proxy": metrics.get("latency_proxy"),
                    "bandwidth_proxy": metrics.get("bandwidth_proxy"),
                    "participate": metrics.get("participate"),
                    "epsilon": metrics.get("epsilon"),
                    "delta": metrics.get("delta"),
                    "clip_norm": metrics.get("clip_norm"),
                    "delta_l2_norm_unclipped": metrics.get("delta_l2_norm_unclipped"),
                    "delta_clip_scale": metrics.get("delta_clip_scale"),
                    "local_epochs": metrics.get("local_epochs"),
                    "batch_size": metrics.get("batch_size"),
                    "simulated_dropout": metrics.get("simulated_dropout"),
                    "malicious_update": metrics.get("malicious_update"),
                    "battery_soc_mean_fmt": _fmt_pct_0_100(metrics.get("battery_soc_mean")),
                    "cpu_util_mean_fmt": _fmt_pct_0_100(metrics.get("cpu_util_mean")),
                }
            )

        fit_payload = {
            "phase": "fit_aggregate",
            "server_round": int(server_round),
            "scenario": {
                "region": sc["region"],
                "place": sc["place"],
                "latitude_deg": sc["latitude_deg"],
                "longitude_deg": sc["longitude_deg"],
                "gps_wgs84": sc["gps_wgs84"],
                "training_scene": sc["training_scene"],
            },
            "drones": rows,
            "failures": len(failures or []),
        }

        print("\n" + "=" * 56)
        print(format_scenario_block(sc, title=f"[SERVER] round {server_round} — fit complete"))
        print("-" * 56)
        if rows:
            joined = "  ".join(
                f"UAV-{r['client_id']}: battery={r['battery_soc_mean_fmt']} CPU={r['cpu_util_mean_fmt']}"
                for r in rows
            )
            print(f"[SERVER] client telemetry snapshot: {joined}")
            print("-" * 56)
        print(json.dumps(fit_payload, indent=2, ensure_ascii=False))
        print("=" * 56 + "\n")

        return super().aggregate_fit(server_round, results, failures)


class RLAPCFedAvg(LoggingFedAvg):
    """FedAvg + 日志：集中式评估后 SERVER→RL→APC；按**单机**信任与威胁调用 APC，经 configure_fit 下发。"""

    def __init__(
        self,
        *,
        apc: AdaptivePrivacyController,
        rl: FLTrustRLBridge | None,
        rl_enabled: bool = True,
        apc_enabled: bool = True,
        fixed_trust_score_0_100: float = 70.0,
        **kwargs: Any,
    ) -> None:
        self.apc = apc
        self.rl = rl
        self.rl_enabled = bool(rl_enabled)
        self.apc_enabled = bool(apc_enabled)
        self.fixed_trust_score_0_100 = float(np.clip(fixed_trust_score_0_100, 0.0, 100.0))
        self._pending_global_policy: dict[str, float] = {
            "participate": 1.0,
            "noise_scale": 0.65,
            "freq_n": 1.0,
        }
        self._pending_per_client: dict[int, dict[str, float]] = {
            i: {"participate": 1.0, "noise_scale": 0.65, "freq_n": 1.0} for i in range(NUM_CLIENTS)
        }
        self._last_fit_rows: list[dict[str, Any]] = []
        self._last_eval_acc: dict[int, float] = {}
        self._trust_by_cid: dict[int, float] = {i: self.fixed_trust_score_0_100 / 100.0 for i in range(NUM_CLIENTS)}
        self._anomaly_by_cid: dict[int, float] = {i: 0.0 for i in range(NUM_CLIENTS)}
        self._last_aggregation: dict[str, Any] = {}
        super().__init__(**kwargs, on_fit_config_fn=None)

    @staticmethod
    def _client_id_int(client: Any) -> int:
        raw = getattr(client, "cid", None)
        if raw is None:
            return -1
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            return -1

    def configure_fit(self, server_round: int, parameters, client_manager):
        sample_size, min_num_clients = self.num_fit_clients(client_manager.num_available())
        clients = client_manager.sample(num_clients=sample_size, min_num_clients=min_num_clients)
        pairs: list[tuple[Any, FitIns]] = []
        fb = self._pending_global_policy
        for client in clients:
            cid = self._client_id_int(client)
            pol = self._pending_per_client.get(cid, fb)
            cfg: dict[str, float] = {
                "server_round": float(server_round),
                "participate": float(pol["participate"]),
                "noise_scale": float(pol["noise_scale"]),
                "freq_n": float(pol["freq_n"]),
                "epsilon": float(pol.get("epsilon", 1.0 / max(float(pol["noise_scale"]), 1e-6))),
                "delta": float(pol.get("delta", DP_DELTA)),
                "clip_norm": float(pol.get("clip_norm", DELTA_CLIP_NORM)),
            }
            pairs.append((client, FitIns(parameters, cfg)))
        return pairs

    def _ingest_fit_rows(self, results: list | None) -> None:
        rows: list[dict[str, Any]] = []
        for item in results or []:
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            cp, fit_res = item
            metrics = getattr(fit_res, "metrics", None) or {}
            cid_int = -1
            if metrics.get("client_id") is not None:
                try:
                    cid_int = int(float(metrics["client_id"]))
                except (TypeError, ValueError):
                    cid_int = -1
            if cid_int < 0:
                raw_cid = getattr(cp, "cid", None)
                try:
                    cid_int = int(str(raw_cid)) if raw_cid is not None else -1
                except (TypeError, ValueError):
                    cid_int = -1
            n_ex = int(getattr(fit_res, "num_examples", 0) or 0)
            has_update = metrics.get("delta_l2_norm_unclipped") is not None
            if metrics.get("malicious_update"):
                self._anomaly_by_cid[cid_int] = 1.0
            elif has_update:
                self._anomaly_by_cid[cid_int] = 0.0
            elif cid_int >= 0:
                self._anomaly_by_cid[cid_int] = float(self._anomaly_by_cid.get(cid_int, 0.0) * 0.85)
            rows.append(
                {
                    "client_id": cid_int,
                    "num_examples": n_ex,
                    "battery_soc_mean": metrics.get("battery_soc_mean"),
                    "cpu_util_mean": metrics.get("cpu_util_mean"),
                    "resource_availability": metrics.get("resource_availability"),
                    "latency_proxy": metrics.get("latency_proxy"),
                    "bandwidth_proxy": metrics.get("bandwidth_proxy"),
                    "participate": metrics.get("participate"),
                    "epsilon": metrics.get("epsilon"),
                    "delta": metrics.get("delta"),
                    "clip_norm": metrics.get("clip_norm"),
                    "delta_l2_norm_unclipped": metrics.get("delta_l2_norm_unclipped"),
                    "delta_clip_scale": metrics.get("delta_clip_scale"),
                    "local_epochs": metrics.get("local_epochs"),
                    "batch_size": metrics.get("batch_size"),
                    "simulated_dropout": metrics.get("simulated_dropout"),
                    "malicious_update": metrics.get("malicious_update"),
                    "update_anomaly_memory": self._anomaly_by_cid.get(cid_int, 0.0),
                }
            )
        self._last_fit_rows = rows

    def aggregate_fit(self, server_round, results, failures):
        self._ingest_fit_rows(results)
        if not results:
            return None, {}
        if not self.accept_failures and failures:
            return None, {}
        if not self.apc_enabled:
            params, metrics = super().aggregate_fit(server_round, results, failures)
            self._last_aggregation = {
                "mode": "plain_fedavg",
                "effective_weights": {},
                "trust_scores": {},
                "resource_factors": {},
                "anomaly_factors": {},
                "malicious_weight_share": 0.0,
                "accepted_clients": len(results or []),
            }
            return params, metrics

        norm_values: list[float] = []
        metrics_by_cid: dict[int, dict[str, Any]] = {}
        for cp, fit_res in results:
            m = getattr(fit_res, "metrics", None) or {}
            cid = -1
            if m.get("client_id") is not None:
                try:
                    cid = int(float(m["client_id"]))
                except (TypeError, ValueError):
                    cid = -1
            if cid < 0:
                cid = self._client_id_int(cp)
            metrics_by_cid[cid] = m
            if m.get("delta_l2_norm_unclipped") is not None:
                norm_values.append(float(m["delta_l2_norm_unclipped"]))
        median_norm = float(np.median(norm_values)) if norm_values else 1.0
        median_norm = max(median_norm, 1e-6)

        weighted_results: list[tuple[list[np.ndarray], float]] = []
        diagnostics: dict[int, dict[str, float]] = {}
        malicious_weight = 0.0
        total_weight = 0.0
        for cp, fit_res in results:
            m = getattr(fit_res, "metrics", None) or {}
            cid = -1
            if m.get("client_id") is not None:
                try:
                    cid = int(float(m["client_id"]))
                except (TypeError, ValueError):
                    cid = -1
            if cid < 0:
                cid = self._client_id_int(cp)
            trust = float(np.clip(self._trust_by_cid.get(cid, self.fixed_trust_score_0_100 / 100.0), 0.05, 1.0))
            resource = m.get("resource_availability")
            resource_factor = float(np.clip(float(resource), 0.2, 1.0)) if resource is not None else 0.75
            norm = float(m.get("delta_l2_norm_unclipped") or median_norm)
            anomaly_factor = float(np.clip(median_norm / max(norm, median_norm), 0.15, 1.0))
            if m.get("malicious_update"):
                anomaly_factor *= 0.1
            if m.get("simulated_dropout"):
                anomaly_factor *= 0.2
            effective_weight = max(1e-6, float(fit_res.num_examples) * trust * resource_factor * anomaly_factor)
            weighted_results.append((parameters_to_ndarrays(fit_res.parameters), effective_weight))
            total_weight += effective_weight
            if m.get("malicious_update"):
                malicious_weight += effective_weight
            diagnostics[cid] = {
                "num_examples": float(fit_res.num_examples),
                "trust_score": trust,
                "resource_factor": resource_factor,
                "anomaly_factor": anomaly_factor,
                "effective_weight": effective_weight,
                "delta_l2_norm_unclipped": norm,
            }

        denom = max(total_weight, 1e-12)
        aggregated_ndarrays = [
            sum(layer * weight for layer, (_, weight) in zip(layers, weighted_results, strict=True)) / denom
            for layers in zip(*[weights for weights, _ in weighted_results], strict=True)
        ]
        params = ndarrays_to_parameters(aggregated_ndarrays)
        metrics: dict[str, Any] = {}
        self._last_aggregation = {
            "mode": "trust_weighted_fedavg",
            "effective_weights": {str(k): v["effective_weight"] for k, v in diagnostics.items()},
            "trust_scores": {str(k): v["trust_score"] for k, v in diagnostics.items()},
            "resource_factors": {str(k): v["resource_factor"] for k, v in diagnostics.items()},
            "anomaly_factors": {str(k): v["anomaly_factor"] for k, v in diagnostics.items()},
            "malicious_weight_share": float(malicious_weight / denom),
            "accepted_clients": len(results or []),
        }
        print("\n" + "=" * 56)
        print(f"[SERVER] trust-weighted aggregation round {server_round}")
        print("-" * 56)
        print(json.dumps(self._last_aggregation, indent=2, ensure_ascii=False))
        print("=" * 56 + "\n")
        return params, metrics

    def aggregate_evaluate(self, server_round, results, failures):
        acc: dict[int, float] = {}
        for item in results or []:
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            cp, er = item
            m = getattr(er, "metrics", None) or {}
            cid_int: int | None = None
            if m.get("client_id") is not None:
                try:
                    cid_int = int(float(m["client_id"]))
                except (TypeError, ValueError):
                    cid_int = None
            if cid_int is None:
                raw_cid = getattr(cp, "cid", None)
                try:
                    cid_int = int(str(raw_cid)) if raw_cid is not None else None
                except (TypeError, ValueError):
                    cid_int = None
            if cid_int is None or cid_int < 0:
                continue
            if "accuracy" in m:
                acc[cid_int] = float(m["accuracy"])
        self._last_eval_acc = acc
        return super().aggregate_evaluate(server_round, results, failures)

    def after_centralized_eval(
        self, server_round: int, loss: float, metrics: dict[str, Any]
    ) -> None:
        # Flower runs a centralized eval at server_round=0 on random-init weights before round-1 fit.
        # RL/APC must ignore that snapshot or APC will often set participate=0 for the first real round.
        if int(server_round) < 1:
            return

        prec = float(metrics.get("precision_macro", 0.5))
        threat = float(np.clip(1.0 - prec, 0.0, 1.0))
        states = build_client_states(
            NUM_CLIENTS, self._last_fit_rows, self._last_eval_acc, loss, prec
        )
        if self.rl_enabled and self.rl is not None:
            self.rl.observe_round_transition(states)
            scores = self.rl.trust_scores_0_100(states)
            phase = "rl_apc_closed_loop"
            trust_source = "trustnet_rl"
            CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
            self.rl.save(TRUST_CHECKPOINT)
        else:
            scores = np.full(NUM_CLIENTS, self.fixed_trust_score_0_100, dtype=np.float32)
            phase = "no_rl_fixed_trust_apc"
            trust_source = "fixed_trust_baseline"
        trust_mean = float(np.clip(float(np.mean(scores)) / 100.0, 0.0, 1.0))
        self._trust_by_cid = {
            cid: float(np.clip(float(scores[cid]) / 100.0, 0.05, 1.0))
            for cid in range(NUM_CLIENTS)
        }
        bats = [
            float(r["battery_soc_mean"])
            for r in self._last_fit_rows
            if r.get("battery_soc_mean") is not None
        ]
        resource_mean = (
            float(np.clip(np.mean(bats) / 100.0, 0.0, 1.0)) if bats else 0.72
        )
        sc_next = scenario_for_round(server_round + 1)
        crit_tbl = {
            "Beijing, China": 0.92,
            "Sudan": 0.74,
            "Tehran, Iran": 0.86,
            "Iran": 0.86,
        }
        mission = float(crit_tbl.get(sc_next.get("place", ""), 0.8))

        def _resource_for_cid(cid: int) -> float:
            row = next(
                (r for r in self._last_fit_rows if int(r.get("client_id", -1)) == cid),
                None,
            )
            if row and row.get("battery_soc_mean") is not None:
                if row.get("resource_availability") is not None:
                    return float(np.clip(float(row["resource_availability"]), 0.0, 1.0))
                return float(np.clip(float(row["battery_soc_mean"]) / 100.0, 0.0, 1.0))
            return resource_mean

        per_uav: dict[int, dict[str, float]] = {}
        per_uav_ctx: dict[int, dict[str, float]] = {}
        for cid in range(NUM_CLIENTS):
            trust_i = float(np.clip(float(scores[cid]) / 100.0, 0.0, 1.0))
            acc_i = float(self._last_eval_acc.get(cid, prec))
            threat_i = client_threat_level(threat, acc_i, blend_global=0.45)
            res_i = _resource_for_cid(cid)
            if self.apc_enabled:
                p_i = self.apc.decide(
                    threat_level=threat_i,
                    mission_criticality=mission,
                    trust_score=trust_i,
                    resource_availability=res_i,
                )
                participate = float(p_i.participation_level)
                noise_scale = float(p_i.noise_scale)
                freq_n = float(p_i.update_frequency)
            else:
                phase = "no_apc_fedavg_baseline"
                participate = 1.0
                noise_scale = 0.0
                freq_n = 1.0
            epsilon = float(1.0 / max(noise_scale, 1e-6)) if noise_scale > 0 else 1_000_000.0
            per_uav[cid] = {
                "participate": participate,
                "noise_scale": noise_scale,
                "freq_n": freq_n,
                "epsilon": epsilon,
                "delta": DP_DELTA,
                "clip_norm": DELTA_CLIP_NORM,
            }
            per_uav_ctx[cid] = {
                "threat_level": threat_i,
                "mission_criticality": mission,
                "trust_score": trust_i,
                "resource_availability": res_i,
                "epsilon": epsilon,
                "delta": DP_DELTA,
            }

        mean_freq = float(np.mean([per_uav[i]["freq_n"] for i in range(NUM_CLIENTS)]))
        mean_noise = float(np.mean([per_uav[i]["noise_scale"] for i in range(NUM_CLIENTS)]))
        min_part = int(min(int(per_uav[i]["participate"]) for i in range(NUM_CLIENTS)))
        self._pending_per_client = {k: dict(v) for k, v in per_uav.items()}
        self._pending_global_policy = {
            "participate": float(min_part),
            "noise_scale": mean_noise,
            "freq_n": mean_freq,
            "epsilon": float(1.0 / max(mean_noise, 1e-6)) if mean_noise > 0 else 1_000_000.0,
            "delta": DP_DELTA,
            "clip_norm": DELTA_CLIP_NORM,
        }

        payload = {
            "phase": phase,
            "ablation": {
                "apc_enabled": self.apc_enabled,
                "rl_enabled": self.rl_enabled,
                "trust_source": trust_source,
                "fixed_trust_score_0_100": None
                if self.rl_enabled
                else self.fixed_trust_score_0_100,
            },
            "after_server_round": int(server_round),
            "next_fit_policy_per_uav": {
                str(k): {
                    "participation": int(v["participate"]),
                    "update_frequency": int(v["freq_n"]),
                    "participate": int(v["participate"]),
                    "freq_n": int(v["freq_n"]),
                    "noise_scale": float(v["noise_scale"]),
                    "epsilon": float(v["epsilon"]),
                    "delta": float(v["delta"]),
                    "clip_norm": float(v["clip_norm"]),
                }
                for k, v in per_uav.items()
            },
            "trust_scores_0_100": [float(scores[i]) for i in range(len(scores))],
            "rl_state_names": STATE_NAMES,
            "rl_state_rows": states.tolist(),
            "rl_action_names": ACTION_NAMES,
            "rl_last_rewards": list(getattr(self.rl, "last_rewards", [])) if self.rl else [],
            "aggregation": self._last_aggregation,
            "apc_context_global": {
                "threat_level_macro": threat,
                "mission_criticality": mission,
                "trust_score_mean": trust_mean,
                "resource_availability_mean": resource_mean,
                "epsilon_mean": self._pending_global_policy["epsilon"],
                "delta": DP_DELTA,
            },
            "apc_context_per_uav": {str(k): per_uav_ctx[k] for k in sorted(per_uav_ctx)},
        }
        print("\n" + "=" * 56)
        print(f"[SERVER] APC policy update ({phase}; next fit config is ready)")
        print("-" * 56)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("=" * 56 + "\n")

        sc_cur = scenario_for_round(server_round)
        telem_pooled = None
        if X_test.dim() == 3 and X_test.size(-1) > TELEM_CPU_IDX:
            telem_pooled = _telemetry_summary_from_tensor(X_test)
        elif metrics.get("battery_soc_mean") is not None:
            telem_pooled = {
                "battery_soc_mean": float(metrics["battery_soc_mean"]),
                "cpu_util_mean": float(metrics["cpu_util_mean"]),
            }
        # Some Flower versions invoke centralized eval with server_round=0 before round 1;
        # skip live JSON so dashboard rounds stay aligned with FL rounds 1–3 and scenario theatres.
        if int(server_round) >= 1:
            dashboard_live.append_live_round(
                server_round=server_round,
                scenario=sc_cur,
                loss=loss,
                metrics=metrics,
                test_windows=int(X_test.size(0)),
                telemetry_pooled=telem_pooled,
                fit_rows=list(self._last_fit_rows),
                eval_acc=dict(self._last_eval_acc),
                trust_scores_0_100=[float(scores[i]) for i in range(len(scores))],
                trust_mean=trust_mean,
                threat_level=threat,
                mission_criticality=mission,
                resource_availability=resource_mean,
                next_policy={
                    "participate": min_part,
                    "noise_scale": mean_noise,
                    "freq_n": int(round(mean_freq)),
                    "epsilon": self._pending_global_policy["epsilon"],
                    "delta": DP_DELTA,
                    "clip_norm": DELTA_CLIP_NORM,
                },
                per_uav_next_policy=per_uav,
                aggregation=dict(self._last_aggregation),
            )
_eval_post_hooks: list[Any] = []


def _build_rl_bridge() -> FLTrustRLBridge | None:
    if not RL_ENABLED:
        return None
    bridge = FLTrustRLBridge(NUM_CLIENTS)
    if os.environ.get("FL_TRUST_RESUME", "1").strip().lower() not in {"0", "false", "no", "off"}:
        if bridge.load(TRUST_CHECKPOINT):
            print(f"[SERVER] Loaded TrustNet checkpoint -> {TRUST_CHECKPOINT.resolve()}")
    return bridge

_kw_base = dict(
    min_fit_clients=3,
    min_available_clients=3,
    min_evaluate_clients=2,
    evaluate_fn=make_evaluate_fn(_eval_post_hooks, SERVER_NUM_ROUNDS),
)
try:
    strategy = RLAPCFedAvg(
        apc=AdaptivePrivacyController(),
        rl=_build_rl_bridge(),
        rl_enabled=RL_ENABLED,
        apc_enabled=APC_ENABLED,
        fixed_trust_score_0_100=RL_FIXED_TRUST_SCORE,
        **_kw_base,
        on_evaluate_config_fn=_eval_config,
    )
    _eval_post_hooks.append(strategy.after_centralized_eval)
except TypeError:
    strategy = RLAPCFedAvg(
        apc=AdaptivePrivacyController(),
        rl=_build_rl_bridge(),
        rl_enabled=RL_ENABLED,
        apc_enabled=APC_ENABLED,
        fixed_trust_score_0_100=RL_FIXED_TRUST_SCORE,
        **_kw_base,
    )
    _eval_post_hooks.append(strategy.after_centralized_eval)


if __name__ == "__main__":
    dashboard_live.reset_live_dashboard()
    load_meta()
    if not APC_ENABLED:
        ablation_mode = "no APC (plain FedAvg baseline)"
    else:
        ablation_mode = "with RL trust bridge" if RL_ENABLED else "no RL (fixed trust baseline)"
    print("[SERVER] Swarm UAV IDS (CNN+LSTM) + FedAvg + APC")
    print(f"   ablation mode: {ablation_mode}")
    print(f"   data: {SWARM_DIR}  X_test shape={tuple(X_test.shape)}  n_features={N_FEATURES}")
    print()
    for r in range(1, SERVER_NUM_ROUNDS + 1):
        s = scenario_for_round(r)
        print(f"   preset round {r}: {s['region']} / {s['place']}  GPS {s['gps_wgs84']}")
    print()

    fl.server.start_server(
        server_address="127.0.0.1:8080",
        config=fl.server.ServerConfig(num_rounds=SERVER_NUM_ROUNDS),
        strategy=strategy,
    )
