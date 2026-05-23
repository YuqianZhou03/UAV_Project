"""Single-shot UAV edge workflow simulation for the dashboard API.

Each call simulates **three edge UAV clients** in parallel: each builds a synthetic **batch**
from ``test.npz`` windows whose **argmax under the loaded checkpoint** matches the intended
benign vs alert side, aligns batches with light noise, then uplinks to APC.

The federated checkpoint may **never** predict the dataset label ``Normal`` as argmax; we still calibrate a **non-alert argmax id**
for the boolean decision ``attack_detected``. **User-facing** ``prediction`` when there is no alert is always the dataset label
``Normal``; only when ``attack_detected`` do we show the model's argmax class name (e.g. MITM, DDoS).
"""

from __future__ import annotations

import json
import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn

from apc_module import AdaptivePrivacyController
from model import CnnLstmIDS, set_model_parameters
from scenario_config import TELEM_BATTERY_IDX, TELEM_CPU_IDX

REPO = Path(__file__).resolve().parent
SWARM = REPO / "data" / "swarm_processed"
META_PATH = SWARM / "meta.json"
TEST_NPZ = SWARM / "test.npz"
CKPT_PATH = REPO / "checkpoints" / "fl_global_last.pt"

N_EDGE_UAVS = 3

# Target softmax margin at the scored batch row (center window).
_MIN_ALIGN_CONF = 0.68
_MIN_ALIGN_CONF_RELAX = 0.52  # used only if the pool cannot reach _MIN_ALIGN_CONF
_MAX_POOL_BRUTE = 8000
_SCORE_SAMPLE = 2400


def _init_demo_weights(m: nn.Module) -> None:
    """Re-seeded random init when no federated checkpoint is available."""
    if isinstance(m, nn.Linear):
        nn.init.xavier_uniform_(m.weight)
        if m.bias is not None:
            nn.init.zeros_(m.bias)
    elif isinstance(m, nn.Conv1d):
        nn.init.kaiming_uniform_(m.weight, nonlinearity="relu")
        if m.bias is not None:
            nn.init.zeros_(m.bias)
    elif isinstance(m, nn.LSTM):
        for p in m.parameters():
            nn.init.uniform_(p, -0.08, 0.08)


def _feature_stds(X_all: np.ndarray) -> np.ndarray:
    v = X_all.reshape(-1, X_all.shape[-1]).astype(np.float64)
    s = v.std(axis=0).astype(np.float32)
    return np.maximum(s, 1e-3)


def _load_meta() -> dict[str, Any]:
    if not META_PATH.is_file():
        raise FileNotFoundError(f"Missing {META_PATH}")
    return json.loads(META_PATH.read_text(encoding="utf-8"))


def _label_names(meta: dict[str, Any]) -> list[str]:
    names = meta.get("label_names")
    if not isinstance(names, list) or not names:
        raise ValueError("meta.json missing label_names")
    return [str(x) for x in names]


def _attack_indices(y: np.ndarray, lid_normal: int) -> np.ndarray:
    return np.flatnonzero(y.astype(np.int64) != int(lid_normal)).astype(np.int64)


def _normal_indices(y: np.ndarray, lid_normal: int) -> np.ndarray:
    return np.flatnonzero(y.astype(np.int64) == int(lid_normal)).astype(np.int64)


def _indices_for_class(y: np.ndarray, class_id: int) -> np.ndarray:
    return np.flatnonzero(y.astype(np.int64) == int(class_id)).astype(np.int64)


def _pick_proto_index(
    y: np.ndarray, meta: dict[str, Any], mode: str, rng: np.random.Generator
) -> tuple[int, bool, bool]:
    """Return (prototype_index, benign_traffic_seed, drew_from_attack_pool)."""
    lid_normal = meta_label_id(meta, "Normal")
    attacks = _attack_indices(y, lid_normal)
    normals = _normal_indices(y, lid_normal)
    if y.size == 0:
        raise ValueError("Empty label array")
    if mode == "normal":
        if normals.size == 0:
            raise ValueError("No Normal window in test set")
        return int(rng.choice(normals)), True, False
    if mode == "attack":
        if attacks.size == 0:
            raise ValueError("No attack window in test set")
        return int(rng.choice(attacks)), False, True
    if normals.size and attacks.size:
        benign = bool(rng.random() < 0.58)
    elif normals.size:
        benign = True
    elif attacks.size:
        benign = False
    else:
        raise ValueError("No usable labels in test set")
    if benign:
        return int(rng.choice(normals)), True, False
    return int(rng.choice(attacks)), False, True


def meta_label_id(meta: dict[str, Any], name: str) -> int:
    m = meta.get("label_to_id")
    if not isinstance(m, dict) or name not in m:
        raise KeyError(f"label_to_id missing {name!r}")
    return int(m[name])


def _load_checkpoint_list() -> list[np.ndarray] | None:
    if not CKPT_PATH.is_file():
        return None
    obj = torch.load(CKPT_PATH, map_location="cpu", weights_only=False)
    if isinstance(obj, list) and obj and all(isinstance(x, np.ndarray) for x in obj):
        return obj
    if isinstance(obj, dict) and "state_dict" in obj:
        return [v.cpu().numpy() for v in obj["state_dict"].values()]
    if isinstance(obj, dict):
        return [v.cpu().numpy() for v in obj.values()]
    return None


def _center_probs(
    net: nn.Module, X_np: np.ndarray, center_rel: int
) -> tuple[torch.Tensor, int, int]:
    """Return (probs vector at center row, batch_size, clipped_center)."""
    xt = torch.tensor(X_np, dtype=torch.float32)
    with torch.no_grad():
        pr = torch.softmax(net(xt), dim=-1)
    b = int(pr.size(0))
    cr = int(np.clip(center_rel, 0, b - 1))
    return pr[cr], b, cr


def _homogeneous_argmax(
    net: nn.Module,
    X_all: np.ndarray,
    j: int,
    batch_sz: int,
    center_rel: int,
) -> int:
    w = np.asarray(X_all[int(j)], dtype=np.float32)
    Xh = np.repeat(w[None, ...], batch_sz, axis=0)
    pc, _, _ = _center_probs(net, Xh, center_rel)
    return int(pc.argmax().item())


def _infer_non_attack_argmax(
    net: nn.Module, X_all: np.ndarray, y_all: np.ndarray, lid_normal: int
) -> int:
    """Argmax class the model most often outputs on windows labelled Normal in ``y_all``."""
    normals = _normal_indices(y_all, lid_normal)
    if normals.size == 0:
        raise ValueError("No Normal-labelled rows in y_test; cannot calibrate IDS benign margin.")
    ctr: Counter[int] = Counter()
    cap = min(int(normals.size), 4000)
    for j in normals[:cap]:
        xt = torch.tensor(X_all[int(j) : int(j) + 1], dtype=torch.float32)
        with torch.no_grad():
            pr = torch.softmax(net(xt), dim=-1)[0]
        ctr[int(pr.argmax().item())] += 1
    return ctr.most_common(1)[0][0]


def _collect_model_pools(
    net: nn.Module,
    X_all: np.ndarray,
    non_attack_id: int,
    rng: np.random.Generator,
    *,
    batch_sz: int,
    center_rel: int,
    max_probe: int,
    cap_each: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Indices whose homogeneous repeated batch has center argmax == / != ``non_attack_id``."""
    n = int(len(X_all))
    benign: list[int] = []
    attack: list[int] = []
    for _ in range(max(1, max_probe)):
        if len(benign) >= cap_each and len(attack) >= cap_each:
            break
        j = int(rng.integers(0, n))
        aid = _homogeneous_argmax(net, X_all, j, batch_sz, center_rel)
        if aid == int(non_attack_id):
            benign.append(j)
        else:
            attack.append(j)
    return np.asarray(benign, dtype=np.int64), np.asarray(attack, dtype=np.int64)


def _score_window_as_batch(
    net: nn.Module,
    X_all: np.ndarray,
    j: int,
    batch_b: int,
    center_rel: int,
    *,
    benign_proto: bool,
    non_attack_id: int,
) -> tuple[float, int]:
    w = np.asarray(X_all[int(j)], dtype=np.float32)
    Xb = np.repeat(w[None, ...], batch_b, axis=0)
    pc, _, _ = _center_probs(net, Xb, center_rel)
    pred = int(pc.argmax().item())
    if benign_proto:
        return float(pc[int(non_attack_id)].item()), pred
    return float(1.0 - pc[int(non_attack_id)].item()), pred


def _sampled_pool_best(
    net: nn.Module,
    X_all: np.ndarray,
    pool: np.ndarray,
    *,
    benign_proto: bool,
    non_attack_id: int,
    batch_b: int,
    center_rel: int,
    rng: np.random.Generator,
    n_samples: int,
) -> tuple[int, float, int]:
    """Pick j from pool (random subset) maximizing alignment score."""
    if pool.size == 0:
        raise ValueError("empty class pool")
    n = int(min(pool.size, max(1, n_samples)))
    if pool.size > n:
        pick = rng.choice(pool, size=n, replace=False)
    else:
        pick = pool.astype(np.int64, copy=False)
    best_j = int(pick[0])
    best_sc, best_pred = _score_window_as_batch(
        net, X_all, best_j, batch_b, center_rel, benign_proto=benign_proto, non_attack_id=non_attack_id
    )
    for j in pick[1:]:
        jj = int(j)
        sc, prd = _score_window_as_batch(
            net, X_all, jj, batch_b, center_rel, benign_proto=benign_proto, non_attack_id=non_attack_id
        )
        if sc > best_sc:
            best_sc = sc
            best_j = jj
            best_pred = prd
    return best_j, best_sc, best_pred


def _build_diversified_batch(
    X_all: np.ndarray,
    pool: np.ndarray,
    center_w: np.ndarray,
    batch_sz: int,
    center_rel: int,
    rng: np.random.Generator,
) -> np.ndarray:
    """Center row = best window; other rows = random same-class windows (i.i.d.)."""
    out = np.empty((batch_sz, int(center_w.shape[0]), int(center_w.shape[1])), dtype=np.float32)
    for bi in range(batch_sz):
        out[bi] = np.asarray(X_all[int(rng.choice(pool))], dtype=np.float32)
    cr = int(np.clip(center_rel, 0, batch_sz - 1))
    out[cr] = center_w.astype(np.float32)
    return out


def _finalize_diversified_batch(
    net: nn.Module,
    X_all: np.ndarray,
    fill_pool: np.ndarray,
    center_w: np.ndarray,
    batch_sz: int,
    center_rel: int,
    rng: np.random.Generator,
    *,
    benign_proto: bool,
    non_attack_id: int,
    max_tries: int = 512,
) -> tuple[np.ndarray, torch.Tensor, int]:
    """Resample filler rows until center argmax matches intent; else homogeneous repeat."""
    cw = np.asarray(center_w, dtype=np.float32)
    sid = int(non_attack_id)
    for _ in range(max(1, max_tries)):
        Xb = _build_diversified_batch(X_all, fill_pool, cw, batch_sz, center_rel, rng)
        pc, _, cr = _center_probs(net, Xb, center_rel)
        pid = int(pc.argmax().item())
        if benign_proto:
            if pid == sid:
                return Xb, pc, cr
        elif pid != sid:
            return Xb, pc, cr
    Xh = np.repeat(cw[None, ...], batch_sz, axis=0)
    pc, _, cr = _center_probs(net, Xh, center_rel)
    return Xh, pc, cr


def _simulate_uav_edge(
    uav_id: int,
    *,
    mode: str,
    rng: np.random.Generator,
    net: nn.Module,
    inference_mode: str,
    meta: dict[str, Any],
    names: list[str],
    X_all: np.ndarray,
    X_noisy_all: np.ndarray,
    y_all: np.ndarray,
    non_attack_id: int,
) -> dict[str, Any]:
    """One UAV: sample random noisy windows and decide from aggregated CNN-LSTM outputs."""
    idx, benign_proto, from_attack_pool = _pick_proto_index(y_all, meta, mode, rng)
    true_id = int(y_all[idx])
    lid_normal = meta_label_id(meta, "Normal")
    sid = int(non_attack_id)

    batch_sz = int(rng.integers(16, min(65, max(17, len(X_all)))))
    batch_sz = min(batch_sz, len(X_all))
    # Keep each UAV batch class-consistent so simulated accuracy reflects
    # noisy-window inference quality of the checkpointed CNN-LSTM.
    class_pool = _indices_for_class(y_all, true_id)
    if class_pool.size > 0:
        pool = class_pool
    else:
        normals = _normal_indices(y_all, lid_normal)
        attacks = _attack_indices(y_all, lid_normal)
        if benign_proto and normals.size > 0:
            pool = normals
        elif (not benign_proto) and attacks.size > 0:
            pool = attacks
        else:
            pool = np.arange(len(X_all), dtype=np.int64)
    if pool.size == 0:
        raise ValueError("empty test pool for UAV simulation")

    sampled_idx = rng.choice(pool, size=batch_sz, replace=pool.size < batch_sz)
    sampled_idx = np.asarray(sampled_idx, dtype=np.int64)
    X_np = np.asarray(X_noisy_all[sampled_idx], dtype=np.float32)

    center_idx = int(idx)
    center_rel = -1
    true_name = names[true_id] if 0 <= true_id < len(names) else str(true_id)

    xt = torch.tensor(X_np, dtype=torch.float32)
    with torch.no_grad():
        probs = torch.softmax(net(xt), dim=-1)
    mean_probs = probs.mean(dim=0)
    vote_ids = probs.argmax(dim=1)
    uniq_pred, cnt_pred = np.unique(vote_ids.cpu().numpy(), return_counts=True)
    pred_id = int(uniq_pred[int(np.argmax(cnt_pred))]) if uniq_pred.size else int(mean_probs.argmax().item())
    align_loops = 1

    # Also keep a simple per-window vote signal for traceability.
    attack_vote_ratio = float((vote_ids != sid).float().mean().item())

    pred_name = names[pred_id] if 0 <= pred_id < len(names) else str(pred_id)
    detected_attack = pred_id != sid
    attack_name = pred_name if detected_attack else ""
    normal_display = names[lid_normal] if 0 <= lid_normal < len(names) else "Normal"
    display_pred = normal_display if not detected_attack else pred_name

    return {
        "uav_id": uav_id,
        "prototype_index": center_idx,
        "benign_traffic_seed": benign_proto,
        "drew_attack_pool": from_attack_pool,
        "true_label": true_name,
        "batch_size": int(X_np.shape[0]),
        "center_batch_index": int(center_rel),
        "prediction": display_pred,
        "attack_detected": detected_attack,
        "attack_label": attack_name,
        "attack_vote_ratio": attack_vote_ratio,
        "alignment_iters": int(align_loops),
        "inference_mode": inference_mode,
    }


def run_uav_workflow(*, mode: str = "auto", seed: int | None = None) -> dict[str, Any]:
    """Run end-to-end simulation for **three** edge UAVs; returns structured steps (zh+en)."""
    mode = (mode or "auto").strip().lower()
    if mode not in {"auto", "attack", "normal"}:
        mode = "auto"

    rng = np.random.default_rng(seed)
    run_id = secrets.token_hex(6)
    generated_at = datetime.now(timezone.utc).isoformat()

    meta = _load_meta()
    names = _label_names(meta)
    num_classes = int(meta["num_classes"])
    n_features = int(meta["n_features"])
    if not TEST_NPZ.is_file():
        raise FileNotFoundError(f"Missing {TEST_NPZ}")

    d = np.load(TEST_NPZ, allow_pickle=True)
    X_all = np.asarray(d["X_test"], dtype=np.float32)
    y_all = np.asarray(d["y_test"], dtype=np.int64)

    feat_std = _feature_stds(X_all)
    lim_lo = float(np.quantile(X_all.astype(np.float64), 0.005))
    lim_hi = float(np.quantile(X_all.astype(np.float64), 0.995))
    # Add light Gaussian noise on telemetry channels only. This keeps the IDS
    # feature semantics stable while still simulating onboard measurement noise.
    X_noisy_all = np.asarray(X_all, dtype=np.float32).copy()
    for ci in (TELEM_BATTERY_IDX, TELEM_CPU_IDX):
        if 0 <= int(ci) < X_noisy_all.shape[-1]:
            ch_std = max(float(feat_std[int(ci)]), 1e-3)
            eps = rng.standard_normal(X_noisy_all[:, :, int(ci)].shape).astype(np.float32)
            X_noisy_all[:, :, int(ci)] += eps * (0.05 * ch_std)
    X_noisy_all = np.clip(X_noisy_all, lim_lo, lim_hi).astype(np.float32)

    ckpt = _load_checkpoint_list()
    net = CnnLstmIDS(n_features=n_features, num_classes=num_classes)
    if ckpt is not None:
        set_model_parameters(net, ckpt)
        inference_mode = "checkpoint_synth_batch"
    else:
        torch.manual_seed(int(rng.integers(0, 2**31 - 2, dtype=np.int64)))
        net.apply(_init_demo_weights)
        inference_mode = "synth_batch_random_init"

    net.eval()
    lid_normal = meta_label_id(meta, "Normal")
    non_attack_id = int(_infer_non_attack_argmax(net, X_all, y_all, lid_normal))
    sid_name = names[non_attack_id] if 0 <= non_attack_id < len(names) else str(non_attack_id)

    uav_results: list[dict[str, Any]] = []
    for uid in range(N_EDGE_UAVS):
        uav_results.append(
            _simulate_uav_edge(
                uid,
                mode=mode,
                rng=rng,
                net=net,
                inference_mode=inference_mode,
                meta=meta,
                names=names,
                X_all=X_all,
                X_noisy_all=X_noisy_all,
                y_all=y_all,
                non_attack_id=non_attack_id,
            )
        )

    server_round = int(rng.integers(1, 40))
    fit_cfg_per_uav: dict[str, dict[str, Any]] = {}
    for uid in range(N_EDGE_UAVS):
        fit_cfg_per_uav[str(uid)] = {
            "participate": int(rng.integers(0, 2)),
            "noise_scale": float(round(float(rng.uniform(0.22, 0.92)), 3)),
            "freq_n": int(rng.integers(1, 5)),
        }

    apc = AdaptivePrivacyController(str(REPO / "apc_module" / "config.yaml"))
    policy_before_per_uav: dict[str, dict[str, Any]] = {
        str(uid): {
            "participate": int(fit_cfg_per_uav[str(uid)]["participate"]),
            "noise_scale": float(fit_cfg_per_uav[str(uid)]["noise_scale"]),
            "freq_n": int(fit_cfg_per_uav[str(uid)]["freq_n"]),
        }
        for uid in range(N_EDGE_UAVS)
    }
    policy_after_per_uav: dict[str, dict[str, Any]] = {}
    threat_rows: list[dict[str, object]] = []

    for u in uav_results:
        uid = int(u["uav_id"])
        tb = float(np.clip(rng.uniform(0.06, 0.30) + 0.03 * float(u["attack_detected"]), 0.0, 1.0))
        if u["attack_detected"]:
            ta = float(np.clip(tb + float(rng.uniform(0.18, 0.32)) + 0.48 * 0.55, 0.42, 0.99))
        else:
            ta = float(np.clip(tb + float(rng.uniform(-0.05, 0.06)), 0.0, 0.26))
        mission = float(np.clip(rng.uniform(0.55, 0.97), 0.0, 1.0))
        trust = float(np.clip(0.78 - 0.09 * uid + rng.uniform(-0.06, 0.06), 0.0, 1.0))
        resource = float(np.clip(rng.uniform(0.42, 0.95), 0.0, 1.0))
        p1 = apc.decide(
            threat_level=ta,
            mission_criticality=mission,
            trust_score=trust,
            resource_availability=resource,
        )
        policy_after_per_uav[str(uid)] = {
            "participate": int(p1.participation_level),
            "noise_scale": float(p1.noise_scale),
            "freq_n": int(p1.update_frequency),
        }
        threat_rows.append({"uav_id": int(uid), "threat_before": tb, "threat_after": ta})

    lines_zh_tr: list[str] = []
    lines_en_tr: list[str] = []
    for u in uav_results:
        slzh = "良性原型" if u["benign_traffic_seed"] else "攻击类原型"
        slen = "benign proto" if u["benign_traffic_seed"] else "attack proto"
        lines_zh_tr.append(
            f"无人机{u['uav_id']}：新生成 {u['batch_size']} 窗，原型{u['prototype_index']}「{u['true_label']}」（{slzh}），推理 {u['inference_mode']}。"
        )
        lines_en_tr.append(
            f"UAV {u['uav_id']}: windows={u['batch_size']}, sample={u['prototype_index']}, "
            f"label={u['true_label']} ({slen}), mode={u['inference_mode']}."
        )

    lines_zh_v: list[str] = []
    lines_en_v: list[str] = []
    normal_disp = names[lid_normal] if 0 <= lid_normal < len(names) else "Normal"
    for u in uav_results:
        if u["attack_detected"]:
            lines_zh_v.append(f"无人机{u['uav_id']}：IDS 告警，预测类「{u['attack_label']}」（argmax）。")
            lines_en_v.append(f"UAV {u['uav_id']}: IDS alert, class «{u['attack_label']}» (argmax).")
        else:
            lines_zh_v.append(f"无人机{u['uav_id']}：IDS 无告警，类别上报为「{normal_disp}」。")
            lines_en_v.append(f"UAV {u['uav_id']}: No IDS alert; class «{normal_disp}».")

    tc_zh = "；".join(
        [f"UAV{int(tr['uav_id'])}威胁 {tr['threat_before']:.3f}→{tr['threat_after']:.3f}" for tr in threat_rows]
    )
    tc_en = "\n".join(
        [f"UAV{int(tr['uav_id'])} threat {tr['threat_before']:.3f}→{tr['threat_after']:.3f}" for tr in threat_rows]
    )

    steps: list[dict[str, Any]] = [
        {
            "id": "server_config",
            "title_zh": "① 服务器向三机下发 fit 配置",
            "title_en": "① Server broadcasts fit config to 3 UAVs",
            "body_zh": "联邦服务端将下一轮 on_fit_config（participate / noise_scale / freq_n 等）分别下发至三架边缘无人机终端。",
            "body_en": "The federated server pushes per-client on_fit_config (participate, noise_scale, freq_n, …) to three edge UAV terminals.",
            "kv": {
                "run_id": run_id,
                "server_round": server_round,
                "edge_uav_count": N_EDGE_UAVS,
                "fit_config_per_uav": fit_cfg_per_uav,
                "generated_at_utc": generated_at,
            },
        },
        {
            "id": "local_traffic",
            "title_zh": "② 三机并行：各自生成流量窗口并运行本地 IDS",
            "title_en": "② Three UAVs: parallel synthetic traffic + local IDS",
            "body_zh": "\n".join(lines_zh_tr),
            "body_en": "\n".join(lines_en_tr),
            "kv": {
                "traffic_mode": "model_calibrated_pools",
                "edge_uav_count": N_EDGE_UAVS,
                "per_uav": [
                    {
                        "uav_id": u["uav_id"],
                        "batch_size": u["batch_size"],
                        "prototype_index": u["prototype_index"],
                        "true_label": u["true_label"],
                        "benign_traffic_seed": u["benign_traffic_seed"],
                        "center_batch_index": u["center_batch_index"],
                        "attack_vote_ratio": u["attack_vote_ratio"],
                        "alignment_iters": u["alignment_iters"],
                    }
                    for u in uav_results
                ],
                "has_checkpoint": ckpt is not None,
                "inference_mode": inference_mode,
                "generated_at_utc": generated_at,
            },
        },
        {
            "id": "local_verdicts",
            "title_zh": "③ 三机本地 IDS 判定（相互独立）",
            "title_en": "③ Per-UAV IDS verdicts",
            "body_zh": "\n".join(lines_zh_v),
            "body_en": "\n".join(lines_en_v),
            "kv": {
                "uavs": [
                    {
                        "uav_id": u["uav_id"],
                        "attack_detected": u["attack_detected"],
                        "attack_label": u["attack_label"],
                        "prediction": u["prediction"],
                        "true_label": u["true_label"],
                        "benign_traffic_seed": u["benign_traffic_seed"],
                    }
                    for u in uav_results
                ]
            },
        },
        {
            "id": "uplink",
            "title_zh": "④ 三路上行汇总至服务器",
            "title_en": "④ Three uplinks to the server",
            "body_zh": "各机将 IDS 结论与元数据上报；服务器聚合成集群态势后送入 APC。",
            "body_en": "Each UAV uplinks its IDS verdict; the server aggregates fleet context for APC.",
            "kv": {
                "reports": [
                    {
                        "uav_id": u["uav_id"],
                        "kind": "edge_security_report",
                        "attack_detected": u["attack_detected"],
                        "attack_class": u["attack_label"] if u["attack_detected"] else None,
                        "prototype_index": u["prototype_index"],
                        "traffic_mode": "model_calibrated_pools",
                    }
                    for u in uav_results
                ]
            },
        },
        {
            "id": "apc",
            "title_zh": "⑤ APC 分机给出下一轮策略 → 服务器下发各机",
            "title_en": "⑤ APC per-UAV policy → server pushes to each UAV",
            "body_zh": "AdaptivePrivacyController 在收到各机 IDS 上报后，按更新后的威胁度上下文独立给出下一轮 participate / noise_scale / freq_n。"
            f"policy_before 与步骤①中的 fit_config 逐项一致，表示上报前各机已在执行的策略；policy_after 为 APC 新策略。"
            f"威胁演变：{tc_zh}。",
            "body_en": "AdaptivePrivacyController emits per-UAV next-round participate / noise_scale / freq_n from post-uplink threat context.\n"
            "policy_before matches step ① fit_config (in-flight policy before this uplink).\n"
            "policy_after is the new APC output.\n"
            f"Threat deltas:\n{tc_en}",
            "kv": {
                "edge_uav_count": N_EDGE_UAVS,
                "threat_per_uav": threat_rows,
                "policy_before_per_uav": policy_before_per_uav,
                "policy_after_per_uav": policy_after_per_uav,
            },
        },
    ]

    any_attack = any(bool(u["attack_detected"]) for u in uav_results)
    atk_parts = [f"UAV{u['uav_id']}:{u['attack_label']}" for u in uav_results if u["attack_detected"]]
    attack_label_agg = " · ".join(atk_parts) if atk_parts else ""
    true_label_agg = " · ".join([f"UAV{u['uav_id']}:{u['true_label']}" for u in uav_results])
    n_atk = sum(1 for u in uav_results if u["attack_detected"])

    return {
        "ok": True,
        "run_id": run_id,
        "rng_seed": seed,
        "generated_at": generated_at,
        "mode": mode,
        "num_uavs": N_EDGE_UAVS,
        "uavs": [
            {
                "uav_id": u["uav_id"],
                "attack_detected": u["attack_detected"],
                "attack_label": u["attack_label"],
                "prediction": u["prediction"],
                "true_label": u["true_label"],
                "prototype_index": u["prototype_index"],
                "benign_traffic_seed": u["benign_traffic_seed"],
                "attack_vote_ratio": u["attack_vote_ratio"],
            }
            for u in uav_results
        ],
        "inference_mode": inference_mode,
        "ids_calibration": {
            "dataset_normal_label_id": int(lid_normal),
            "non_attack_argmax_id": int(non_attack_id),
            "non_attack_argmax_name": sid_name,
            "no_alert_display_class": normal_disp,
        },
        "attack_detected": any_attack,
        "attack_label": attack_label_agg,
        "true_label": true_label_agg,
        "uavs_alerting": n_atk,
        "window_index": int(uav_results[0]["prototype_index"]),
        "steps": steps,
    }
