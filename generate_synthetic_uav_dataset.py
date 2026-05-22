"""
Generate synthetic Wireshark-style UAV IDS CSVs compatible with preprocess_swarm_federated.py.

Each file matches the canonical 44 feature names (same as preprocess when Case1 header is absent).
Class-specific statistics make labels learnable after StandardScaler + sliding windows, so you can:

  set UAV_DATASET_ROOT=dataset/synthetic_uav   # PowerShell: $env:UAV_DATASET_ROOT="dataset/synthetic_uav"
  python preprocess_swarm_federated.py
  python enrich_swarm_telemetry.py
  python server.py   # + clients

Or:  python generate_synthetic_uav_dataset.py --run-pipeline --verify

For **FL checkpoint** cross-test (recommended — uses real packet scaler + richer real features):

  python generate_synthetic_uav_dataset.py \\
    --margin-source dataset --margin-root dataset \\
    --loose-signatures \\
    --out dataset/synth_eval \\
    --run-pipeline \\
    --reference-scaler data/swarm_processed \\
    --pipeline-swarm-dir data/swarm_processed_synth_eval \\
    --eval-checkpoint checkpoints/fl_global_last.pt

  (`--loose-signatures` keeps fewer synthetic overrides so more IDS columns match real PCAPs;
   temporal columns follow a consecutive slice of real packets unless `--no-real-temporal`.)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from preprocess_swarm_federated import (
    MANIFEST,
    _CANONICAL_44,
    read_wireshark_table,
    series_to_float,
)

# Mirror MANIFEST: (filename under DATASET_ROOT, label) — used for generation order.
SYNTH_FILES: list[tuple[str, str]] = list(MANIFEST)

# When `--margin-source dataset`, non-signature columns come from real rows (same rel path);
# signature columns stay synthetic so labels remain learnable / aligned with FL attack semantics.
_TIME_COLS = frozenset({"frame.time_epoch", "frame.time_relative", "frame.number"})
_TEMPORAL_FOR_REAL = (
    "frame.time_epoch",
    "frame.time_relative",
    "frame.number",
    "frame.time_delta_displayed",
)
_SIGNATURE_COLS: dict[str, frozenset[str]] = {
    "Normal": frozenset(),  # almost entirely real marginals (time columns still synthetic for ordering)
    "DDoS": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "radiotap.length",
            "radiotap.dbm_antsignal",
            "wlan_radio.signal_dbm",
            "udp.dstport",
            "udp.srcport",
            "udp.length",
            "ip.proto",
        }
    ),
    "UDP Flooding": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "radiotap.dbm_antsignal",
            "wlan_radio.signal_dbm",
            "udp.dstport",
            "udp.srcport",
            "udp.length",
        }
    ),
    "ICMP Flooding": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "radiotap.dbm_antsignal",
            "wlan.fc.retry",
            "ip.proto",
        }
    ),
    "De-authentication": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "wlan.fc.retry",
            "wlan.fc.subtype",
            "radiotap.dbm_antsignal",
        }
    ),
    "Jamming": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "radiotap.channel.freq",
            "wlan_radio.frequency",
            "radiotap.dbm_antsignal",
            "wlan_radio.signal_dbm",
            "udp.dstport",
        }
    ),
    "Scanning": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "udp.dstport",
            "ip.ttl",
            "radiotap.dbm_antsignal",
        }
    ),
    "BruteForce": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "tcp.ack",
            "udp.dstport",
            "ip.ttl",
        }
    ),
    "MITM": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "udp.dstport",
            "udp.srcport",
            "ip.ttl",
        }
    ),
    "FakeLanding": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "udp.dstport",
            "radiotap.dbm_antsignal",
        }
    ),
    "Reconnassiance": frozenset(
        {
            "frame.len",
            "frame.time_delta_displayed",
            "udp.dstport",
            "wlan.fc.retry",
        }
    ),
}

# Fewer synthetic overrides → more columns from real PCAPs (better FL transfer when scaler matches).
_SIGNATURE_COLS_LOOSE: dict[str, frozenset[str]] = {
    "Normal": frozenset(),
    "DDoS": frozenset({"frame.len", "udp.dstport", "udp.length", "ip.proto"}),
    "UDP Flooding": frozenset({"frame.len", "udp.dstport", "udp.length"}),
    "ICMP Flooding": frozenset({"frame.len", "wlan.fc.retry", "ip.proto"}),
    "De-authentication": frozenset({"wlan.fc.retry", "wlan.fc.subtype"}),
    "Jamming": frozenset({"radiotap.channel.freq", "wlan_radio.frequency", "udp.dstport"}),
    "Scanning": frozenset({"udp.dstport", "ip.ttl"}),
    "BruteForce": frozenset({"tcp.ack", "udp.dstport", "ip.ttl"}),
    "MITM": frozenset({"udp.dstport", "udp.srcport", "ip.ttl"}),
    "FakeLanding": frozenset({"udp.dstport"}),
    "Reconnassiance": frozenset({"udp.dstport", "wlan.fc.retry"}),
}


def _signature_for_label(label: str, *, loose: bool) -> frozenset[str]:
    if loose:
        return _SIGNATURE_COLS_LOOSE.get(label, _SIGNATURE_COLS.get(label, frozenset()))
    return _SIGNATURE_COLS.get(label, frozenset())


def _load_real_feature_matrix(csv_path: Path, max_rows: int = 120_000) -> np.ndarray | None:
    if not csv_path.is_file():
        return None
    try:
        df = read_wireshark_table(csv_path)
    except Exception as e:
        print(f"margin-source: skip {csv_path}: {e}")
        return None
    mats: list[np.ndarray] = []
    for c in _CANONICAL_44:
        if c in df.columns:
            mats.append(series_to_float(df[c]))
        else:
            mats.append(np.zeros(len(df), dtype=np.float64))
    X = np.column_stack(mats)
    if len(X) > max_rows:
        X = X[:max_rows].copy()
    return X.astype(np.float64, copy=False)


def _blend_with_real_margins(
    rng: np.random.Generator,
    synth_df: pd.DataFrame,
    label: str,
    real_mat: np.ndarray | None,
    *,
    loose_signatures: bool,
) -> pd.DataFrame:
    if real_mat is None or len(real_mat) == 0:
        return synth_df
    sig = _signature_for_label(label, loose=loose_signatures)
    col_loc = {c: synth_df.columns.get_loc(c) for c in _CANONICAL_44}
    feat_ix = {c: i for i, c in enumerate(_CANONICAL_44)}
    out = synth_df.copy()
    M = len(real_mat)
    for i in range(len(out)):
        r = real_mat[rng.integers(0, M)]
        for c in _CANONICAL_44:
            j = col_loc[c]
            if c in _TIME_COLS:
                continue
            if c in sig:
                out.iat[i, j] = synth_df.iat[i, j]
            else:
                out.iat[i, j] = float(r[feat_ix[c]])
    return out


def _inject_real_temporal_consecutive(
    rng: np.random.Generator,
    df: pd.DataFrame,
    real_mat: np.ndarray | None,
) -> pd.DataFrame:
    """Replace time / inter-arrival columns with a consecutive slice of real packets (sorted file order in matrix)."""
    if real_mat is None or len(real_mat) == 0:
        return df
    idx = [_CANONICAL_44.index(c) for c in _TEMPORAL_FOR_REAL]
    col_loc = {c: df.columns.get_loc(c) for c in _TEMPORAL_FOR_REAL}
    M, n = len(real_mat), len(df)
    out = df.copy()
    if M >= n:
        start = int(rng.integers(0, M - n + 1))
        for i in range(n):
            r = real_mat[start + i]
            for c, j in zip(_TEMPORAL_FOR_REAL, idx, strict=True):
                out.iat[i, col_loc[c]] = float(r[j])
    else:
        for i in range(n):
            r = real_mat[i % M]
            for c, j in zip(_TEMPORAL_FOR_REAL, idx, strict=True):
                out.iat[i, col_loc[c]] = float(r[j])
    return out


def _base_row(
    rng: np.random.Generator,
    *,
    t_epoch: float,
    frame_no: int,
    len_mean: float,
    len_std: float,
    delta_mean: float,
    delta_std: float,
    dbm_mean: float,
    udp_cluster: float | None,
    ttl_mean: float,
    wlan_retry_rate: float,
) -> dict[str, float]:
    flen = float(np.clip(rng.lognormal(np.log(len_mean), len_std / max(len_mean, 1e-3)), 20.0, 9000.0))
    dt = float(np.clip(rng.exponential(delta_mean) + rng.normal(0, delta_std), 1e-9, 5.0))
    dbm = float(np.clip(rng.normal(dbm_mean, 6.0), -95.0, -20.0))
    row: dict[str, float] = {c: 0.0 for c in _CANONICAL_44}
    row["frame.encap_type"] = 20.0
    row["frame.len"] = flen
    row["frame.number"] = float(frame_no)
    row["frame.time_delta_displayed"] = dt
    row["frame.time_epoch"] = t_epoch
    row["frame.time_relative"] = t_epoch % 10_000.0
    row["radiotap.channel.freq"] = float(rng.choice([2412, 2437, 2462, 5180, 5200]))
    row["radiotap.datarate"] = float(rng.choice([6, 9, 12, 18, 24, 36, 48, 54]))
    row["radiotap.dbm_antsignal"] = dbm
    row["radiotap.length"] = flen * 0.98
    row["radiotap.mactime"] = float(rng.integers(0, 2_000_000_000))
    row["wlan.duration"] = float(rng.integers(50, 500))
    row["wlan.fc.retry"] = 1.0 if rng.random() < wlan_retry_rate else 0.0
    row["wlan.fc.subtype"] = float(rng.integers(0, 16))
    row["wlan.seq"] = float(frame_no % 4096)
    row["wlan_radio.frequency"] = row["radiotap.channel.freq"]
    row["wlan_radio.signal_dbm"] = dbm
    row["wlan_radio.phy"] = float(rng.integers(0, 8))
    row["ip.ttl"] = float(np.clip(rng.normal(ttl_mean, 4.0), 1.0, 128.0))
    row["ip.proto"] = float(rng.choice([6, 17, 1]))
    if udp_cluster is not None:
        row["udp.dstport"] = float(np.clip(rng.normal(udp_cluster, 40.0), 1.0, 65535.0))
        row["udp.srcport"] = float(rng.integers(1024, 65000))
        row["udp.length"] = float(np.clip(rng.lognormal(4.0, 0.6), 8.0, 1400.0))
    row["tcp.ack"] = float(rng.integers(0, 1_000_000_000))
    return row


def _rows_for_label(rng: np.random.Generator, label: str, n_rows: int) -> pd.DataFrame:
    """Return n_rows x 44 float table with time ordering."""
    rows: list[dict[str, float]] = []
    t0 = 1_700_000_000.0 + rng.integers(0, 10_000_000)
    # Distinct regimes so a classifier can beat chance after global scaling.
    if label == "Normal":
        prof = dict(
            len_mean=320, len_std=0.35, delta_mean=0.012, delta_std=0.004,
            dbm_mean=-62, udp_cluster=443.0, ttl_mean=64, wlan_retry_rate=0.02,
        )
    elif label == "DDoS":
        prof = dict(
            len_mean=1200, len_std=0.5, delta_mean=0.0004, delta_std=0.0002,
            dbm_mean=-58, udp_cluster=53.0, ttl_mean=64, wlan_retry_rate=0.01,
        )
    elif label in ("UDP Flooding", "ICMP Flooding"):
        prof = dict(
            len_mean=600, len_std=0.45, delta_mean=0.001, delta_std=0.0005,
            dbm_mean=-55, udp_cluster=50000.0, ttl_mean=64, wlan_retry_rate=0.05,
        )
    elif label == "De-authentication":
        prof = dict(
            len_mean=180, len_std=0.4, delta_mean=0.003, delta_std=0.001,
            dbm_mean=-48, udp_cluster=None, ttl_mean=64, wlan_retry_rate=0.55,
        )
    elif label == "Jamming":
        prof = dict(
            len_mean=400, len_std=0.5, delta_mean=0.008, delta_std=0.003,
            dbm_mean=-35, udp_cluster=8888.0, ttl_mean=64, wlan_retry_rate=0.08,
        )
    elif label == "Scanning":
        prof = dict(
            len_mean=220, len_std=0.42, delta_mean=0.002, delta_std=0.0008,
            dbm_mean=-60, udp_cluster=22.0, ttl_mean=48, wlan_retry_rate=0.04,
        )
    elif label == "BruteForce":
        prof = dict(
            len_mean=500, len_std=0.4, delta_mean=0.05, delta_std=0.02,
            dbm_mean=-58, udp_cluster=445.0, ttl_mean=128, wlan_retry_rate=0.03,
        )
    elif label == "MITM":
        prof = dict(
            len_mean=700, len_std=0.45, delta_mean=0.015, delta_std=0.006,
            dbm_mean=-52, udp_cluster=8080.0, ttl_mean=32, wlan_retry_rate=0.06,
        )
    elif label == "FakeLanding":
        prof = dict(
            len_mean=900, len_std=0.5, delta_mean=0.04, delta_std=0.015,
            dbm_mean=-65, udp_cluster=67.0, ttl_mean=64, wlan_retry_rate=0.02,
        )
    elif label == "Reconnassiance":
        prof = dict(
            len_mean=260, len_std=0.38, delta_mean=0.006, delta_std=0.002,
            dbm_mean=-63, udp_cluster=53.0, ttl_mean=64, wlan_retry_rate=0.03,
        )
    else:
        # FakeLanding-like default for any remaining attack names
        prof = dict(
            len_mean=450, len_std=0.42, delta_mean=0.01, delta_std=0.004,
            dbm_mean=-57, udp_cluster=1234.0, ttl_mean=64, wlan_retry_rate=0.04,
        )

    for i in range(n_rows):
        te = t0 + i * 1e-4 + rng.normal(0, 1e-6)
        rows.append(_base_row(rng, t_epoch=te, frame_no=i + 1, **prof))
    return pd.DataFrame(rows, columns=_CANONICAL_44)


def _normal_margin_matrix(margin_root: Path) -> np.ndarray | None:
    """Stack CSVs under <margin_root>/Normal-Flights/*.csv if present."""
    nf = margin_root / "Normal-Flights"
    if not nf.is_dir():
        return None
    parts: list[np.ndarray] = []
    for p in sorted(nf.glob("*.csv")):
        m = _load_real_feature_matrix(p)
        if m is not None and len(m):
            parts.append(m)
    if not parts:
        return None
    return np.vstack(parts)


def write_synthetic_dataset(
    out_root: Path,
    rows_per_class: int,
    seed: int,
    *,
    margin_dataset_root: Path | None = None,
    loose_signatures: bool = False,
    real_temporal: bool = True,
) -> None:
    out_root = out_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "Normal-Flights").mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    mroot = margin_dataset_root.resolve() if margin_dataset_root else None

    seen: set[str] = set()
    for rel, lab in SYNTH_FILES:
        if rel in seen:
            continue
        seen.add(rel)
        df = _rows_for_label(rng, lab, rows_per_class)
        if mroot is not None:
            real = _load_real_feature_matrix(mroot / rel)
            df = _blend_with_real_margins(
                rng, df, lab, real, loose_signatures=loose_signatures
            )
            if real_temporal and real is not None and len(real):
                df = _inject_real_temporal_consecutive(rng, df, real)
        path = out_root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(path, index=False)
        bits = []
        if mroot:
            bits.append("margin+dataset")
            if loose_signatures:
                bits.append("loose-sig")
            if real_temporal:
                bits.append("real-time")
        src = "+".join(bits) if bits else "synthetic"
        print(f"wrote {path}  label={lab}  rows={len(df)}  ({src})", flush=True)

    n_normal = max(rows_per_class, 2500)
    df_n = _rows_for_label(rng, "Normal", n_normal)
    if mroot is not None:
        nm = _normal_margin_matrix(mroot)
        df_n = _blend_with_real_margins(
            rng, df_n, "Normal", nm, loose_signatures=loose_signatures
        )
        if real_temporal and nm is not None and len(nm):
            df_n = _inject_real_temporal_consecutive(rng, df_n, nm)
    npath = out_root / "Normal-Flights" / "synthetic_normal.csv"
    df_n.to_csv(npath, index=False)
    print(f"wrote {npath}  label=Normal  rows={len(df_n)}", flush=True)
    print(f"\nDone. Use:\n  UAV_DATASET_ROOT={out_root.as_posix()}\n  python preprocess_swarm_federated.py\n  python enrich_swarm_telemetry.py\n", flush=True)


def run_preprocess_pipeline(
    out_root: Path,
    *,
    swarm_dir: Path | None = None,
    reference_scaler: Path | None = None,
    enrich_seed: int = 42,
) -> None:
    env = os.environ.copy()
    env["UAV_DATASET_ROOT"] = str(out_root.resolve())
    if swarm_dir is not None:
        env["UAV_SWARM_DIR"] = str(swarm_dir.resolve())
    else:
        env.pop("UAV_SWARM_DIR", None)
    if reference_scaler is not None:
        env["UAV_REFERENCE_SCALER"] = str(reference_scaler.resolve())
    else:
        env.pop("UAV_REFERENCE_SCALER", None)
    root = Path(__file__).resolve().parent
    subprocess.run([sys.executable, "preprocess_swarm_federated.py"], cwd=root, env=env, check=True)
    subprocess.run(
        [sys.executable, "enrich_swarm_telemetry.py", "--seed", str(enrich_seed)],
        cwd=root,
        env=env,
        check=True,
    )
    print("preprocess + enrich completed.")


def verify_swarm_bundle(swarm_dir: Path | None = None) -> bool:
    """Light checks + quick linear baseline on flattened windows (sklearn)."""
    swarm_dir = swarm_dir or Path("data/swarm_processed")
    meta_path = swarm_dir / "meta.json"
    if not meta_path.is_file():
        print("verify: missing meta.json — run preprocess first.")
        return False
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    nc = int(meta["num_classes"])
    F = int(meta["n_features"])
    print(f"verify: num_classes={nc}  n_features={F}")

    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import train_test_split

    xs, ys = [], []
    for s in range(9):
        p = swarm_dir / f"train_split_{s}.npz"
        if not p.is_file():
            print(f"verify: missing {p}")
            return False
        d = np.load(p, allow_pickle=True)
        xs.append(np.asarray(d["X_train"], dtype=np.float32).reshape(len(d["X_train"]), -1))
        ys.append(np.asarray(d["y_train"], dtype=np.int64))
    X = np.vstack(xs)
    y = np.concatenate(ys)
    uniq = np.unique(y)
    print(f"verify: pooled train windows={len(y)}  unique labels={len(uniq)}")
    if len(uniq) < 2:
        print("verify: need at least 2 classes in train pool")
        return False

    n = min(12_000, len(y))
    idx = np.random.RandomState(0).choice(len(y), size=n, replace=False)
    Xs, ys = X[idx], y[idx]
    Xtr, Xte, ytr, yte = train_test_split(Xs, ys, test_size=0.25, random_state=0, stratify=ys)
    clf = LogisticRegression(max_iter=600, solver="lbfgs", random_state=0)
    clf.fit(Xtr, ytr)
    acc = accuracy_score(yte, clf.predict(Xte))
    chance = 1.0 / nc
    print(f"verify: sklearn multinomial LR on flattened windows  holdout_acc={acc:.3f}  chance={chance:.3f}")
    ok = acc > chance * 2.0
    if not ok:
        print("verify: WARNING accuracy not clearly above chance — synthetic separation may be weak.")
    else:
        print("verify: OK — labels appear linearly separable enough for a smoke baseline.")
    return ok


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--out",
        type=Path,
        default=Path("dataset/synthetic_uav"),
        help="Output folder (same leaf filenames as dataset/).",
    )
    p.add_argument("--rows", type=int, default=3200, help="Rows per attack CSV (Normal gets at least this).")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--margin-source",
        choices=("none", "dataset"),
        default="none",
        help="dataset: blend each class with real rows from the same CSV path under --margin-root (FL-friendly cross-domain stats).",
    )
    p.add_argument(
        "--margin-root",
        type=Path,
        default=Path("dataset"),
        help="Folder containing MANIFEST CSVs (and optional Normal-Flights/*.csv) when --margin-source dataset.",
    )
    p.add_argument(
        "--loose-signatures",
        action="store_true",
        help="With --margin-source dataset: keep fewer synthetic 'signature' columns so more IDS fields come from real rows.",
    )
    p.add_argument(
        "--no-real-temporal",
        action="store_true",
        help="With --margin-source dataset: do not overwrite time_* / frame.number / delta with a real consecutive slice.",
    )
    p.add_argument(
        "--pipeline-swarm-dir",
        type=Path,
        default=None,
        help="With --run-pipeline: set UAV_SWARM_DIR (default: data/swarm_processed when no --reference-scaler, else data/swarm_processed_synth).",
    )
    p.add_argument(
        "--reference-scaler",
        type=Path,
        default=None,
        help="Directory with packet_scaler.pkl from REAL preprocess, or path to the .pkl. Strongly recommended for FL checkpoint eval.",
    )
    p.add_argument(
        "--eval-checkpoint",
        type=Path,
        default=None,
        help="After --run-pipeline: run eval_fl_checkpoint_on_npz.py on the pipeline swarm dir.",
    )
    p.add_argument(
        "--run-pipeline",
        action="store_true",
        help="After writing CSVs, run preprocess_swarm_federated.py + enrich_swarm_telemetry.py with UAV_DATASET_ROOT set.",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="After --run-pipeline (or if swarm_processed already exists), run bundle checks + sklearn smoke test.",
    )
    args = p.parse_args()

    margin_root = args.margin_root if args.margin_source == "dataset" else None
    write_synthetic_dataset(
        args.out,
        args.rows,
        args.seed,
        margin_dataset_root=margin_root,
        loose_signatures=args.loose_signatures,
        real_temporal=not args.no_real_temporal,
    )
    if args.run_pipeline:
        default_swarm = (
            Path("data/swarm_processed_synth")
            if args.reference_scaler is not None
            else Path("data/swarm_processed")
        )
        swarm = args.pipeline_swarm_dir or default_swarm
        run_preprocess_pipeline(
            args.out,
            swarm_dir=swarm,
            reference_scaler=args.reference_scaler,
            enrich_seed=args.seed,
        )
    if args.eval_checkpoint is not None:
        if not args.run_pipeline:
            print("--eval-checkpoint requires --run-pipeline", file=sys.stderr)
            sys.exit(2)
        swarm = args.pipeline_swarm_dir or (
            Path("data/swarm_processed_synth")
            if args.reference_scaler is not None
            else Path("data/swarm_processed")
        )
        root = Path(__file__).resolve().parent
        r = subprocess.run(
            [
                sys.executable,
                "eval_fl_checkpoint_on_npz.py",
                "--checkpoint",
                str(args.eval_checkpoint.resolve()),
                "--swarm-dir",
                str(swarm.resolve()),
            ],
            cwd=root,
            check=False,
        )
        if r.returncode != 0:
            sys.exit(r.returncode)
    if args.verify:
        swarm_v = args.pipeline_swarm_dir or (
            Path("data/swarm_processed_synth")
            if args.reference_scaler is not None
            else Path("data/swarm_processed")
        )
        ok = verify_swarm_bundle(swarm_v)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
