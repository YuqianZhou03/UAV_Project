"""
Build federated swarm IDS bundles from dataset/ (per-attack CSV files).

Outputs under data/swarm_processed/ (or UAV_SWARM_DIR):
  - meta.json: label_names, label_to_id, n_features, window, paths
  - packet_scaler.pkl: sklearn StandardScaler fit on TRAINING packets (first pass); needed for synthetic alignment
  - test.npz: X_test (N,16,F), y_test — pooled time-hold-out from EACH source file (last 20% packets per file)
  - train_split_{0..8}.npz: disjoint training windows; stratified round-robin so each split mixes classes

Cross-domain (synthetic CSVs, same FL model):
  After building the REAL bundle once, preprocess synthetic data with the SAME scaler so window features
  match what CnnLstmIDS was trained on:

    set UAV_DATASET_ROOT=dataset/synthetic_fl_eval
    set UAV_SWARM_DIR=data/swarm_processed_synth
    set UAV_REFERENCE_SCALER=data/swarm_processed
    python preprocess_swarm_federated.py

  (UAV_REFERENCE_SCALER may be a directory that contains packet_scaler.pkl, or the path to the .pkl file.)

Uses data/UAV-Case1-Label.csv first line for 44 feature names if present; otherwise built-in list (for GitHub clone without the large Case1 file).
"""

from __future__ import annotations

import json
import os
import pickle
import shutil
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Point to a folder of CSVs with the same layout as dataset/ (e.g. dataset/synthetic_uav).
DATASET_ROOT = Path(os.environ.get("UAV_DATASET_ROOT", "dataset"))
CASE1_HEADER = Path("data/UAV-Case1-Label.csv")

# Same order as Case1 / swarm meta — used when CASE1_HEADER is absent (repo size limits).
_CANONICAL_44: list[str] = [
    "frame.encap_type",
    "frame.len",
    "frame.number",
    "frame.time_delta_displayed",
    "frame.time_epoch",
    "frame.time_relative",
    "radiotap.channel.flags.cck",
    "radiotap.channel.flags.ofdm",
    "radiotap.channel.freq",
    "radiotap.datarate",
    "radiotap.dbm_antsignal",
    "radiotap.length",
    "radiotap.mactime",
    "radiotap.present.tsft",
    "radiotap.rxflags",
    "radiotap.timestamp.ts",
    "radiotap.vendor_oui",
    "wlan.duration",
    "wlan.bssid",
    "wlan.fc.retry",
    "wlan.fc.subtype",
    "wlan.fcs.bad_checksum",
    "wlan.fixed.beacon",
    "wlan.fixed.capabilities.ess",
    "wlan.seq",
    "wlan.tag",
    "wlan_radio.frequency",
    "wlan_radio.signal_dbm",
    "wlan_radio.start_tsf",
    "wlan_radio.phy",
    "wlan_radio.timestamp",
    "wlan.rsn.capabilities.mfpc",
    "wlan_rsna_eapol.keydes.msgnr",
    "arp",
    "arp.hw.type",
    "arp.proto.type",
    "ip.dst",
    "ip.proto",
    "ip.src",
    "ip.ttl",
    "tcp.ack",
    "udp.dstport",
    "udp.srcport",
    "udp.length",
]
OUT_DIR = Path(os.environ.get("UAV_SWARM_DIR", "data/swarm_processed"))
PACKET_SCALER_NAME = "packet_scaler.pkl"
WINDOW = 16
STRIDE = 16
PACKET_HOLDOUT_FRAC = float(os.environ.get("UAV_PACKET_HOLDOUT_FRAC", "0.20"))  # tail of each file -> test windows
MAX_ROWS_PER_FILE = 180_000  # cap very large PCAP exports (e.g. DDoS)
NUM_TRAIN_SPLITS = 9

# Paths are relative to DATASET_ROOT (default: dataset/).
MANIFEST: list[tuple[str, str]] = [
    ("Bruteforce-AP.csv", "BruteForce"),
    ("DDos.csv", "DDoS"),
    ("Deauthentication1.csv", "De-authentication"),
    ("Deauthentication2.csv", "De-authentication"),
    ("FakeLanding.csv", "FakeLanding"),
    ("GPS Jammong UAV.csv", "Jamming"),
    ("MITM UAV.csv", "MITM"),
    ("Reconnassiance-02.csv", "Reconnassiance"),
    ("Scanning.csv", "Scanning"),
    ("0floods.csv", "UDP Flooding"),
    ("0flood66s.csv", "ICMP Flooding"),
]


def _feat_columns() -> list[str]:
    if CASE1_HEADER.is_file():
        line = CASE1_HEADER.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        cols = [c.strip() for c in line.split(",")]
        return [c for c in cols if c != "Label"]
    return list(_CANONICAL_44)


def series_to_float(s: pd.Series) -> np.ndarray:
    if pd.api.types.is_numeric_dtype(s.dtype):
        v = pd.to_numeric(s, errors="coerce").to_numpy(dtype=np.float64)
        return np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0)
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.99:
        v = num.to_numpy(dtype=np.float64)
        return np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0)
    codes, _ = pd.factorize(s.astype("string"), use_na_sentinel=True)
    codes = np.asarray(codes, dtype=np.float64)
    codes[codes < 0] = 0.0
    return codes


def read_wireshark_table(path: Path) -> pd.DataFrame:
    with open(path, encoding="utf-8", errors="replace") as f:
        header = f.readline()
    sep = "\t" if header.count("\t") > header.count(",") else ","
    return pd.read_csv(path, sep=sep, low_memory=False, nrows=MAX_ROWS_PER_FILE)


def sort_order(df: pd.DataFrame) -> np.ndarray:
    if "frame.time_epoch" in df.columns:
        e = pd.to_numeric(df["frame.time_epoch"], errors="coerce").fillna(0).to_numpy()
    else:
        e = np.zeros(len(df), dtype=np.float64)
    if "frame.number" in df.columns:
        n = pd.to_numeric(df["frame.number"], errors="coerce").fillna(0).to_numpy()
    else:
        n = np.arange(len(df), dtype=np.float64)
    return np.lexsort((n, e))


def align_features(df: pd.DataFrame, feat_cols: list[str]) -> np.ndarray:
    parts = []
    for col in feat_cols:
        if col in df.columns:
            parts.append(series_to_float(df[col]))
        else:
            parts.append(np.zeros(len(df), dtype=np.float64))
    return np.column_stack(parts)


def majority_class(window_ids: np.ndarray, num_classes: int) -> int:
    c = np.bincount(window_ids.astype(int), minlength=num_classes)
    return int(np.argmax(c))


def _resolve_reference_scaler_path(raw: str) -> Path:
    p = Path(raw.strip())
    if p.is_dir():
        p = p / PACKET_SCALER_NAME
    return p


def windows_from_packets(X: np.ndarray, y: np.ndarray, num_classes: int) -> tuple[np.ndarray, np.ndarray]:
    if len(X) < WINDOW:
        return np.empty((0, WINDOW, X.shape[1]), dtype=np.float32), np.empty((0,), dtype=np.int64)
    xs, yw = [], []
    last = len(X) - WINDOW
    for i in range(0, last + 1, STRIDE):
        sl = slice(i, i + WINDOW)
        xs.append(X[sl])
        yw.append(majority_class(y[sl], num_classes))
    if not xs:
        return np.empty((0, WINDOW, X.shape[1]), dtype=np.float32), np.empty((0,), dtype=np.int64)
    return np.stack(xs, axis=0).astype(np.float32), np.array(yw, dtype=np.int64)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    feat_cols = _feat_columns()
    F = len(feat_cols)

    paths: list[tuple[Path, str]] = [(DATASET_ROOT / rel, lab) for rel, lab in MANIFEST]
    nf = DATASET_ROOT / "Normal-Flights"
    if nf.is_dir():
        for p in sorted(nf.glob("*.csv")):
            paths.append((p, "Normal"))

    labels = sorted({lab for _, lab in paths})
    label_to_id = {name: i for i, name in enumerate(labels)}
    num_classes = len(labels)

    train_windows_X: list[np.ndarray] = []
    train_windows_y: list[np.ndarray] = []
    test_blocks_Xw: list[np.ndarray] = []
    test_blocks_yw: list[np.ndarray] = []

    ref_raw = os.environ.get("UAV_REFERENCE_SCALER", "").strip()
    if ref_raw:
        ref_path = _resolve_reference_scaler_path(ref_raw)
        if not ref_path.is_file():
            raise FileNotFoundError(
                f"UAV_REFERENCE_SCALER: expected scaler at {ref_path}. "
                f"Run preprocess once on the REAL dataset (without UAV_REFERENCE_SCALER) "
                f"so {PACKET_SCALER_NAME} is written into that swarm directory."
            )
        with ref_path.open("rb") as sf:
            scaler = pickle.load(sf)
        if not isinstance(scaler, StandardScaler):
            raise TypeError(f"{ref_path}: expected sklearn.preprocessing.StandardScaler")
        if scaler.mean_.shape[0] != F:
            raise ValueError(
                f"Reference scaler has n={scaler.mean_.shape[0]} features but current feat_cols has F={F}. "
                "Use the same Case1 header / canonical column set as the reference bundle."
            )
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ref_path, OUT_DIR / PACKET_SCALER_NAME)
        print(f"Using reference StandardScaler from {ref_path.resolve()} (no refit on this CSV set).")
    else:
        train_packet_blocks: list[np.ndarray] = []
        for path, lab in paths:
            if not path.is_file():
                print(f"skip missing: {path}")
                continue
            print(f"load {path} as {lab}")
            df = read_wireshark_table(path)
            if len(df) < WINDOW + 4:
                print(f"  too few rows ({len(df)}), skip")
                continue
            order = sort_order(df)
            df = df.iloc[order].reset_index(drop=True)
            Xp = align_features(df, feat_cols)
            cid = label_to_id[lab]
            yp = np.full(len(df), cid, dtype=np.int64)
            cut = int(len(df) * (1.0 - PACKET_HOLDOUT_FRAC))
            cut = max(WINDOW + 1, min(cut, len(df) - WINDOW - 1))
            X_tr, y_tr = Xp[:cut], yp[:cut]
            train_packet_blocks.append(X_tr)

        if not train_packet_blocks:
            raise RuntimeError("No training data loaded; check dataset/ paths.")

        scaler = StandardScaler()
        scaler.fit(np.vstack(train_packet_blocks))
        scaler_out = OUT_DIR / PACKET_SCALER_NAME
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        with scaler_out.open("wb") as sf:
            pickle.dump(scaler, sf, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"Wrote {scaler_out.resolve()} (reuse with UAV_REFERENCE_SCALER for synthetic CSV bundles).")

    for path, lab in paths:
        if not path.is_file():
            continue
        df = read_wireshark_table(path)
        if len(df) < WINDOW + 4:
            continue
        order = sort_order(df)
        df = df.iloc[order].reset_index(drop=True)
        Xp = align_features(df, feat_cols)
        cid = label_to_id[lab]
        yp = np.full(len(df), cid, dtype=np.int64)
        cut = int(len(df) * (1.0 - PACKET_HOLDOUT_FRAC))
        cut = max(WINDOW + 1, min(cut, len(df) - WINDOW - 1))
        X_tr, y_tr = Xp[:cut], yp[:cut]
        X_te, y_te = Xp[cut:], yp[cut:]
        X_tr_s = scaler.transform(X_tr).astype(np.float32)
        Xw_tr_f, yw_tr_f = windows_from_packets(X_tr_s.astype(np.float64), y_tr, num_classes)
        if len(Xw_tr_f):
            train_windows_X.append(Xw_tr_f)
            train_windows_y.append(yw_tr_f)
        X_te_s = scaler.transform(X_te).astype(np.float32)
        Xw_te, yw_te = windows_from_packets(X_te_s.astype(np.float64), y_te, num_classes)
        if len(Xw_te):
            test_blocks_Xw.append(Xw_te)
            test_blocks_yw.append(yw_te)

    Xw_tr = np.vstack(train_windows_X) if train_windows_X else np.empty((0, WINDOW, F), dtype=np.float32)
    yw_tr = np.concatenate(train_windows_y) if train_windows_y else np.empty((0,), dtype=np.int64)

    X_test = np.vstack(test_blocks_Xw) if test_blocks_Xw else np.empty((0, WINDOW, F), dtype=np.float32)
    y_test = np.concatenate(test_blocks_yw) if test_blocks_yw else np.empty((0,), dtype=np.int64)

    # stratified round-robin into 9 train files
    split_X: list[list[np.ndarray]] = [[] for _ in range(NUM_TRAIN_SPLITS)]
    split_y: list[list[int]] = [[] for _ in range(NUM_TRAIN_SPLITS)]
    by_class: dict[int, list[int]] = defaultdict(list)
    for i in range(len(yw_tr)):
        by_class[int(yw_tr[i])].append(i)
    for cls, idxs in by_class.items():
        for j, idx in enumerate(idxs):
            s = j % NUM_TRAIN_SPLITS
            split_X[s].append(Xw_tr[idx])
            split_y[s].append(int(yw_tr[idx]))

    for s in range(NUM_TRAIN_SPLITS):
        if not split_X[s]:
            Xs = np.empty((0, WINDOW, F), dtype=np.float32)
            ys = np.empty((0,), dtype=np.int64)
        else:
            Xs = np.stack(split_X[s], axis=0)
            ys = np.array(split_y[s], dtype=np.int64)
        np.savez_compressed(OUT_DIR / f"train_split_{s}.npz", X_train=Xs, y_train=ys)

    np.savez_compressed(OUT_DIR / "test.npz", X_test=X_test, y_test=y_test)

    meta = {
        "label_names": labels,
        "label_to_id": label_to_id,
        "num_classes": num_classes,
        "n_features": F,
        "window": WINDOW,
        "stride": STRIDE,
        "packet_holdout_frac": PACKET_HOLDOUT_FRAC,
        "max_rows_per_file": MAX_ROWS_PER_FILE,
        "train_window_total": int(len(yw_tr)),
        "test_window_total": int(len(y_test)),
        "split_counts": [
            int(np.load(OUT_DIR / f"train_split_{s}.npz")["y_train"].shape[0]) for s in range(NUM_TRAIN_SPLITS)
        ],
        "feature_columns": feat_cols,
        "packet_scaler": {
            "file": PACKET_SCALER_NAME,
            "mode": "reference_transform" if ref_raw else "fitted_local",
            "reference_path": str(_resolve_reference_scaler_path(ref_raw).resolve()) if ref_raw else None,
        },
    }
    (OUT_DIR / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Wrote", OUT_DIR)
    print(json.dumps({k: v for k, v in meta.items() if k != "feature_columns"}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
