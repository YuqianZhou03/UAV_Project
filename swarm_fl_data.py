"""Paths and helpers for swarm federated dataset (data/swarm_processed/)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np

SWARM_DIR = Path(os.environ.get("UAV_SWARM_DIR", "data/swarm_processed"))
META_PATH = SWARM_DIR / "meta.json"
TEST_NPZ = SWARM_DIR / "test.npz"
NUM_CLIENTS = 3


def load_meta() -> dict:
    if not META_PATH.is_file():
        raise FileNotFoundError(
            f"Missing {META_PATH}. Run: python preprocess_swarm_federated.py"
        )
    return json.loads(META_PATH.read_text(encoding="utf-8"))


def train_split_path(split_index: int) -> Path:
    if not (0 <= split_index < 9):
        raise ValueError("split_index must be in [0, 8]")
    return SWARM_DIR / f"train_split_{split_index}.npz"


def load_train_split(split_index: int) -> tuple[np.ndarray, np.ndarray]:
    p = train_split_path(split_index)
    if not p.is_file():
        raise FileNotFoundError(p)
    d = np.load(p, allow_pickle=True)
    return np.asarray(d["X_train"], dtype=np.float32), np.asarray(d["y_train"], dtype=np.int64)


def load_global_test() -> tuple[np.ndarray, np.ndarray, int, int]:
    if not TEST_NPZ.is_file():
        raise FileNotFoundError(TEST_NPZ)
    meta = load_meta()
    d = np.load(TEST_NPZ, allow_pickle=True)
    X = np.asarray(d["X_test"], dtype=np.float32)
    y = np.asarray(d["y_test"], dtype=np.int64)
    return X, y, int(meta["num_classes"]), int(meta["n_features"])


def local_train_test_split(
    X: np.ndarray,
    y: np.ndarray,
    fraction: float = 0.8,
    *,
    rng_seed: int | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Split each client shard into local train / eval.

    If *rng_seed* is None, use the legacy contiguous split (first *fraction* vs tail).
    Otherwise shuffle with a deterministic seed so each (split_idx, client_id) gets a
    different eval subset — avoids identical accuracy across UAVs on near-identical shards.
    """
    if len(X) < 4:
        raise ValueError("Shard too small for local train/test split")
    if rng_seed is None:
        split = int(len(X) * fraction)
        split = max(1, min(split, len(X) - 1))
        return X[:split], y[:split], X[split:], y[split:]

    from sklearn.model_selection import train_test_split

    test_size = 1.0 - float(fraction)
    test_size = float(min(max(test_size, 0.08), 0.45))
    rs = int(rng_seed) % (2**31 - 1)
    try:
        x_tr, x_te, y_tr, y_te = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=rs,
            stratify=y,
            shuffle=True,
        )
    except ValueError:
        x_tr, x_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=rs, shuffle=True
        )
    return x_tr, y_tr, x_te, y_te


def split_index_for_round_client(server_round: int, client_id: int) -> int:
    """Round 1 -> splits 0,1,2; round 2 -> 3,4,5; round 3 -> 6,7,8.

    Longer ablations cycle the same nine shards so RL/APC dynamics can be
    observed beyond the original three-round demo bundle.
    """
    r = int(server_round)
    if r < 1:
        r = 1
    return ((r - 1) * NUM_CLIENTS + client_id) % 9
