"""
Evaluate a **saved global FL model** (from server.py final round) on any compatible
`test.npz` + `meta.json` — e.g. synthetic swarm after `preprocess` + `enrich`.

Does **not** train; only loads `checkpoints/fl_global_last.pt` (or `--checkpoint`).

Typical workflow (real PCAP → FL → save; synthetic CSV → preprocess → eval here):

  1) Train FL on real data (UAV_DATASET_ROOT unset or dataset/), run server + clients to completion.
  2) Confirm checkpoints/fl_global_last.pt exists.
  3) Build synthetic bundle under e.g. data/swarm_processed_synth/ OR temporarily replace test:
       python generate_synthetic_uav_dataset.py --margin-source dataset --out ... --run-pipeline
  4) Preprocess synthetic CSVs with **UAV_REFERENCE_SCALER** pointing at the REAL swarm dir
     (uses the same packet StandardScaler as FL training — see preprocess_swarm_federated.py).
  5) Point --swarm-dir at the folder that contains meta.json + test.npz for the **synthetic** run.

  python eval_fl_checkpoint_on_npz.py \\
    --checkpoint checkpoints/fl_global_last.pt \\
    --swarm-dir data/swarm_processed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, classification_report

from model import CnnLstmIDS


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--checkpoint", type=Path, default=Path("checkpoints/fl_global_last.pt"))
    p.add_argument("--swarm-dir", type=Path, default=Path("data/swarm_processed"))
    p.add_argument("--test-npz", type=Path, default=None, help="Default: <swarm-dir>/test.npz")
    p.add_argument("--batch", type=int, default=256)
    p.add_argument("--device", default=None)
    p.add_argument(
        "--expect-min",
        type=float,
        default=None,
        help="If set, exit 1 when accuracy < this (e.g. 0.7 for your target band).",
    )
    p.add_argument("--expect-max", type=float, default=None, help="If set, exit 1 when accuracy > this.")
    args = p.parse_args()

    ckpt_path = args.checkpoint
    if not ckpt_path.is_file():
        print(f"Missing checkpoint: {ckpt_path.resolve()}")
        print("Run Flower server + clients to completion on TRAINING data; the server saves after the final round.")
        sys.exit(2)

    swarm = args.swarm_dir
    meta_path = swarm / "meta.json"
    test_path = args.test_npz or (swarm / "test.npz")
    if not meta_path.is_file() or not test_path.is_file():
        print(f"Need meta.json + test.npz under {swarm.resolve()}")
        sys.exit(2)

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    label_names = list(meta["label_names"])
    nc_meta = int(meta["num_classes"])
    nf_meta = int(meta["n_features"])

    try:
        ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    except TypeError:
        ckpt = torch.load(ckpt_path, map_location="cpu")
    if isinstance(ckpt, dict) and "state_dict" in ckpt:
        state = ckpt["state_dict"]
        nc = int(ckpt.get("num_classes", nc_meta))
        nf = int(ckpt.get("n_features", nf_meta))
    else:
        print("Checkpoint must be a dict with state_dict, n_features, num_classes (saved by server.py).")
        sys.exit(2)

    if nc != nc_meta or nf != nf_meta:
        print(
            f"Checkpoint nc,nf=({nc},{nf}) vs swarm meta ({nc_meta},{nf_meta}). "
            "Use the same feature layout (e.g. run enrich on synthetic bundle)."
        )
        sys.exit(3)

    d = np.load(test_path, allow_pickle=True)
    X = np.asarray(d["X_test"], dtype=np.float32)
    y = np.asarray(d["y_test"], dtype=np.int64)
    device = torch.device(args.device or ("cuda" if torch.cuda.is_available() else "cpu"))

    net = CnnLstmIDS(n_features=nf, num_classes=nc).to(device)
    model_sd = net.state_dict()
    missing = [k for k in model_sd if k not in state]
    if missing:
        print("Checkpoint state_dict keys mismatch:", missing[:5], "...")
        sys.exit(4)
    new_sd = {}
    for k in model_sd:
        v = state[k]
        if not isinstance(v, torch.Tensor):
            v = torch.as_tensor(v, dtype=model_sd[k].dtype)
        new_sd[k] = v.to(device=device, dtype=model_sd[k].dtype)
    net.load_state_dict(new_sd, strict=True)
    net.eval()

    preds = []
    with torch.no_grad():
        for i in range(0, len(X), args.batch):
            xb = torch.tensor(X[i : i + args.batch], device=device)
            logits = net(xb)
            preds.append(torch.argmax(logits, dim=1).cpu().numpy())
    y_pred = np.concatenate(preds)
    acc = float(accuracy_score(y, y_pred))

    print(f"checkpoint: {ckpt_path.resolve()}")
    print(f"test:       {test_path.resolve()}  windows={len(y)}")
    print(f"accuracy:   {acc:.4f}  (random ≈ {1.0 / nc:.4f})")
    print()
    labels_all = np.arange(len(label_names))
    print(
        classification_report(
            y, y_pred, labels=labels_all, target_names=label_names, zero_division=0
        )
    )

    if args.expect_min is not None and acc < args.expect_min:
        print(f"FAIL: accuracy {acc:.4f} < --expect-min {args.expect_min}")
        sys.exit(1)
    if args.expect_max is not None and acc > args.expect_max:
        print(f"FAIL: accuracy {acc:.4f} > --expect-max {args.expect_max}")
        sys.exit(1)


if __name__ == "__main__":
    main()
