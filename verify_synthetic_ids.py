"""
Train CnnLstmIDS briefly on data/swarm_processed (e.g. synthetic_uav pipeline output)
and evaluate on test.npz — proves the IDS head can learn attack vs normal + attack type.

Usage (from repo root, after preprocess + enrich):
  python verify_synthetic_ids.py
  python verify_synthetic_ids.py --epochs 8 --device cpu
"""

from __future__ import annotations

import argparse

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report
from torch.utils.data import DataLoader, TensorDataset

from model import CnnLstmIDS
from swarm_fl_data import SWARM_DIR, load_global_test, load_meta, load_train_split


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--batch", type=int, default=64)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--device", default=None)
    args = p.parse_args()

    meta = load_meta()
    names = list(meta["label_names"])
    nc = int(meta["num_classes"])
    nf = int(meta["n_features"])

    xs, ys = [], []
    for s in range(9):
        X, y = load_train_split(s)
        if len(X):
            xs.append(X)
            ys.append(y)
    if not xs:
        raise SystemExit("No train splits found. Run preprocess + enrich first.")
    X_tr = np.concatenate(xs, axis=0)
    y_tr = np.concatenate(ys, axis=0)

    X_te, y_te, nc_te, nf_te = load_global_test()
    assert nc_te == nc and nf_te == nf, (nc, nf, nc_te, nf_te)

    device = torch.device(args.device or ("cuda" if torch.cuda.is_available() else "cpu"))
    ds = DataLoader(
        TensorDataset(
            torch.tensor(X_tr, dtype=torch.float32),
            torch.tensor(y_tr, dtype=torch.long),
        ),
        batch_size=args.batch,
        shuffle=True,
    )
    ds_te = DataLoader(
        TensorDataset(
            torch.tensor(X_te, dtype=torch.float32),
            torch.tensor(y_te, dtype=torch.long),
        ),
        batch_size=args.batch,
        shuffle=False,
    )

    net = CnnLstmIDS(n_features=nf, num_classes=nc).to(device)
    opt = torch.optim.Adam(net.parameters(), lr=args.lr)
    crit = nn.CrossEntropyLoss()

    net.train()
    for ep in range(args.epochs):
        tot, n = 0.0, 0
        for xb, yb in ds:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            logits = net(xb)
            loss = crit(logits, yb)
            loss.backward()
            opt.step()
            tot += float(loss.item()) * len(yb)
            n += len(yb)
        print(f"epoch {ep + 1}/{args.epochs}  train_loss={tot / max(n, 1):.4f}")

    net.eval()
    preds, gold = [], []
    with torch.no_grad():
        for xb, yb in ds_te:
            xb = xb.to(device)
            logits = net(xb)
            preds.append(torch.argmax(logits, dim=1).cpu().numpy())
            gold.append(yb.numpy())
    y_pred = np.concatenate(preds)
    y_true = np.concatenate(gold)
    acc = float((y_pred == y_true).mean())
    print(f"\n=== CnnLstmIDS on global test.npz ===")
    print(f"accuracy: {acc:.4f}  (random baseline ≈ {1.0 / nc:.4f})")
    print("\n" + classification_report(y_true, y_pred, target_names=names, zero_division=0))

    if acc < 0.35:
        raise SystemExit("Accuracy too low — synthetic or model setup may be wrong.")
    print("OK: IDS reaches usable accuracy on synthetic bundle.")


if __name__ == "__main__":
    main()
