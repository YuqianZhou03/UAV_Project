import os
import random
import sys

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import flwr as fl

from model import CnnLstmIDS, get_model_parameters, set_model_parameters
from scenario_config import (
    TELEM_BATTERY_IDX,
    TELEM_CPU_IDX,
    format_scenario_block,
    scenario_for_round,
)
from swarm_fl_data import (
    NUM_CLIENTS,
    SWARM_DIR,
    load_meta,
    load_train_split,
    local_train_test_split,
    split_index_for_round_client,
)

SWARM_SCENARIO = os.environ.get("FL_SWARM_SCENARIO", "iid").strip().lower()
MALICIOUS_CLIENTS = {
    int(x)
    for x in os.environ.get("FL_MALICIOUS_CLIENTS", "2").replace(";", ",").split(",")
    if x.strip().isdigit()
}
DROP_CLIENTS = {
    int(x)
    for x in os.environ.get("FL_DROPOUT_CLIENTS", "2").replace(";", ",").split(",")
    if x.strip().isdigit()
}
DELTA_CLIP_NORM = float(os.environ.get("FL_DELTA_CLIP_NORM", "1.0"))
DP_DELTA = float(os.environ.get("FL_DP_DELTA", "1e-5"))
LOCAL_EPOCHS = max(1, int(os.environ.get("FL_LOCAL_EPOCHS", "1")))
LOCAL_BATCH_SIZE = max(1, int(os.environ.get("FL_LOCAL_BATCH_SIZE", "32")))


def _scenario_active(name: str) -> bool:
    return SWARM_SCENARIO == name


def _simulate_non_iid(X: np.ndarray, y: np.ndarray, client_id: int) -> tuple[np.ndarray, np.ndarray]:
    labels = np.unique(y)
    if len(labels) <= 3:
        return X, y
    preferred = labels[client_id % len(labels) :: 3]
    mask = np.isin(y, preferred)
    if int(mask.sum()) >= 16:
        return X[mask], y[mask]
    return X, y


def _delta_l2_norm(old_w: list[np.ndarray], new_w: list[np.ndarray]) -> float:
    total = 0.0
    for old, new in zip(old_w, new_w, strict=True):
        d = np.asarray(new - old, dtype=np.float64)
        total += float(np.sum(d * d))
    return float(np.sqrt(total))


def _clip_weight_delta(
    old_w: list[np.ndarray], new_w: list[np.ndarray], clip_norm: float
) -> tuple[list[np.ndarray], float, float]:
    norm = _delta_l2_norm(old_w, new_w)
    if clip_norm <= 0.0 or norm <= clip_norm:
        return new_w, norm, 1.0
    scale = float(clip_norm / (norm + 1e-12))
    clipped = [old + (new - old) * scale for old, new in zip(old_w, new_w, strict=True)]
    return clipped, norm, scale


def _apply_gaussian_delta_noise(
    old_w: list[np.ndarray], new_w: list[np.ndarray], noise_scale: float, clip_norm: float
) -> list[np.ndarray]:
    sigma = max(0.0, float(noise_scale)) * max(clip_norm, 1e-6) * 0.02
    if sigma <= 0.0:
        return new_w
    out: list[np.ndarray] = []
    for old, new in zip(old_w, new_w, strict=True):
        delta = new - old
        noise = sigma * np.random.randn(*delta.shape).astype(np.float32)
        out.append(old + delta + noise)
    return out


def _seed_from_env(client_id: int) -> None:
    raw = os.environ.get("FL_SEED")
    if not raw:
        return
    seed = int(raw) + int(client_id) * 10007
    random.seed(seed)
    np.random.seed(seed % (2**32 - 1))
    torch.manual_seed(seed)


class DroneClient(fl.client.NumPyClient):
    """Each FL round uses train_split_{(round-1)*3 + client_id} from data/swarm_processed/."""

    def __init__(self, client_id: int):
        self.client_id = client_id
        _seed_from_env(client_id)
        meta = load_meta()
        self.num_classes = int(meta["num_classes"])
        self.n_features = int(meta["n_features"])
        self.model = CnnLstmIDS(n_features=self.n_features, num_classes=self.num_classes)
        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        self.round_count = 0
        self._train_loader: DataLoader | None = None
        self._test_loader: DataLoader | None = None
        self._num_train = 0
        self._cached_split = -1

    def _round_from_config(self, config: dict) -> int:
        v = config.get("server_round", 1)
        return int(float(v))

    def _rebuild_loaders(self, split_idx: int) -> None:
        if split_idx == self._cached_split and self._train_loader is not None:
            return
        X, y = load_train_split(split_idx)
        if _scenario_active("non_iid"):
            X, y = _simulate_non_iid(X, y, self.client_id)
        if len(X) < 4:
            raise ValueError(f"train_split_{split_idx} too small: {len(X)}")
        rng_seed = int(split_idx) * 1009 + int(self.client_id) * 17
        x_tr, y_tr, x_te, y_te = local_train_test_split(
            X, y, fraction=0.8, rng_seed=rng_seed
        )
        self.x_train = torch.tensor(x_tr, dtype=torch.float32)
        self.y_train = torch.tensor(y_tr, dtype=torch.long)
        self.x_test = torch.tensor(x_te, dtype=torch.float32)
        self.y_test = torch.tensor(y_te, dtype=torch.long)
        self._num_train = len(self.x_train)
        self._train_loader = DataLoader(
            TensorDataset(self.x_train, self.y_train), batch_size=LOCAL_BATCH_SIZE, shuffle=True
        )
        self._test_loader = DataLoader(
            TensorDataset(self.x_test, self.y_test), batch_size=LOCAL_BATCH_SIZE, shuffle=False
        )
        self._cached_split = split_idx

    def get_parameters(self, config):
        return get_model_parameters(self.model)

    def fit(self, parameters, config):
        rnd = self._round_from_config(config)
        split_idx = split_index_for_round_client(rnd, self.client_id)
        self.round_count += 1
        sc = scenario_for_round(rnd)
        self._rebuild_loaders(split_idx)
        set_model_parameters(self.model, parameters)

        participate = int(float(config.get("participate", 1.0)))
        noise_scale = float(config.get("noise_scale", 0.65))
        freq_n = max(1, int(float(config.get("freq_n", 1.0))))
        epsilon = float(config.get("epsilon", 1.0 / max(noise_scale, 1e-6)))
        dp_delta = float(config.get("delta", DP_DELTA))
        clip_norm = float(config.get("clip_norm", DELTA_CLIP_NORM))

        if _scenario_active("dropout") and self.client_id in DROP_CLIENTS and rnd % 2 == 0:
            print(f"  [CLIENT {self.client_id}] simulated dropout in round {rnd}; returning global weights.")
            fit_metrics: dict[str, float] = {
                "client_id": float(self.client_id),
                "simulated_dropout": 1.0,
                "participate": 0.0,
            }
            return parameters, 1, fit_metrics

        if participate == 0:
            print(f"  [CLIENT {self.client_id}] [APC] 本轮不参与 FL（participation=0），回传当前全局参数。")
            print("=" * 56 + "\n")
            fit_metrics: dict[str, float] = {
                "client_id": float(self.client_id),
                "participate": 0.0,
                "epsilon": float(epsilon),
                "delta": float(dp_delta),
            }
            return parameters, 1, fit_metrics

        if ((rnd - 1) % freq_n) != 0:
            print(
                f"  [CLIENT {self.client_id}] [APC] 按更新频率跳过本地训练 "
                f"(round={rnd}, freq_n={freq_n})，回传全局参数。"
            )
            print("=" * 56 + "\n")
            fit_metrics = {
                "client_id": float(self.client_id),
                "participate": 0.0,
                "freq_n": float(freq_n),
                "epsilon": float(epsilon),
                "delta": float(dp_delta),
            }
            return parameters, 1, fit_metrics

        print("\n" + "=" * 56)
        print(
            format_scenario_block(
                sc,
                title=f"[CLIENT {self.client_id}] FL round={rnd}  split={split_idx}  ({SWARM_DIR})",
            )
        )

        fit_metrics: dict[str, float] = {"client_id": float(self.client_id)}
        if self.x_train.size(-1) > TELEM_CPU_IDX:
            battery_mean = float(self.x_train[:, :, TELEM_BATTERY_IDX].mean().item())
            cpu_mean = float(self.x_train[:, :, TELEM_CPU_IDX].mean().item())
            if _scenario_active("low_resource"):
                battery_mean = max(5.0, battery_mean - (28.0 + 4.0 * self.client_id))
                cpu_mean = min(99.0, cpu_mean + (25.0 + 3.0 * self.client_id))
            fit_metrics["battery_soc_mean"] = battery_mean
            fit_metrics["cpu_util_mean"] = cpu_mean
            fit_metrics["resource_availability"] = max(0.0, min(1.0, battery_mean / 100.0))
            fit_metrics["latency_proxy"] = min(1.0, 0.12 + cpu_mean / 180.0)
            fit_metrics["bandwidth_proxy"] = max(0.05, 1.0 - fit_metrics["latency_proxy"])
            print(
                f"  [UAV-{self.client_id}] local train telemetry (mean over windows×timesteps): "
                f"battery={fit_metrics['battery_soc_mean']:.2f}%  "
                f"CPU={fit_metrics['cpu_util_mean']:.2f}%"
            )

        self.model.train()
        assert self._train_loader is not None
        for _epoch in range(LOCAL_EPOCHS):
            for batch_x, batch_y in self._train_loader:
                self.optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = self.criterion(outputs, batch_y)
                loss.backward()
                self.optimizer.step()

        print(
            f"  [CLIENT {self.client_id}] train_windows={self._num_train}  "
            f"local_epochs={LOCAL_EPOCHS}  training done."
        )
        if noise_scale > 0.0:
            print(
                f"  [CLIENT {self.client_id}] [APC] 对权重增量注入 DP 风格噪声 "
                f"(noise_scale={noise_scale:.3f})"
            )
        print("=" * 56 + "\n")

        old_w = parameters
        new_w = get_model_parameters(self.model)
        if _scenario_active("malicious") and self.client_id in MALICIOUS_CLIENTS:
            fit_metrics["malicious_update"] = 1.0
            poisoned: list[np.ndarray] = []
            for o, n in zip(old_w, new_w, strict=True):
                poisoned.append(o - 1.5 * (n - o))
            new_w = poisoned

        new_w, unclipped_norm, clip_scale = _clip_weight_delta(old_w, new_w, clip_norm)
        if noise_scale > 0.0:
            new_w = _apply_gaussian_delta_noise(old_w, new_w, noise_scale, clip_norm)

        fit_metrics["participate"] = 1.0
        fit_metrics["local_epochs"] = float(LOCAL_EPOCHS)
        fit_metrics["batch_size"] = float(LOCAL_BATCH_SIZE)
        fit_metrics["noise_scale"] = float(noise_scale)
        fit_metrics["freq_n"] = float(freq_n)
        fit_metrics["epsilon"] = float(epsilon)
        fit_metrics["delta"] = float(dp_delta)
        fit_metrics["clip_norm"] = float(clip_norm)
        fit_metrics["delta_l2_norm_unclipped"] = float(unclipped_norm)
        fit_metrics["delta_clip_scale"] = float(clip_scale)
        return new_w, self._num_train, fit_metrics

    def evaluate(self, parameters, config):
        rnd = self._round_from_config(config)
        split_idx = split_index_for_round_client(rnd, self.client_id)
        sc = scenario_for_round(rnd)
        self._rebuild_loaders(split_idx)
        set_model_parameters(self.model, parameters)

        self.model.eval()
        correct = 0
        total = 0
        assert self._test_loader is not None
        with torch.no_grad():
            for batch_x, batch_y in self._test_loader:
                outputs = self.model(batch_x)
                _, predicted = torch.max(outputs.data, 1)
                total += batch_y.size(0)
                correct += (predicted == batch_y).sum().item()

        accuracy = correct / total if total else 0.0
        ev_metrics: dict[str, float] = {"accuracy": accuracy, "client_id": float(self.client_id)}
        if self.x_test.size(-1) > TELEM_CPU_IDX:
            ev_metrics["battery_soc_mean"] = float(
                self.x_test[:, :, TELEM_BATTERY_IDX].mean().item()
            )
            ev_metrics["cpu_util_mean"] = float(
                self.x_test[:, :, TELEM_CPU_IDX].mean().item()
            )
            print(
                f"[CLIENT {self.client_id}] eval  round={rnd}  split={split_idx}  "
                f"acc={accuracy:.4%}  "
                f"battery={ev_metrics['battery_soc_mean']:.2f}%  "
                f"CPU={ev_metrics['cpu_util_mean']:.2f}%  "
                f"({sc['place']})"
            )
        else:
            print(
                f"[CLIENT {self.client_id}] eval  round={rnd}  split={split_idx}  "
                f"acc={accuracy:.4%}  ({sc['place']})"
            )

        return 0.0, total, ev_metrics


if __name__ == "__main__":
    client_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if not (0 <= client_id < NUM_CLIENTS):
        print(f"client_id must be in [0, {NUM_CLIENTS})")
        sys.exit(1)

    load_meta()
    print(f"--- client {client_id} --- swarm data: {SWARM_DIR}")

    fl.client.start_client(
        server_address="127.0.0.1:8080",
        client=DroneClient(client_id).to_client(),
    )
