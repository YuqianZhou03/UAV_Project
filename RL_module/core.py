"""
FL 联调用 RL 桥接：在原始 TrustNet / ReplayBuffer / reward 定义上提供
「每轮观测 → 信任分」接口，避免在 import 时跑完整离线训练循环。
"""

from __future__ import annotations

import random
from collections import deque
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

STATE_DIM = 6
STATE_NAMES = [
    "quality",
    "latency_proxy",
    "loss_proxy",
    "energy",
    "attack_proxy",
    "update_anomaly",
]
ACTION_NAMES = ["participate", "update_frequency", "noise_scale"]
DEFAULT_BUFFER = 2000
DEFAULT_BATCH = 32
GAMMA = 0.95
LR = 1e-3


class ReplayBuffer:
    def __init__(self, maxlen: int = DEFAULT_BUFFER):
        self.buffer: deque[tuple[np.ndarray, float, np.ndarray]] = deque(maxlen=maxlen)

    def push(self, s: np.ndarray, r: float, s_next: np.ndarray) -> None:
        self.buffer.append((s.astype(np.float32), float(r), s_next.astype(np.float32)))

    def sample(self, batch: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        data = random.sample(self.buffer, batch)
        s, r, s_next = zip(*data, strict=True)
        return np.stack(s), np.asarray(r, dtype=np.float32), np.stack(s_next)

    def __len__(self) -> int:
        return len(self.buffer)


class TrustNet(nn.Module):
    """与 RL.py 一致：5 维状态 → 1 维信任分."""

    def __init__(self, state_dim: int = STATE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def reward_function(state_row: np.ndarray) -> float:
    """与 RL.py 中 reward_function 对齐（单行 5 维）."""
    dq, lat, loss, energy, attack, anomaly = state_row.tolist()
    return (
        2.0 * dq
        - 1.2 * lat
        - 0.8 * loss
        + 1.0 * energy
        - 2.0 * attack
        - 1.5 * anomaly
    )


def build_client_states(
    num_clients: int,
    fit_rows: list[dict],
    eval_acc_by_cid: dict[int, float],
    centralized_loss: float,
    precision_macro: float,
) -> np.ndarray:
    """
    将 SERVER 侧可观测指标映射为 TrustNet 的 5 维状态（每机一行）：
    [quality, latency_proxy, loss_proxy, energy, attack_proxy]
    """
    rows_by_cid: dict[int, dict] = {}
    for row in fit_rows:
        cid = int(row.get("client_id", -1))
        if cid >= 0:
            rows_by_cid[cid] = row

    prec = float(np.clip(precision_macro, 0.0, 1.0))
    attack_global = float(np.clip(1.0 - prec, 0.0, 1.0))
    loss_n = float(np.clip(centralized_loss / 5.0, 0.0, 1.0))

    update_norms = [
        float(row.get("delta_l2_norm_unclipped"))
        for row in rows_by_cid.values()
        if row.get("delta_l2_norm_unclipped") is not None
    ]
    median_norm = float(np.median(update_norms)) if update_norms else 1.0
    median_norm = max(median_norm, 1e-6)

    states = np.zeros((num_clients, STATE_DIM), dtype=np.float32)
    for cid in range(num_clients):
        row = rows_by_cid.get(cid, {})
        n_ex = int(row.get("num_examples", 0) or 0)
        bat = row.get("battery_soc_mean")
        quality = float(np.clip(eval_acc_by_cid.get(cid, 0.35), 0.0, 1.0))
        if row.get("latency_proxy") is not None:
            latency = float(np.clip(float(row["latency_proxy"]), 0.0, 1.0))
        else:
            latency = float(np.clip(1.0 - min(1.0, n_ex / 12000.0), 0.0, 1.0))
        if row.get("resource_availability") is not None:
            energy = float(np.clip(float(row["resource_availability"]), 0.0, 1.0))
        elif bat is None:
            energy = 0.65
        else:
            energy = float(np.clip(float(bat) / 100.0, 0.0, 1.0))
        norm = row.get("delta_l2_norm_unclipped")
        if row.get("update_anomaly_memory") is not None:
            anomaly = float(np.clip(float(row["update_anomaly_memory"]), 0.0, 1.0))
        elif row.get("malicious_update"):
            anomaly = 1.0
        elif norm is None:
            anomaly = 0.0
        else:
            anomaly = float(np.clip((float(norm) / median_norm - 1.0) / 2.0, 0.0, 1.0))
        states[cid] = np.array(
            [quality, latency, loss_n, energy, attack_global, anomaly],
            dtype=np.float32,
        )
    return states


def client_threat_level(
    global_threat: float,
    eval_accuracy: float,
    *,
    blend_global: float = 0.45,
) -> float:
    """供 APC 使用：融合全局威胁 (1−macro_precision) 与单机本地 eval 漏检率。

    eval_accuracy 缺省时在调用方用 macro 精度代替，使「无单机信号」时退化为全局威胁。
    blend_global 越大越相信宏观 IDS；越小越强调本机 eval 异常。
    """
    miss = 1.0 - float(np.clip(eval_accuracy, 0.0, 1.0))
    g = float(np.clip(global_threat, 0.0, 1.0))
    b = float(np.clip(blend_global, 0.0, 1.0))
    return float(np.clip(b * g + (1.0 - b) * miss, 0.0, 1.0))


class FLTrustRLBridge:
    """维护 TrustNet + 经验回放，在联邦每轮末用 (s,a,r,s') 做一次 TD 更新."""

    def __init__(self, num_clients: int, device: torch.device | None = None):
        self.num_clients = int(num_clients)
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = TrustNet().to(self.device)
        self.target_model = TrustNet().to(self.device)
        self.target_model.load_state_dict(self.model.state_dict())
        self.optimizer = optim.Adam(self.model.parameters(), lr=LR)
        self.loss_fn = nn.MSELoss()
        self.memory = ReplayBuffer()
        self._prev_states: np.ndarray | None = None
        self._step_count = 0
        self.last_rewards: list[float] = []

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state_dict": self.model.state_dict(),
                "target_model_state_dict": self.target_model.state_dict(),
                "optimizer_state_dict": self.optimizer.state_dict(),
                "step_count": self._step_count,
                "state_names": STATE_NAMES,
                "action_names": ACTION_NAMES,
            },
            path,
        )

    def load(self, path: str | Path) -> bool:
        path = Path(path)
        if not path.is_file():
            return False
        try:
            payload = torch.load(path, map_location=self.device)
            self.model.load_state_dict(payload["model_state_dict"])
            self.target_model.load_state_dict(payload.get("target_model_state_dict", payload["model_state_dict"]))
            if "optimizer_state_dict" in payload:
                self.optimizer.load_state_dict(payload["optimizer_state_dict"])
            self._step_count = int(payload.get("step_count", 0))
            return True
        except Exception as exc:
            print(f"[RL] Skip incompatible TrustNet checkpoint {path}: {exc}")
            return False

    def observe_round_transition(self, states_now: np.ndarray) -> None:
        """在联邦一轮结束时调用；用上一时刻状态与当前状态组成转移."""
        if self._prev_states is not None:
            rewards: list[float] = []
            for i in range(self.num_clients):
                s = self._prev_states[i]
                s_next = states_now[i]
                r = reward_function(s)
                rewards.append(float(r))
                self.memory.push(s, r, s_next)
            self.last_rewards = rewards
        else:
            self.last_rewards = []
        self._prev_states = states_now.copy()

        if len(self.memory) >= DEFAULT_BATCH:
            s_b, r_b, sn_b = self.memory.sample(DEFAULT_BATCH)
            s_b = torch.FloatTensor(s_b).to(self.device)
            r_b = torch.FloatTensor(r_b).unsqueeze(1).to(self.device)
            sn_b = torch.FloatTensor(sn_b).to(self.device)
            self.model.train()
            q = self.model(s_b)
            with torch.no_grad():
                next_q = self.target_model(sn_b)
                y = r_b + GAMMA * next_q
            loss = self.loss_fn(q, y)
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            self._step_count += 1
            if self._step_count % 5 == 0:
                self.target_model.load_state_dict(self.model.state_dict())

    def trust_scores_0_100(self, states: np.ndarray) -> np.ndarray:
        """对当前状态前向得到信任分，映射到约 **(5, 95)** 的「百分制可读区间」。

        不再使用「跨客户端 min-max」：那种做法每轮必有一台为 100、一台为 0，且只要
        TrustNet 对某个特征（如 quality）近似单调、而某台机（常见为 client 0）长期
        raw 最大，就会**永远显示 100**。改为每台独立 logistic，再线性压到 5–95，
        避免 logits 略正就四舍五入成满分 100 的错觉。
        """
        self.model.eval()
        with torch.no_grad():
            t = torch.FloatTensor(states).to(self.device)
            raw = self.model(t).cpu().numpy().astype(np.float64).flatten()
        # 数值稳定，避免 exp 溢出；映射到 (5,95) 而非紧贴 0/100，避免 logits 略正就显示成「满分 100」
        z = np.clip(raw, -40.0, 40.0)
        s = 1.0 / (1.0 + np.exp(-z))
        scores = 5.0 + 90.0 * s
        if states.shape[1] > 5:
            anomaly = np.clip(states[:, 5].astype(np.float64), 0.0, 1.0)
            scores = scores * (1.0 - 0.45 * anomaly)
        scores = np.clip(scores, 5.0, 95.0).astype(np.float32)
        return scores
