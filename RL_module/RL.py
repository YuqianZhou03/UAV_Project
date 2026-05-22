"""
原始离线训练脚本（100 架无人机仿真）。
仅在直接运行本文件时执行；被其他模块 import 时不会产生副作用。
"""

from __future__ import annotations

import numpy as np
import torch

try:
    from .core import DEFAULT_BATCH, GAMMA, LR, ReplayBuffer, TrustNet, reward_function
except ImportError:
    import sys
    from pathlib import Path

    _root = Path(__file__).resolve().parent.parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))
    from RL_module.core import DEFAULT_BATCH, GAMMA, LR, ReplayBuffer, TrustNet, reward_function

# 与历史脚本保持接近的参数（仅 __main__ 使用）
num_clients = 100
episodes = 300
batch_size = DEFAULT_BATCH
buffer_size = 5000
target_update = 10

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def init_state():
    return np.stack(
        [
            np.random.rand(num_clients),
            np.random.rand(num_clients),
            np.random.rand(num_clients),
            np.random.rand(num_clients),
            np.random.randint(0, 2, num_clients),
        ],
        axis=1,
    )


def update_state(state: np.ndarray) -> np.ndarray:
    s = state.copy()
    s[:, 1] = np.clip(s[:, 1] + np.random.normal(0, 0.05, num_clients), 0, 1)
    s[:, 2] = np.clip(s[:, 2] + np.random.normal(0, 0.05, num_clients), 0, 1)
    s[:, 3] = np.clip(s[:, 3] - np.random.uniform(0.01, 0.03, num_clients), 0, 1)
    s[:, 4] = np.random.randint(0, 2, num_clients)
    return s


if __name__ == "__main__":
    memory = ReplayBuffer(maxlen=buffer_size)
    model = TrustNet(state_dim=5).to(device)
    target_model = TrustNet(state_dim=5).to(device)
    target_model.load_state_dict(model.state_dict())
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = torch.nn.MSELoss()

    state = init_state()
    for ep in range(episodes):
        next_state = update_state(state)
        for i in range(num_clients):
            s = state[i]
            s_next = next_state[i]
            r = reward_function(s)
            memory.push(s, r, s_next)
        state = next_state

        if len(memory) >= batch_size:
            s_batch, r_batch, s_next_batch = memory.sample(batch_size)
            s_batch = torch.FloatTensor(s_batch).to(device)
            r_batch = torch.FloatTensor(r_batch).unsqueeze(1).to(device)
            s_next_batch = torch.FloatTensor(s_next_batch).to(device)
            q = model(s_batch)
            with torch.no_grad():
                next_q = target_model(s_next_batch)
                y = r_batch + GAMMA * next_q
            loss = loss_fn(q, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        if ep % target_update == 0:
            target_model.load_state_dict(model.state_dict())

        if (ep + 1) % 20 == 0:
            print(f"Episode {ep + 1}")

    model.eval()
    with torch.no_grad():
        scores = model(torch.FloatTensor(state).to(device)).cpu().numpy().flatten()
    scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
    scores = scores * 100
    print("\n======= 所有无人机信任评分（离线仿真）=======")
    for i in range(min(num_clients, 20)):
        print(f"UAV {i:03d}: {scores[i]:.2f}")
    print(f"... 共 {num_clients} 架，此处仅展示前 20 条。")
