# UAV_Project — Federated swarm IDS (Flower + CNN–LSTM)

**中文简介：** 面向无人机（UAV）网络场景的入侵检测实验仓库：将多类攻击的 PCAP 衍生特征整理为滑动时间窗样本，在 **Flower** 上做 **FedAvg** 联邦训练，模型为 **CNN + LSTM**；并串联 **信任 RL 桥接（`RL_module`）** 与 **自适应隐私控制器 APC（`apc_module`）**，在服务器端根据集中式评估与客户端遥测形成闭环策略（参与与否、更新频率、噪声强度）。可选 **仪表板** 用于可视化。

English: research-style codebase for **federated learning** on **windowed UAV/IDS features**, with optional **RL → adaptive privacy control** and a small **static dashboard**.

---

## Highlights

| Area | What this repo does |
|------|---------------------|
| **Data** | Reads per-attack CSVs under `dataset/` (see manifest in `preprocess_swarm_federated.py`), builds `(N, T, F)` tensors with `T=16`, pooled test holdout, and `9` disjoint train shards for 3 clients × 3 rounds. |
| **Telemetry** | `enrich_swarm_telemetry.py` aligns **synthetic battery / CPU** channels with each window (`telemetry_synth.py`). After enrichment, `meta.json` uses **`n_features = 46`**. |
| **Model** | `CnnLstmIDS` in `model.py` — Conv1d over time, LSTM, linear classifier (`SimpleIDS` kept as a flat baseline). |
| **FL** | **Flower** `server.py` / `client.py`, `127.0.0.1:8080`, **3 rounds**, **3 clients**, strategy **`RLAPCFedAvg`** (FedAvg + structured logging + post-eval RL→APC). |
| **Scenario** | `scenario_config.py` attaches a **deployment narrative + GPS anchor** per round (cycles Beijing → Sudan → Tehran). |
| **Dashboard** | `dashboard/serve.py` — local HTTP server on port **8765** (ZH/EN UI). |

---

## Repository layout

| Path | Role |
|------|------|
| `preprocess_swarm_federated.py` | Build `data/swarm_processed/` (`meta.json`, `train_split_0..8.npz`, `test.npz`). |
| `enrich_swarm_telemetry.py` | Append / normalize telemetry columns; sync `meta.json` feature count. |
| `telemetry_synth.py` | Rules for synthetic SOC and CPU given IDS windows. |
| `swarm_fl_data.py` | Paths, loaders, shard index `split_index_for_round_client`. |
| `model.py` | `CnnLstmIDS`, parameter serde for Flower. |
| `client.py` | `DroneClient` — local fit/eval, APC noise on weight delta, telemetry metrics. |
| `server.py` | FedAvg strategy, centralized test eval, **RL → APC** policy for next round. |
| `scenario_config.py` | Round-based theatre / GPS / text block for logs. |
| `apc_module/` | YAML-driven **AdaptivePrivacyController** (participation, frequency, noise). See `apc_module/README.md`. |
| `RL_module/` | `TrustNet`, replay buffer, **`FLTrustRLBridge`** for server-side trust scores. |
| `dashboard/` | Static dashboard + `serve.py`. |
| `final_group_thesis_overleaf/` | LaTeX thesis skeleton (course/report formatting). |

---

## Prerequisites

- **Python 3.10+** (3.11/3.12 OK).
- **PyTorch** matching your OS/CUDA (CPU is fine for the default demo).
- Raw **dataset CSVs** if you regenerate splits (see **Data & `.gitignore`** below).

---

## Installation

```bash
git clone https://github.com/YuqianZhou03/UAV_Project.git
cd UAV_Project
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
# source .venv/bin/activate

pip install -U pip
pip install -r requirements.txt
```

If you prefer a minimal manual install:

```bash
pip install torch flwr pandas scikit-learn numpy pyyaml
```

---

## Data and `.gitignore` (important for GitHub)

This repo’s `.gitignore` **excludes**:

- `dataset/` — raw attack CSVs used by the preprocessor.
- `data/UAV-Case1-Label.csv` — optional header source for the 44 IDS column names.

**Ways to make a fresh clone runnable:**

1. **Ship preprocessed tensors** — commit `data/swarm_processed/*.npz` and `meta.json` (large: consider [Git LFS](https://git-lfs.github.com/)). Then you can **skip** preprocessing for inference/FL demos.  
2. **Ship raw CSVs** — remove or adjust the `/dataset/` ignore rule (or use LFS), add files matching `MANIFEST` in `preprocess_swarm_federated.py`, then run the pipeline below.

Optional: place `data/UAV-Case1-Label.csv` so feature names are read from its header; otherwise the built-in `_CANONICAL_44` list is used.

---

## Build `data/swarm_processed/`

From the repository root:

```bash
python preprocess_swarm_federated.py
python enrich_swarm_telemetry.py
```

Check that `data/swarm_processed/meta.json` exists and that `n_features` matches your tensors (**46** after enrichment).

### Synthetic benchmark (no real PCAP CSVs)

`generate_synthetic_uav_dataset.py` writes Wireshark-style **44-column** CSVs (same names as `preprocess_swarm_federated.py`) for **Normal + every attack in `MANIFEST`**, with class-specific statistics so labels stay learnable after scaling and windowing.

```bash
# Back up data/swarm_processed/ first — this overwrites it.
python generate_synthetic_uav_dataset.py --out dataset/synthetic_uav --rows 3200 --run-pipeline --verify
```

`--run-pipeline` runs preprocessing + telemetry enrichment with `UAV_DATASET_ROOT` pointing at your synthetic folder; `--verify` runs a quick sklearn sanity check on the pooled train windows.

To confirm the **CNN+LSTM IDS** can learn **attack vs normal + attack type** on the same bundle:

```bash
python verify_synthetic_ids.py --epochs 15
```

---

## Run federated learning

### RL ablation: no RL vs with RL

Run one no-RL baseline and one RL-enabled run with the same seed, then write a
metric comparison:

```bash
python run_rl_ablation.py --rounds 15 --seed 2026 --local-epochs 2
```

By default the ablation now runs three variants:

- `no_apc`: plain FedAvg-style baseline with APC disabled.
- `no_rl`: APC enabled, but trust is a fixed baseline score (`--fixed-trust-score`, default `70.0`).
- `with_rl`: APC enabled with TrustNet-driven trust scores.

Scenario stress tests can be selected with `--scenario iid|non_iid|malicious|dropout|low_resource`.
For example:

```bash
python run_rl_ablation.py --rounds 15 --seed 2026 --local-epochs 2 --scenario malicious
python run_rl_ablation.py --rounds 15 --seed 2026 --local-epochs 2 --scenario low_resource --variants no_rl,with_rl
```

Outputs are saved under `outputs/rl_ablation/<timestamp>/`:

- `no_apc/live_rounds.json` and `no_apc/server.log`
- `no_rl/live_rounds.json` and `no_rl/server.log`
- `with_rl/live_rounds.json` and `with_rl/server.log`
- `comparison.json` and `comparison.md`

The live JSON records stable APC/RL fields for thesis tables and dashboard checks:
`threat_level`, `mission_criticality`, `trust_score`, `resource_availability`,
`epsilon`, `delta`, `clip_norm`, `noise_scale`, `update_frequency`, and `participate`.

### Reproducibility preflight

Before a demo or experiment, run:

```bash
python check_env.py
```

This checks Python dependencies, `data/swarm_processed`, ports `8080` / `8765`, and
whether a checkpoint already exists. Conda users can create a clean environment with:

```bash
conda env create -f environment.yml
conda activate uav-fl-ids
```

### Privacy-control note

The client now clips each weight update delta (`FL_DELTA_CLIP_NORM`, default `1.0`)
before adding Gaussian update noise. The APC exports an effective epsilon proxy
(`epsilon = 1 / noise_scale`) plus `delta` (`FL_DP_DELTA`, default `1e-5`) for
auditability. This is still an experimental privacy controller for research
evaluation, not a certified formal DP accounting implementation.

### Recommended train/test split and rounds

The preprocessing default is now an 80/20 packet split per source file
(`UAV_PACKET_HOLDOUT_FRAC=0.20`), which is easier to explain in the thesis:
80% of each attack trace is used for federated training shards and 20% is held
out for pooled server-side testing.

For stronger IDS results, use 15 rounds and 2 local epochs first:

```bash
python run_rl_ablation.py --rounds 15 --local-epochs 2 --seed 2026 --scenario iid
```

If the curve is still rising, repeat with 20 rounds for the final table. For
RL/APC stress testing, use the same rounds/epochs with `--scenario malicious`.

You can also run the server directly in either mode:

```bash
# no RL: fixed-trust APC baseline
FL_RL_ENABLED=0 python server.py

# with RL: TrustNet -> APC closed loop
FL_RL_ENABLED=1 python server.py
```

**Terminal A — server**

```bash
python server.py
```

Wait until the Flower gRPC server is listening on **`127.0.0.1:8080`**.

**Terminals B–D — three clients**

```bash
python client.py 0
python client.py 1
python client.py 2
```

**Windows shortcut:** double-click `start_fl.bat` or run `.\start_fl.ps1` — frees ports **8080** and **8765**, starts **Flower server + 3 clients + dashboard**, then opens your **default browser** to **http://127.0.0.1:8765/** (five PowerShell windows stay open).

---

## Optional dashboard

```bash
python dashboard/serve.py
```

Open **http://127.0.0.1:8765/** (Chinese) or **http://127.0.0.1:8765/en/** (English).

While **`server.py`** is running it writes **`dashboard/data/live_rounds.json`** after each federated round. The dashboard **merges that file when it exists and has rounds**, so R1–R3 match your latest local run; otherwise it falls back to the bundled demo `rounds.json` / `rounds_en.json`. `live_rounds.json` is gitignored.

---

## GitHub deployment checklist

- [x] Public clone URL: `https://github.com/YuqianZhou03/UAV_Project.git`  
- [ ] Add a **LICENSE** file if the repo is public.  
- [ ] Decide on **data distribution**: Git LFS for `dataset/` and/or `data/swarm_processed/`, or document an external download link.  
- [ ] Ignore local noise: add patterns such as `*.log`, `_*.log`, `_fl_capture_run.txt` to `.gitignore` if you do not want run artifacts pushed.  
- [ ] Remove or do not commit secrets (tokens, personal paths).  
- [ ] Pin versions in `requirements.txt` once you freeze a reproducible environment (`pip freeze > requirements-lock.txt`).  

---

## Related / upstream

If this work continues a fork or collaboration line, add your **paper**, **thesis**, or **upstream repo** link here.

---

## Disclaimer

Attack traces and scenario text are for **network security research and education** only. Synthetic telemetry is **not** flight-certified data. Respect your institution’s data-handling and publication rules when publishing the repository or derived models.
