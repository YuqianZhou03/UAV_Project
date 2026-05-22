# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.290729 | 0.185549 | 0.185549 |
| loss | 2.118508 | 2.416551 | 2.416551 |
| precision_macro | 0.157047 | 0.018764 | 0.018764 |
| recall_macro | 0.168805 | 0.100000 | 0.100000 |
| trust_mean | 0.700000 | 0.700000 | 0.582359 |
| threat_level | 0.842953 | 0.981236 | 0.981236 |
| next_noise_scale | 0.000000 | 1.223713 | 1.259990 |
| next_freq_n | 1.000000 | 96.000000 | 96.000000 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.105180 | 0.000000 | 0.000000 |
| loss | -0.298043 | 0.000000 | 0.000000 |
| precision_macro | 0.138283 | 0.000000 | 0.000000 |
| recall_macro | 0.068805 | 0.000000 | 0.000000 |
| trust_mean | 0.000000 | 0.000000 | -0.117641 |
| threat_level | -0.138283 | 0.000000 | 0.000000 |
| next_noise_scale | -1.223713 | 0.000000 | 0.036277 |
| next_freq_n | -95.000000 | 0.000000 | 0.000000 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_conda_retry\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_conda_retry\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_conda_retry\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_conda_retry\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_conda_retry\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_conda_retry\with_rl\live_rounds.json`
