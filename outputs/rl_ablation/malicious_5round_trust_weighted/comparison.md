# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.281425 | 0.229957 | 0.229957 |
| loss | 2.150412 | 2.310477 | 2.310477 |
| precision_macro | 0.178888 | 0.218292 | 0.218292 |
| recall_macro | 0.186798 | 0.124912 | 0.124912 |
| trust_mean | 0.700000 | 0.700000 | 0.580350 |
| threat_level | 0.821112 | 0.781708 | 0.781708 |
| next_noise_scale | 0.000000 | 1.178895 | 1.213118 |
| next_freq_n | 1.000000 | 95.000000 | 95.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.051468 | 0.000000 | 0.000000 |
| loss | -0.160065 | 0.000000 | 0.000000 |
| precision_macro | -0.039404 | 0.000000 | 0.000000 |
| recall_macro | 0.061885 | 0.000000 | 0.000000 |
| trust_mean | 0.000000 | 0.000000 | -0.119650 |
| threat_level | 0.039404 | 0.000000 | 0.000000 |
| next_noise_scale | -1.178895 | 0.000000 | 0.034223 |
| next_freq_n | -94.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_trust_weighted\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_trust_weighted\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_trust_weighted\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_trust_weighted\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_trust_weighted\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_trust_weighted\with_rl\live_rounds.json`
