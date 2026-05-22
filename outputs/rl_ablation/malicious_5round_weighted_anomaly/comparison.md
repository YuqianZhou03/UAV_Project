# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.460706 | 0.372418 | 0.266447 |
| loss | 2.123003 | 2.150460 | 2.167893 |
| precision_macro | 0.239532 | 0.205966 | 0.177148 |
| recall_macro | 0.268302 | 0.205938 | 0.149325 |
| trust_mean | 0.700000 | 0.700000 | 0.483730 |
| threat_level | 0.760468 | 0.794034 | 0.822852 |
| next_noise_scale | 0.000000 | 1.139515 | 1.242928 |
| next_freq_n | 1.000000 | 3.000000 | 3.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.088288 | 0.000000 | -0.105972 |
| loss | -0.027457 | 0.000000 | 0.017433 |
| precision_macro | 0.033566 | 0.000000 | -0.028818 |
| recall_macro | 0.062364 | 0.000000 | -0.056613 |
| trust_mean | 0.000000 | 0.000000 | -0.216270 |
| threat_level | -0.033566 | 0.000000 | 0.028818 |
| next_noise_scale | -1.139515 | 0.000000 | 0.103413 |
| next_freq_n | -2.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_weighted_anomaly\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_weighted_anomaly\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_weighted_anomaly\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_weighted_anomaly\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_weighted_anomaly\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_5round_weighted_anomaly\with_rl\live_rounds.json`
