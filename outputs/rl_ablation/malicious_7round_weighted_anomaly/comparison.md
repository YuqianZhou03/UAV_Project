# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.545629 | 0.425866 | 0.532827 |
| loss | 1.845970 | 1.946076 | 1.913265 |
| precision_macro | 0.362893 | 0.250463 | 0.259347 |
| recall_macro | 0.338842 | 0.242942 | 0.313698 |
| trust_mean | 0.700000 | 0.700000 | 0.370694 |
| threat_level | 0.637107 | 0.749537 | 0.740653 |
| next_noise_scale | 0.000000 | 1.164452 | 1.290243 |
| next_freq_n | 1.000000 | 3.000000 | 3.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.032145 | 0.033275 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.119762 | 0.000000 | 0.106961 |
| loss | -0.100106 | 0.000000 | -0.032810 |
| precision_macro | 0.112430 | 0.000000 | 0.008884 |
| recall_macro | 0.095900 | 0.000000 | 0.070756 |
| trust_mean | 0.000000 | 0.000000 | -0.329306 |
| threat_level | -0.112430 | 0.000000 | -0.008884 |
| next_noise_scale | -1.164452 | 0.000000 | 0.125791 |
| next_freq_n | -2.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | -0.032145 | 0.000000 | 0.001130 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_weighted_anomaly\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_weighted_anomaly\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_weighted_anomaly\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_weighted_anomaly\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_weighted_anomaly\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_weighted_anomaly\with_rl\live_rounds.json`
