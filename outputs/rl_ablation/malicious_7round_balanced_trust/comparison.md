# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.490399 | 0.508413 | 0.512966 |
| loss | 1.861476 | 1.955672 | 1.925256 |
| precision_macro | 0.362850 | 0.253757 | 0.256349 |
| recall_macro | 0.304686 | 0.301071 | 0.307541 |
| trust_mean | 0.700000 | 0.700000 | 0.411151 |
| threat_level | 0.637150 | 0.746243 | 0.743651 |
| next_noise_scale | 0.000000 | 1.045868 | 1.077045 |
| next_freq_n | 1.000000 | 3.000000 | 3.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.030647 | 0.023339 |
| mean_malicious_weight_share | 0.000000 | 0.013986 | 0.011451 |
| max_malicious_weight_share | 0.000000 | 0.034336 | 0.034336 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 48.408455 |
| final_malicious_trust | 70.000000 | 70.000000 | 26.528292 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | -0.018014 | 0.000000 | 0.004553 |
| loss | -0.094197 | 0.000000 | -0.030417 |
| precision_macro | 0.109093 | 0.000000 | 0.002592 |
| recall_macro | 0.003615 | 0.000000 | 0.006470 |
| trust_mean | 0.000000 | 0.000000 | -0.288849 |
| threat_level | -0.109093 | 0.000000 | -0.002592 |
| next_noise_scale | -1.045868 | 0.000000 | 0.031177 |
| next_freq_n | -2.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | -0.030647 | 0.000000 | -0.007308 |
| mean_malicious_weight_share | -0.013986 | 0.000000 | -0.002535 |
| max_malicious_weight_share | -0.034336 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -21.591545 |
| final_malicious_trust | 0.000000 | 0.000000 | -43.471708 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_balanced_trust\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_balanced_trust\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_balanced_trust\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_balanced_trust\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_balanced_trust\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_balanced_trust\with_rl\live_rounds.json`
