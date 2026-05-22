# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 1.000000 | 0.846774 | 0.861559 |
| loss | 0.023561 | 0.557064 | 0.374454 |
| precision_macro | 1.000000 | 0.895678 | 0.880408 |
| recall_macro | 1.000000 | 0.832845 | 0.848974 |
| trust_mean | 0.700000 | 0.700000 | 0.425929 |
| threat_level | 0.000000 | 0.104322 | 0.119592 |
| next_noise_scale | 0.000000 | 0.914717 | 0.940861 |
| next_freq_n | 1.000000 | 1.000000 | 1.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 42.609295 |
| final_malicious_trust | 70.000000 | 70.000000 | 42.560204 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.153226 | 0.000000 | 0.014785 |
| loss | -0.533503 | 0.000000 | -0.182609 |
| precision_macro | 0.104322 | 0.000000 | -0.015270 |
| recall_macro | 0.167155 | 0.000000 | 0.016129 |
| trust_mean | 0.000000 | 0.000000 | -0.274071 |
| threat_level | -0.104322 | 0.000000 | 0.015270 |
| next_noise_scale | -0.914717 | 0.000000 | 0.026144 |
| next_freq_n | 0.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -27.390705 |
| final_malicious_trust | 0.000000 | 0.000000 | -27.439796 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_20round\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_20round\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_20round\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_20round\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_20round\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_20round\with_rl\live_rounds.json`
