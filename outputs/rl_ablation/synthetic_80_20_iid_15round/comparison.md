# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 1.000000 | 0.626344 | 0.602151 |
| loss | 0.044544 | 1.121851 | 1.124392 |
| precision_macro | 1.000000 | 0.627643 | 0.638453 |
| recall_macro | 1.000000 | 0.631965 | 0.603372 |
| trust_mean | 0.700000 | 0.700000 | 0.444870 |
| threat_level | 0.000000 | 0.372357 | 0.361547 |
| next_noise_scale | 0.000000 | 0.938226 | 0.953886 |
| next_freq_n | 1.000000 | 1.000000 | 1.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 44.482000 |
| final_malicious_trust | 70.000000 | 70.000000 | 44.496948 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.373656 | 0.000000 | -0.024194 |
| loss | -1.077307 | 0.000000 | 0.002541 |
| precision_macro | 0.372357 | 0.000000 | 0.010810 |
| recall_macro | 0.368035 | 0.000000 | -0.028592 |
| trust_mean | 0.000000 | 0.000000 | -0.255130 |
| threat_level | -0.372357 | 0.000000 | -0.010810 |
| next_noise_scale | -0.938226 | 0.000000 | 0.015661 |
| next_freq_n | 0.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -25.518000 |
| final_malicious_trust | 0.000000 | 0.000000 | -25.503052 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_15round\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_15round\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_15round\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_15round\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_15round\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_15round\with_rl\live_rounds.json`
