# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 1.000000 | 0.860215 | 0.977151 |
| loss | 0.016521 | 0.373349 | 0.203874 |
| precision_macro | 1.000000 | 0.884329 | 0.976229 |
| recall_macro | 1.000000 | 0.847507 | 0.975073 |
| trust_mean | 0.700000 | 0.700000 | 0.431350 |
| threat_level | 0.000000 | 0.115671 | 0.023771 |
| next_noise_scale | 0.000000 | 0.944086 | 0.963978 |
| next_freq_n | 1.000000 | 1.000000 | 1.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 43.093628 |
| final_malicious_trust | 70.000000 | 70.000000 | 43.217781 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.139785 | 0.000000 | 0.116935 |
| loss | -0.356828 | 0.000000 | -0.169475 |
| precision_macro | 0.115671 | 0.000000 | 0.091901 |
| recall_macro | 0.152493 | 0.000000 | 0.127566 |
| trust_mean | 0.000000 | 0.000000 | -0.268650 |
| threat_level | -0.115671 | 0.000000 | -0.091901 |
| next_noise_scale | -0.944086 | 0.000000 | 0.019892 |
| next_freq_n | 0.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -26.906372 |
| final_malicious_trust | 0.000000 | 0.000000 | -26.782219 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_25round\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_25round\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_25round\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_25round\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_25round\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_iid_25round\with_rl\live_rounds.json`
