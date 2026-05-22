# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.372312 | 0.217742 | 0.217742 |
| loss | 1.828357 | 2.269653 | 2.269654 |
| precision_macro | 0.193997 | 0.059157 | 0.059157 |
| recall_macro | 0.315982 | 0.146628 | 0.146628 |
| trust_mean | 0.700000 | 0.700000 | 0.484728 |
| threat_level | 0.806003 | 0.940843 | 0.940843 |
| next_noise_scale | 0.000000 | 1.047519 | 1.071686 |
| next_freq_n | 1.000000 | 3.000000 | 3.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 48.489750 |
| final_malicious_trust | 70.000000 | 70.000000 | 48.438873 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.154570 | 0.000000 | 0.000000 |
| loss | -0.441296 | 0.000000 | 0.000000 |
| precision_macro | 0.134841 | 0.000000 | 0.000000 |
| recall_macro | 0.169355 | 0.000000 | 0.000000 |
| trust_mean | 0.000000 | 0.000000 | -0.215272 |
| threat_level | -0.134841 | 0.000000 | 0.000000 |
| next_noise_scale | -1.047519 | 0.000000 | 0.024167 |
| next_freq_n | -2.000000 | 0.000000 | 0.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -21.510250 |
| final_malicious_trust | 0.000000 | 0.000000 | -21.561127 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_smoke\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_smoke\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_smoke\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_smoke\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_smoke\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\synthetic_80_20_smoke\with_rl\live_rounds.json`
