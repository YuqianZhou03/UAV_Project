# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.497130 | 0.366942 | 0.242362 |
| loss | 1.571985 | 2.096581 | 2.102894 |
| precision_macro | 0.373723 | 0.274697 | 0.145883 |
| recall_macro | 0.308635 | 0.198735 | 0.131353 |
| trust_mean | 0.700000 | 0.700000 | 0.484970 |
| threat_level | 0.626277 | 0.725303 | 0.854117 |
| next_noise_scale | 0.000000 | 0.999956 | 1.034182 |
| next_freq_n | 1.000000 | 2.000000 | 3.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 48.496758 |
| final_malicious_trust | 70.000000 | 70.000000 | 48.497475 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.130188 | 0.000000 | -0.124579 |
| loss | -0.524596 | 0.000000 | 0.006313 |
| precision_macro | 0.099026 | 0.000000 | -0.128814 |
| recall_macro | 0.109900 | 0.000000 | -0.067382 |
| trust_mean | 0.000000 | 0.000000 | -0.215030 |
| threat_level | -0.099026 | 0.000000 | 0.128814 |
| next_noise_scale | -0.999956 | 0.000000 | 0.034226 |
| next_freq_n | -1.000000 | 0.000000 | 1.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| mean_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| max_malicious_weight_share | 0.000000 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -21.503242 |
| final_malicious_trust | 0.000000 | 0.000000 | -21.502525 |

## Artifacts

- no_apc log: `C:\Users\13911\Projects\UAV-of-BDIC-2026\outputs\rl_ablation\20260523_150144\no_apc\server.log`
- no_apc live rounds: `C:\Users\13911\Projects\UAV-of-BDIC-2026\outputs\rl_ablation\20260523_150144\no_apc\live_rounds.json`
- no_rl log: `C:\Users\13911\Projects\UAV-of-BDIC-2026\outputs\rl_ablation\20260523_150144\no_rl\server.log`
- no_rl live rounds: `C:\Users\13911\Projects\UAV-of-BDIC-2026\outputs\rl_ablation\20260523_150144\no_rl\live_rounds.json`
- with_rl log: `C:\Users\13911\Projects\UAV-of-BDIC-2026\outputs\rl_ablation\20260523_150144\with_rl\server.log`
- with_rl live rounds: `C:\Users\13911\Projects\UAV-of-BDIC-2026\outputs\rl_ablation\20260523_150144\with_rl\live_rounds.json`
