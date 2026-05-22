# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.478060 | 0.386275 | 0.259056 |
| loss | 1.887810 | 1.940654 | 2.139096 |
| precision_macro | 0.362395 | 0.269990 | 0.172798 |
| recall_macro | 0.296228 | 0.231832 | 0.160580 |
| trust_mean | 0.700000 | 0.700000 | 0.371526 |
| threat_level | 0.637605 | 0.730010 | 0.827202 |
| next_noise_scale | 0.000000 | 1.157157 | 1.332662 |
| next_freq_n | 1.000000 | 2.000000 | 3.000000 |
| accepted_clients | 3.000000 | 3.000000 | 3.000000 |
| malicious_weight_share | 0.000000 | 0.032728 | 0.022444 |
| mean_malicious_weight_share | 0.000000 | 0.014449 | 0.008112 |
| max_malicious_weight_share | 0.000000 | 0.034336 | 0.034336 |
| final_clean_trust_mean | 70.000000 | 70.000000 | 48.478754 |
| final_malicious_trust | 70.000000 | 70.000000 | 14.500417 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.091785 | 0.000000 | -0.127219 |
| loss | -0.052844 | 0.000000 | 0.198442 |
| precision_macro | 0.092405 | 0.000000 | -0.097192 |
| recall_macro | 0.064396 | 0.000000 | -0.071252 |
| trust_mean | 0.000000 | 0.000000 | -0.328474 |
| threat_level | -0.092405 | 0.000000 | 0.097192 |
| next_noise_scale | -1.157157 | 0.000000 | 0.175505 |
| next_freq_n | -1.000000 | 0.000000 | 1.000000 |
| accepted_clients | 0.000000 | 0.000000 | 0.000000 |
| malicious_weight_share | -0.032728 | 0.000000 | -0.010284 |
| mean_malicious_weight_share | -0.014449 | 0.000000 | -0.006337 |
| max_malicious_weight_share | -0.034336 | 0.000000 | 0.000000 |
| final_clean_trust_mean | 0.000000 | 0.000000 | -21.521246 |
| final_malicious_trust | 0.000000 | 0.000000 | -55.499583 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_trust_memory\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_trust_memory\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_trust_memory\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_trust_memory\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_trust_memory\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\malicious_7round_trust_memory\with_rl\live_rounds.json`
