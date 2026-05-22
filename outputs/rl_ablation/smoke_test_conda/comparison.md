# RL Ablation Comparison

| Metric | No RL | With RL | Delta (with - no) |
|---|---:|---:|---:|
| accuracy | 0.569647 | 0.683207 | 0.113560 |
| loss | 0.864569 | 0.935688 | 0.071118 |
| precision_macro | 0.372271 | 0.386943 | 0.014673 |
| recall_macro | 0.399624 | 0.438508 | 0.038884 |
| trust_mean | 0.700000 | 0.571418 | -0.128582 |
| threat_level | 0.627729 | 0.613057 | -0.014673 |
| next_noise_scale | 1.147931 | 1.176723 | 0.028792 |
| next_freq_n | 65.000000 | 61.000000 | -4.000000 |

## Artifacts

- No RL log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_test_conda\no_rl\server.log`
- With RL log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_test_conda\with_rl\server.log`
- No RL live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_test_conda\no_rl\live_rounds.json`
- With RL live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_test_conda\with_rl\live_rounds.json`
