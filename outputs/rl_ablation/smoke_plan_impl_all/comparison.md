# RL Ablation Comparison

Baseline for deltas: `no_rl`

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.413857 | 0.413857 | 0.413857 |
| loss | 2.295347 | 2.295347 | 2.295347 |
| precision_macro | 0.248343 | 0.248343 | 0.248343 |
| recall_macro | 0.230468 | 0.230468 | 0.230468 |
| trust_mean | 0.700000 | 0.700000 | 0.569525 |
| threat_level | 0.751657 | 0.751657 | 0.751657 |
| next_noise_scale | 0.000000 | 1.246975 | 1.288918 |
| next_freq_n | 1.000000 | 91.000000 | 91.000000 |

## Delta vs baseline

| Metric | no_apc | no_rl | with_rl |
|---|---:|---:|---:|
| accuracy | 0.000000 | 0.000000 | 0.000000 |
| loss | 0.000000 | 0.000000 | 0.000000 |
| precision_macro | 0.000000 | 0.000000 | 0.000000 |
| recall_macro | 0.000000 | 0.000000 | 0.000000 |
| trust_mean | 0.000000 | 0.000000 | -0.130475 |
| threat_level | 0.000000 | 0.000000 | 0.000000 |
| next_noise_scale | -1.246975 | 0.000000 | 0.041943 |
| next_freq_n | -90.000000 | 0.000000 | 0.000000 |

## Artifacts

- no_apc log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_plan_impl_all\no_apc\server.log`
- no_apc live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_plan_impl_all\no_apc\live_rounds.json`
- no_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_plan_impl_all\no_rl\server.log`
- no_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_plan_impl_all\no_rl\live_rounds.json`
- with_rl log: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_plan_impl_all\with_rl\server.log`
- with_rl live rounds: `D:\Documents\UAV_Project-main\UAV_Project-main\outputs\rl_ablation\smoke_plan_impl_all\with_rl\live_rounds.json`
