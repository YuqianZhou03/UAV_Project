"""APC 决策规则
所有规则集中在此文件，修改规则只需改这里
"""

from typing import Any, Dict

from .models import Context


def _smoothstep01(x: float) -> float:
    x = max(0.0, min(1.0, x))
    return x * x * (3.0 - 2.0 * x)


class ParticipationRule:
    """规则1：决定是否参与 FL 轮次"""

    def __init__(self, config: Dict[str, float]):
        self.min_trust = config.get("min_trust_score", 0.3)
        self.min_resource = config.get("min_resource", 0.2)
        self.suspend_threat = config.get("suspend_participation_threat", 0.62)
        self.critical_threat = config.get("critical_suspend_threat", 0.92)
        self.threat_suspend_trust = config.get("threat_suspend_trust", 0.35)

    def decide(self, ctx: Context) -> int:
        if ctx.trust_score < self.min_trust:
            return 0
        if ctx.resource_availability < self.min_resource:
            return 0
        if (
            ctx.threat_level >= self.critical_threat
            and ctx.trust_score < self.threat_suspend_trust
        ):
            return 0
        return 1


class FrequencyRule:
    """规则2：每 N 轮参与一次（freq_n）。

    低威胁（含「宏观 + 本地 eval 均正常」）保持 freq_n=freq_benign（默认 1），
    不人为抬高上传间隔；威胁升高后在 [freq_benign, freq_cap] 内随威胁平滑增大。
    """

    def __init__(self, config: Dict[str, Any]):
        self.low_res_th = float(config.get("low_resource_threshold", 0.3))
        self.freq_low_resource = int(config.get("freq_low_resource", 64))

        self.neutral_th = float(config.get("neutral_threat_max", 0.32))
        self.freq_benign = int(config.get("freq_benign", 1))
        self.t_ramp0 = float(config.get("threat_ramp_start", 0.32))
        self.t_ramp1 = float(config.get("threat_ramp_end", 0.82))
        self.freq_at_ramp_end = int(config.get("freq_at_ramp_end", 96))
        self.freq_cap = int(config.get("freq_cap", 180))

    def decide(self, ctx: Context) -> int:
        if ctx.resource_availability < self.low_res_th:
            return max(self.freq_benign, self.freq_low_resource)

        t = float(ctx.threat_level)
        if t <= self.neutral_th:
            return max(1, self.freq_benign)

        if self.t_ramp1 <= self.t_ramp0 + 1e-9:
            return max(self.freq_benign, min(self.freq_cap, self.freq_at_ramp_end))

        u = (t - self.t_ramp0) / (self.t_ramp1 - self.t_ramp0)
        w = _smoothstep01(u)
        freq = float(self.freq_benign) + w * float(max(self.freq_at_ramp_end, self.freq_benign) - self.freq_benign)
        out = int(max(self.freq_benign, min(self.freq_cap, round(freq))))
        return max(1, out)


class NoiseRule:
    """规则3：决定噪声尺度（基于 epsilon 计算）"""

    def __init__(self, config: Dict[str, float]):
        self.base_epsilon = config.get("base_epsilon", 1.0)
        self.min_epsilon = config.get("min_epsilon", 0.2)
        self.max_epsilon = config.get("max_epsilon", 1.5)

        self.w_threat = config.get("weight_threat", 0.3)
        self.w_trust = config.get("weight_trust", 0.2)
        self.w_criticality = config.get("weight_criticality", 0.2)
        self.w_resource = config.get("weight_resource", 0.1)

    def decide(self, ctx: Context) -> float:
        threat_penalty = self.w_threat * ctx.threat_level
        trust_penalty = self.w_trust * (1 - ctx.trust_score)
        criticality_bonus = self.w_criticality * ctx.mission_criticality
        resource_penalty = self.w_resource * (1 - ctx.resource_availability)

        epsilon = self.base_epsilon * (
            1 - threat_penalty - trust_penalty + criticality_bonus - resource_penalty
        )
        epsilon = max(self.min_epsilon, min(self.max_epsilon, epsilon))
        noise_scale = 1.0 / epsilon
        return max(0.1, min(2.0, noise_scale))
