"""APC 模块单元测试"""

import unittest
from pathlib import Path

from apc_module.apc_core import AdaptivePrivacyController
from apc_module.models import Context, PrivacyParams


class TestAPC(unittest.TestCase):
    def setUp(self) -> None:
        cfg = Path(__file__).resolve().parent / "config.yaml"
        self.apc = AdaptivePrivacyController(str(cfg))

    def test_normal_scenario(self) -> None:
        """低威胁：freq_n 应保持 freq_benign（默认 1）"""
        params = self.apc.decide(0.12, 0.5, 0.8, 0.7)
        self.assertEqual(params.participation_level, 1)
        self.assertEqual(params.update_frequency, 1)

    def test_low_trust(self) -> None:
        params = self.apc.decide(0.3, 0.5, 0.2, 0.7)
        self.assertEqual(params.participation_level, 0)

    def test_low_resource(self) -> None:
        params = self.apc.decide(0.3, 0.5, 0.8, 0.15)
        self.assertEqual(params.participation_level, 0)
        self.assertEqual(params.update_frequency, 3)

    def test_high_threat(self) -> None:
        params = self.apc.decide(0.9, 0.5, 0.8, 0.7)
        self.assertEqual(params.participation_level, 1)
        self.assertGreaterEqual(params.update_frequency, 3)
        self.assertGreater(params.noise_scale, 0.5)

    def test_critical_threat_low_trust_suspends(self) -> None:
        params = self.apc.decide(0.98, 0.5, 0.32, 0.7)
        self.assertEqual(params.participation_level, 0)

    def test_mid_threat_scales_freq(self) -> None:
        low = self.apc.decide(0.35, 0.5, 0.8, 0.7)
        high = self.apc.decide(0.72, 0.5, 0.8, 0.7)
        self.assertGreater(high.update_frequency, low.update_frequency)

    def test_high_criticality_low_threat_stays_benign_freq(self) -> None:
        params = self.apc.decide(0.15, 0.95, 0.8, 0.7)
        self.assertEqual(params.update_frequency, 1)

    def test_extreme_values(self) -> None:
        params = self.apc.decide(2.0, -1.0, 0.5, 1.5)
        self.assertIsInstance(params, PrivacyParams)

    def test_noise_scale_range(self) -> None:
        high_noise = self.apc.decide(1.0, 0.0, 0.0, 0.0)
        self.assertGreaterEqual(high_noise.noise_scale, 1.0)
        low_noise = self.apc.decide(0.0, 1.0, 1.0, 1.0)
        self.assertLess(low_noise.noise_scale, 1.0)
        self.assertGreater(low_noise.noise_scale, 0.1)


if __name__ == "__main__":
    unittest.main()
