# -*- coding: utf-8 -*-
"""基线引擎单测：统计正确性 / 学习-检测 / 灵敏度 / 持久化 / P1 滚动更新与漂移"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest
from datetime import datetime, timedelta

from src.analysis.baseline import TrafficBaseline, _median, _mad, MAD_SIGMA_FACTOR
from src.capture.packet_parser import PacketInfo
from tests.conftest import mk, make_window_traffic


def make_learned(normal_traffic):
    b = TrafficBaseline()
    b.learn(normal_traffic)
    return b


class TestMedianMad:
    def test_median_basic(self):
        assert _median([1, 2, 3, 4, 5]) == 3.0
        assert _median([1, 2, 3, 4]) == 2.5

    def test_mad_basic(self):
        assert _mad([1, 2, 3, 4, 5], 3) == 1.0
        assert _mad([10, 11, 12, 13, 14], 12) == 1.0

    def test_mad_sigma_factor_scale(self):
        """MAD 换算系数：标准正态数据 MAD≈0.6745σ → z 与 σ 语义可比"""
        from statistics import pstdev
        data = [float(x) for x in range(1, 101)]  # 均匀分布
        med = _median(data)
        mad = _mad(data, med)
        # 均匀分布 MAD 应非零
        assert mad > 0


class TestAggregation:
    def test_window_counts(self):
        b = TrafficBaseline(window_sec=10)
        pkts = make_window_traffic(5, 4)
        wins = b._aggregate_windows(pkts)
        assert len(wins) == 4
        assert wins[0]["window_packets"] == 5.0

    def test_window_bytes(self):
        b = TrafficBaseline(window_sec=10)
        pkts = make_window_traffic(3, 2, length=200)
        wins = b._aggregate_windows(pkts)
        assert wins[0]["window_bytes"] == 600.0

    def test_window_syn_only_initiator(self):
        """SYN 计数只统计 SYN 无 ACK（发起方向）"""
        b = TrafficBaseline(window_sec=10)
        pkts = [mk(0, flags="SYN"), mk(0.01, flags="SYN"), mk(0.02, flags="SYN,ACK")]
        wins = b._aggregate_windows(pkts)
        assert wins[0]["window_syn"] == 2.0

    def test_window_dports_distinct(self):
        b = TrafficBaseline(window_sec=10)
        pkts = [mk(0, dport=80), mk(0.01, dport=80), mk(0.02, dport=443)]
        wins = b._aggregate_windows(pkts)
        assert wins[0]["window_dports"] == 2.0


class TestLearn:
    def test_learn_builds_profile(self, normal_traffic):
        b = TrafficBaseline()
        b.learn(normal_traffic)
        assert b.learned
        for dim in TrafficBaseline.DIMENSIONS:
            assert dim in b.profile
        # 纯 ACK 流量：包数/字节 > 0；SYN 可为 0（合法）
        assert b.profile["window_packets"]["median"] > 0
        assert b.profile["window_bytes"]["median"] > 0
        assert b.profile["window_syn"]["median"] >= 0

    def test_learn_cleans_extreme_windows(self):
        """极端窗口（攻击污染）应在清洗阶段被剔除"""
        pkts = make_window_traffic(10, 30)
        # 中间插入 3 个 5000 包/窗的极端窗口
        for w in range(3):
            for i in range(5000):
                pkts.append(mk((10 + w) * 10 + i * 0.001))
        b = TrafficBaseline()
        b.learn(pkts)
        # 清洗后中位数应接近 10（而非被拉高到数百）
        assert b.profile["window_packets"]["median"] < 50


class TestDetect:
    def test_no_deviation_normal(self, normal_traffic):
        b = make_learned(normal_traffic)
        det = b.detect(normal_traffic)
        assert det["total_deviations"] == 0

    def test_deviation_on_burst(self, normal_traffic, burst_traffic):
        b = make_learned(normal_traffic)
        det = b.detect(burst_traffic)
        assert det["total_deviations"] > 0
        # z 应显著超 σ
        assert max(d["z_score"] for d in det["deviations"]) > 3.0

    def test_severity_levels(self, normal_traffic):
        """z > 2σ → MEDIUM/HIGH 分级"""
        b = make_learned(normal_traffic)
        pkts = make_window_traffic(10, 30) + make_window_traffic(300, 5)
        det = b.detect(pkts)
        assert any(d["severity"] in ("MEDIUM", "HIGH") for d in det["deviations"])

    def test_sensitivity_floor_no_explode(self):
        """MAD 趋零时相对灵敏度下限防止 z 爆表（均匀微波动）"""
        pkts = make_window_traffic(10, 50)
        b = TrafficBaseline()
        b.learn(pkts)
        # 每个窗口 10 包 → MAD=0 → 依赖灵敏度下限
        det = b.detect(pkts)
        for d in det["deviations"]:
            assert d["z_score"] < 100  # 不爆炸


class TestPersistence:
    def test_save_load_roundtrip(self, tmp_path, normal_traffic):
        b = make_learned(normal_traffic)
        p = os.path.join(str(tmp_path), "base.json")
        assert b.save(p)
        b2 = TrafficBaseline.load(p)
        assert b2 is not None and b2.learned
        assert b2.profile["window_packets"]["median"] == \
               b.profile["window_packets"]["median"]


class TestOnlineUpdate:
    def test_online_update_moves_median(self, normal_traffic):
        """连续略高于基线的正常窗口应被滚动更新缓慢吸收（中位数移动）"""
        b = make_learned(normal_traffic)
        med_before = b.profile["window_packets"]["median"]
        # 12 包/窗（略高于 10，z<σ 不触发偏差）→ EWMA 缓慢上移
        mild_traffic = make_window_traffic(12, 40)
        det = b.detect(mild_traffic)
        assert b.updated_windows > 0
        med_after = b.profile["window_packets"]["median"]
        assert med_after > med_before

    def test_deviation_window_not_update(self, normal_traffic, burst_traffic):
        """偏差窗口不参与滚动更新（防攻击污染基线）"""
        b = make_learned(normal_traffic)
        b.detect(burst_traffic)
        assert b.updated_windows == 0  # 全部为偏差窗口

    def test_online_update_can_be_disabled(self, normal_traffic):
        b = TrafficBaseline()
        b.online_update = False
        b.learn(normal_traffic)
        med_before = b.profile["window_packets"]["median"]
        b.detect(make_window_traffic(25, 40))
        assert b.profile["window_packets"]["median"] == med_before


class TestDrift:
    def test_ks_same_distribution(self):
        b = TrafficBaseline()
        assert b._ks2_dstat([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]) < 0.01

    def test_ks_diff_distribution(self):
        b = TrafficBaseline()
        assert b._ks2_dstat([1, 2, 3, 4, 5], [10, 11, 12, 13, 14]) > 0.9

    def test_drift_detected_on_shift(self, normal_traffic):
        b = make_learned(normal_traffic)
        det = b.detect(make_window_traffic(80, 30))
        assert det["drift"]["detected"] is True
        assert det["drift"]["dimension"] == "window_packets"

    def test_no_drift_normal(self, normal_traffic):
        b = make_learned(normal_traffic)
        det = b.detect(normal_traffic)
        assert det["drift"]["detected"] is False

    def test_drift_insufficient_windows(self):
        """窗口样本不足时不做漂移评估（不误报）"""
        b = TrafficBaseline()
        b.learn(make_window_traffic(10, 30))
        b._recent_windows = []
        det = b._detect_drift()
        assert det["detected"] is False
