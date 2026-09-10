# -*- coding: utf-8 -*-
"""L2 孤立森林检测引擎单元测试：学习/检测/接口/同口径"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.analysis.isolation_detector import IsolationDetector
from src.analysis.baseline import WindowAccumulator
from src.capture.pcap_parser import PcapParser

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "samples", "golden")


def windows_of(fname, window_sec=1):
    wa = WindowAccumulator(window_sec=window_sec)
    for p in PcapParser().iter_packets(os.path.join(GOLDEN, fname)):
        wa.add(p)
    return wa.get_windows()


class TestIsolationDetector:
    def test_learn_requires_min_windows(self):
        det = IsolationDetector()
        det.learn_windows([{"window_packets": 1.0, "window_bytes": 10.0,
                            "window_syn": 0.0, "window_dports": 1.0}] * 5)
        assert det.learned
        assert det.model is not None

    def test_detect_before_learn_returns_empty(self):
        det = IsolationDetector()
        res = det.detect_windows([{"window_packets": 1.0, "window_bytes": 10.0,
                                   "window_syn": 0.0, "window_dports": 1.0}])
        assert res["total_anomalies"] == 0
        assert "error" in res

    def test_learn_normal_detect_normal_low_fpr(self):
        """同分布数据：异常窗口占比应受控（≈ contamination 水平）"""
        normal_ws = windows_of("normal.pcap")
        split = int(len(normal_ws) * 0.7)
        det = IsolationDetector(contamination=0.1, random_state=42)
        det.learn_windows(normal_ws[:split])
        res = det.detect_windows(normal_ws[split:])
        fpr = res["total_anomalies"] / max(1, len(normal_ws[split:]))
        assert fpr <= 0.25, f"FPR 过高: {fpr}"

    def test_detect_attack_windows_raises_anomaly(self):
        """攻击样本：孤立森林应标记异常（至少 1 窗口）"""
        normal_ws = windows_of("normal.pcap")
        split = int(len(normal_ws) * 0.8)
        det = IsolationDetector(contamination=0.1, random_state=42)
        det.learn_windows(normal_ws[:split])
        for fname in ["synflood.pcap", "dnstunnel.pcap", "rststorm.pcap"]:
            aw = windows_of(fname)
            res = det.detect_windows(aw)
            assert res["total_anomalies"] > 0, f"{fname} 未被 ML 检出"

    def test_anomaly_structure_fields(self):
        """告警结构含证据字段（score/threshold/top dimension）"""
        normal_ws = windows_of("normal.pcap")
        split = int(len(normal_ws) * 0.8)
        det = IsolationDetector(contamination=0.1, random_state=42)
        det.learn_windows(normal_ws[:split])
        res = det.detect_windows(windows_of("synflood.pcap"))
        assert res["total_anomalies"] > 0
        a = res["anomalies"][0]
        for k in ("window_index", "dimension", "anomaly_score", "score_threshold", "severity"):
            assert k in a

    def test_reproducible_random_state(self):
        """固定 random_state 可复现"""
        normal_ws = windows_of("normal.pcap")
        d1 = IsolationDetector(random_state=7)
        d1.learn_windows(normal_ws)
        d2 = IsolationDetector(random_state=7)
        d2.learn_windows(normal_ws)
        assert d1._score_threshold == d2._score_threshold

    def test_to_dict_metadata(self):
        normal_ws = windows_of("normal.pcap")
        det = IsolationDetector(random_state=42)
        det.learn_windows(normal_ws[:80])
        d = det.to_dict()
        assert d["learned"] is True
        assert d["name"] == "isolation-forest-unsupervised"
        assert d["train_windows"] == 80
