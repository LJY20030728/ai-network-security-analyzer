# -*- coding: utf-8 -*-
"""规则引擎单测：5 类规则触发 / 状态化方向化防误报 / 证据链"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest

from src.analysis.flow_extractor import TrafficAnalyzer, FlowExtractor
from src.capture.packet_parser import PacketInfo
from tests.conftest import mk


@pytest.fixture
def analyzer():
    return TrafficAnalyzer(use_baseline=False)


def detect(analyzer, pkts):
    flows = FlowExtractor().extract_flows(pkts)
    return analyzer._detect_anomalies(pkts, flows)


class TestSynFlood:
    def test_synflood_detected(self, analyzer):
        """100+ 未完成握手 SYN → 告警"""
        pkts = [mk(i * 0.001, flags="SYN") for i in range(120)]
        rep = detect(analyzer, pkts)
        assert any(a["type"] == "SYN_FLOOD_SUSPECTED" for a in rep["alerts"])

    def test_synflood_normal_handshake_no_false_positive(self, analyzer):
        """正常握手（SYN + SYN-ACK + ACK）不应误报"""
        pkts = []
        for i in range(60):  # 60 次完整握手
            pkts.append(mk(i * 0.1, flags="SYN"))
            pkts.append(mk(i * 0.1 + 0.01, flags="SYN,ACK"))
            pkts.append(mk(i * 0.1 + 0.02, flags="ACK"))
        rep = detect(analyzer, pkts)
        assert not any(a["type"] == "SYN_FLOOD_SUSPECTED" for a in rep["alerts"])


class TestPortScan:
    def test_portscan_detected(self, analyzer):
        """≥20 distinct 目的端口 SYN 探测 → 告警"""
        pkts = [mk(i * 0.001, dport=1000 + i, flags="SYN") for i in range(25)]
        rep = detect(analyzer, pkts)
        assert any(a["type"] == "PORT_SCAN_SUSPECTED" for a in rep["alerts"])

    def test_portscan_response_not_counted(self, analyzer):
        """响应方向（SYN-ACK/ACK）不应计数为扫描"""
        pkts = []
        for i in range(30):
            pkts.append(mk(i * 0.01, dport=443, flags="SYN"))
            pkts.append(mk(i * 0.01 + 0.005, dst="1.1.1.1", src="2.2.2.2",
                           sport=443, dport=1000 + i, flags="SYN,ACK"))
        rep = detect(analyzer, pkts)
        # 只有 1 个 distinct 发起端口（443），不应触发 20 端口扫描
        assert not any(a["type"] == "PORT_SCAN_SUSPECTED" for a in rep["alerts"])


class TestDnsTunnel:
    def test_dnstunnel_detected(self, analyzer):
        """超长 DNS 查询 ≥5 次 → 告警"""
        pkts = [mk(i * 0.01, proto="DNS", dns_query="a" * 40 + f".{i}.example.com")
                for i in range(6)]
        rep = detect(analyzer, pkts)
        assert any(a["type"] == "DNS_TUNNEL_SUSPECTED" for a in rep["alerts"])


class TestLargeFlow:
    def test_large_flow_detected(self, analyzer):
        """单流 >10MB → 告警"""
        pkts = [mk(i * 0.01, length=1_000_000) for i in range(12)]  # 12MB
        rep = detect(analyzer, pkts)
        assert any(a["type"] == "LARGE_DATA_TRANSFER" for a in rep["alerts"])


class TestRstStorm:
    def test_rststorm_detected(self, analyzer):
        """≥50 RST → 告警"""
        pkts = [mk(i * 0.001, flags="RST") for i in range(60)]
        rep = detect(analyzer, pkts)
        assert any(a["type"] == "RST_STORM" for a in rep["alerts"])


class TestAlertQuality:
    def test_alert_evidence_chain_fields(self, analyzer):
        """告警必须带证据链：detector / rule_threshold / time_window"""
        pkts = [mk(i * 0.001, flags="SYN") for i in range(120)]
        rep = detect(analyzer, pkts)
        a = next(x for x in rep["alerts"] if x["type"] == "SYN_FLOOD_SUSPECTED")
        assert a["detector"] == "syn-flood-rate"
        assert "syn_flood_min_count" in a["rule_threshold"]
        assert a["time_window"] != ""

    def test_alert_severity_high_vs_medium(self, analyzer):
        """超阈值 2 倍 → HIGH，否则 MEDIUM"""
        pkts_med = [mk(i * 0.001, flags="SYN") for i in range(120)]   # >100 → MEDIUM
        pkts_high = [mk(i * 0.001, flags="SYN") for i in range(600)]  # >500 → HIGH
        r1 = detect(analyzer, pkts_med)
        r2 = detect(analyzer, pkts_high)
        a1 = next(x for x in r1["alerts"] if x["type"] == "SYN_FLOOD_SUSPECTED")
        a2 = next(x for x in r2["alerts"] if x["type"] == "SYN_FLOOD_SUSPECTED")
        assert a1["severity"] == "MEDIUM"
        assert a2["severity"] == "HIGH"

    def test_normal_traffic_no_alerts(self, analyzer):
        """正常混合流量（握手+DNS+ACK）不应产生任何告警"""
        pkts = []
        for i in range(50):
            pkts.append(mk(i * 0.1, flags="SYN"))
            pkts.append(mk(i * 0.1 + 0.01, flags="SYN,ACK"))
            pkts.append(mk(i * 0.1 + 0.02, flags="ACK"))
            pkts.append(mk(i * 0.1 + 0.03, proto="DNS",
                           dns_query="www.example.com", dport=53))
        rep = detect(analyzer, pkts)
        assert rep["total_alerts"] == 0
