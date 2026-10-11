# -*- coding: utf-8 -*-
"""
UDP/QUIC 端到端测试：PCAP 文件 → analysis_service.run_analysis → 报告告警

## 测试目的

验证从真实 PCAP 文件到完整分析报告的全链路中，UDP/QUIC 攻击检测
规则能够正确触发。不同于 test_stream_udp_quic.py（合成 PacketInfo 直接
调用 TrafficAnalyzer），本测试走 PcapParser → analyze_stream →
run_analysis 的完整流水线，覆盖解析层与服务层。

## 覆盖的攻击类型

1. UDP Flood —— 大量 UDP 包发往同一目标
2. DNS Amplification —— DNS 响应字节远大于请求
3. QUIC Connection Flood —— 大量不同源端口的 QUIC(UDP/443) 连接
4. 正常流量基线 —— 确认正常 UDP 流量不产生误报

## 为什么需要端到端测试

规则引擎的单元测试只能证明"给定累加器状态能产出告警"，但无法证明：
- PcapParser 能正确解析 UDP/DNS/QUIC 包的字段（protocol、dns_response 等）
- analyze_stream 的累加器能正确统计这些字段
- run_analysis 的报告结构中告警能正确传递到最终输出

本测试用 scapy 构造真实 PCAP，走完整链路，锁定端到端不变量。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, DNSRR, wrpcap  # noqa: E402

from src.services.analysis_service import run_analysis  # noqa: E402


# ----------------------------------------------------------------------
# 辅助函数
# ----------------------------------------------------------------------

def _alert_types(report):
    """从 run_analysis 返回的 report 中提取所有告警类型。

    注意：analyze_stream 返回的 report 中告警字典的键是 "anomaly_detection"，
    不是 "anomalies"。这是历史命名，两条路径（analyze_packets/analyze_stream）
    都使用 "anomaly_detection"。
    """
    anomaly_section = report.get("anomaly_detection", {})
    return {a.get("type") for a in anomaly_section.get("alerts", [])}


def _write_pcap(tmp_path, name, packets):
    """将 scapy 包列表写入临时 PCAP 文件，返回路径。"""
    path = str(tmp_path / name)
    wrpcap(path, packets)
    return path


def _udp_packet(src, dst, sport, dport, payload_size=100):
    """构造一个 UDP 包。"""
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / (b"X" * payload_size)


def _dns_query(src, dst, qname):
    """构造 DNS 查询包。"""
    return (Ether() / IP(src=src, dst=dst) / UDP(sport=53000, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=qname)))


def _dns_response(src, dst, qname, rdata, payload_size=512):
    """构造 DNS 响应包（含应答记录，触发 dns_response 字段）。"""
    return (Ether() / IP(src=src, dst=dst) / UDP(sport=53, dport=53000) /
            DNS(qr=1, qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, rdata=rdata) / (b"X" * max(0, payload_size - 100))))


def _quic_packet(src, dst, sport, dport=443, payload_size=1200):
    """构造 QUIC 包（UDP/443，大包模拟 Initial 包）。"""
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / (b"Q" * payload_size)


# ----------------------------------------------------------------------
# 测试用例
# ----------------------------------------------------------------------

class TestE2EUdpFlood:
    """UDP Flood 端到端检测。"""

    def test_udp_flood_triggers_alert(self, tmp_path):
        """100 个 UDP 包发往同一目标 → 应触发 UDP_FLOOD_SUSPECTED。"""
        packets = [
            _udp_packet("10.0.0.1", "10.0.0.2", sport=10000 + i, dport=80)
            for i in range(100)
        ]
        pcap = _write_pcap(tmp_path, "udp_flood.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)
        types = _alert_types(outcome.report)

        assert "UDP_FLOOD_SUSPECTED" in types, (
            f"UDP Flood 未检测到。实际告警类型: {types}"
        )

    def test_normal_udp_no_false_positive(self, tmp_path):
        """少量正常 UDP 包 → 不应触发 UDP_FLOOD_SUSPECTED。"""
        packets = [
            _udp_packet("10.0.0.1", "10.0.0.2", sport=12345, dport=53, payload_size=50)
            for _ in range(5)
        ]
        pcap = _write_pcap(tmp_path, "normal_udp.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)
        types = _alert_types(outcome.report)

        assert "UDP_FLOOD_SUSPECTED" not in types, (
            f"正常 UDP 流量误报 UDP Flood。实际告警类型: {types}"
        )


class TestE2EDnsAmplification:
    """DNS Amplification 端到端检测。"""

    def test_dns_amplification_triggers_alert(self, tmp_path):
        """DNS 响应字节远大于请求 → 应触发 DNS_AMPLIFICATION_SUSPECTED。

        构造 10 个小请求 + 10 个大响应（响应/请求比 > 5x），
        验证 PcapParser 能正确识别 DNS 响应包（dns_response 字段非空）。
        """
        packets = []
        # 10 个小请求（约 60 字节）
        for i in range(10):
            packets.append(_dns_query("10.0.0.2", "8.8.8.8", f"test{i}.example.com"))
        # 10 个大响应（约 512+ 字节）
        for i in range(10):
            packets.append(_dns_response("8.8.8.8", "10.0.0.2",
                                         f"test{i}.example.com",
                                         f"1.2.3.{i}", payload_size=512))

        pcap = _write_pcap(tmp_path, "dns_amp.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)
        types = _alert_types(outcome.report)

        assert "DNS_AMPLIFICATION_SUSPECTED" in types, (
            f"DNS Amplification 未检测到。实际告警类型: {types}"
        )


class TestE2EQuicConnectionFlood:
    """QUIC Connection Flood 端到端检测。"""

    def test_quic_connection_flood_triggers_alert(self, tmp_path):
        """50 个不同源端口的 QUIC(UDP/443) 包 → 应触发 QUIC_CONNECTION_FLOOD。"""
        packets = [
            _quic_packet("10.0.0.1", "10.0.0.2", sport=20000 + i, payload_size=1200)
            for i in range(50)
        ]
        pcap = _write_pcap(tmp_path, "quic_flood.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)
        types = _alert_types(outcome.report)

        assert "QUIC_CONNECTION_FLOOD" in types, (
            f"QUIC Connection Flood 未检测到。实际告警类型: {types}"
        )

    def test_quic_initial_ratio_alert(self, tmp_path):
        """大量 QUIC 大包（>1200字节）→ 应触发 QUIC_INITIAL_RATIO_ANOMALY。

        所有包都是 1200+ 字节，初始包占比 100%，远超 5% 阈值。
        """
        packets = [
            _quic_packet("10.0.0.1", "10.0.0.2", sport=30000 + i, payload_size=1250)
            for i in range(20)
        ]
        pcap = _write_pcap(tmp_path, "quic_initial.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)
        types = _alert_types(outcome.report)

        assert "QUIC_INITIAL_RATIO_ANOMALY" in types, (
            f"QUIC Initial Ratio 异常未检测到。实际告警类型: {types}"
        )


class TestE2EReportStructure:
    """验证端到端报告结构完整性。"""

    def test_report_contains_evidence_chain(self, tmp_path):
        """告警应包含证据链字段：detector、time_window、rule_threshold。"""
        packets = [
            _udp_packet("10.0.0.1", "10.0.0.2", sport=40000 + i, dport=80)
            for i in range(100)
        ]
        pcap = _write_pcap(tmp_path, "evidence.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)
        alerts = outcome.report.get("anomaly_detection", {}).get("alerts", [])
        udp_alerts = [a for a in alerts if a.get("type") == "UDP_FLOOD_SUSPECTED"]

        assert len(udp_alerts) >= 1, "未找到 UDP Flood 告警"
        alert = udp_alerts[0]

        # 证据链字段完整性
        assert "detector" in alert, "告警缺少 detector 字段"
        assert alert["detector"] == "rule-based-udp-flood", (
            f"detector 不匹配: {alert['detector']}"
        )
        assert "time_window" in alert, "告警缺少 time_window 字段"
        assert "rule_threshold" in alert, "告警缺少 rule_threshold 字段"
        assert "dst_ip" in alert, "告警缺少 dst_ip 字段"
        assert "udp_packet_count" in alert, "告警缺少 udp_packet_count 字段"

    def test_outcome_has_case_id_and_sha256(self, tmp_path):
        """AnalysisOutcome 应包含 case_id 和 evidence（sha256）。"""
        packets = [_udp_packet("10.0.0.1", "10.0.0.2", sport=1234, dport=53)]
        pcap = _write_pcap(tmp_path, "small.pcap", packets)

        outcome = run_analysis(pcap, enable_ai=False, generate_report=False)

        assert outcome.case_id is not None, "case_id 为空"
        assert outcome.case_id.startswith("PCAP-"), (
            f"case_id 格式错误: {outcome.case_id}"
        )
        assert "source_sha256" in outcome.evidence, "evidence 缺少 source_sha256"
        assert outcome.evidence["source_sha256"], "source_sha256 为空"
