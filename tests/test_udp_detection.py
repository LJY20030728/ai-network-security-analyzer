# -*- coding: utf-8 -*-
"""
测试 UDP/QUIC 攻击检测（v3.4.0 新增）

验证：
1. UDP flood 检测
2. DNS amplification 检测
3. QUIC 连接风暴检测
4. QUIC 长流检测
5. QUIC 初始包比例异常检测
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.capture.packet_parser import PacketInfo
from src.analysis.flow_extractor import TrafficAnalyzer


def _make_packet(protocol="UDP", src_ip="10.0.0.1", src_port=12345,
                 dst_ip="10.0.0.2", dst_port=80, length=100, flags="",
                 dns_query="", dns_response=""):
    """构造测试用 PacketInfo"""
    return PacketInfo(
        timestamp="2026-01-01 00:00:00.000",
        protocol=protocol, src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port, length=length,
        flags=flags, dns_query=dns_query, dns_response=dns_response,
    )


def test_udp_flood_detection():
    """单目标收到大量UDP包应触发UDP_FLOOD_SUSPECTED"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    packets = [_make_packet(dst_port=53, length=60) for _ in range(150)]
    flows = analyzer.flow_extractor.extract_flows(packets)
    result = analyzer._detect_anomalies(packets, flows)
    types = [a["type"] for a in result["alerts"]]
    assert "UDP_FLOOD_SUSPECTED" in types, f"未检测到UDP flood，实际告警: {types}"


def test_udp_flood_not_triggered_for_normal():
    """少量UDP包不应触发UDP flood"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    packets = [_make_packet(dst_port=53, length=60) for _ in range(10)]
    flows = analyzer.flow_extractor.extract_flows(packets)
    result = analyzer._detect_anomalies(packets, flows)
    types = [a["type"] for a in result["alerts"]]
    assert "UDP_FLOOD_SUSPECTED" not in types


def test_dns_amplification_detection():
    """DNS响应远大于请求应触发DNS_AMPLIFICATION_SUSPECTED"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    packets = []
    # 10个小请求 + 10个大响应（放大10倍）
    for i in range(10):
        packets.append(_make_packet(protocol="DNS", src_ip="10.0.0.2", dst_port=53,
                                    length=50, dns_query="example.com"))
        packets.append(_make_packet(protocol="DNS", src_ip="10.0.0.2", src_port=53,
                                    dst_ip="10.0.0.1", length=500, dns_response="1.2.3.4"))
    flows = analyzer.flow_extractor.extract_flows(packets)
    result = analyzer._detect_anomalies(packets, flows)
    types = [a["type"] for a in result["alerts"]]
    assert "DNS_AMPLIFICATION_SUSPECTED" in types, f"未检测到DNS放大，实际告警: {types}"


def test_quic_connection_flood():
    """大量不同源端口的UDP 443包应触发QUIC_CONNECTION_FLOOD"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    packets = [_make_packet(src_port=10000 + i, dst_port=443, length=1200)
               for i in range(60)]
    flows = analyzer.flow_extractor.extract_flows(packets)
    result = analyzer._detect_anomalies(packets, flows)
    types = [a["type"] for a in result["alerts"]]
    assert "QUIC_CONNECTION_FLOOD" in types, f"未检测到QUIC连接风暴，实际告警: {types}"


def test_quic_long_flow():
    """单条QUIC流包数过多应触发QUIC_LONG_FLOW_ANOMALY"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    packets = [_make_packet(src_port=12345, dst_port=443, length=100)
               for _ in range(250)]
    flows = analyzer.flow_extractor.extract_flows(packets)
    result = analyzer._detect_anomalies(packets, flows)
    types = [a["type"] for a in result["alerts"]]
    assert "QUIC_LONG_FLOW_ANOMALY" in types, f"未检测到QUIC长流，实际告警: {types}"


def test_quic_initial_ratio_anomaly():
    """QUIC大包（初始包）占比过高应触发QUIC_INITIAL_RATIO_ANOMALY"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    # 50%的包是大包（>1200字节），正常应<5%
    packets = []
    for i in range(20):
        packets.append(_make_packet(src_port=10000 + i, dst_port=443, length=1300))
        packets.append(_make_packet(src_port=10000 + i, dst_port=443, length=100))
    flows = analyzer.flow_extractor.extract_flows(packets)
    result = analyzer._detect_anomalies(packets, flows)
    types = [a["type"] for a in result["alerts"]]
    assert "QUIC_INITIAL_RATIO_ANOMALY" in types, f"未检测到QUIC初始包比例异常，实际告警: {types}"


def test_udp_thresholds_in_config():
    """配置文件应包含UDP/QUIC阈值"""
    from config.settings import settings
    assert hasattr(settings, "udp_flood_min_packets")
    assert hasattr(settings, "dns_amp_min_ratio")
    assert hasattr(settings, "quic_flood_min_connections")
    assert hasattr(settings, "quic_long_flow_min_packets")
    assert settings.udp_flood_min_packets == 100
    assert settings.dns_amp_min_ratio == 5.0
    assert settings.quic_flood_min_connections == 50


if __name__ == "__main__":
    test_udp_flood_detection()
    test_udp_flood_not_triggered_for_normal()
    test_dns_amplification_detection()
    test_quic_connection_flood()
    test_quic_long_flow()
    test_quic_initial_ratio_anomaly()
    test_udp_thresholds_in_config()
    print("所有UDP/QUIC检测测试通过")
