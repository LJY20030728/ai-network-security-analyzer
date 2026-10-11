# -*- coding: utf-8 -*-
"""
流式路径规则覆盖 的回归测试

## 缺陷背景

`TrafficAnalyzer` 有两条检测路径，规则数不一致：

  · `analyze_packets()` → `_detect_anomalies()`：**11 条**规则（完整）
  · `analyze_stream()`  → 内联组装：**5 条**规则

`analyze_stream` 的文档字符串声称"规则累加器与 _detect_anomalies 同阈值、
同告警字段"，但**没有任何机制强制它一致**。UDP/QUIC 规则于 ebfe80a(v3.4.0)
只加进 `_detect_anomalies`，流式路径漏掉 6 条：

    UDP_FLOOD_SUSPECTED / DNS_AMPLIFICATION_SUSPECTED
    QUIC_CONNECTION_FLOOD / QUIC_LONG_FLOW_ANOMALY
    QUIC_INITIAL_RATIO_ANOMALY / QUIC_UNKNOWN_VERSION

而 `analysis_service`（UI 实际调用）走的是 **analyze_stream** ——
**用户运行时 UDP/QUIC 攻击完全检测不到**。

## 为什么既有测试没抓到

`tests/test_streaming.py::test_stream_matches_full` 遍历所有 golden 样本断言
两条路径告警一致 —— 但 **golden 样本里没有任何 UDP/QUIC 样本**，
该断言恰好落在两条路径唯一相同的交集上，所以一直通过。

本文件用**合成包**覆盖这个盲区，并锁定"两条路径必须一致"这一不变量。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings  # noqa: E402
from src.analysis.flow_extractor import TrafficAnalyzer  # noqa: E402
from src.capture.packet_parser import PacketInfo  # noqa: E402


# ----------------------------------------------------------------------
# 合成包工具
# ----------------------------------------------------------------------

def _pkt(ts, src, dst, sport, dport, proto, length=100,
         flags="", dns_query="", dns_response="", raw_summary=""):
    p = PacketInfo()
    p.timestamp = ts
    p.src_ip = src
    p.dst_ip = dst
    p.src_port = sport
    p.dst_port = dport
    p.protocol = proto
    p.length = length
    p.payload_size = max(0, length - 42)
    p.flags = flags
    p.dns_query = dns_query
    p.dns_response = dns_response
    p.raw_summary = raw_summary
    return p


def _t(i, step=0.01):
    return float(1700000000 + i * step)


def _alert_types(anomalies):
    return {a.get("type") for a in anomalies["alerts"]}


def _rule_alert_types(anomalies):
    """只取**规则引擎**产出的告警类型。

    为什么只比规则告警：本次修复的范围是"规则引擎在两条路径上一致"
    （`detector` 以 `rule-based-` 开头）。
    基线引擎（BASELINE_DEVIATION）与孤立森林（ML_ANOMALY）有各自的聚合差异，
    其中 BASELINE_DEVIATION 的差异**早于本次修复就存在**（已用改动前的代码
    实测确认：DNS 放大样本下"仅全量有 BASELINE_DEVIATION"），属另一个问题，
    不在本次范围内 —— 强行在这里断言会让本测试因无关原因变红，
    反而掩盖真正要守住的规则一致性。
    """
    return {a.get("type") for a in anomalies["alerts"]
            if str(a.get("detector", "")).startswith("rule-based-")}


# ----------------------------------------------------------------------
# 各类攻击的合成流量
# ----------------------------------------------------------------------

def udp_flood_packets():
    """单向大量 UDP 包（目标同一 IP），超过 udp_flood_min_packets。"""
    n = int(settings.udp_flood_min_packets) + 60
    return [_pkt(_t(i), "10.0.0.1", "10.0.0.2", 40000 + (i % 5), 53, "UDP", 1400)
            for i in range(n)]


def dns_amplification_packets():
    """DNS 响应字节数远大于请求（放大特征）。"""
    pkts = []
    n = int(settings.dns_amp_min_responses) + 3
    for i in range(n):
        # 请求：小包
        pkts.append(_pkt(_t(i * 2), "10.0.0.9", "8.8.8.8", 50000 + i, 53, "DNS",
                         60, dns_query=f"a{i}.example.com"))
        # 响应：大包（放大）
        pkts.append(_pkt(_t(i * 2 + 1), "8.8.8.8", "10.0.0.9", 53, 50000 + i, "DNS",
                         4000, dns_response="10.0.0.9"))
    return pkts


def quic_flood_packets():
    """大量不同源端口的 QUIC 连接（QUIC 连接风暴）。"""
    n = int(settings.quic_flood_min_connections) + 10
    return [_pkt(_t(i), "10.0.0.5", "1.1.1.1", 30000 + i, 443, "UDP", 1200)
            for i in range(n)]


def quic_long_flow_packets():
    """单条 QUIC 流包数过多。"""
    n = int(settings.quic_long_flow_min_packets) + 10
    return [_pkt(_t(i), "10.0.0.6", "1.1.1.1", 44444, 443, "UDP", 1100)
            for i in range(n)]


def quic_initial_ratio_packets():
    """QUIC 大包（>1200B）占比超阈值。"""
    pkts = []
    n = 40
    for i in range(n):
        # 全部用大包 → 占比 100% > 阈值
        pkts.append(_pkt(_t(i), "10.0.0.7", "1.1.1.1", 30000 + (i % 3), 443, "UDP", 1350))
    return pkts


def quic_unknown_version_packets():
    """raw_summary 含未知 QUIC 版本号。"""
    return [_pkt(_t(i), "10.0.0.8", "1.1.1.1", 30000 + i, 443, "UDP", 1200,
                 raw_summary=f"UDP 1200 -> 443 Len=1200 QUIC Version=0x{0xdeadbeef:08x}")
            for i in range(5)]


ALL_CASES = {
    "udp_flood": (udp_flood_packets, "UDP_FLOOD_SUSPECTED"),
    "dns_amplification": (dns_amplification_packets, "DNS_AMPLIFICATION_SUSPECTED"),
    "quic_flood": (quic_flood_packets, "QUIC_CONNECTION_FLOOD"),
    "quic_long_flow": (quic_long_flow_packets, "QUIC_LONG_FLOW_ANOMALY"),
    "quic_initial_ratio": (quic_initial_ratio_packets, "QUIC_INITIAL_RATIO_ANOMALY"),
    "quic_unknown_version": (quic_unknown_version_packets, "QUIC_UNKNOWN_VERSION"),
}


# ----------------------------------------------------------------------
# 核心断言：两条路径的告警类型集合必须完全一致
# ----------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(ALL_CASES))
def test_stream_path_detects_same_rule_as_full_path(name):
    """★ 核心回归：analyze_stream 必须能检出与 analyze_packets 相同的规则。

    修复前这些用例全部失败 —— 流式路径（UI 实际使用）漏检 UDP/QUIC。
    """
    maker, expected_type = ALL_CASES[name]
    pkts = maker()

    full = TrafficAnalyzer().analyze_packets(pkts)["anomaly_detection"]
    stream = TrafficAnalyzer().analyze_stream(iter(pkts))["anomaly_detection"]

    full_types = _alert_types(full)
    stream_types = _alert_types(stream)

    # 全量路径应能命中该规则（前置条件，确认合成流量有效）
    assert expected_type in full_types, (
        f"[{name}] 合成流量未能触发 {expected_type}（全量路径未命中）——"
        f"测试用例本身无效。实际命中: {sorted(full_types)}")

    # 流式路径也必须命中
    assert expected_type in stream_types, (
        f"[{name}] 流式路径（UI 实际调用）漏检 {expected_type}。\n"
        f"  全量路径命中: {sorted(full_types)}\n"
        f"  流式路径命中: {sorted(stream_types)}\n"
        f"  缺失: {sorted(full_types - stream_types)}")


@pytest.mark.parametrize("name", sorted(ALL_CASES))
def test_two_paths_rule_alert_sets_are_identical(name):
    """两条路径的**规则**告警类型集合必须完全相同。

    只比规则告警（detector 以 rule-based- 开头）——理由见 _rule_alert_types。
    """
    maker, _ = ALL_CASES[name]
    pkts = maker()
    full_types = _rule_alert_types(
        TrafficAnalyzer().analyze_packets(pkts)["anomaly_detection"])
    stream_types = _rule_alert_types(
        TrafficAnalyzer().analyze_stream(iter(pkts))["anomaly_detection"])
    assert full_types == stream_types, (
        f"[{name}] 两条路径规则告警不一致。\n"
        f"  仅全量有: {sorted(full_types - stream_types)}\n"
        f"  仅流式有: {sorted(stream_types - full_types)}")


def test_stream_covers_all_rule_types_of_full_path():
    """逐案对照：每个 UDP/QUIC 用例在两条路径上都必须给出相同的规则告警。

    注意这里**逐个用例**比较、而非把所有合成流量合并后跑一遍：
    合并会让 QUIC_INITIAL_RATIO_ANOMALY 这类"占比型"规则的分子被分母稀释
    （实测合并后比例从 1.0 降到 0.127，低于阈值 0.3，两条路径都不再触发），
    那样断言"必须触发全部 6 条"就是错的 —— 是测试假设问题，不是代码缺陷。
    """
    udp_quic = {
        "UDP_FLOOD_SUSPECTED", "DNS_AMPLIFICATION_SUSPECTED",
        "QUIC_CONNECTION_FLOOD", "QUIC_LONG_FLOW_ANOMALY",
        "QUIC_INITIAL_RATIO_ANOMALY", "QUIC_UNKNOWN_VERSION",
    }
    covered_full, covered_stream, problems = set(), set(), []
    for name, (maker, _expected) in sorted(ALL_CASES.items()):
        pkts = maker()
        ft = _rule_alert_types(TrafficAnalyzer().analyze_packets(pkts)["anomaly_detection"])
        st = _rule_alert_types(TrafficAnalyzer().analyze_stream(iter(pkts))["anomaly_detection"])
        covered_full |= ft & udp_quic
        covered_stream |= st & udp_quic
        if ft != st:
            problems.append(f"{name}: 仅全量={sorted(ft - st)} 仅流式={sorted(st - ft)}")

    assert not problems, "以下用例两条路径不一致:\n  " + "\n  ".join(problems)
    assert covered_full == udp_quic, (
        f"合成用例未覆盖全部 6 条规则，测试自身不完整。\n"
        f"  已覆盖: {sorted(covered_full)}\n"
        f"  缺失: {sorted(udp_quic - covered_full)}")
    assert covered_stream == udp_quic, (
        f"流式路径未覆盖全部 6 条规则。\n"
        f"  已覆盖: {sorted(covered_stream)}\n"
        f"  缺失: {sorted(udp_quic - covered_stream)}")
