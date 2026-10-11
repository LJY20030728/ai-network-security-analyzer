# -*- coding: utf-8 -*-
"""
大流量告警的"方向"与"时间窗"修复 的回归测试

## 缺陷（实测复现）

`FlowExtractor.extract_flows()` 用 `sorted([ep1, ep2])` 做双向流规范化，
于是 `NetworkFlow.src_ip/src_port` 是**字典序较小**的端点，与真实发包方向无关。
`_detect_anomalies()` 的 `LARGE_DATA_TRANSFER` 规则直接采用它，导致两个错误：

以 `data/samples/golden/largeflow.pcap` 为例（实际 8239 个包均为 10.0.0.2:40000 → 10.0.0.1:21）：

  1. `time_window` 恒为空字符串
     规则用 `[p for p in packets if p.src_ip == flow.src_ip and p.dst_ip == flow.dst_ip]`
     过滤，而 `flow.src_ip=10.0.0.1`、真实包是 `src_ip=10.0.0.2` → 匹配 0 个包 → 空。
     报告里渲染成 "—"，证据链缺失一项。
  2. `description` 的源/目的写反
     写成 "流 10.0.0.1:21 -> 10.0.0.2:40000"，与真实方向相反 ——
     对取证工具而言会让分析师追错方向。

## 修复方向

在 `NetworkFlow` 上增加**按真实包统计**的主导方向字段，供告警使用；
`src_ip/dst_ip` 保持原语义不变（`get_flows_by_ip` 等既有调用者不受影响）。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.flow_extractor import FlowExtractor, TrafficAnalyzer  # noqa: E402
from src.capture.pcap_parser import PcapParser  # noqa: E402

GOLDEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "data", "samples", "golden")
LARGEFLOW = os.path.join(GOLDEN, "largeflow.pcap")


def _large_alerts(path):
    pkts = PcapParser().parse_file(path)
    alerts = TrafficAnalyzer().analyze_packets(pkts)["anomaly_detection"]["alerts"]
    return [a for a in alerts if a.get("type") == "LARGE_DATA_TRANSFER"]


# ----------------------------------------------------------------------
# 1) NetworkFlow 必须提供按真实包统计的主导方向
# ----------------------------------------------------------------------

def test_networkflow_exposes_dominant_direction():
    """NetworkFlow 应带主导方向字段，且与真实包方向一致。"""
    pkts = PcapParser().parse_file(LARGEFLOW)
    flows = FlowExtractor().extract_flows(pkts)
    big = [f for f in flows if f.total_bytes > 10 * 1024 * 1024]
    assert big, "largeflow.pcap 未产出 >10MB 的流，测试前提不成立"
    f = big[0]

    for attr in ("dom_src_ip", "dom_src_port", "dom_dst_ip", "dom_dst_port", "dom_bytes"):
        assert hasattr(f, attr), f"NetworkFlow 缺少主导方向字段 {attr}"

    # 用真实包独立统计该流的主导方向，作为对照
    from collections import Counter
    c = Counter()
    for p in pkts:
        if {p.src_ip, p.dst_ip} == {f.src_ip, f.dst_ip} and p.protocol == f.protocol:
            c[(p.src_ip, p.src_port, p.dst_ip, p.dst_port)] += 1
    assert c, "未找到该流的真实包"
    (ts, tsp, td, tdp), _n = c.most_common(1)[0]

    assert (f.dom_src_ip, f.dom_src_port, f.dom_dst_ip, f.dom_dst_port) == (ts, tsp, td, tdp), (
        f"主导方向与实际包方向不符：\n"
        f"  实际最多方向: {ts}:{tsp} -> {td}:{tdp}\n"
        f"  流的 dom_*:   {f.dom_src_ip}:{f.dom_src_port} -> {f.dom_dst_ip}:{f.dom_dst_port}")


# ----------------------------------------------------------------------
# 2) 告警的 time_window 必须非空
# ----------------------------------------------------------------------

def test_large_transfer_alert_has_time_window():
    """★ 核心回归：LARGE_DATA_TRANSFER 的 time_window 不得为空。"""
    alerts = _large_alerts(LARGEFLOW)
    assert alerts, "largeflow.pcap 未产出 LARGE_DATA_TRANSFER 告警"
    for a in alerts:
        assert a.get("time_window"), (
            f"time_window 为空 —— 证据链缺失。告警: {a}")


def test_large_transfer_time_window_matches_flow_span():
    """time_window 应等于该流的真实起止时间，而不是被错误过滤后的空值。"""
    pkts = PcapParser().parse_file(LARGEFLOW)
    flows = [f for f in FlowExtractor().extract_flows(pkts)
             if f.total_bytes > 10 * 1024 * 1024]
    assert flows
    f = flows[0]
    alerts = _large_alerts(LARGEFLOW)
    assert alerts
    tw = alerts[0]["time_window"]
    assert tw == f"{f.start_time} ~ {f.end_time}", (
        f"time_window 与流的起止时间不符：\n  告警: {tw}\n  流:   {f.start_time} ~ {f.end_time}")


# ----------------------------------------------------------------------
# 3) 告警描述的方向必须与真实包方向一致
# ----------------------------------------------------------------------

def test_large_transfer_description_direction_is_truthful():
    """描述里写的 src -> dst 必须与真实主导方向一致（不得写反）。"""
    pkts = PcapParser().parse_file(LARGEFLOW)
    flows = [f for f in FlowExtractor().extract_flows(pkts)
             if f.total_bytes > 10 * 1024 * 1024]
    assert flows
    f = flows[0]
    alerts = _large_alerts(LARGEFLOW)
    assert alerts
    desc = alerts[0]["description"]
    expected = f"{f.dom_src_ip}:{f.dom_src_port} -> {f.dom_dst_ip}:{f.dom_dst_port}"
    assert expected in desc, (
        f"描述中的方向与实际主导方向不符：\n"
        f"  期望包含: {expected}\n"
        f"  实际描述: {desc}")


def test_large_transfer_alert_src_dst_fields_match_direction():
    """告警的 src_ip/dst_ip 必须与描述里的方向自洽（不能一个用排序、一个用真实）。"""
    alerts = _large_alerts(LARGEFLOW)
    assert alerts
    a = alerts[0]
    desc = a["description"]
    assert f"{a['src_ip']}" in desc and f"{a['dst_ip']}" in desc, (
        f"src_ip/dst_ip 与描述方向不自洽：src={a['src_ip']} dst={a['dst_ip']} desc={desc}")


# ----------------------------------------------------------------------
# 4) 不得破坏既有行为
# ----------------------------------------------------------------------

def test_src_dst_semantics_unchanged_for_existing_consumers():
    """src_ip/dst_ip 仍是"规范化端点"（排序后），不影响 get_flows_by_ip 等调用者。"""
    pkts = PcapParser().parse_file(LARGEFLOW)
    fe = FlowExtractor()
    flows = fe.extract_flows(pkts)
    for f in flows:
        assert f.src_ip and f.dst_ip
        # 规范化语义：src 端点应 <= dst 端点（字符串序）
        assert f"{f.src_ip}:{f.src_port}" <= f"{f.dst_ip}:{f.dst_port}", (
            f"src/dst 规范化语义被破坏: {f.src_ip}:{f.src_port} vs {f.dst_ip}:{f.dst_port}")
    # get_flows_by_ip 仍能双向命中
    hit = fe.get_flows_by_ip("10.0.0.2")
    assert hit, "get_flows_by_ip 未命中 10.0.0.2"


def test_two_paths_large_transfer_now_fully_consistent():
    """修复后两条路径的 LARGE_DATA_TRANSFER 字段应完全一致。"""
    pkts = PcapParser().parse_file(LARGEFLOW)
    full = [a for a in TrafficAnalyzer().analyze_packets(pkts)["anomaly_detection"]["alerts"]
            if a.get("type") == "LARGE_DATA_TRANSFER"]
    stream = [a for a in TrafficAnalyzer().analyze_stream(
        PcapParser().iter_packets(LARGEFLOW))["anomaly_detection"]["alerts"]
        if a.get("type") == "LARGE_DATA_TRANSFER"]
    assert len(full) == len(stream) == 1, f"条数不一致: 全量{len(full)} 流式{len(stream)}"
    for fld in ("time_window", "bytes_transferred", "severity", "detector"):
        assert full[0].get(fld) == stream[0].get(fld), (
            f"字段 {fld} 不一致:\n  全量={full[0].get(fld)}\n  流式={stream[0].get(fld)}")
