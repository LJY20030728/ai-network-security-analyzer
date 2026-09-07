# -*- coding: utf-8 -*-
"""P0-1 流式解析/流式分析一致性测试"""
import os
import sys
from collections import Counter

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.baseline import WindowAccumulator

GOLDEN = os.path.join("data", "samples", "golden")


def _norm(alerts):
    out = []
    for a in alerts:
        d = {k: v for k, v in a.items() if k != "time_window"}
        out.append((a["type"], a.get("src_ip", ""), a.get("dst_ip", ""),
                    tuple(sorted(d.items()))))
    return sorted(out)


def _all_golden():
    return [f for f in sorted(os.listdir(GOLDEN)) if f.endswith(".pcap")]


@pytest.mark.parametrize("fname", _all_golden())
def test_stream_matches_full(fname):
    """流式 vs 全量：告警集合一致（time_window 语义差异除外）"""
    path = os.path.join(GOLDEN, fname)
    packets = PcapParser().parse_file(path)
    full = TrafficAnalyzer().analyze_packets(packets)
    stream = TrafficAnalyzer().analyze_stream(iter(packets))
    assert _norm(full["anomaly_detection"]["alerts"]) == _norm(
        stream["anomaly_detection"]["alerts"])
    assert full["summary"]["total_packets"] == stream["summary"]["total_packets"]
    assert full["summary"]["total_bytes"] == stream["summary"]["total_bytes"]


def test_iter_packets_counts_match():
    """iter_packets 生成器产出数 == parse_file 列表数"""
    path = os.path.join(GOLDEN, "largeflow.pcap")
    parser = PcapParser()
    n_full = len(parser.parse_file(path))
    n_stream = sum(1 for _ in PcapParser().iter_packets(path))
    assert n_stream == n_full


def test_stream_sample_count():
    """sample_count 采集前 N 包"""
    path = os.path.join(GOLDEN, "largeflow.pcap")
    report = TrafficAnalyzer().analyze_stream(
        PcapParser().iter_packets(path), sample_count=50)
    assert len(report["_samples"]) == 50
    assert report["_samples"][0].timestamp  # PacketInfo 可用


def test_window_accumulator_matches_aggregate():
    """WindowAccumulator 增量聚合 == _aggregate_windows 全量聚合"""
    from src.analysis.baseline import TrafficBaseline
    path = os.path.join(GOLDEN, "burst.pcap")
    packets = PcapParser().parse_file(path)
    bl = TrafficBaseline(window_sec=10)
    agg = bl._aggregate_windows(packets)
    acc = WindowAccumulator(window_sec=10)
    for p in packets:
        acc.add(p)
    assert acc.get_windows() == agg


def test_stream_no_baseline_flag():
    """use_baseline=False 时流式不加载基线"""
    path = os.path.join(GOLDEN, "burst.pcap")
    report = TrafficAnalyzer().analyze_stream(
        PcapParser().iter_packets(path), use_baseline=False)
    assert report["baseline_profile"] is None
