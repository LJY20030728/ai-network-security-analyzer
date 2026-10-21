# -*- coding: utf-8 -*-
"""
流式报告字段完整性测试（packets / 主导方向）

## 背景

流式路径的报告里曾有两处"看起来正常、实际是占位值"的字段：

1. `top_flows[*].packets` 被硬编码为 `0`
   → UI 的"流量排行"表在流式模式下包数整列为 0（看起来像数据缺失）
   → 但包数其实一直都在：逐包聚合时已按方向记录在 `dirs[dir]["count"]`

2. `_dom()`（主导方向）**定义了却从未被调用**（死代码）
   → 报告里的 `flow` 字段用的是**排序后的端点**（lo -> hi），不是真实数据流向
   → 与全量路径 `NetworkFlow.dom_*` 的语义不一致

本文件锁定这两项修复：
  · packets 必须等于各方向包数之和（双向流两个方向都算）
  · 必须输出 dominant_direction / dominant_bytes，且与排序端点区分得开

设计注意：不使用"packets > 0"这种弱断言 —— 单包流恰好也是 1，
所以用**多包流**验证求和逻辑，用**双向流**验证方向逻辑。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.helpers import force_utf8_stdout  # noqa: E402

force_utf8_stdout()

from src.analysis.flow_extractor import TrafficAnalyzer  # noqa: E402
from src.capture.packet_parser import PacketInfo  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pkt(ts, src_ip, src_port, dst_ip, dst_port, length=100,
         protocol="TCP", flags="", dns_query="", dns_response=""):
    """构造测试包（不依赖真实 PCAP，使阈值可精确控制）"""
    return PacketInfo(
        timestamp=ts, src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port, protocol=protocol,
        length=length, payload_size=max(length - 54, 0), flags=flags,
        tcp_window=0, raw_summary="", dns_query=dns_query,
        dns_response=dns_response,
    )


def _stream(packets):
    a = TrafficAnalyzer(use_baseline=False, use_ml=False)
    return a.analyze_stream(iter(packets))


# ----------------------------------------------------------------------
# packets 字段
# ----------------------------------------------------------------------

def test_streaming_top_flows_packets_counts_all_directions():
    """双向流：packets 必须是两个方向的包数之和，不能只算一个方向。

    构造 客户端->服务端 3 个包 + 服务端->客户端 2 个包 = 5 个包。
    两个方向端点相同（同一五元组），故应聚合成**一条**流。
    """
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.5", 51000, "10.0.0.9", 80)
        for i in range(3)
    ] + [
        _pkt("2026-01-01 00:00:1%d" % i, "10.0.0.9", 80, "10.0.0.5", 51000)
        for i in range(2)
    ]
    rep = _stream(packets)
    flows = rep["flow_stats"]["top_flows"]
    assert len(flows) == 1, f"双向流应聚合为 1 条，实际 {len(flows)} 条"
    assert flows[0]["packets"] == 5, (
        f"packets 应为两方向之和 5，实际 {flows[0]['packets']}。"
        f"若为 0 说明仍硬编码；若为 3 或 2 说明只算了一个方向。"
    )


def test_streaming_packets_not_hardcoded_zero():
    """packets 不得恒为 0（原缺陷的直接表征）

    注意：源端口必须相同才算同一条流 —— 若每个包的源端口不同，
    会形成 N 条各含 1 包的流，断言就无法区分"求和"与"硬编码 0"。
    """
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.1", 40000, "10.0.0.2", 443)
        for i in range(4)
    ]
    rep = _stream(packets)
    assert rep["summary"]["total_flows"] == 1
    assert rep["flow_stats"]["top_flows"][0]["packets"] == 4


def test_streaming_packets_matches_total_packet_count():
    """所有流的 packets 之和不得超过总包数，且单一流时应等于总包数"""
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.1", 40000, "10.0.0.2", 443)
        for i in range(7)
    ]
    rep = _stream(packets)
    assert rep["flow_stats"]["top_flows"][0]["packets"] == rep["summary"]["total_packets"] == 7


def test_top_talkers_and_top_flows_share_packets():
    """top_talkers 与 flow_stats.top_flows 应来自同一批流，packets 一致"""
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.1", 40000, "10.0.0.2", 443)
        for i in range(3)
    ]
    rep = _stream(packets)
    assert rep["top_talkers"][0]["packets"] == rep["flow_stats"]["top_flows"][0]["packets"] == 3


# ----------------------------------------------------------------------
# 主导方向
# ----------------------------------------------------------------------

def test_streaming_reports_dominant_direction():
    """必须输出 dominant_direction 与 dominant_bytes（`_dom()` 已接线）"""
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.5", 51000, "10.0.0.9", 80, length=200)
        for i in range(3)
    ]
    rep = _stream(packets)
    flow = rep["flow_stats"]["top_flows"][0]
    assert "dominant_direction" in flow, "缺少 dominant_direction（_dom 未接线）"
    assert "dominant_bytes" in flow
    assert flow["dominant_direction"] == "10.0.0.5:51000 -> 10.0.0.9:80"
    assert flow["dominant_bytes"] == 600


def test_dominant_direction_uses_most_packets_not_sorted_endpoints():
    """主导方向按**包数最多**的方向，而不是字典序小的端点。

    构造一个"排序端点是服务端、但客户端包更多"的场景：
      · 端点排序：10.0.0.9:80 < 10.0.0.5:51000 ? 需按字符串比较
      · 客户端 10.0.0.5 发 5 包，服务端 10.0.0.9 发 1 包
    → dominant_direction 必须是客户端 -> 服务端
    """
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.5", 51000, "10.0.0.9", 80)
        for i in range(5)
    ] + [
        _pkt("2026-01-01 00:00:10", "10.0.0.9", 80, "10.0.0.5", 51000),
    ]
    rep = _stream(packets)
    flow = rep["flow_stats"]["top_flows"][0]
    assert flow["dominant_direction"] == "10.0.0.5:51000 -> 10.0.0.9:80", (
        f"主导方向应取包数多的客户端方向，实际 {flow['dominant_direction']}"
    )


def test_flow_string_unchanged_for_backward_compat():
    """`flow` 字段格式必须保持 "lo -> hi"（该字符串会进入 LLM prompt）。

    主导方向以**新增字段**形式提供，不改变既有格式 —— 这是一次刻意的取舍：
    改 flow 格式会波及 threat_analyzer 传给模型的 JSON，风险大于收益。
    """
    packets = [
        _pkt("2026-01-01 00:00:0%d" % i, "10.0.0.5", 51000, "10.0.0.9", 80)
        for i in range(2)
    ]
    rep = _stream(packets)
    flow = rep["flow_stats"]["top_flows"][0]
    a = "10.0.0.5:51000"
    b = "10.0.0.9:80"
    lo, hi = sorted([a, b])
    assert flow["flow"] == f"{lo} -> {hi}", (
        f"flow 字段格式被改动（会影响 LLM prompt）：{flow['flow']}"
    )


# ----------------------------------------------------------------------
# 与全量路径的一致性
# ----------------------------------------------------------------------

@pytest.mark.skipif(
    not os.path.exists(os.path.join(
        ROOT, "data", "samples", "golden", "baseline_demo_attack.pcap")),
    reason="golden 样本不存在",
)
def test_streaming_and_full_path_agree_on_top_flow_bytes():
    """同一 PCAP 上，流式与全量的 top 流字节数应一致（口径对齐的基本保障）"""
    from src.capture.pcap_parser import PcapParser

    fp = os.path.join(ROOT, "data", "samples", "golden", "baseline_demo_attack.pcap")
    pp = PcapParser()
    a = TrafficAnalyzer()

    stream_rep = a.analyze_stream(pp.iter_packets(fp))
    full_rep = a.analyze_packets(PcapParser().parse_file(fp))

    s_bytes = [x["bytes"] for x in stream_rep["flow_stats"]["top_flows"][:5]]
    f_bytes = [x["bytes"] for x in full_rep["top_talkers"][:5]]
    assert s_bytes == f_bytes, f"top 流字节数不一致: 流式={s_bytes} 全量={f_bytes}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header"]))
