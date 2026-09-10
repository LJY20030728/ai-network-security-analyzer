# -*- coding: utf-8 -*-
"""P1-3 性能基线：全量 vs 流式（时间 + tracemalloc 峰值内存 + 告警一致性）
生成 30 万包混合流量 pcap（SYN 扫描 + 正常浏览 + 大流量 + DNS），双路径对比。
"""
import os
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger

logger.remove()

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether, wrpcap
from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer

OUT_PCAP = os.path.join("data", "bench_stream.pcap")
N_PACKETS = 300_000


def build_big_pcap(path, n):
    """混合流量：70% 正常浏览 / 15% SYN 扫描 / 10% DNS / 5% 大流量"""
    pkts = []
    base_ts = 1700000000.0
    srcs = [f"10.0.{i % 5}.{10 + (i % 240)}" for i in range(50)]
    for i in range(n):
        src = srcs[i % len(srcs)]
        kind = i % 100
        ts = base_ts + i * 0.05  # 20 pkt/s
        if kind < 70:
            p = IP(src=src, dst=f"8.8.{(i//7) % 4}.{i % 250}") / TCP(
                sport=40000 + i % 1000, dport=80, flags="PA", seq=i, ack=i)
        elif kind < 85:
            p = IP(src=src, dst=f"192.168.1.{i % 250}") / TCP(
                sport=30000 + i % 500, dport=100 + (i % 300), flags="S", seq=i)
        elif kind < 95:
            p = IP(src=src, dst="8.8.8.8") / UDP(sport=50000 + i % 1000, dport=53) / DNS(
                rd=1, qd=DNSQR(qname=f"dns{i % 500}.example.com"))
        else:
            p = IP(src=src, dst=f"10.99.{i % 4}.{i % 250}") / TCP(
                sport=21, dport=40000 + i % 50, flags="PA", seq=i, ack=i) / Raw(load=b"x" * 800)
        p.time = ts
        pkts.append(p)
    wrpcap(path, pkts)
    return os.path.getsize(path)


def run_full(path):
    t0 = time.perf_counter()
    tracemalloc.start()
    packets = PcapParser().parse_file(path)
    report = TrafficAnalyzer().analyze_packets(packets)
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return time.perf_counter() - t0, peak, report


def run_stream(path):
    t0 = time.perf_counter()
    tracemalloc.start()
    parser = PcapParser()
    report = TrafficAnalyzer().analyze_stream(parser.iter_packets(path))
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return time.perf_counter() - t0, peak, report


def main():
    print(f"生成 {N_PACKETS} 包混合流量 pcap...")
    size = build_big_pcap(OUT_PCAP, N_PACKETS)
    print(f"pcap 大小: {size/1024/1024:.1f} MB")

    tf, peak_f, rf = run_full(OUT_PCAP)
    ts, peak_s, rs = run_stream(OUT_PCAP)

    af = sorted((a["type"], a.get("src_ip", "")) for a in rf["anomaly_detection"]["alerts"])
    as_ = sorted((a["type"], a.get("src_ip", "")) for a in rs["anomaly_detection"]["alerts"])
    same = af == as_

    print("\n================ P1-3 性能基线（30 万包） ================")
    print(f"{'路径':<8} {'耗时(s)':<10} {'峰值内存(MB)':<14} {'告警数'}")
    print(f"{'全量':<8} {tf:<10.2f} {peak_f/1024/1024:<14.1f} {rf['anomaly_detection']['total_alerts']}")
    print(f"{'流式':<8} {ts:<10.2f} {peak_s/1024/1024:<14.1f} {rs['anomaly_detection']['total_alerts']}")
    print(f"\n耗时加速比: 全量/流式 = {tf/ts:.2f}x")
    print(f"内存降低: {peak_f/max(peak_s,1):.1f}x  ({peak_f/1024/1024:.1f}MB -> {peak_s/1024/1024:.1f}MB)")
    print(f"告警一致性: {'PASS' if same else 'FAIL'} (全量 {len(af)} 条 / 流式 {len(as_)} 条)")
    print(f"\n吞吐: 全量 {N_PACKETS/tf/1000:.1f}k pkt/s | 流式 {N_PACKETS/ts/1000:.1f}k pkt/s")

    # 固化结果
    import json
    result = {
        "n_packets": N_PACKETS,
        "pcap_mb": round(size / 1024 / 1024, 1),
        "full": {"seconds": round(tf, 2), "peak_mb": round(peak_f / 1024 / 1024, 1),
                 "alerts": rf["anomaly_detection"]["total_alerts"]},
        "stream": {"seconds": round(ts, 2), "peak_mb": round(peak_s / 1024 / 1024, 1),
                   "alerts": rs["anomaly_detection"]["total_alerts"]},
        "speedup_x": round(tf / ts, 2),
        "memory_reduction_x": round(peak_f / max(peak_s, 1), 1),
        "alerts_consistent": same,
    }
    os.makedirs("data/eval_perf", exist_ok=True)
    with open("data/eval_perf/perf_baseline.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("\n结果已写入 data/eval_perf/perf_baseline.json")
    # 清理大 pcap
    os.remove(OUT_PCAP)
    print("已清理 bench pcap")


if __name__ == "__main__":
    main()
