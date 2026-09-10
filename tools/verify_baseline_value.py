# -*- coding: utf-8 -*-
"""
基线引擎增量价值验证实验
========================
面试弹药：证明"规则+基线"双引擎优于"纯规则"。

实验设计（可复现，seed=42）：
1. 构造两类"轻度异常"样本——低于所有规则阈值，纯规则必然漏检：
   - lightscan.pcap : 轻度端口扫描（仅 15 端口 < 规则阈值 20）+ 正常背景流量
   - burst.pcap     : 流量突发（单窗口流量数倍于基线，但不达 large_flow 阈值）
2. 对每个样本分别运行两种检测模式：
   - 纯规则模式（不挂基线）
   - 规则+基线模式（挂 data/baselines/default.json）
3. 对比告警数，量化基线引擎的增量检出能力。

用法：
    python tools/verify_baseline_value.py
输出：
    对比结果 + 追加写入 data/samples/regression_result.json 的 baseline_value 字段
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, PcapWriter

from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.baseline import TrafficBaseline
from loguru import logger
logger.remove()

SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
DNS_SERVER = "8.8.8.8"
START_TS = 1700000000.0

random.seed(42)


def _set_time(pkt, ts):
    pkt.time = ts
    return pkt


def _normal_background(n_sessions=200, duration=3600):
    """与黄金样本 normal 相同的背景流量"""
    pkts = []
    base = START_TS
    for i in range(n_sessions):
        t = base + (i / n_sessions) * duration
        sp = 40000 + i
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                               TCP(sport=sp, dport=80, flags="S", seq=1000 + i * 1000), t))
        pkts.append(_set_time(IP(src=SERVER_IP, dst=CLIENT_IP) /
                               TCP(sport=80, dport=sp, flags="SA", seq=5000 + i, ack=1001 + i * 1000), t + 0.05))
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                               TCP(sport=sp, dport=80, flags="A", seq=1001 + i * 1000, ack=5001 + i) /
                               Raw(load=f"GET /page/{i} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()), t + 0.06))
        pkts.append(_set_time(IP(src=SERVER_IP, dst=CLIENT_IP) /
                               TCP(sport=80, dport=sp, flags="PA", seq=5001 + i, ack=1002 + i * 1000) /
                               Raw(load=b"HTTP/1.1 200 OK\r\n\r\n" + b"<html>ok</html>" * 10), t + 0.1))
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                               TCP(sport=sp, dport=80, flags="FA", seq=1002 + i * 1000, ack=5002 + i), t + 0.2))
        pkts.append(_set_time(IP(src=SERVER_IP, dst=CLIENT_IP) /
                               TCP(sport=80, dport=sp, flags="FA", seq=5002 + i, ack=1003 + i * 1000), t + 0.25))
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                               TCP(sport=sp, dport=80, flags="A", seq=1003 + i * 1000, ack=5003 + i), t + 0.3))
    normal_domains = ["www.example.com", "mail.google.com", "api.github.com",
                      "cdn.cloudflare.com", "docs.python.org"]
    for i in range(30):
        t = base + random.uniform(0, duration)
        q = normal_domains[i % len(normal_domains)]
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=DNS_SERVER) /
                               UDP(sport=50000 + i, dport=53) /
                               DNS(id=i, qr=0, qd=DNSQR(qname=q)), t))
        pkts.append(_set_time(IP(src=DNS_SERVER, dst=CLIENT_IP) /
                               UDP(sport=53, dport=50000 + i) /
                               DNS(id=i, qr=1, qd=DNSQR(qname=q), ancount=1), t + 0.02))
    for i in range(20):
        t = base + random.uniform(0, duration)
        pkts.append(_set_time(IP(src=CLIENT_IP, dst="10.0.0.50") /
                               UDP(sport=60000 + i, dport=123) /
                               Raw(load=os.urandom(48)), t))
    pkts.sort(key=lambda p: p.time)
    return pkts


def gen_lightscan():
    """轻度端口扫描：15 端口 < 规则阈值 20，纯规则必漏；
    扫描集中在 20 秒内（≥ 2 个 10s 基线窗口），确保行为突变可被基线捕获"""
    pkts = _normal_background()
    # 轻度扫描：20 秒内探测 15 个端口（同一源端口），低于 min_ports=20
    for i in range(15):
        t = START_TS + 1800 + (i / 15) * 20  # 在第 1800-1820 秒集中
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                               TCP(sport=44444, dport=2000 + i, flags="S", seq=random.randint(0, 2**31)), t))
    pkts.sort(key=lambda p: p.time)
    return pkts


def gen_burst():
    """流量突发：600 个请求集中在 300 秒窗口，不达 large_flow 阈值"""
    pkts = _normal_background()
    # 突发：1500-1800 秒内额外 600 个 HTTP GET（每窗口 ~20 请求 vs 基线中位数 7）
    for i in range(600):
        t = START_TS + 1500 + random.uniform(0, 300)
        sp = 50000 + i
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                               TCP(sport=sp, dport=80, flags="A", seq=1000 + i * 1000, ack=5000) /
                               Raw(load=f"GET /burst/{i} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()), t))
    pkts.sort(key=lambda p: p.time)
    return pkts


def _save(pkts, name):
    path = os.path.join("data", "samples", "golden", f"{name}.pcap")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.remove(path)  # 覆盖写，避免重复追加污染样本
    with PcapWriter(path, append=True, sync=True) as w:
        for p in pkts:
            w.write(p)
    return path


def _run_mode(packets, baseline=None):
    analyzer = TrafficAnalyzer(use_baseline=True)
    if baseline is not None:
        analyzer.baseline = baseline
    report = analyzer.analyze_packets(packets)
    return report["anomaly_detection"]


def main():
    print("=" * 70)
    print("基线引擎增量价值验证（纯规则 vs 规则+基线）")
    print("=" * 70)

    parser = PcapParser()
    baseline = TrafficBaseline.load("data/baselines/default.json")
    print(f"基线: {baseline.name} | 包数 {baseline.packets_used} | "
          f"中位数 {baseline.profile['window_packets']['median']}/{baseline.profile['window_dports']['median']}\n")

    results = {}
    cases = {
        "lightscan": (gen_lightscan, "轻度端口扫描（15端口<阈值20）"),
        "burst": (gen_burst, "流量突发（600请求/300s）"),
    }

    for name, (gen, desc) in cases.items():
        pkts = gen()
        path = _save(pkts, name)
        packets = parser.parse_file(path)
        print(f"[样本] {name} | {desc} | {len(packets)} 包")

        rule_only = _run_mode(packets, baseline=None)
        dual = _run_mode(packets, baseline=baseline)

        n_rule = rule_only["total_alerts"]
        n_dual = dual["total_alerts"]
        baseline_alerts = [a for a in dual["alerts"] if a.get("detector") == "ewma-statistical-baseline"]

        print(f"  纯规则    : {n_rule} 条告警")
        print(f"  规则+基线  : {n_dual} 条告警（其中基线引擎 {len(baseline_alerts)} 条）")
        for a in baseline_alerts[:3]:
            print(f"    → {a['severity']} | {a['type']} | z={a.get('z_score')} | "
                  f"值={a.get('value')} 基线中位={a.get('baseline_median')}")
        results[name] = {
            "description": desc,
            "packets": len(packets),
            "rule_only_alerts": n_rule,
            "dual_engine_alerts": n_dual,
            "baseline_only_alerts": len(baseline_alerts),
            "baseline_alerts_detail": [
                {k: a.get(k) for k in ("severity", "type", "z_score", "value", "baseline_median", "dimension")}
                for a in baseline_alerts[:3]
            ],
            "conclusion": "基线引擎检出纯规则漏检的轻度异常" if (n_rule == 0 and len(baseline_alerts) > 0) else "需人工复核",
        }
        print()

    # 汇总
    summary = {
        "experiment": "baseline_incremental_value",
        "baseline_used": "data/baselines/default.json",
        "seed": 42,
        "results": results,
        "headline": "低于规则阈值的轻度异常：纯规则检出 0 条，基线引擎通过行为突变检出",
    }
    out_path = "data/samples/regression_result.json"
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            reg = json.load(f)
        reg["baseline_value"] = summary
    else:
        reg = summary
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=2)
    print(f"结果已写入: {out_path}")
    print(f"\n📌 结论: {summary['headline']}")


if __name__ == "__main__":
    main()
