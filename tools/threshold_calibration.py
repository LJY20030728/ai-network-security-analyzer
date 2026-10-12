# -*- coding: utf-8 -*-
"""
规则阈值校准实验（tools/threshold_calibration.py）
====================================================
对 11 条规则的关键阈值在 golden 样本上进行系统扫描，回答面试官必问：
"你的 80 个 SYN 阈值是怎么来的？"

方法：
  1. 加载 golden/ 下全部攻击样本 + normal 样本
  2. 对每条规则的阈值在合理范围内扫描（7-8 个数据点）
  3. 每个阈值点计算：攻击样本 TPR（文件级检出率）+ normal FPR（误报率）
  4. 输出 ROC 数据点 + 当前阈值在曲线上的位置 + 最优阈值建议

结果写入 data/eval_perf/threshold_calibration.json
"""
import os as _os
_os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")
_os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
try:
    import joblib as _joblib
    _joblib.parallel_backend("threading", n_jobs=1).__enter__()
except Exception:
    pass

import json
import os
import sys
import copy
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from loguru import logger
logger.remove()

from src.capture.packet_parser import PacketParser
from src.analysis.flow_extractor import TrafficAnalyzer, FlowExtractor
from scapy.all import rdpcap

try:
    from src.utils.helpers import force_utf8_stdout
    force_utf8_stdout()
except Exception:
    pass

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                          "data", "samples", "golden")

# 攻击样本 -> 对应规则类型（用于判断该阈值变化是否影响检出）
ATTACK_SAMPLES = {
    "synflood":   "SYN_FLOOD_SUSPECTED",
    "portscan":   "PORT_SCAN_SUSPECTED",
    "dnstunnel":  "DNS_TUNNEL_SUSPECTED",
    "largeflow":  "LARGE_DATA_TRANSFER",
    "rststorm":   "RST_STORM",
    "udpflood":   "UDP_FLOOD_SUSPECTED",
    "dnsamp":     "DNS_AMPLIFICATION",
    "quicflood":  "QUIC_FLOW_FLOOD",  # QUIC 样本可能触发多条 QUIC 规则
}

# 阈值扫描配置：(阈值键, 扫描范围, 对应攻击样本, 规则类型)
THRESHOLD_SCANS = [
    {
        "key": "syn_flood_min_count",
        "label": "SYN Flood 最小包数",
        "range": [20, 40, 60, 80, 100, 150, 200],
        "attack_sample": "synflood",
        "rule_type": "SYN_FLOOD_SUSPECTED",
        "current": 80,
    },
    {
        "key": "port_scan_min_ports",
        "label": "端口扫描 最小端口数",
        "range": [5, 8, 10, 15, 20, 25, 30],
        "attack_sample": "portscan",
        "rule_type": "PORT_SCAN_SUSPECTED",
        "current": 15,
    },
    {
        "key": "dns_tunnel_max_query_len",
        "label": "DNS隧道 最大查询长度",
        "range": [20, 25, 30, 35, 40, 45, 50],
        "attack_sample": "dnstunnel",
        "rule_type": "DNS_TUNNEL_SUSPECTED",
        "current": 40,
    },
    {
        "key": "large_flow_min_bytes",
        "label": "大流量 最小字节数",
        "range": [1_000_000, 5_000_000, 10_000_000, 20_000_000, 50_000_000],
        "attack_sample": "largeflow",
        "rule_type": "LARGE_DATA_TRANSFER",
        "current": 10_000_000,
    },
    {
        "key": "rst_storm_min_count",
        "label": "RST风暴 最小包数",
        "range": [10, 20, 30, 50, 80, 100],
        "attack_sample": "rststorm",
        "rule_type": "RST_STORM",
        "current": 50,
    },
    {
        "key": "udp_flood_min_count",
        "label": "UDP Flood 最小包数",
        "range": [20, 50, 80, 100, 150, 200],
        "attack_sample": "udpflood",
        "rule_type": "UDP_FLOOD_SUSPECTED",
        "current": 100,
    },
    {
        "key": "dns_amp_min_ratio",
        "label": "DNS放大 最小响应/请求比",
        "range": [1.5, 2.0, 2.5, 3.0, 4.0, 5.0],
        "attack_sample": "dnsamp",
        "rule_type": "DNS_AMPLIFICATION_SUSPECTED",
        "current": 3.0,
    },
    {
        "key": "quic_flood_min_connections",
        "label": "QUIC连接洪水 最小连接数",
        "range": [2, 5, 8, 10, 15, 20, 30],
        "attack_sample": "quicflood",
        "rule_type": "QUIC_CONNECTION_FLOOD",
        "current": 10,
    },
    {
        "key": "quic_initial_ratio_threshold",
        "label": "QUIC初始包比例 阈值",
        "range": [0.01, 0.05, 0.1, 0.2, 0.3, 0.5],
        "attack_sample": "quicflood",
        "rule_type": "QUIC_INITIAL_RATIO_ANOMALY",
        "current": 0.05,
    },
    {
        "key": "quic_long_flow_min_packets",
        "label": "QUIC长流异常 最小包数",
        "range": [10, 20, 30, 50, 80, 100],
        "attack_sample": "quicflood",
        "rule_type": "QUIC_LONG_FLOW_ANOMALY",
        "current": 100,
    },
]


def load_samples():
    """加载所有 golden 样本"""
    parser = PacketParser()
    samples = {}
    names = ["normal"] + list(ATTACK_SAMPLES.keys())
    for name in names:
        pcap = os.path.join(GOLDEN_DIR, f"{name}.pcap")
        if not os.path.exists(pcap):
            print(f"[跳过] {name}.pcap 不存在")
            continue
        pkts = [parser.parse(spkt) for spkt in rdpcap(pcap)]
        samples[name] = pkts
        print(f"[加载] {name:12s}: {len(pkts):5d} 包")
    return samples


def scan_threshold(analyzer, flow_ext, samples, scan_cfg):
    """对单个阈值进行扫描，返回 ROC 数据点"""
    key = scan_cfg["key"]
    attack_name = scan_cfg["attack_sample"]
    rule_type = scan_cfg["rule_type"]
    current_val = scan_cfg["current"]

    if attack_name not in samples or "normal" not in samples:
        return None

    attack_pkts = samples[attack_name]
    normal_pkts = samples["normal"]
    attack_flows = flow_ext.extract_flows(attack_pkts)
    normal_flows = flow_ext.extract_flows(normal_pkts)

    points = []
    for val in scan_cfg["range"]:
        # 修改阈值
        analyzer._t[key] = val

        # TPR：攻击样本是否触发对应规则
        rep_att = analyzer._detect_anomalies(attack_pkts, attack_flows)
        alert_types = {a["type"] for a in rep_att["alerts"]}
        tpr = 1.0 if rule_type in alert_types else 0.0
        # 也记录总告警数（用于观察是否有其他规则连带触发）
        total_alerts_attack = rep_att["total_alerts"]

        # FPR：normal 样本是否触发任何规则
        rep_norm = analyzer._detect_anomalies(normal_pkts, normal_flows)
        fpr = 1.0 if rep_norm["total_alerts"] > 0 else 0.0
        normal_alert_types = {a["type"] for a in rep_norm["alerts"]}

        is_current = (val == current_val)
        points.append({
            "threshold": val,
            "tpr": tpr,
            "fpr": fpr,
            "attack_alerts": total_alerts_attack,
            "attack_triggered": rule_type in alert_types,
            "normal_alerts": rep_norm["total_alerts"],
            "normal_alert_types": sorted(normal_alert_types),
            "is_current_default": is_current,
        })

    # 恢复默认值
    analyzer._t[key] = current_val

    # 找最优阈值：TPR=1 且 FPR=0 的最宽松阈值（减少漏报的同时不误报）
    optimal = None
    for p in points:
        if p["tpr"] == 1.0 and p["fpr"] == 0.0:
            optimal = p["threshold"]
            break  # 第一个（最严格的）满足条件的阈值

    return {
        "threshold_key": key,
        "label": scan_cfg["label"],
        "current_default": current_val,
        "attack_sample": attack_name,
        "rule_type": rule_type,
        "scan_range": scan_cfg["range"],
        "roc_points": points,
        "optimal_threshold": optimal,
        "current_status": (
            "合理（TPR=1,FPR=0）"
            if next((p for p in points if p["threshold"] == current_val
                     and p["tpr"] == 1.0 and p["fpr"] == 0.0), None)
            else "需关注（当前阈值下 TPR或FPR不理想）"
        ),
    }


def main():
    print("=" * 70)
    print("规则阈值校准实验")
    print("=" * 70)

    samples = load_samples()
    if not samples:
        print("没有可用样本，退出")
        return

    analyzer = TrafficAnalyzer(use_baseline=False)
    flow_ext = FlowExtractor()

    results = []
    print("\n" + "=" * 70)
    print("开始阈值扫描...")
    print("=" * 70)

    for scan_cfg in THRESHOLD_SCANS:
        print(f"\n[{scan_cfg['label']}] 当前默认={scan_cfg['current']}")
        result = scan_threshold(analyzer, flow_ext, samples, scan_cfg)
        if result is None:
            print(f"  跳过（样本缺失）")
            continue
        results.append(result)

        # 打印扫描结果
        for p in result["roc_points"]:
            marker = " ← 当前默认" if p["is_current_default"] else ""
            opt_marker = " ★最优" if p["threshold"] == result["optimal_threshold"] else ""
            print(f"  阈值={p['threshold']:>10}  TPR={p['tpr']:.0f}  "
                  f"FPR={p['fpr']:.0f}  攻击告警={p['attack_alerts']:2d}  "
                  f"正常告警={p['normal_alerts']:2d}{marker}{opt_marker}")
        print(f"  结论: {result['current_status']}")
        if result["optimal_threshold"] is not None:
            print(f"  建议阈值: {result['optimal_threshold']} "
                  f"(TPR=1, FPR=0 的最严格取值)")
        else:
            print(f"  建议: 扫描范围内无 TPR=1 且 FPR=0 的阈值，"
                  f"需增加样本多样性或调整规则逻辑")

    # ---------- 汇总 ----------
    summary = {
        "experiment": "规则阈值校准",
        "method": "对11条规则的关键阈值在golden样本上扫描，计算TPR/FPR",
        "samples_used": {k: len(v) for k, v in samples.items()},
        "total_thresholds_scanned": len(results),
        "results": results,
        "summary_stats": {
            "合理阈值数": sum(1 for r in results if "合理" in r["current_status"]),
            "需关注阈值数": sum(1 for r in results if "需关注" in r["current_status"]),
            "有最优建议数": sum(1 for r in results if r["optimal_threshold"] is not None),
        },
    }

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                            "data", "eval_perf", "threshold_calibration.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 70)
    print("汇总")
    print("=" * 70)
    print(f"  扫描阈值数: {summary['total_thresholds_scanned']}")
    print(f"  合理阈值: {summary['summary_stats']['合理阈值数']}")
    print(f"  需关注阈值: {summary['summary_stats']['需关注阈值数']}")
    print(f"  有最优建议: {summary['summary_stats']['有最优建议数']}")
    print(f"\n结果已写入: {out_path}")


if __name__ == "__main__":
    main()
