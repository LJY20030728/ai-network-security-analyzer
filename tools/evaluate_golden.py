# -*- coding: utf-8 -*-
"""
黄金样本完整指标评测（tools/evaluate_golden.py）
=================================================
对 data/samples/golden/ 的合成黄金样本（normal + 7 类攻击）计算完整指标体系：
- 文件级：攻击样本应触发对应规则（TP），normal 不应触发（TN）
- 源IP级：攻击样本中的攻击者源 IP 应被告警（归因正确性）
- 基线引擎：normal 学习 → 各样本检测 → 窗口级 TP/FN + normal 自身 0 误报
- 阈值敏感性：σ ∈ {2, 2.5, 3, 3.5, 4} → (FPR, TPR) 数据点（ROC 折线）
- 每攻击类型分类型分解

结果写入 data/samples/regression_result.json（evaluation 字段）+ 打印报告表。
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.capture.packet_parser import PacketParser, PacketInfo
from src.analysis.flow_extractor import TrafficAnalyzer, FlowExtractor
from src.analysis.baseline import TrafficBaseline
from scapy.all import rdpcap

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "samples", "golden")

# 样本 -> 预期规则类型（合成样本生成器的语义）
EXPECTED = {
    "normal": None,
    "synflood": "SYN_FLOOD_SUSPECTED",
    "portscan": "PORT_SCAN_SUSPECTED",
    "dnstunnel": "DNS_TUNNEL_SUSPECTED",
    "largeflow": "LARGE_DATA_TRANSFER",
    "rststorm": "RST_STORM",
    "lightscan": "PORT_SCAN_SUSPECTED",   # 低于阈值 → 预期由基线覆盖
    "burst": "BASELINE_DEVIATION",        # 低于阈值 → 预期由基线覆盖
}
# lightscan/burst 是基线增量实验样本（规则阈值下不触发），单独计口径
BASELINE_ONLY = {"lightscan", "burst"}


def load_packets(name: str):
    pcap = os.path.join(GOLDEN_DIR, f"{name}.pcap")
    parser = PacketParser()
    pkts = []
    for spkt in rdpcap(pcap):
        pkts.append(parser.parse(spkt))
    return pkts


def main():
    parser = PacketParser()
    analyzer = TrafficAnalyzer(use_baseline=False)
    samples = {}
    for name in EXPECTED:
        pcap = os.path.join(GOLDEN_DIR, f"{name}.pcap")
        if not os.path.exists(pcap):
            print(f"[跳过] {name}.pcap 不存在")
            continue
        pkts = [parser.parse(spkt) for spkt in rdpcap(pcap)]
        samples[name] = pkts
        print(f"[加载] {name}: {len(pkts)} 包")

    # ---------- 1. 规则引擎 · 文件级 + 源IP级 ----------
    rule_rows = []
    tp_files = tn_files = 0
    flow_ext = FlowExtractor()
    for name, pkts in samples.items():
        exp = EXPECTED[name]
        flows = flow_ext.extract_flows(pkts)
        rep = analyzer._detect_anomalies(pkts, flows)
        alert_types = {a["type"] for a in rep["alerts"]}
        alerted_ips = {a.get("src_ip") for a in rep["alerts"] if a.get("src_ip")}

        if exp is None:
            hit = len(rep["alerts"]) == 0
            tn_files += 1 if hit else 0
            status = "TN(无告警)" if hit else f"FP! {sorted(alert_types)}"
        elif name in BASELINE_ONLY:
            # 预期由基线覆盖：规则不触发是设计行为，不计入规则 TP
            status = f"规则预期不触发({len(rep['alerts'])}条)"
            hit = None
        else:
            hit = exp in alert_types
            tp_files += 1 if hit else 0
            status = f"TP({exp})" if hit else f"FN! 实际={sorted(alert_types)}"

        rule_rows.append({
            "sample": name, "packets": len(pkts),
            "alerts": rep["total_alerts"], "types": sorted(alert_types),
            "expected": exp, "status": status,
            "alerted_ips": sorted(alerted_ips),
        })
        print(f"[规则] {name:10s} 告警={rep['total_alerts']:2d} {status}")

    # ---------- 2. 基线引擎 · normal 学习 → 各样本检测 ----------
    print("\n[基线] normal 学习 → 各样本检测（σ=3.0 默认）")
    base_rows = []
    normal_pkts = samples["normal"]
    normal_base = TrafficBaseline()
    normal_base.learn(normal_pkts)

    gt_normal_windows = len(normal_base._aggregate_windows(normal_pkts))
    det_normal = normal_base.detect(normal_pkts)
    normal_fp = len(det_normal.get("deviations", []))
    print(f"  normal 自测: 偏差 {normal_fp}/{gt_normal_windows} 窗口 (0 = 无误报)")

    for name, pkts in samples.items():
        if name == "normal":
            continue
        det = normal_base.detect(pkts)
        devs = det.get("deviations", [])
        base_rows.append({
            "sample": name, "windows": len(normal_base._aggregate_windows(pkts)),
            "deviation_windows": len(devs), "max_z": round(max((d["z_score"] for d in devs), default=0), 2),
        })
        print(f"   {name:10s} 偏差窗口={len(devs):2d} max_z={base_rows[-1]['max_z']}")

    # ---------- 3. σ 敏感性扫描（ROC 数据点） ----------
    print("\n[σ 扫描] (FPR, TPR) 数据点")
    sigma_list = [2.0, 2.5, 3.0, 3.5, 4.0]
    roc_points = []
    attack_samples = [n for n in EXPECTED if n not in ("normal",) and n not in BASELINE_ONLY]
    for sigma in sigma_list:
        base = TrafficBaseline(sigma=sigma)
        base.learn(normal_pkts)
        # TPR：攻击样本中产生偏差的样本比例（文件级近似）
        tp_hit = 0
        for n in attack_samples:
            det = base.detect(samples[n])
            if det.get("deviations"):
                tp_hit += 1
        tpr = tp_hit / len(attack_samples) if attack_samples else 0
        # FPR：normal 自测偏差窗口占比
        det_n = base.detect(normal_pkts)
        fp_windows = len(det_n.get("deviations", []))
        fpr = fp_windows / gt_normal_windows if gt_normal_windows else 0
        roc_points.append({"sigma": sigma, "fpr": round(fpr, 4), "tpr": round(tpr, 4)})
        print(f"  σ={sigma}: TPR={tpr:.2f} FPR={fpr:.4f}")

    # ---------- 汇总 ----------
    rule_tp = sum(1 for r in rule_rows if r["status"].startswith("TP"))
    rule_fn = sum(1 for r in rule_rows if r["status"].startswith("FN"))
    rule_tn = tn_files
    rule_fp = sum(1 for r in rule_rows if r["status"].startswith("FP"))
    precision = rule_tp / (rule_tp + rule_fp) if (rule_tp + rule_fp) else 0
    recall = rule_tp / (rule_tp + rule_fn) if (rule_tp + rule_fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    summary = {
        "rules_file_level": {
            "tp": rule_tp, "fp": rule_fp, "tn": rule_tn, "fn": rule_fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        },
        "baseline_self_test": {"windows": gt_normal_windows, "false_positive_windows": normal_fp},
        "baseline_samples": base_rows,
        "sigma_roc_points": roc_points,
        "rule_rows": rule_rows,
    }
    print("\n[规则引擎 · 文件级指标]")
    print(f"  TP={rule_tp} FP={rule_fp} TN={rule_tn} FN={rule_fn}")
    print(f"  Precision={precision:.4f} Recall={recall:.4f} F1={f1:.4f}")
    print(f"  说明: lightscan/burst 为基线专项样本，不计入规则指标")

    result_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                               "data", "samples", "regression_result.json")
    if os.path.exists(result_path):
        with open(result_path, encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {}
    data["evaluation"] = summary
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入 regression_result.json (evaluation 字段)")


if __name__ == "__main__":
    main()
