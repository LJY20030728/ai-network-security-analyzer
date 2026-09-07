# -*- coding: utf-8 -*-
"""
CICIDS2017 独立数据集评测脚本（tools/evaluate_cicids.py）
================================================================
目的：用官方 CICIDS2017 流级标注 CSV（独立于自造黄金样本）评测检测内核，
      产出可审计的 Precision/Recall/F1 与阈值敏感性（TPR/FPR）数据点。

方法（评测口径，README 中同步声明）：
1. CSV 每条流记录重放为一条合成 PacketInfo（流级重放）：
   - 端口扫描规则（distinct 目的端口）与包级语义完全无损
   - SYN flood / RST 规则按"含该标志的流数"计数（偏保守 → 评测偏严格，不虚高）
   - DNS 隧道规则依赖查询内容，CSV 无此字段 → 本评测不覆盖（明确边界）
2. 检测输入直接复用生产检测内核（TrafficAnalyzer._detect_anomalies / TrafficBaseline），
   不另写评测专用规则 —— 保证评估对象 = 产品检测器本体。
3. 粒度：
   - 规则引擎：源 IP 级攻击者识别（攻击者 = 标注非 BENIGN 流的源 IP）
   - 基线引擎：10s 窗口级（含攻击流窗口 = 正样本）
4. 阈值敏感性：σ ∈ {2.0, 2.5, 3.0, 3.5, 4.0} 扫描 → (FPR, TPR) 数据点（ROC 折线）

用法：python tools/evaluate_cicids.py [csv_path] [--name portscan]
"""
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.capture.packet_parser import PacketInfo
from src.analysis.flow_extractor import TrafficAnalyzer, NetworkFlow
from src.analysis.baseline import TrafficBaseline

# ---------- CSV 解析 ----------

CSV_TS_FMT = "%d/%m/%Y %H:%M:%S.%f"
OUT_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP", 47: "GRE", 50: "ESP", 53: "OTHER"}


def parse_csv(path: str):
    """解析 CICIDS2017 CSV，返回 (records, label_by_key)
    record: dict(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, length,
                 syn, ack, rst, packets, bytes_total, label)
    """
    records = []
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        raw_header = next(reader)
        # 统一去空格列名
        header = [h.strip() for h in raw_header]
        for row in reader:
            if len(row) != len(header):
                continue
            row_dict = {h: v for h, v in zip(header, row)}
            rec = {}
            try:
                ts_raw = row_dict.get("Timestamp") or ""
                if not ts_raw:
                    continue
                rec["timestamp"] = datetime.strptime(ts_raw.strip(), CSV_TS_FMT).strftime(OUT_TS_FMT)
                rec["src_ip"] = (row_dict.get("Source IP") or "").strip()
                rec["dst_ip"] = (row_dict.get("Destination IP") or "").strip()
                rec["src_port"] = int(float((row_dict.get("Source Port") or 0)))
                rec["dst_port"] = int(float((row_dict.get("Destination Port") or 0)))
                rec["protocol"] = PROTO_MAP.get(int(float((row_dict.get("Protocol") or 0))), "OTHER")
                rec["syn"] = int(float((row_dict.get("SYN Flag Count") or 0)))
                rec["ack"] = int(float((row_dict.get("ACK Flag Count") or 0)))
                rec["rst"] = int(float((row_dict.get("RST Flag Count") or 0)))
                fwd_len = float((row_dict.get("Total Length of Fwd Packets") or 0) or 0)
                bwd_len = float((row_dict.get("Total Length of Bwd Packets") or 0) or 0)
                rec["length"] = int(fwd_len + bwd_len)
                rec["packets"] = int(float((row_dict.get("Total Fwd Packets") or 0) or 0)) + \
                                 int(float((row_dict.get("Total Backward Packets") or 0) or 0))
                rec["label"] = (row_dict.get("Label") or "").strip()
                if not rec["src_ip"] or not rec["dst_ip"]:
                    continue
                records.append(rec)
            except (ValueError, TypeError):
                continue
    return records


def rec_to_packet(rec: Dict[str, Any]) -> PacketInfo:
    """流记录 → 合成 PacketInfo（流级重放）"""
    flags = []
    if rec["protocol"] == "TCP":
        if rec["syn"] > 0:
            flags.append("SYN")
        if rec["ack"] > 0:
            flags.append("ACK")
        if rec["rst"] > 0:
            flags.append("RST")
    p = PacketInfo(
        timestamp=rec["timestamp"],
        protocol=rec["protocol"],
        src_ip=rec["src_ip"],
        src_port=rec["src_port"],
        dst_ip=rec["dst_ip"],
        dst_port=rec["dst_port"],
        length=rec["length"],
        flags=",".join(flags),
        payload_size=rec["length"],
    )
    return p


def rec_to_flow(rec: Dict[str, Any]) -> NetworkFlow:
    fc = {}
    if rec["syn"] > 0:
        fc["SYN"] = rec["syn"]
    if rec["ack"] > 0:
        fc["ACK"] = rec["ack"]
    if rec["rst"] > 0:
        fc["RST"] = rec["rst"]
    return NetworkFlow(
        src_ip=rec["src_ip"], src_port=rec["src_port"],
        dst_ip=rec["dst_ip"], dst_port=rec["dst_port"],
        protocol=rec["protocol"],
        packet_count=rec["packets"], total_bytes=rec["length"],
        start_time=rec["timestamp"], end_time=rec["timestamp"],
        flag_counts=fc,
    )


# ---------- 源 IP 级规则评测 ----------

def evaluate_rules(packets: List[PacketInfo], attacker_ips: set, benign_ips: set,
                   analyzer: TrafficAnalyzer) -> Dict[str, Any]:
    """规则引擎：源 IP 级攻击者识别"""
    flows = []  # 大流量检测依赖构造流（评测覆盖）
    report = analyzer._detect_anomalies(packets, flows)

    alerted_ips = set()
    by_type: Dict[str, set] = defaultdict(set)
    for a in report["alerts"]:
        if a.get("src_ip"):
            alerted_ips.add(a["src_ip"])
            by_type[a["type"]].add(a["src_ip"])

    tp = len(attacker_ips & alerted_ips)
    fn = len(attacker_ips - alerted_ips)
    fp = len(alerted_ips - attacker_ips)  # 对 BENIGN 源 IP 的误报

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "attacker_ips": len(attacker_ips),
        "benign_ips": len(benign_ips),
        "alerted_ips": len(alerted_ips),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "alerts_by_type": {k: len(v) for k, v in by_type.items()},
        "total_alerts": report["total_alerts"],
        "alerted_ip_sample": sorted(alerted_ips)[:8],
    }


# ---------- 基线引擎评测（窗口级 + σ 扫描） ----------

def evaluate_baseline(records: List[Dict[str, Any]], sigma_list=None) -> Dict[str, Any]:
    """基线引擎：窗口级偏差检测
    learn: 仅 BENIGN 流（模拟正常画像）
    detect: 全文件
    正样本窗口 = 含攻击流（Label!=BENIGN）的窗口
    """
    if sigma_list is None:
        sigma_list = [2.0, 2.5, 3.0, 3.5, 4.0]

    benign_packets = [rec_to_packet(r) for r in records if r["label"] == "BENIGN"]
    all_packets = [rec_to_packet(r) for r in records]

    # 窗口真值：每个 10s 窗口是否含攻击流
    from src.analysis.baseline import TrafficBaseline as TB
    from collections import defaultdict as dd
    win_size = 10
    try:
        times = [datetime.strptime(p.timestamp, OUT_TS_FMT) for p in all_packets]
        t0 = times[0]
        rel = [(t - t0).total_seconds() for t in times]
    except Exception:
        rel = [float(i) for i in range(len(all_packets))]
    gt_window = dd(bool)
    for rec, sec in zip(records, rel):
        if rec["label"] != "BENIGN":
            gt_window[int(sec // win_size)] = True

    points = []
    metrics = {}
    for sigma in sigma_list:
        base = TrafficBaseline(sigma=sigma, window_sec=win_size)
        base.learn(benign_packets)
        det = base.detect(all_packets)
        dev_windows = set()
        for d in det.get("deviations", []):
            dev_windows.add(d["window_index"])

        # 窗口级混淆
        all_windows = set(range(max(gt_window.keys()) + 1))
        pred_pos = dev_windows
        gt_pos = {w for w, v in gt_window.items() if v}
        tp = len(pred_pos & gt_pos)
        fp = len(pred_pos - gt_pos)
        fn = len(gt_pos - pred_pos)
        tn = len(all_windows - pred_pos - gt_pos)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tpr
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        points.append({"sigma": sigma, "fpr": round(fpr, 4), "tpr": round(tpr, 4)})
        metrics[sigma] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        }

    return {
        "windows_total": len(all_windows),
        "windows_gt_positive": len(gt_pos),
        "benign_packets_for_learn": len(benign_packets),
        "sigma_points": points,
        "metrics_by_sigma": metrics,
    }


# ---------- 主流程 ----------

def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else \
        "data/eval_cicids/csv/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    name = "portscan"
    if "--name" in sys.argv:
        name = sys.argv[sys.argv.index("--name") + 1]

    print(f"[CICIDS2017 评测] {name} | {os.path.basename(csv_path)}")
    records = parse_csv(csv_path)
    print(f"  流总数: {len(records)}")

    from collections import Counter
    label_dist = Counter(r["label"] for r in records)
    print(f"  标签分布: {dict(label_dist)}")

    attacker_ips = {r["src_ip"] for r in records if r["label"] != "BENIGN"}
    benign_ips = {r["src_ip"] for r in records if r["label"] == "BENIGN"}
    print(f"  攻击者源IP: {len(attacker_ips)} | 正常源IP: {len(benign_ips)}")

    # 规则评测
    packets = [rec_to_packet(r) for r in records]
    analyzer = TrafficAnalyzer()
    rule_result = evaluate_rules(packets, attacker_ips, benign_ips, analyzer)
    print("\n[规则引擎 · 源IP级]")
    print(f"  TP={rule_result['tp']} FP={rule_result['fp']} FN={rule_result['fn']}")
    print(f"  Precision={rule_result['precision']} Recall={rule_result['recall']} F1={rule_result['f1']}")
    print(f"  告警按类型: {rule_result['alerts_by_type']}")

    # 基线评测
    print("\n[基线引擎 · 窗口级 + σ扫描]")
    base_result = evaluate_baseline(records)
    print(f"  窗口总数: {base_result['windows_total']} | 含攻击窗口: {base_result['windows_gt_positive']}")
    for pt in base_result["sigma_points"]:
        m = base_result["metrics_by_sigma"][str(pt["sigma"])] if str(pt["sigma"]) in base_result["metrics_by_sigma"] else base_result["metrics_by_sigma"][pt["sigma"]]
        print(f"  σ={pt['sigma']}: TPR={pt['tpr']} FPR={pt['fpr']} P={m['precision']} R={m['recall']} F1={m['f1']}")

    result = {
        "dataset": name,
        "csv": os.path.basename(csv_path),
        "flows_total": len(records),
        "label_distribution": dict(label_dist),
        "attacker_ips": len(attacker_ips),
        "benign_ips": len(benign_ips),
        "rules": rule_result,
        "baseline": base_result,
    }
    out = f"data/eval_cicids/result_{name}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入: {out}")


if __name__ == "__main__":
    main()
