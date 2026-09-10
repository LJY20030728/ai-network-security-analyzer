# -*- coding: utf-8 -*-
"""
UNSW-NB15 公开数据集评测脚本（tools/evaluate_unsw.py）
================================================================
目的：用论文标准公开数据集 UNSW-NB15（training-set, 175,341 流，
      Argus/Bro 特征，真实 IXIA PerfectStorm 生成流量）评测检测内核，
      验证"自造黄金样本 → 公开数据集"的泛化性，补齐 P0 证据缺口。

评测口径（诚实声明，README 同步）：
1. 数据适配：UNSW-NB15 为流级特征 CSV（无时间戳、无 SYN 标志计数）。
   - 时间轴：按行序合成（每流 0.5s），声明为"合成时间轴"——基线/ML 窗口
     语义模拟真实时序窗口，数字不虚标为"真实时序验证"。
   - SYN 标志：UNSW 无 SYN Flag Count，以 state=REQ 近似 SYN 请求流
     （偏保守；synflood 检出率因此被低估而非虚高）。
2. 检测输入 = 生产检测内核本体（TrafficAnalyzer._detect_anomalies /
   TrafficBaseline / IsolationDetector），不写评测专用规则。
3. 三个引擎同输入同口径：
   - 规则引擎：源 IP 级攻击者识别 + attack_cat 覆盖矩阵（暴露盲区）
   - EWMA 基线：10s 窗口级（合成时间轴），σ∈{2,2.5,3,3.5,4} 扫描
   - 孤立森林：10s 窗口级 4 维特征（window_packets/bytes/syn/dports），
     仅 Normal 流窗口训练（无监督），全量检测
4. 输出：data/eval_cicids/result_unsw_nb15.json（可审计、可复跑）

用法：python tools/evaluate_unsw.py [csv_path]
"""
import csv
import json
import os
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.capture.packet_parser import PacketInfo
from src.analysis.flow_extractor import TrafficAnalyzer, NetworkFlow
from src.analysis.baseline import TrafficBaseline
from src.analysis.isolation_detector import IsolationDetector

DEFAULT_CSV = "data/eval_cicids/csv/UNSW_NB15_training-set.csv"
SYNTHETIC_STEP_SEC = 0.5          # 合成时间轴步长（无真实时间戳）
WINDOW_SEC = 10
SIGMA_LIST = [2.0, 2.5, 3.0, 3.5, 4.0]

# UNSW attack_cat → 我们的规则类型映射（仅映射有明确语义的；无规则类别 → None）
ATTACK_TO_RULE = {
    "Reconnaissance": ["portscan", "lightscan"],
    "DoS": ["synflood", "rststorm", "burst"],
    "Exploits": ["largeflow", "burst"],
    "Generic": ["largeflow"],
    "Fuzzers": ["burst"],
    "Backdoors": ["largeflow"],
    "Analysis": None,        # 无直接规则 → 盲区（评测诚实暴露）
    "Shellcode": None,
    "Worms": None,
}
# state 近似：REQ → SYN 请求流；含 RST → RST 流
STATE_SYN = {"REQ"}
STATE_RST = {"RST", "RSTO", "RSTR", "RSTOS0"}


def parse_unsw(path: str):
    """解析 UNSW-NB15 CSV → records
    record: src_ip, dst_ip, src_port, dst_port, protocol, state,
            packets, bytes_total, syn_approx, rst_approx, label(0/1), attack_cat
    兼容两种官方格式：
      - 原始 4 CSV（含 srcip/sport/dstip/dsport）
      - 标准划分 training/testing-set（官方匿名化，无 IP/端口 → 置空）
    """
    records = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        raw_header = next(reader)
        header = [h.strip() for h in raw_header]
        col = {name: i for i, name in enumerate(header)}
        has_ip = "srcip" in col
        for row in reader:
            if len(row) != len(header):
                continue
            try:
                def g(name):
                    return (row[col[name]] or "").strip() if name in col else ""
                rec = {}
                rec["src_ip"] = g("srcip") if has_ip else ""
                rec["dst_ip"] = g("dstip") if has_ip else ""
                rec["src_port"] = int(float(g("sport") or 0) or 0) if has_ip else 0
                rec["dst_port"] = int(float(g("dsport") or 0) or 0) if has_ip else 0
                rec["protocol"] = g("proto").upper() or "OTHER"
                rec["state"] = g("state").upper()
                rec["packets"] = int(float(g("spkts") or 0) or 0) + int(float(g("dpkts") or 0) or 0)
                rec["bytes_total"] = int(float(g("sbytes") or 0) or 0) + int(float(g("dbytes") or 0) or 0)
                rec["syn_approx"] = 1 if rec["state"] in STATE_SYN else 0
                rec["rst_approx"] = 1 if rec["state"] in STATE_RST else 0
                label_raw = (g("Label") or g("label") or "").strip()
                rec["label"] = 0 if label_raw in ("", "0", "Normal", "normal") else 1
                rec["attack_cat"] = (g("attack_cat") or "Normal").strip()
                records.append(rec)
            except (ValueError, TypeError):
                continue
    return records, has_ip


def synth_timestamp(idx: int) -> str:
    """行序 → 合成时间戳（0.5s 步长，从 2025-01-01 00:00:00 起）"""
    t = datetime(2025, 1, 1) + timedelta(seconds=idx * SYNTHETIC_STEP_SEC)
    return t.strftime("%Y-%m-%d %H:%M:%S.%f")


def rec_to_packet(rec: Dict[str, Any], idx: int) -> PacketInfo:
    flags = []
    if rec["protocol"] in ("TCP", "SCTP"):
        if rec["syn_approx"]:
            flags.append("SYN")
        if rec["rst_approx"]:
            flags.append("RST")
    return PacketInfo(
        timestamp=synth_timestamp(idx),
        protocol=rec["protocol"],
        src_ip=rec["src_ip"],
        src_port=rec["src_port"],
        dst_ip=rec["dst_ip"],
        dst_port=rec["dst_port"],
        length=max(1, rec["bytes_total"]),
        flags=",".join(flags),
        payload_size=max(1, rec["bytes_total"]),
    )


def rec_to_flow(rec: Dict[str, Any]) -> NetworkFlow:
    fc = {}
    if rec["syn_approx"]:
        fc["SYN"] = 1
    if rec["rst_approx"]:
        fc["RST"] = 1
    return NetworkFlow(
        src_ip=rec["src_ip"], src_port=rec["src_port"],
        dst_ip=rec["dst_ip"], dst_port=rec["dst_port"],
        protocol=rec["protocol"],
        packet_count=rec["packets"], total_bytes=max(1, rec["bytes_total"]),
        start_time="", end_time="",
        flag_counts=fc,
    )


# ---------- 规则引擎 ----------
# 产品规则共 5 类（settings 阈值）：SYN_FLOOD / PORT_SCAN / DNS_TUNNEL / LARGE / RST_STORM
#   - 原始 4 CSV（含 IP/端口）→ 源 IP 级完整评测
#   - 标准划分（官方匿名化，无 IP/端口/SYN/DNS 内容）→ 仅 LARGE 流级 + RST 窗口级，
#     其余规则诚实标注"不可测（数据匿名化缺字段）"

def _flow_rule_hits(records, has_ip, window_sec=WINDOW_SEC):
    """流级/窗口级规则命中（无 IP 时使用）
    LARGE: 单流 bytes > large_flow_min_mb（产品阈值，流级语义与产品一致）
    RST:   窗口内 RST 近似流数 >= rst_storm_min_count（无 IP，窗口级近似；标注偏差）
    """
    from config.settings import settings
    t = settings
    large_mb = t.large_flow_min_mb * 1024 * 1024
    hit_flows = set()       # 被 LARGE 命中的行 index
    rst_win = defaultdict(int)
    for idx, r in enumerate(records):
        if r["bytes_total"] > large_mb:
            hit_flows.add(idx)
        w = int((idx * SYNTHETIC_STEP_SEC) // window_sec)
        rst_win[w] += r["rst_approx"]
    return hit_flows, rst_win


def evaluate_rules(packets, records, has_ip):
    if has_ip:
        return _evaluate_rules_ip(packets, records)
    return _evaluate_rules_flow(packets, records)


def _evaluate_rules_ip(packets, records):
    attacker_by_cat = defaultdict(set)
    for r in records:
        if r["label"] == 1:
            attacker_by_cat[r["attack_cat"]].add(r["src_ip"])
    attacker_ips = set().union(*attacker_by_cat.values()) if attacker_by_cat else set()
    benign_ips = {r["src_ip"] for r in records if r["label"] == 0}

    analyzer = TrafficAnalyzer()
    flows = [rec_to_flow(r) for r in records]
    report = analyzer._detect_anomalies(packets, flows)

    alerted_ips = set()
    by_type = defaultdict(set)
    for a in report["alerts"]:
        if a.get("src_ip"):
            alerted_ips.add(a["src_ip"])
            by_type[a["type"]].add(a["src_ip"])

    tp = len(attacker_ips & alerted_ips)
    fn = len(attacker_ips - alerted_ips)
    fp = len(alerted_ips - attacker_ips)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    coverage = {}
    for cat, ips in attacker_by_cat.items():
        detected = len(ips & alerted_ips)
        coverage[cat] = {
            "attacker_ips": len(ips),
            "detected_ips": detected,
            "detect_rate": round(detected / len(ips), 4) if ips else 0.0,
            "mapped_rules": ATTACK_TO_RULE.get(cat, None),
        }

    return {
        "mode": "source_ip_level",
        "attacker_ips": len(attacker_ips),
        "benign_ips": len(benign_ips),
        "alerted_ips": len(alerted_ips),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "coverage_by_attack_cat": coverage,
        "alerts_by_type": {k: len(v) for k, v in by_type.items()},
        "total_alerts": report["total_alerts"],
    }


def _evaluate_rules_flow(packets, records):
    """匿名版：流级 LARGE + 窗口级 RST（产品阈值）"""
    from config.settings import settings
    hit_flows, rst_win = _flow_rule_hits(records, has_ip=False)
    attack_idx = {i for i, r in enumerate(records) if r["label"] == 1}
    benign_idx = {i for i, r in enumerate(records) if r["label"] == 0}

    # 窗口级 RST：窗口真值 = 含攻击流
    wins = build_windows(records)
    win_of_idx = {}
    for idx in range(len(records)):
        win_of_idx[idx] = int((idx * SYNTHETIC_STEP_SEC) // WINDOW_SEC)

    # LARGE 流级命中（攻击流命中 / 正常流误报）
    large_hit = hit_flows
    large_tp = len(large_hit & attack_idx)
    large_fp = len(large_hit & benign_idx)
    large_fn = len(attack_idx - large_hit)
    large_precision = large_tp / (large_tp + large_fp) if (large_tp + large_fp) else 0.0
    large_recall = large_tp / (large_tp + large_fn) if (large_tp + large_fn) else 0.0
    large_f1 = 2 * large_precision * large_recall / (large_precision + large_recall) if (large_precision + large_recall) else 0.0

    # RST 窗口级命中
    rst_pos_wins = {w for w, c in rst_win.items() if c >= settings.rst_storm_min_count}
    gt_wins = {w["window_index"] for w in wins if w["attack"]}
    all_wins_idx = {w["window_index"] for w in wins}
    rst_tp = len(rst_pos_wins & gt_wins)
    rst_fp = len(rst_pos_wins - gt_wins)
    rst_fn = len(gt_wins - rst_pos_wins)
    rst_tn = len(all_wins_idx - rst_pos_wins - gt_wins)
    rst_tpr = rst_tp / (rst_tp + rst_fn) if (rst_tp + rst_fn) else 0.0
    rst_fpr = rst_fp / (rst_fp + rst_tn) if (rst_fp + rst_tn) else 0.0

    # attack_cat 类别流级命中率（LARGE 维度）
    coverage = {}
    for cat in sorted({r["attack_cat"] for r in records if r["label"] == 1}):
        cat_idx = {i for i, r in enumerate(records) if r["attack_cat"] == cat}
        detected = len(cat_idx & large_hit)
        coverage[cat] = {
            "attack_flows": len(cat_idx),
            "large_flow_hits": detected,
            "detect_rate_large": round(detected / len(cat_idx), 4) if cat_idx else 0.0,
            "mapped_rules": ATTACK_TO_RULE.get(cat, None),
        }

    return {
        "mode": "flow_level_anonymized",
        "note": "官方划分匿名化（无 IP/端口/SYN/DNS 内容）：SYN_FLOOD/PORT_SCAN/DNS_TUNNEL 不可测；"
                "LARGE 流级语义与产品一致，RST 为窗口级近似（产品为单源语义）",
        "large_flow": {
            "threshold_mb": settings.large_flow_min_mb,
            "tp": large_tp, "fp": large_fp, "fn": large_fn,
            "precision": round(large_precision, 4), "recall": round(large_recall, 4), "f1": round(large_f1, 4),
        },
        "rst_window": {
            "threshold_count": settings.rst_storm_min_count,
            "tp": rst_tp, "fp": rst_fp, "fn": rst_fn, "tn": rst_tn,
            "tpr": round(rst_tpr, 4), "fpr": round(rst_fpr, 4),
        },
        "coverage_by_attack_cat": coverage,
        "untestable_rules": ["SYN_FLOOD_SUSPECTED", "PORT_SCAN_SUSPECTED", "DNS_TUNNEL_SUSPECTED"],
    }


# ---------- 窗口构建（合成时间轴） ----------

def build_windows(records: List[Dict[str, Any]]):
    """行序合成时间轴 → 10s 窗口聚合 {packets, bytes, syn, dports} + 真值"""
    win = defaultdict(lambda: {"packets": 0, "bytes": 0, "syn": 0, "dports": set(), "attack": False})
    for idx, r in enumerate(records):
        w = int((idx * SYNTHETIC_STEP_SEC) // WINDOW_SEC)
        cell = win[w]
        cell["packets"] += r["packets"]
        cell["bytes"] += r["bytes_total"]
        cell["syn"] += r["syn_approx"]
        cell["dports"].add(r["dst_port"])
        if r["label"] == 1:
            cell["attack"] = True
    wins = []
    for w in sorted(win):
        cell = win[w]
        wins.append({
            "window_index": w,
            "window_packets": float(cell["packets"]),
            "window_bytes": float(cell["bytes"]),
            "window_syn": float(cell["syn"]),
            "window_dports": float(len(cell["dports"])),
            "attack": cell["attack"],
        })
    return wins


# ---------- 基线引擎（窗口级 + σ 扫描） ----------

def evaluate_baseline(wins: List[Dict[str, Any]]) -> Dict[str, Any]:
    train_wins = [w for w in wins if not w["attack"]]
    all_wins = wins
    points, metrics = [], {}
    for sigma in SIGMA_LIST:
        base = TrafficBaseline(sigma=sigma, window_sec=WINDOW_SEC)
        base.learn_windows([{k: v for k, v in w.items() if k != "attack"} for w in train_wins])
        det = base.detect_windows([{k: v for k, v in w.items() if k != "attack"} for w in all_wins])
        pred_pos = {a["window_index"] for a in det.get("deviations", [])}
        gt_pos = {w["window_index"] for w in all_wins if w["attack"]}
        all_idx = {w["window_index"] for w in all_wins}
        tp = len(pred_pos & gt_pos)
        fp = len(pred_pos - gt_pos)
        fn = len(gt_pos - pred_pos)
        tn = len(all_idx - pred_pos - gt_pos)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0
        points.append({"sigma": sigma, "fpr": round(fpr, 4), "tpr": round(tpr, 4)})
        metrics[str(sigma)] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(tpr, 4), "f1": round(f1, 4),
        }
    return {
        "windows_total": len(wins),
        "windows_gt_positive": len(gt_pos),
        "train_windows_normal_only": len(train_wins),
        "sigma_points": points,
        "metrics_by_sigma": metrics,
        "note": "合成时间轴（行序×0.5s）；learn 仅 Normal 窗口",
    }


# ---------- 孤立森林（窗口级，仅 Normal 训练） ----------

def evaluate_ml(wins: List[Dict[str, Any]]) -> Dict[str, Any]:
    train_wins = [w for w in wins if not w["attack"]]
    all_wins = wins
    det = IsolationDetector(contamination=0.10, random_state=42)
    det.learn_windows([{k: v for k, v in w.items() if k != "attack"} for w in train_wins])
    res = det.detect_windows([{k: v for k, v in w.items() if k != "attack"} for w in all_wins])

    pred_pos = {a["window_index"] for a in res.get("anomalies", [])}
    gt_pos = {w["window_index"] for w in all_wins if w["attack"]}
    all_idx = {w["window_index"] for w in all_wins}
    tp = len(pred_pos & gt_pos)
    fp = len(pred_pos - gt_pos)
    fn = len(gt_pos - pred_pos)
    tn = len(all_idx - pred_pos - gt_pos)
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "tpr": round(tpr, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4), "f1": round(f1, 4),
        "train_windows_normal_only": len(train_wins),
        "score_threshold": det.to_dict()["score_threshold"],
        "contamination": 0.10,
    }


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV
    print(f"[UNSW-NB15 评测] {os.path.basename(csv_path)}")
    records, has_ip = parse_unsw(csv_path)
    print(f"  流总数: {len(records)}，含 IP 列: {has_ip}")
    label_dist = Counter("attack" if r["label"] else "normal" for r in records)
    cat_dist = Counter(r["attack_cat"] for r in records if r["label"] == 1)
    print(f"  标签分布: {dict(label_dist)}")
    print(f"  攻击类别: {dict(cat_dist)}")

    packets = [rec_to_packet(r, i) for i, r in enumerate(records)]

    rule_result = evaluate_rules(packets, records, has_ip)
    print(f"\n[规则引擎 · {rule_result['mode']}]")
    if rule_result["mode"] == "source_ip_level":
        print(f"  Precision={rule_result['precision']} Recall={rule_result['recall']} F1={rule_result['f1']} "
              f"(TP={rule_result['tp']} FP={rule_result['fp']} FN={rule_result['fn']})")
        for cat, c in rule_result["coverage_by_attack_cat"].items():
            print(f"  {cat:<14} 检出率={c['detect_rate']:.2f} ({c['detected_ips']}/{c['attacker_ips']}) "
                  f"映射规则={c['mapped_rules']}")
    else:
        lf = rule_result["large_flow"]
        print(f"  LARGE: P={lf['precision']} R={lf['recall']} F1={lf['f1']} "
              f"(TP={lf['tp']} FP={lf['fp']} FN={lf['fn']}) 阈值={lf['threshold_mb']}MB")
        rst = rule_result["rst_window"]
        print(f"  RST(窗口): TPR={rst['tpr']} FPR={rst['fpr']} (TP={rst['tp']} FP={rst['fp']} FN={rst['fn']} TN={rst['tn']})")
        for cat, c in rule_result["coverage_by_attack_cat"].items():
            print(f"  {cat:<14} LARGE命中率={c['detect_rate_large']:.2f} ({c['large_flow_hits']}/{c['attack_flows']})")
        print(f"  不可测规则: {rule_result['untestable_rules']}")

    wins = build_windows(records)
    print(f"\n[窗口构建] 共 {len(wins)} 窗口（10s 合成时间轴），含攻击 {sum(1 for w in wins if w['attack'])}")

    base_result = evaluate_baseline(wins)
    print("\n[基线引擎 · 窗口级 + σ 扫描]")
    for pt in base_result["sigma_points"]:
        m = base_result["metrics_by_sigma"][str(pt["sigma"])]
        print(f"  σ={pt['sigma']}: TPR={pt['tpr']} FPR={pt['fpr']} P={m['precision']} F1={m['f1']}")

    ml_result = evaluate_ml(wins)
    print("\n[孤立森林 · 窗口级 · 仅Normal训练]")
    print(f"  TPR={ml_result['tpr']} FPR={ml_result['fpr']} P={ml_result['precision']} F1={ml_result['f1']} "
          f"(TP={ml_result['tp']} FP={ml_result['fp']} FN={ml_result['fn']} TN={ml_result['tn']})")

    result = {
        "dataset": "UNSW-NB15",
        "csv": os.path.basename(csv_path),
        "has_ip_columns": has_ip,
        "flows_total": len(records),
        "label_distribution": dict(label_dist),
        "attack_cat_distribution": dict(cat_dist),
        "synthetic_time_axis": f"行序 × {SYNTHETIC_STEP_SEC}s（UNSW 无时间戳，声明为合成）",
        "rules": rule_result,
        "baseline": base_result,
        "isolation_forest": ml_result,
    }
    out = "data/eval_cicids/result_unsw_nb15.json"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入: {out}")


if __name__ == "__main__":
    main()
