# -*- coding: utf-8 -*-
"""
CIC-UNSW-NB15 评测（tools/evaluate_unsw_cic.py）
================================================================
数据：bencorn/CIC-UNSW-NB15（HuggingFace 镜像）——同一 UNSW-NB15 底层流量
     经 CICFlowMeter 重提取的 76 维数值特征（447,915 流，10 类标签）。
     注意：该版本同样匿名化（无 IP/端口/时间戳/SYN 标志）。

评测口径（与 evaluate_unsw.py 对齐，声明合成时间轴）：
1. 流级 ML（亮点）：76 维原始特征直接喂 IsolationForest（复用产品配置
   contamination=0.10, random_state=42），仅 Normal 流训练（无监督）→
   流级 TPR/FPR + 10 类 attack_cat 检出率 + anomaly 分分布。
   与 evaluate_unsw.py 的"4 维窗口聚合版"构成特征工程对比实验：
   原始流特征 vs 窗口聚合特征对检测能力的影响。
2. 窗口级交叉验证：合成时间轴 10s 窗口，与官方 training-set 同口径，
   基线（σ 扫描）+ 孤立森林（4 维窗口，产品接口 IsolationDetector）。
3. 规则 LARGE：流级 Fwd+Bwd 字节 >10MB（产品阈值）。其余规则因匿名化
   不可测（同 training-set 口径，诚实标注）。

用法：python tools/evaluate_unsw_cic.py [data_csv] [label_csv]
输出：data/eval_cicids/result_unsw_cic.json
"""
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any

import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from config.settings import settings
from src.analysis.baseline import TrafficBaseline
from src.analysis.isolation_detector import IsolationDetector

DEFAULT_DATA = "data/eval_cicids/csv/CIC_Data.csv"
DEFAULT_LABEL = "data/eval_cicids/csv/CIC_Lable.csv"
SYNTHETIC_STEP_SEC = 0.5
WINDOW_SEC = 10
SIGMA_LIST = [2.0, 2.5, 3.0, 3.5, 4.0]

CAT_MAP = {0: "Benign", 1: "Analysis", 2: "Backdoor", 3: "DoS", 4: "Exploits",
           5: "Fuzzers", 6: "Generic", 7: "Reconnaissance", 8: "Shellcode", 9: "Worms"}


def load_data(data_csv: str, label_csv: str):
    feats, labels = [], []
    with open(data_csv, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        n_cols = len(header)
        for row in reader:
            if len(row) != n_cols:
                continue
            vec = []
            ok = True
            for v in row:
                try:
                    vec.append(float(v))
                except (ValueError, TypeError):
                    vec.append(0.0)
            feats.append(vec)
    with open(label_csv, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        next(reader)  # Label
        for row in reader:
            try:
                labels.append(int(float(row[0])))
            except (ValueError, TypeError, IndexError):
                labels.append(0)
    n = min(len(feats), len(labels))
    X = np.asarray(feats[:n], dtype=np.float64)
    y = np.asarray(labels[:n], dtype=np.int64)
    return X, y, header


def evaluate_flow_ml(X, y):
    """流级 76 维孤立森林（无监督，仅 Normal 训练）"""
    norm_idx = np.where(y == 0)[0]
    atk_idx = np.where(y != 0)[0]
    model = IsolationForest(n_estimators=100, contamination=0.10,
                            random_state=42, n_jobs=-1)
    model.fit(X[norm_idx])
    scores = model.score_samples(X)  # 越高越正常
    thr = np.percentile(scores[norm_idx], 10)  # Normal 训练分布 10% 分位（contamination）
    pred = (scores < thr).astype(int)

    tp = int(np.sum(pred[atk_idx] == 1))
    fn = int(np.sum(pred[atk_idx] == 0))
    fp = int(np.sum(pred[norm_idx] == 1))
    tn = int(np.sum(pred[norm_idx] == 0))
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0

    # attack_cat 检出率
    cat_result = {}
    for cat_id in sorted(set(y)):
        name = CAT_MAP.get(int(cat_id), str(int(cat_id)))
        cat_idx = np.where(y == cat_id)[0]
        if cat_id == 0:
            cat_result[name] = {"flows": int(len(cat_idx)), "false_positive_rate": round(float(np.mean(pred[cat_idx])), 4)}
        else:
            cat_result[name] = {
                "flows": int(len(cat_idx)),
                "detect_rate": round(float(np.mean(pred[cat_idx])), 4),
                "detected": int(np.sum(pred[cat_idx])),
            }

    # anomaly 分分布（攻击 vs 正常 的 score 均值）
    return {
        "mode": "flow_level_76dim",
        "feature_dim": int(X.shape[1]),
        "train_normal_flows": int(len(norm_idx)),
        "total_flows": int(len(y)),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "tpr": round(tpr, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4), "f1": round(f1, 4),
        "score_threshold_percentile": "Normal 训练分位 10%（=contamination 0.10）",
        "mean_score_normal": round(float(np.mean(scores[norm_idx])), 4),
        "mean_score_attack": round(float(np.mean(scores[atk_idx])), 4),
        "coverage_by_attack_cat": cat_result,
        "note": "复用产品 ML 配置（IsolationForest, contamination=0.10, seed=42）；"
                "仅 Normal 流训练（无监督）；76 维原始特征",
    }


def build_windows(X, y):
    """合成时间轴 → 10s 窗口聚合 {packets, bytes, syn, dports}
    CIC 版无包数/字节/SYN/端口列 → 用 Total Fwd/Bwd Packet 与 Length 近似：
    window_packets=Σ(Fwd+Bwd Packet)，window_bytes=Σ(Fwd+Bwd Length)，
    syn/dports 无列 → 0（标注）。
    """
    rows = []
    # 列索引：Flow Duration=0, Total Fwd Packet=1, Total Bwd packets=2,
    #         Total Length of Fwd Packet=3, Total Length of Bwd Packet=4
    for i in range(len(y)):
        x = X[i]
        packets = x[1] + x[2]
        bytes_total = x[3] + x[4]
        rows.append({"packets": packets, "bytes": bytes_total, "label": int(y[i])})

    win = defaultdict(lambda: {"packets": 0.0, "bytes": 0.0, "syn": 0.0,
                               "dports": 0.0, "attack": False})
    for idx, r in enumerate(rows):
        w = int((idx * SYNTHETIC_STEP_SEC) // WINDOW_SEC)
        cell = win[w]
        cell["packets"] += r["packets"]
        cell["bytes"] += r["bytes"]
        if r["label"] != 0:
            cell["attack"] = True
    wins = []
    for w in sorted(win):
        c = win[w]
        wins.append({
            "window_index": w,
            "window_packets": c["packets"],
            "window_bytes": c["bytes"],
            "window_syn": c["syn"],
            "window_dports": c["dports"],
            "attack": c["attack"],
        })
    return wins


def evaluate_baseline(wins):
    train_wins = [w for w in wins if not w["attack"]]
    points, metrics = [], {}
    for sigma in SIGMA_LIST:
        base = TrafficBaseline(sigma=sigma, window_sec=WINDOW_SEC)
        base.learn_windows([{k: v for k, v in w.items() if k != "attack"} for w in train_wins])
        det = base.detect_windows([{k: v for k, v in w.items() if k != "attack"} for w in wins])
        pred_pos = {a["window_index"] for a in det.get("deviations", [])}
        gt_pos = {w["window_index"] for w in wins if w["attack"]}
        all_idx = {w["window_index"] for w in wins}
        tp = len(pred_pos & gt_pos)
        fp = len(pred_pos - gt_pos)
        fn = len(gt_pos - pred_pos)
        tn = len(all_idx - pred_pos - gt_pos)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0
        points.append({"sigma": sigma, "fpr": round(fpr, 4), "tpr": round(tpr, 4)})
        metrics[str(sigma)] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                               "precision": round(precision, 4), "recall": round(tpr, 4), "f1": round(f1, 4)}
    return {"windows_total": len(wins), "sigma_points": points, "metrics_by_sigma": metrics,
            "note": "合成时间轴（行序×0.5s）；CIC 版无 SYN/端口列 → syn/dports=0"}


def evaluate_window_ml(wins):
    train_wins = [w for w in wins if not w["attack"]]
    det = IsolationDetector(contamination=0.10, random_state=42)
    det.learn_windows([{k: v for k, v in w.items() if k != "attack"} for w in train_wins])
    res = det.detect_windows([{k: v for k, v in w.items() if k != "attack"} for w in wins])
    pred_pos = {a["window_index"] for a in res.get("anomalies", [])}
    gt_pos = {w["window_index"] for w in wins if w["attack"]}
    all_idx = {w["window_index"] for w in wins}
    tp = len(pred_pos & gt_pos)
    fp = len(pred_pos - gt_pos)
    fn = len(gt_pos - pred_pos)
    tn = len(all_idx - pred_pos - gt_pos)
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "tpr": round(tpr, 4),
            "fpr": round(fpr, 4), "precision": round(precision, 4), "f1": round(f1, 4),
            "mode": "window_level_4dim_product_interface"}


def evaluate_large_rule(X, y):
    """流级 LARGE 规则：Fwd+Bwd Length > 10MB（产品阈值 large_flow_min_mb）"""
    bytes_total = X[:, 3] + X[:, 4]
    thr = settings.large_flow_min_mb * 1024 * 1024
    hit = bytes_total > thr
    atk = y != 0
    norm = y == 0
    tp = int(np.sum(hit & atk))
    fp = int(np.sum(hit & norm))
    fn = int(np.sum(atk & ~hit))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"threshold_mb": settings.large_flow_min_mb, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def main():
    data_csv = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATA
    label_csv = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_LABEL
    print(f"[CIC-UNSW-NB15 评测] {os.path.basename(data_csv)}")
    X, y, header = load_data(data_csv, label_csv)
    dist = Counter(CAT_MAP.get(int(v), str(int(v))) for v in y)
    print(f"  流总数: {len(y)}，特征维数: {X.shape[1]}")
    print(f"  标签分布: {dict(dist)}")

    flow_ml = evaluate_flow_ml(X, y)
    print("\n[流级 ML · 76 维 · 仅Normal训练]")
    print(f"  TPR={flow_ml['tpr']} FPR={flow_ml['fpr']} P={flow_ml['precision']} F1={flow_ml['f1']} "
          f"(TP={flow_ml['tp']} FP={flow_ml['fp']} FN={flow_ml['fn']} TN={flow_ml['tn']})")
    print(f"  Normal均分={flow_ml['mean_score_normal']} vs Attack均分={flow_ml['mean_score_attack']}")
    for cat, c in flow_ml["coverage_by_attack_cat"].items():
        if cat == "Benign":
            print(f"  {cat:<14} FPR={c['false_positive_rate']} ({c['flows']} 流)")
        else:
            print(f"  {cat:<14} 检出率={c['detect_rate']:.2f} ({c['detected']}/{c['flows']})")

    large = evaluate_large_rule(X, y)
    print(f"\n[规则 LARGE · 流级] P={large['precision']} R={large['recall']} F1={large['f1']} "
          f"(TP={large['tp']} FP={large['fp']} FN={large['fn']}) 阈值={large['threshold_mb']}MB")

    wins = build_windows(X, y)
    print(f"\n[窗口构建] 共 {len(wins)} 窗口（10s 合成），含攻击 {sum(1 for w in wins if w['attack'])}")
    base_result = evaluate_baseline(wins)
    print("[基线引擎 · 窗口级 + σ 扫描]")
    for pt in base_result["sigma_points"]:
        m = base_result["metrics_by_sigma"][str(pt["sigma"])]
        print(f"  σ={pt['sigma']}: TPR={pt['tpr']} FPR={pt['fpr']} F1={m['f1']}")
    win_ml = evaluate_window_ml(wins)
    print(f"[窗口级 ML · 4维产品接口] TPR={win_ml['tpr']} FPR={win_ml['fpr']} F1={win_ml['f1']}")

    result = {
        "dataset": "CIC-UNSW-NB15（UNSW-NB15 底层流量的 CICFlowMeter 重提取版）",
        "flows_total": int(len(y)),
        "label_distribution": dict(dist),
        "synthetic_time_axis": f"行序 × {SYNTHETIC_STEP_SEC}s（无时间戳，声明为合成）",
        "flow_level_ml": flow_ml,
        "rule_large_flow": large,
        "baseline": base_result,
        "window_level_ml": win_ml,
    }
    out = "data/eval_cicids/result_unsw_cic.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入: {out}")


if __name__ == "__main__":
    main()
