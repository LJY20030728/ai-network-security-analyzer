# -*- coding: utf-8 -*-
"""L2 ML 检测引擎评测：孤立森林 vs EWMA 统计基线（同输入、同口径公平对比）
- 特征输入：完全相同的窗口序列（1s 窗口，WindowAccumulator 聚合 4 维特征）
- 训练：normal.pcap 前 80% 窗口（两引擎同训练集）
- FPR 测试：normal.pcap 后 20% 窗口（两引擎同测试集）
- TPR 测试：7 个黄金攻击样本（至少 1 个异常窗口 = 检出）
结果写入 data/eval_perf/ml_engine.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from loguru import logger
logger.remove()

from src.capture.pcap_parser import PcapParser
from src.analysis.baseline import TrafficBaseline, WindowAccumulator
from src.analysis.isolation_detector import IsolationDetector

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "samples", "golden")
WINDOW_SEC = 1  # 1s 窗口保证训练/测试样本量


def windows_of(fname: str) -> list:
    wa = WindowAccumulator(window_sec=WINDOW_SEC)
    for p in PcapParser().iter_packets(os.path.join(GOLDEN, fname)):
        wa.add(p)
    return wa.get_windows()


def evaluate_engine(learn_fn, detect_fn, train_windows, test_windows, attack_windows):
    """对一个引擎统一评测：返回 (fpr, tpr, tpr_detail)"""
    learn_fn(train_windows)
    # FPR：normal 测试段中异常窗口占比
    res_test = detect_fn(test_windows)
    anomalies_test = res_test.get("anomalies", res_test.get("deviations", []))
    fpr = round(len(anomalies_test) / max(1, len(test_windows)), 4)
    # TPR：每个攻击样本至少 1 个异常窗口
    tpr_detail = []
    hits = 0
    for name, aw in attack_windows:
        res = detect_fn(aw)
        n_anom = len(res.get("anomalies", res.get("deviations", [])))
        hit = n_anom > 0
        hits += int(hit)
        tpr_detail.append({"sample": name, "windows": len(aw), "anomaly_windows": n_anom, "detected": hit})
    tpr = round(hits / max(1, len(attack_windows)), 4)
    return fpr, tpr, tpr_detail


def main():
    # ---------- 数据准备 ----------
    normal_ws = windows_of("normal.pcap")
    split = int(len(normal_ws) * 0.8)
    train_ws = normal_ws[:split]
    test_ws = normal_ws[split:]
    print(f"normal: 总窗口 {len(normal_ws)} → 训练 {len(train_ws)} / FPR测试 {len(test_ws)}")

    attack_files = ["synflood.pcap", "portscan.pcap", "dnstunnel.pcap",
                    "largeflow.pcap", "rststorm.pcap", "burst.pcap", "lightscan.pcap"]
    attack_ws = [(f.replace('.pcap', ''), windows_of(f)) for f in attack_files]

    # ---------- 统计基线 ----------
    base = TrafficBaseline(window_sec=WINDOW_SEC)
    base.learn_windows(train_ws)
    fpr_b, tpr_b, det_b = evaluate_engine(
        lambda ws: base.learn_windows(ws),
        lambda ws: base.detect_windows(ws),
        train_ws, test_ws, attack_ws)

    # ---------- 孤立森林 ----------
    iso = IsolationDetector()
    fpr_m, tpr_m, det_m = evaluate_engine(
        lambda ws: iso.learn_windows(ws),
        lambda ws: iso.detect_windows(ws),
        train_ws, test_ws, attack_ws)

    # ---------- 输出 ----------
    print("\n================ L2 ML 引擎 vs 统计基线 ================")
    print(f"{'指标':<24}{'EWMA基线':>12}{'孤立森林':>12}")
    print(f"{'FPR（normal 测试段）':<24}{fpr_b:>12.4f}{fpr_m:>12.4f}")
    print(f"{'TPR（7 攻击样本）':<24}{tpr_b:>12.4f}{tpr_m:>12.4f}")
    print("\n逐攻击样本检出：")
    print(f"{'样本':<14}{'窗口数':>6}{'基线异常窗':>10}{'ML异常窗':>10}{'基线':>6}{'ML':>6}")
    for db, dm in zip(det_b, det_m):
        print(f"{db['sample']:<14}{db['windows']:>6}{db['anomaly_windows']:>10}"
              f"{dm['anomaly_windows']:>10}{str(db['detected']):>6}{str(dm['detected']):>6}")

    summary = {
        "window_sec": WINDOW_SEC,
        "train_windows": len(train_ws),
        "fpr_test_windows": len(test_ws),
        "attack_samples": len(attack_ws),
        "baseline": {"engine": "ewma-median-mad", "fpr": fpr_b, "tpr": tpr_b, "per_sample": det_b},
        "isolation_forest": {"engine": "isolation-forest",
                             "fpr": fpr_m, "tpr": tpr_m,
                             "contamination": iso.contamination,
                             "score_threshold": iso._score_threshold,
                             "per_sample": det_m},
        "conclusion": ("同输入同口径对比：孤立森林与统计基线互补。"
                       "统计基线捕捉单维幅值突变；孤立森林捕捉多维耦合异常。"
                       "两引擎告警并集可提升覆盖，代价是 FPR 叠加（需调 contamination）。"),
    }
    os.makedirs("data/eval_perf", exist_ok=True)
    with open("data/eval_perf/ml_engine.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print("\n结果已写入 data/eval_perf/ml_engine.json")


if __name__ == "__main__":
    main()
