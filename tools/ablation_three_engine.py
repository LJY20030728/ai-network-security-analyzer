# -*- coding: utf-8 -*-
"""
三引擎消融实验（Ablation Study）
================================
对比四种检测策略在同一样本集上的性能：
  A. 规则引擎单独（rule_only）
  B. EWMA时序基线单独（baseline_only）
  C. 孤立森林单独（isolation_only）
  D. 三引擎Stacking融合（stacking）

实验设计（公平对比）：
  - 同输入：前缀累计窗口（与训练一致，模拟流式到达）
  - 同标签：样本级标签下推到窗口级（混合样本用精确窗口级标签）
  - 同口径：窗口级二分类（攻击/正常），计算F1/Precision/Recall
  - 留一法（LOO）：评估Stacking跨样本泛化能力

输出：
  data/eval_perf/ablation_three_engine.json
  控制台打印对比表

用法：python tools/ablation_three_engine.py
"""
import os
import sys
import json
import numpy as np
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
try:
    import joblib as _joblib
    _joblib.parallel_backend("threading", n_jobs=1).__enter__()
except Exception:
    pass

try:
    from src.utils.helpers import force_utf8_stdout
    force_utf8_stdout()
except Exception:
    pass

from loguru import logger
logger.remove()

from scapy.all import rdpcap
from src.capture.packet_parser import PacketParser
from src.analysis.baseline import TrafficBaseline, WindowAccumulator
from src.analysis.isolation_detector import IsolationDetector
from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.stacking_fusion import ThreeEngineStacking, get_three_engine_stacking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "data", "samples", "golden")
MIXED = os.path.join(ROOT, "data", "samples", "mixed")
OUT_JSON = os.path.join(ROOT, "data", "eval_perf", "ablation_three_engine.json")

SAMPLE_LABELS = {
    "normal": 0, "baseline_demo_normal": 0,
    "synflood": 1, "portscan": 1, "dnstunnel": 1, "largeflow": 1,
    "rststorm": 1, "lightscan": 1, "burst": 1, "baseline_demo_attack": 1,
    "dnsamp": 1, "quicflood": 1, "udpflood": 1,
}

MIXED_PLANS = {
    "mix_normal_synflood": ("baseline_demo_normal", 30),
    "mix_normal_portscan": ("baseline_demo_normal", 30),
    "mix_normal_dnstunnel": ("baseline_demo_normal", 30),
    "mix_normal_rststorm": ("baseline_demo_normal", 30),
    "mix_normal_burst": ("baseline_demo_normal", 30),
    "mix_short_normal_synflood": ("normal", 15),
    "mix_short_normal_portscan": ("normal", 15),
}


def _base_normal_last_ts(base_name):
    path = os.path.join(GOLDEN, f"{base_name}.pcap")
    if not os.path.exists(path):
        return None
    pkts = rdpcap(path)
    return float(pkts[-1].time) if pkts else None


def mixed_attack_start(sample_name):
    plan = MIXED_PLANS.get(sample_name)
    if not plan:
        return None
    base_name, offset = plan
    base_end = _base_normal_last_ts(base_name)
    return None if base_end is None else base_end + offset


def _window_ts_key(p, window_sec):
    from datetime import datetime
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(datetime.strptime(p.timestamp, fmt).timestamp() // window_sec)
        except Exception:
            continue
    return 0


def window_packet_slices(packets, window_sec, with_keys=False):
    if not packets:
        return []
    from itertools import groupby
    out = []
    for key, grp in groupby(sorted(packets, key=lambda p: _window_ts_key(p, window_sec)),
                            key=lambda p: _window_ts_key(p, window_sec)):
        out.append((key, list(grp)) if with_keys else list(grp))
    return out


def label_frames(sample_name, frame_keys):
    """为混合样本的每个时间窗打标（与train_stacking.py一致）
    :param frame_keys: 窗口起始时间戳列表（秒）
    """
    attack_start = mixed_attack_start(sample_name)
    if attack_start is None:
        return [None] * len(frame_keys)
    out = []
    for key in frame_keys:
        if key is None:
            out.append(None)
        elif key + 10 <= attack_start:
            out.append(0)
        elif key >= attack_start:
            out.append(1)
        else:
            out.append(None)
    return out


def compute_metrics(y_true, y_pred):
    y_true, y_pred = np.array(y_true), np.array(y_pred)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    acc = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "accuracy": round(acc, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "total": len(y_true)}


def extract_per_window(analyzer, baseline, iso, packets, labels, window_sec):
    """逐窗口提取三引擎特征和各引擎独立预测（前缀累计，模拟流式）"""
    rows, out_labels = [], []
    slices = window_packet_slices(packets, window_sec, with_keys=True)
    if not slices:
        return rows, out_labels

    keys = [k for k, _ in slices]
    if isinstance(labels, (list, tuple)):
        per_window = labels
    else:
        per_window = [labels] * len(slices)

    prefix = []
    fusion = get_three_engine_stacking()  # 加载已训练的元学习器

    for i, (key, chunk) in enumerate(slices):
        prefix.extend(chunk)
        this_label = per_window[i] if i < len(per_window) else None
        if this_label is None:
            continue
        try:
            flows = analyzer.flow_extractor.extract_flows(prefix)
            anomalies = analyzer._detect_anomalies(prefix, flows)
            win_acc = WindowAccumulator(window_sec=window_sec)
            for p in prefix:
                win_acc.add(p)
            windows = win_acc.get_windows()
            if not windows:
                continue

            # 基线
            bres = baseline.detect_windows(windows) if baseline._learned else {}
            anomalies = analyzer._merge_baseline_deviations(anomalies, bres)

            # 孤立森林
            ml_profile = None
            if iso is not None and iso._learned:
                mlres = iso.detect_windows(windows)
                anoms = mlres.get("anomalies", [])
                if anoms:
                    scores = [a.get("anomaly_score", 0.0) for a in anoms]
                    mean_score = sum(scores) / len(scores)
                    max_score = min(scores)
                    dims = [a.get("dimension", "") for a in anoms if a.get("dimension")]
                    top_dim = Counter(dims).most_common(1)[0][0] if dims else ""
                else:
                    mean_score = max_score = 0.0
                    top_dim = ""
                ml_profile = {
                    "name": "isolation-forest-unsupervised", "learned": True,
                    "anomaly_windows": len(anoms), "total_windows": len(windows),
                    "mean_anomaly_score": round(mean_score, 4),
                    "max_anomaly_score": round(max_score, 4),
                    "top_dimension": top_dim,
                    "score_threshold": float(iso._score_threshold),
                }

            # 13维Stacking特征
            feats = fusion.extract_features(
                anomalies,
                {"drift": bres.get("drift"), "multi_dim_alerts": bres.get("multi_dim_alerts")},
                ml_profile,
            )

            # 各引擎独立预测
            rule_pred = 1 if anomalies.get("alerts") else 0
            baseline_pred = 1 if bres.get("deviations") or bres.get("multi_dim_alerts") else 0
            iso_pred = 1 if (ml_profile and ml_profile.get("anomaly_windows", 0) > 0) else 0

            rows.append({
                "features": feats, "rule_pred": rule_pred,
                "baseline_pred": baseline_pred, "isolation_pred": iso_pred,
            })
            out_labels.append(this_label)
        except Exception as e:
            logger.debug(f"窗口 {i} 特征提取失败，跳过: {e}")
            continue
    return rows, out_labels


def main():
    print("=" * 70)
    print("三引擎消融实验（Ablation Study）")
    print("=" * 70)

    parser = PacketParser()
    print("\n[1] 学习正常流量基线（normal.pcap）...")
    normal_raw = rdpcap(os.path.join(GOLDEN, "normal.pcap"))
    normal_pkts = parser.parse_list(normal_raw)
    baseline = TrafficBaseline()
    baseline.learn(normal_pkts)
    win_sec = getattr(baseline, "window_sec", 10)
    print(f"    基线已学习 | 窗口 {win_sec}s")

    iso = IsolationDetector()
    n_acc = WindowAccumulator(window_sec=win_sec)
    for p in normal_pkts:
        n_acc.add(p)
    n_windows = n_acc.get_windows()
    if len(n_windows) >= 10:
        iso.learn_windows(n_windows)
        print(f"    孤立森林已训练 | 正常窗口 {len(n_windows)}")

    analyzer = TrafficAnalyzer()
    stacking = get_three_engine_stacking()

    # 收集样本
    all_samples = {}
    for name, label in SAMPLE_LABELS.items():
        path = os.path.join(GOLDEN, f"{name}.pcap")
        if os.path.exists(path):
            all_samples[name] = (path, label, "golden")
    for name in MIXED_PLANS.keys():
        path = os.path.join(MIXED, f"{name}.pcap")
        if os.path.exists(path):
            all_samples[name] = (path, 1, "mixed")

    print(f"\n[2] 提取窗口特征（{len(all_samples)} 个样本）...")
    all_rows = []
    per_sample = {}
    for name, (path, label, src) in sorted(all_samples.items()):
        raw = rdpcap(path)
        packets = parser.parse_list(raw)
        slices = window_packet_slices(packets, win_sec, with_keys=True)
        keys = [k * win_sec for k, _ in slices]  # 窗口起始时间戳（秒）
        if name in MIXED_PLANS:
            win_labels = label_frames(name, keys)
        else:
            win_labels = label
        rows, labs = extract_per_window(analyzer, baseline, iso, packets, win_labels, win_sec)
        n_atk = sum(1 for l in labs if l == 1)
        n_norm = sum(1 for l in labs if l == 0)
        print(f"    {name:<35} {src:7} 窗口={len(rows):>4} 攻击={n_atk:>4} 正常={n_norm:>4}")
        for r, l in zip(rows, labs):
            r["label"] = l
        all_rows.extend(rows)
        per_sample[name] = rows

    if not all_rows:
        print("\n[错误] 无可用窗口数据")
        return 1

    print(f"\n[3] Stacking融合预测（{len(all_rows)} 窗口）...")
    X = np.array([r["features"] for r in all_rows])
    if stacking.meta_learner is not None and hasattr(stacking.meta_learner, "predict_proba"):
        probs = stacking.meta_learner.predict_proba(X)[:, 1]
        stacking_preds = (probs >= 0.5).astype(int)
    else:
        stacking_preds = np.zeros(len(all_rows), dtype=int)
    for i, r in enumerate(all_rows):
        r["stacking_pred"] = int(stacking_preds[i])

    print("\n[4] 计算全局指标...")
    y_true = [r["label"] for r in all_rows]
    methods = {
        "rule_only": [r["rule_pred"] for r in all_rows],
        "baseline_only": [r["baseline_pred"] for r in all_rows],
        "isolation_only": [r["isolation_pred"] for r in all_rows],
        "stacking": [r["stacking_pred"] for r in all_rows],
    }
    global_metrics = {m: compute_metrics(y_true, p) for m, p in methods.items()}

    print("\n[5] 留一法（LOO）评估Stacking泛化...")
    from sklearn.linear_model import LogisticRegression
    loo_results = []
    for test_name in per_sample.keys():
        train_rows, test_rows = [], []
        for name, rows in per_sample.items():
            (test_rows if name == test_name else train_rows).extend(rows)
        if not train_rows or not test_rows:
            continue
        Xtr = np.array([r["features"] for r in train_rows])
        ytr = np.array([r["label"] for r in train_rows])
        Xte = np.array([r["features"] for r in test_rows])
        yte = [r["label"] for r in test_rows]
        if len(set(ytr)) < 2:
            continue
        clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf.fit(Xtr, ytr)
        loo_results.append((test_name, compute_metrics(yte, clf.predict(Xte))))

    loo_avg = {}
    if loo_results:
        for k in ["precision", "recall", "f1", "accuracy"]:
            loo_avg[k] = round(np.mean([r[1][k] for r in loo_results]), 4)

    # 输出
    print("\n" + "=" * 70)
    print("消融实验结果（全局，窗口级）")
    print("=" * 70)
    print(f"{'方法':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Accuracy':>10}")
    print("-" * 70)
    for m in ["rule_only", "baseline_only", "isolation_only", "stacking"]:
        d = global_metrics[m]
        print(f"{m:<20} {d['precision']:>10.4f} {d['recall']:>10.4f} {d['f1']:>10.4f} {d['accuracy']:>10.4f}")
    if loo_avg:
        print("-" * 70)
        print(f"{'stacking_LOO':<20} {loo_avg['precision']:>10.4f} {loo_avg['recall']:>10.4f} "
              f"{loo_avg['f1']:>10.4f} {loo_avg['accuracy']:>10.4f}")
        print("  (LOO = 留一法跨样本泛化，更能反映真实泛化能力)")

    f1s = [global_metrics[m]["f1"] for m in ["rule_only", "baseline_only", "isolation_only"]]
    best_single = max(f1s)
    best_name = ["rule_only", "baseline_only", "isolation_only"][f1s.index(best_single)]
    f1_stack = global_metrics["stacking"]["f1"]
    print("\n" + "=" * 70)
    print("关键发现")
    print("=" * 70)
    print(f"  最优单引擎: {best_name} (F1={best_single:.4f})")
    print(f"  Stacking融合: F1={f1_stack:.4f}")
    if f1_stack > best_single:
        print(f"  融合增益: +{f1_stack - best_single:.4f} ({(f1_stack/best_single - 1)*100:.1f}%)")
    else:
        print(f"  融合未优于最优单引擎 (差 {best_single - f1_stack:.4f})")
    if loo_avg:
        print(f"  LOO泛化F1: {loo_avg['f1']:.4f} (vs 训练内 {f1_stack:.4f})")

    result = {
        "experiment": "three_engine_ablation", "window_sec": win_sec,
        "n_samples": len(all_samples), "n_windows": len(all_rows),
        "n_attack_windows": sum(1 for r in all_rows if r["label"] == 1),
        "n_normal_windows": sum(1 for r in all_rows if r["label"] == 0),
        "global_metrics": global_metrics, "loo_average": loo_avg,
        "loo_per_sample": {n: m for n, m in loo_results},
        "best_single_engine": best_name, "best_single_f1": best_single,
        "stacking_f1": f1_stack, "fusion_gain": round(f1_stack - best_single, 4),
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
