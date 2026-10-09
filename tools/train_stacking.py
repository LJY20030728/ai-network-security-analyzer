# -*- coding: utf-8 -*-
"""
训练三引擎 Stacking 元学习器（3.3.0）

三个引擎：规则（阈值）/ 时序基线（EWMA）/ 孤立森林（无监督）

训练数据构造（完全自给自足、可复现，不依赖任何外部数据集）：
  1. 用 normal.pcap 学习正常流量基线画像（并同步训练孤立森林）
  2. 对每个 golden 样本，按窗口增量聚合，逐窗口提取三引擎特征：
       · 规则：该窗口内累计触发的规则告警
       · 基线：该窗口的偏差情况
       · 孤立森林：该窗口的异常判定
  3. 窗口标签取自样本级真值（见 SAMPLE_LABELS）
  4. LogisticRegression（class_weight=balanced）+ 分层交叉验证

【诚实声明 —— 样本量与口径局限】
  · 训练数据来自 10 个**合成** golden 样本，非真实生产流量
  · 样本级标签下推到窗口级，属于弱标注，存在标签噪声
  · 因此产出的元学习器只用于验证融合链路可跑通，
    其权重不应被解读为"生产环境最优融合策略"
  · 真实部署前请用自有标注流量重新运行本脚本

产物：models/stacking_meta_learner.joblib
      data/eval_perf/stacking_training.json

用法：python tools/train_stacking.py
"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger

try:
    from src.utils.helpers import force_utf8_stdout, resolve_n_jobs
    force_utf8_stdout()
except Exception:
    pass

# 受限环境下强制 joblib 单线程（保证可复现）
os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
try:
    import joblib as _joblib
    _joblib.parallel_backend("threading", n_jobs=1).__enter__()
except Exception:
    pass

import numpy as np

from scapy.all import rdpcap
from src.analysis.baseline import TrafficBaseline, WindowAccumulator
from src.analysis.isolation_detector import IsolationDetector
from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.stacking_fusion import ThreeEngineStacking, DEFAULT_MODEL_PATH
from src.capture.packet_parser import PacketParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "data", "samples", "golden")
MIXED = os.path.join(ROOT, "data", "samples", "mixed")
OUT_JSON = os.path.join(ROOT, "data", "eval_perf", "stacking_training.json")

# 窗口标签：样本级真值下推到窗口级（弱标注，见 docstring）
SAMPLE_LABELS = {
    "normal": 0,
    "baseline_demo_normal": 0,
    "synflood": 1,
    "portscan": 1,
    "dnstunnel": 1,
    "largeflow": 1,
    "rststorm": 1,
    "lightscan": 1,
    "burst": 1,
    "baseline_demo_attack": 1,
}
# v3.4.0 新增：时间混合样本（正常流量+攻击流量拼接，整体标签为攻击）
MIXED_LABELS = {
    "mix_normal_synflood": 1,
    "mix_normal_portscan": 1,
    "mix_normal_dnstunnel": 1,
    "mix_normal_rststorm": 1,
    "mix_short_normal_synflood": 1,
    "mix_short_normal_portscan": 1,
    "mix_normal_burst": 1,
}


def build_windows(packets, window_sec=10):
    """按窗口聚合包，返回 (窗口列表, 每窗口的包切片)"""
    acc = WindowAccumulator(window_sec=window_sec)
    slices = {}
    for p in packets:
        acc.add(p)
        slices.setdefault(len(acc.get_windows()), []).append(p)
    # 重新按窗口序号收集包（累加器内部按时间戳分桶，这里用索引近似）
    windows = acc.get_windows()
    return windows, slices


def window_packet_slices(packets, window_sec):
    """把包列表按 window_sec 时间窗切片，返回 [(窗口索引, 包列表), ...]"""
    if not packets:
        return []
    from itertools import groupby

    def ts_key(p):
        try:
            from datetime import datetime
            return int(datetime.strptime(p.timestamp, "%Y-%m-%d %H:%M:%S.%f").timestamp() // window_sec)
        except Exception:
            try:
                from datetime import datetime
                return int(datetime.strptime(p.timestamp, "%Y-%m-%d %H:%M:%S").timestamp() // window_sec)
            except Exception:
                return 0

    out = []
    for _, grp in groupby(sorted(packets, key=ts_key), key=ts_key):
        out.append(list(grp))
    return out


def collect_features(analyzer, baseline, iso, packets, label, window_sec):
    """逐窗口提取三引擎特征（前缀累计，模拟流式到达）"""
    rows, labels = [], []
    slices = window_packet_slices(packets, window_sec)
    if not slices:
        return rows, labels

    prefix = []
    fusion = ThreeEngineStacking(model_path=None)  # 仅用其特征提取，不预测

    for i, chunk in enumerate(slices):
        prefix.extend(chunk)
        try:
            flows = analyzer.flow_extractor.extract_flows(prefix)
            anomalies = analyzer._detect_anomalies(prefix, flows)
            win_acc = WindowAccumulator(window_sec=window_sec)
            for p in prefix:
                win_acc.add(p)
            windows = win_acc.get_windows()
            if not windows:
                continue
            bres = baseline.detect_windows(windows) if baseline.learned else {}
            anomalies = analyzer._merge_baseline_deviations(anomalies, bres)
            ml_profile = None
            if iso is not None and iso.learned:
                mlres = iso.detect_windows(windows)
                # 修复：构建包含实际检测结果的 ml_profile（to_dict 只含元信息）
                anoms = mlres.get("anomalies", [])
                if anoms:
                    scores = [a.get("anomaly_score", 0.0) for a in anoms]
                    mean_score = sum(scores) / len(scores)
                    max_score = min(scores)
                    from collections import Counter
                    dims = [a.get("dimension", "") for a in anoms if a.get("dimension")]
                    top_dim = Counter(dims).most_common(1)[0][0] if dims else ""
                else:
                    mean_score = max_score = 0.0
                    top_dim = ""
                ml_profile = {
                    "name": "isolation-forest-unsupervised",
                    "learned": True,
                    "anomaly_windows": len(anoms),
                    "total_windows": len(windows),
                    "mean_anomaly_score": round(mean_score, 4),
                    "max_anomaly_score": round(max_score, 4),
                    "top_dimension": top_dim,
                    "score_threshold": float(iso._score_threshold),
                }
            feats = fusion.extract_features(
                anomalies,
                {"drift": bres.get("drift"), "multi_dim_alerts": bres.get("multi_dim_alerts")},
                ml_profile,
            )
            rows.append(feats)
            labels.append(label)
        except Exception as e:
            logger.debug(f"窗口 {i} 特征提取失败，跳过: {e}")
            continue
    return rows, labels


def main():
    parser = PacketParser()
    normal_path = os.path.join(GOLDEN, "normal.pcap")
    if not os.path.exists(normal_path):
        print("缺少 normal.pcap，无法学习基线")
        return 1

    print("=" * 76)
    print("训练三引擎 Stacking 元学习器（v3.4.0，13维特征）")
    print("=" * 76)

    # 1) 用正常流量学习基线 + 孤立森林
    print("\n[1] 学习正常流量基线画像（normal.pcap）")
    normal_raw = rdpcap(normal_path)
    normal_pkts = parser.parse_list(normal_raw)
    baseline = TrafficBaseline()
    baseline.learn(normal_pkts)
    win_sec = getattr(baseline, "window_sec", 10)
    print(f"    基线已学习 | 窗口 {win_sec}s | 中位数包数="
          f"{baseline.profile['window_packets']['median']}")

    iso = IsolationDetector()
    n_acc = WindowAccumulator(window_sec=win_sec)
    for p in normal_pkts:
        n_acc.add(p)
    n_windows = n_acc.get_windows()
    if len(n_windows) >= 10:
        iso.learn_windows(n_windows)
        print(f"    孤立森林已训练 | 正常窗口 {len(n_windows)}")
    else:
        print(f"    ⚠ 正常窗口不足（{len(n_windows)}），孤立森林不参与训练")
        iso = None

    # 2) 逐样本、逐窗口提取特征（golden + 混合样本）
    print("\n[2] 逐窗口提取三引擎特征（golden + 混合样本）")
    X_rows, y_rows, per_sample = [], [], {}
    analyzer = TrafficAnalyzer(use_baseline=True)
    analyzer.baseline = baseline
    analyzer.isolation_detector = iso

    # 合并所有样本标签
    all_labels = dict(SAMPLE_LABELS)
    all_labels.update(MIXED_LABELS)
    # 混合样本目录
    sample_dirs = {name: GOLDEN for name in SAMPLE_LABELS}
    sample_dirs.update({name: MIXED for name in MIXED_LABELS})

    for name, label in sorted(all_labels.items()):
        path = os.path.join(sample_dirs[name], f"{name}.pcap")
        if not os.path.exists(path):
            print(f"    [跳过] {name} 不存在")
            continue
        raw = rdpcap(path)
        packets = parser.parse_list(raw)
        rows, labs = collect_features(analyzer, baseline, iso, packets, label, win_sec)
        if rows:
            X_rows.extend(rows)
            y_rows.extend(labs)
        per_sample[name] = {"label": label, "windows": len(rows), "packets": len(packets)}
        print(f"    {name:<32} 标签={label} | 包 {len(packets):>6} | 窗口特征 {len(rows):>4}")

    if len(X_rows) < 10:
        print(f"\n可用训练样本仅 {len(X_rows)} 条，不足以训练元学习器，已中止")
        return 1

    X = np.vstack(X_rows)
    y = np.array(y_rows, dtype=int)
    print(f"\n    训练矩阵: {X.shape} | 攻击窗口 {int(y.sum())} / 正常窗口 {int((y == 0).sum())}")

    # 3) 训练
    print("\n[3] 训练 LogisticRegression 元学习器")
    fusion = ThreeEngineStacking(model_path=None)
    result = fusion.train_meta_learner(X, y, model_path=DEFAULT_MODEL_PATH)
    print(f"    CV F1: {result['cv_f1_mean']} ± {result['cv_f1_std']}（{result['cv_splits']} 折）")
    print("    学到的特征权重（前 5）:")
    for k, v in sorted(result["feature_importance"].items(), key=lambda x: -abs(x[1]))[:5]:
        print(f"      {k:<32} {v:+.4f}")

    # 4) 落盘
    payload = {
        "architecture": "three_engine_stacking",
        "engine_order": ["rule_based", "baseline", "isolation_forest"],
        "window_sec": win_sec,
        "training_samples": int(len(y)),
        "n_attack_windows": int(y.sum()),
        "n_normal_windows": int(len(y) - y.sum()),
        "cv_f1_mean": result["cv_f1_mean"],
        "cv_f1_std": result["cv_f1_std"],
        "feature_importance": result["feature_importance"],
        "per_sample": per_sample,
        "limitations": [
            "训练数据来自 10 个合成 golden 样本 + 7 个时间混合样本，非真实生产流量",
            "样本级标签下推到窗口级属于弱标注，存在标签噪声",
            "v3.4.0 起特征维度从10扩展到13（新增孤立森林异常分统计+top维度风险）",
            "元学习器权重不应被解读为生产环境最优融合策略",
            "真实部署前请用自有标注流量重新运行本脚本",
        ],
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n已保存模型: {DEFAULT_MODEL_PATH}")
    print(f"已保存训练报告: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
