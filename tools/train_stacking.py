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

import numpy as np

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
# v3.4.0 新增：时间混合样本（正常流量+攻击流量拼接）
#
# 【重要修复】此前这些样本**整文件**被标为攻击（value=1），但其正常前缀与
# SAMPLE_LABELS 里的 normal / baseline_demo_normal 是同一批包（逐位相同），
# 于是同一特征向量同时被标为 0 和 1 —— 264 行矛盾标签，训练集仅 50.7% 唯一。
#
# 现改为按窗口打标：窗口内包**全部早于**攻击起点 → 0；**含任一攻击包** → 1；
# 跨界窗（正常包与攻击包并存）**丢弃**（宁缺毋滥，避免弱标注噪声）。
#
# 攻击起点不需要新增 manifest：generate_mixed_samples.py 用
#   attack_start = (基底正常样本最后一包时间) + offset
# 生成样本，该式可确定性重建（实测两个样本误差 < 1s）。
MIXED_PLANS = {
    # 样本名: (基底正常样本, 攻击段起始偏移秒)
    "mix_normal_synflood": ("baseline_demo_normal", 30),
    "mix_normal_portscan": ("baseline_demo_normal", 30),
    "mix_normal_dnstunnel": ("baseline_demo_normal", 30),
    "mix_normal_rststorm": ("baseline_demo_normal", 30),
    "mix_normal_burst": ("baseline_demo_normal", 30),
    "mix_short_normal_synflood": ("normal", 15),
    "mix_short_normal_portscan": ("normal", 15),
}

# 兼容旧引用：这些样本仍需被遍历（标签在窗口级决定）
MIXED_LABELS = {name: 1 for name in MIXED_PLANS}


def _base_normal_last_ts(base_name):
    """基底正常样本最后一包的时间戳（float 秒）"""
    path = os.path.join(GOLDEN, f"{base_name}.pcap")
    if not os.path.exists(path):
        return None
    pkts = rdpcap(path)
    return float(pkts[-1].time) if pkts else None


def mixed_attack_start(sample_name):
    """重建混合样本的攻击段起始时间戳；无法重建时返回 None"""
    plan = MIXED_PLANS.get(sample_name)
    if not plan:
        return None
    base_name, offset = plan
    base_end = _base_normal_last_ts(base_name)
    return None if base_end is None else base_end + offset


def label_frames(sample_name, frame_keys):
    """为混合样本的每个时间窗打标。

    :param frame_keys: 与 `window_packet_slices` 输出顺序一致的窗口起始时间戳列表
    :return: 与 frame_keys 等长的标签列表，跨界窗为 None（调用方丢弃）
    """
    attack_start = mixed_attack_start(sample_name)
    if attack_start is None:
        return [None] * len(frame_keys)
    out = []
    for key in frame_keys:
        if key is None:
            out.append(None)
        elif key + 1 <= attack_start:      # 窗口整段早于攻击起点
            out.append(0)
        elif key >= attack_start:          # 窗口起点已在攻击段内
            out.append(1)
        else:                              # 跨界窗 → 丢弃
            out.append(None)
    return out



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


def _window_ts_key(p, window_sec):
    """包时间戳 → 所属时间窗的整数键（秒 // window_sec）"""
    from datetime import datetime

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(datetime.strptime(p.timestamp, fmt).timestamp() // window_sec)
        except Exception:
            continue
    return 0


def window_packet_slices(packets, window_sec, with_keys=False):
    """把包列表按 window_sec 时间窗切片。

    :param with_keys: 为 True 时返回 [(窗口键, 包列表), ...]，窗口键可用于打标
                      （混合样本需要判断窗口相对攻击起点的位置）。
    """
    if not packets:
        return []
    from itertools import groupby

    out = []
    for key, grp in groupby(sorted(packets, key=lambda p: _window_ts_key(p, window_sec)),
                            key=lambda p: _window_ts_key(p, window_sec)):
        out.append((key, list(grp)) if with_keys else list(grp))
    return out


def collect_features(analyzer, baseline, iso, packets, labels, window_sec):
    """逐窗口提取三引擎特征（前缀累计，模拟流式到达）

    :param labels: 单个标签（样本级，整样本同标）或等长标签列表（窗口级，
                   混合样本用；None 表示该窗丢弃，如跨界窗）
    """
    rows, out_labels = [], []
    slices = window_packet_slices(packets, window_sec)
    if not slices:
        return rows, out_labels

    per_window = labels if isinstance(labels, (list, tuple)) else [labels] * len(slices)

    prefix = []
    fusion = ThreeEngineStacking(model_path=None)  # 仅用其特征提取，不预测

    for i, chunk in enumerate(slices):
        prefix.extend(chunk)
        # 窗口级标签：None 表示丢弃（跨界窗），仍推进 prefix 以保持因果一致性
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
            out_labels.append(this_label)
        except Exception as e:
            logger.debug(f"窗口 {i} 特征提取失败，跳过: {e}")
            continue
    return rows, out_labels


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
    print("\n[2] 逐窗口提取三引擎特征（golden + 混合样本，混合样本按窗口打标）")
    X_rows, y_rows, groups, per_sample = [], [], [], {}
    analyzer = TrafficAnalyzer(use_baseline=True)
    analyzer.baseline = baseline
    analyzer.isolation_detector = iso

    # 合并所有样本标签（混合样本的标签在窗口级决定，这里的值仅作占位）
    all_labels = dict(SAMPLE_LABELS)
    all_labels.update(MIXED_LABELS)
    # 混合样本目录
    sample_dirs = {name: GOLDEN for name in SAMPLE_LABELS}
    sample_dirs.update({name: MIXED for name in MIXED_LABELS})

    for name, sample_label in sorted(all_labels.items()):
        path = os.path.join(sample_dirs[name], f"{name}.pcap")
        if not os.path.exists(path):
            print(f"    [跳过] {name} 不存在")
            continue
        raw = rdpcap(path)
        packets = parser.parse_list(raw)

        if name in MIXED_PLANS:
            # 窗口级打标：正常前缀=0、攻击段=1、跨界窗丢弃
            slices = window_packet_slices(packets, win_sec, with_keys=True)
            win_labels = label_frames(name, [k * win_sec for k, _ in slices])
            dropped = sum(1 for lab in win_labels if lab is None)
            rows, labs = collect_features(analyzer, baseline, iso, packets, win_labels, win_sec)
            n_norm = sum(1 for lab in labs if lab == 0)
            n_atk = sum(1 for lab in labs if lab == 1)
            print(f"    {name:<30} 窗口级标签 正常={n_norm:>4} 攻击={n_atk:>4} "
                  f"丢弃跨界={dropped:>3} | 包 {len(packets):>6}")
            per_sample[name] = {"labels": "per_window", "normal_windows": n_norm,
                                "attack_windows": n_atk, "dropped_boundary": dropped,
                                "windows": len(rows), "packets": len(packets),
                                "attack_start": mixed_attack_start(name)}
        else:
            rows, labs = collect_features(analyzer, baseline, iso, packets,
                                          sample_label, win_sec)
            print(f"    {name:<30} 标签={sample_label} | 包 {len(packets):>6} | 窗口特征 {len(rows):>4}")
            per_sample[name] = {"label": sample_label, "windows": len(rows),
                                "packets": len(packets)}

        if rows:
            X_rows.extend(rows)
            y_rows.extend(labs)
            groups.extend([name] * len(rows))

    if len(X_rows) < 10:
        print(f"\n可用训练样本仅 {len(X_rows)} 条，不足以训练元学习器，已中止")
        return 1

    X = np.vstack(X_rows)
    y = np.array(y_rows, dtype=int)
    groups = np.array(groups)
    n_total = len(y)

    # 去重：逐位相同的特征向量只保留一条（同组同标签才可安全合并）
    seen, keep = {}, []
    for i in range(n_total):
        key = (groups[i], int(y[i]), X[i].tobytes())
        if key in seen:
            continue
        seen[key] = i
        keep.append(i)
    n_dup = n_total - len(keep)
    X, y, groups = X[keep], y[keep], groups[keep]

    print(f"\n    训练矩阵: {X.shape} | 攻击窗口 {int(y.sum())} / 正常窗口 {int((y == 0).sum())}")
    print(f"    去重: 原始 {n_total} 行 → 唯一 {len(y)} 行（移除 {n_dup} 行重复）")
    print(f"    样本组数（GroupKFold 分组数）: {len(set(groups))}")

    # 3) 训练（按源 PCAP 分组交叉验证，避免同一样本窗口跨折导致泄漏）
    print("\n[3] 训练 LogisticRegression 元学习器（GroupKFold，按源 PCAP 分组）")
    fusion = ThreeEngineStacking(model_path=None)

    # 训练数据指纹（必须在 train_meta_learner 之前设置：该函数内部会写盘）
    import hashlib as _hashlib
    from datetime import datetime as _dt

    def _git_sha():
        try:
            import subprocess
            return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                  cwd=ROOT, capture_output=True, text=True,
                                  timeout=10).stdout.strip() or "unknown"
        except Exception:
            return "unknown"

    provenance = {
        "dataset_rows": int(len(y)),
        "dataset_distinct_rows": int(len(y)),
        "dataset_raw_rows": int(n_total),
        "n_features": int(X.shape[1]),
        "n_attack": int(y.sum()),
        "n_normal": int(len(y) - int(y.sum())),
        "n_groups": int(len(set(groups))),
        "groups": sorted(set(groups.tolist())),
        "dataset_hash": _hashlib.sha256(
            np.ascontiguousarray(X, dtype=np.float64).tobytes()
            + np.ascontiguousarray(y, dtype=np.int64).tobytes()
        ).hexdigest()[:16],
        "window_sec": win_sec,
        "labeling": "per_window(混合样本正常前缀=0/攻击段=1/跨界窗丢弃)",
        "trained_at": _dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "git_sha": _git_sha(),
    }
    fusion.set_provenance(provenance)
    print(f"    数据指纹: {provenance['dataset_hash']} | 唯一行 {provenance['dataset_rows']}"
          f"/原始 {provenance['dataset_raw_rows']} | 组 {provenance['n_groups']}")

    result = fusion.train_meta_learner(X, y, model_path=DEFAULT_MODEL_PATH, groups=groups)
    print(f"    分组 CV F1: {result['cv_f1_mean']} ± {result['cv_f1_std']}"
          f"（{result['cv_splits']} 折，按样本分组）")
    if result.get("cv_f1_ungrouped_mean") is not None:
        print(f"    对照·普通分层 CV F1: {result['cv_f1_ungrouped_mean']} ± "
              f"{result['cv_f1_ungrouped_std']}（同折数，存在样本内泄漏，偏高）")
    print("    学到的特征权重（前 5）:")
    for k, v in sorted(result["feature_importance"].items(), key=lambda x: -abs(x[1]))[:5]:
        print(f"      {k:<32} {v:+.4f}")

    # 4) 落盘
    payload = {
        "architecture": "three_engine_stacking",
        "engine_order": ["rule_based", "baseline", "isolation_forest"],
        "window_sec": win_sec,
        "training_samples": int(len(y)),
        "training_samples_raw": int(n_total),
        "training_samples_removed_as_duplicate": int(n_dup),
        "n_attack_windows": int(y.sum()),
        "n_normal_windows": int(len(y) - y.sum()),
        "n_groups": int(len(set(groups))),
        # 主口径：按源 PCAP 分组的 CV（无样本内泄漏）
        "cv_scheme": result.get("cv_scheme", "stratified"),
        "cv_f1_mean": result["cv_f1_mean"],
        "cv_f1_std": result["cv_f1_std"],
        # 对照口径：普通分层 CV（存在样本内泄漏，系统性偏高）——保留以便对比
        "cv_f1_ungrouped_mean": result.get("cv_f1_ungrouped_mean"),
        "cv_f1_ungrouped_std": result.get("cv_f1_ungrouped_std"),
        "feature_importance": result["feature_importance"],
        "per_sample": per_sample,
        "provenance": provenance,
        "limitations": [
            "训练数据来自合成 golden 样本 + 时间混合样本，非真实生产流量",
            "混合样本按窗口打标：正常前缀=0、攻击段=1、跨界窗丢弃（此前整文件标 1，"
            "导致同一正常窗口同时被标为 0 和 1，264 行矛盾标签）",
            "仍属弱标注：窗口级真值由攻击段起止时间推导，非逐流人工标注",
            "13 维特征（v3.4.0 起，新增孤立森林异常分统计 + top 维度风险）",
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
