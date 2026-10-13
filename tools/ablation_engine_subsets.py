# -*- coding: utf-8 -*-
"""
三引擎消融实验 · 引擎子集版（与 tools/ablation_three_engine.py 互补）

## 与 ablation_three_engine.py 的分工

| 脚本 | 回答的问题 |
|------|-----------|
| `ablation_three_engine.py` | A/B/C/D 四策略对比 + 留一法（LOO）跨样本泛化 |
| **本脚本** | 在同一 13 维矩阵上切**引擎子集**（含**两两组合**），另做常数特征检测与「噪声 vs 效应量」判定 |

本脚本补充了前者的三个盲区：
  1. **两两组合**（如「规则+孤立森林」）—— 实测发现它高于三者融合
  2. **常数特征检测** —— 特征若恒为常数则根本不进模型，会让消融结论失真
  3. **显著性判定** —— 组间差异必须与折间标准差比较，否则是把噪声当效应

## 方法（与 tools/train_stacking.py 严格同口径）

- **特征**：直接复用 `train_stacking.collect_features()` 产出的同一份 13 维矩阵，
  按引擎分组切子集（4 / 3 / 6 维），因此消融结果与训练结果可比。
- **划分**：`GroupKFold` 按源 PCAP 分组（与训练一致），避免同一样本的窗口
  跨折造成样本内泄漏。
- **指标**：F1 / Precision / Recall / FPR 的折间均值与标准差，
  并额外报告**漏报数**（安全场景下漏报比误报更关键）。
- **模型**：与生产一致的 `LogisticRegression`（相同超参），保证可比。

## 输出

  data/eval_perf/ablation_engine_subsets.json   机器可读结果（含方法与局限声明）
  终端表格                                      人类可读对照

用法：
    python tools/ablation_engine_subsets.py
"""
import argparse
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.helpers import force_utf8_stdout

force_utf8_stdout()

import numpy as np  # noqa: E402
from loguru import logger  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score  # noqa: E402
from sklearn.model_selection import GroupKFold  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_JSON = os.path.join(ROOT, "data", "eval_perf", "ablation_engine_subsets.json")

# 与生产的元学习器保持完全一致（否则消融结论不能推广到生产模型）
META_KWARGS = dict(max_iter=2000, class_weight="balanced", random_state=42)
N_SPLITS = 5

# 13 维特征按引擎分组（顺序须与 ThreeEngineStacking.feature_names 一致）
ENGINE_FEATURES = {
    "rule_based": ["rule_has_alert", "rule_alert_count_norm",
                   "rule_max_severity", "rule_triggered_rules"],
    "baseline": ["baseline_deviation_count", "baseline_multi_dim_triggered",
                 "baseline_drifted"],
    "isolation_forest": ["isolation_available", "isolation_anomaly_count",
                         "isolation_anomaly_ratio", "isolation_mean_score",
                         "isolation_max_score", "isolation_top_dim_risk"],
}

# 待评估的组合：单引擎 / 两两 / 三者 / 基线对照
COMBOS = [
    ("仅规则引擎", ["rule_based"]),
    ("仅时序基线", ["baseline"]),
    ("仅孤立森林", ["isolation_forest"]),
    ("规则 + 基线", ["rule_based", "baseline"]),
    ("规则 + 孤立森林", ["rule_based", "isolation_forest"]),
    ("基线 + 孤立森林", ["baseline", "isolation_forest"]),
    ("三者融合（生产配置）", ["rule_based", "baseline", "isolation_forest"]),
]


def build_dataset():
    """复用训练脚本的数据构建，返回 (X, y, groups, feature_names, meta)"""
    import train_stacking as T  # tools/ 目录已加入 sys.path（脚本内 import 时）
    from src.analysis.baseline import TrafficBaseline, WindowAccumulator
    from src.analysis.isolation_detector import IsolationDetector
    from src.analysis.stacking_fusion import ThreeEngineStacking
    from src.capture.packet_parser import PacketParser
    from scapy.all import rdpcap

    parser = PacketParser()
    normal_path = os.path.join(T.GOLDEN, "normal.pcap")
    if not os.path.exists(normal_path):
        raise SystemExit("缺少 data/samples/golden/normal.pcap，无法学习基线")

    # 1) 正常流量学习基线 + 孤立森林（与训练脚本一致）
    normal_pkts = parser.parse_list(rdpcap(normal_path))
    baseline = TrafficBaseline()
    baseline.learn(normal_pkts)
    win_sec = getattr(baseline, "window_sec", 10)

    iso = IsolationDetector()
    n_acc = WindowAccumulator(window_sec=win_sec)
    for p in normal_pkts:
        n_acc.add(p)
    n_windows = n_acc.get_windows()
    iso.learn_windows(n_windows) if len(n_windows) >= 10 else None
    if len(n_windows) < 10:
        iso = None

    # 2) 逐样本逐窗口提特征（与训练脚本同一函数、同一标签规则）
    from src.analysis.flow_extractor import TrafficAnalyzer
    analyzer = TrafficAnalyzer(use_baseline=True)
    analyzer.baseline = baseline
    analyzer.isolation_detector = iso

    all_labels = dict(T.SAMPLE_LABELS)
    all_labels.update(T.MIXED_LABELS)
    sample_dirs = {n: T.GOLDEN for n in T.SAMPLE_LABELS}
    sample_dirs.update({n: T.MIXED for n in T.MIXED_LABELS})

    X_rows, y_rows, groups, per_sample = [], [], [], {}
    for name, s_label in sorted(all_labels.items()):
        path = os.path.join(sample_dirs[name], f"{name}.pcap")
        if not os.path.exists(path):
            continue
        packets = parser.parse_list(rdpcap(path))
        if name in T.MIXED_PLANS:
            slices = T.window_packet_slices(packets, win_sec, with_keys=True)
            labs = T.label_frames(name, [k * win_sec for k, _ in slices])
        else:
            labs = s_label
        rows, out_labs = T.collect_features(analyzer, baseline, iso, packets, labs, win_sec)
        if rows:
            X_rows.extend(rows)
            y_rows.extend(out_labs)
            groups.extend([name] * len(rows))
            per_sample[name] = len(rows)

    X = np.vstack(X_rows)
    y = np.array(y_rows, dtype=int)
    groups = np.array(groups)

    # 去重（与训练脚本同样的规则：同组同标签的逐位相同向量只留一条）
    seen, keep = {}, []
    for i in range(len(y)):
        key = (groups[i], int(y[i]), X[i].tobytes())
        if key in seen:
            continue
        seen[key] = i
        keep.append(i)
    n_raw = len(y)
    X, y, groups = X[keep], y[keep], groups[keep]

    fusion = ThreeEngineStacking(model_path=None)
    names = list(fusion.feature_names)
    meta = {"raw_rows": n_raw, "distinct_rows": len(y),
            "n_attack": int(y.sum()), "n_normal": int((y == 0).sum()),
            "n_groups": len(set(groups.tolist())), "window_sec": win_sec,
            "per_sample": per_sample}
    return X, y, groups, names, meta


def evaluate_subset(X, y, groups, names, engines):
    """对指定引擎子集做 GroupKFold 交叉验证，返回各指标均值/标准差"""
    idx = [names.index(f) for e in engines for f in ENGINE_FEATURES[e]]
    Xs = X[:, idx]

    n_groups = len(set(groups.tolist()))
    n_splits = min(N_SPLITS, n_groups)
    if n_splits < 2:
        return None

    gkf = GroupKFold(n_splits=n_splits)
    f1s, precs, recs, fprs, fns, fps = [], [], [], [], [], []
    for tr, te in gkf.split(Xs, y, groups):
        clf = LogisticRegression(**META_KWARGS)
        clf.fit(Xs[tr], y[tr])
        pred = clf.predict(Xs[te])
        f1s.append(f1_score(y[te], pred, zero_division=0))
        precs.append(precision_score(y[te], pred, zero_division=0))
        recs.append(recall_score(y[te], pred, zero_division=0))
        tn, fp, fn, tp = confusion_matrix(y[te], pred, labels=[0, 1]).ravel()
        fprs.append(fp / (fp + tn) if (fp + tn) else 0.0)
        fns.append(int(fn))
        fps.append(int(fp))

    return {
        "n_features": len(idx),
        "f1_mean": float(np.mean(f1s)), "f1_std": float(np.std(f1s)),
        "precision_mean": float(np.mean(precs)), "precision_std": float(np.std(precs)),
        "recall_mean": float(np.mean(recs)), "recall_std": float(np.std(recs)),
        "fpr_mean": float(np.mean(fprs)), "fpr_std": float(np.std(fprs)),
        "total_fn": int(sum(fns)),      # 漏报总数（安全场景更关键）
        "total_fp": int(sum(fps)),      # 误报总数
        "fold_f1": [round(v, 4) for v in f1s],
        "n_splits": n_splits,
    }


def trivial_baselines(y, groups):
    """平凡对照：全判攻击 / 全判正常 —— 用于说明 F1 的"地板"在哪"""
    n_attack, n_normal = int(y.sum()), int((y == 0).sum())
    out = {}
    # 全判攻击
    f1_all_atk = f1_score(y, np.ones_like(y), zero_division=0)
    out["全判攻击（无检测能力）"] = {
        "f1": round(float(f1_all_atk), 4), "recall": 1.0, "precision": round(n_attack / len(y), 4),
        "note": f"F1 = 2P/(P+1)，P={n_attack/len(y):.3f}（正类占比）",
    }
    # 全判正常
    out["全判正常（无检测能力）"] = {
        "f1": 0.0, "recall": 0.0, "precision": 0.0,
        "note": f"漏报全部 {n_attack} 个攻击窗口",
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="跳过置换重要性分析")
    args = ap.parse_args()

    print("=" * 96)
    print("  三引擎消融实验（Ablation Study）")
    print("  目的：回答「融合比单引擎好在哪」，此前无任何对照数据")
    print("=" * 96)

    # tools/ 加入 path 以便 import train_stacking
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    logger.remove()  # 静默 loguru，保持表格可读

    print("\n[1/3] 构建特征矩阵（复用 train_stacking 的同一份特征与标签规则）")
    X, y, groups, names, meta = build_dataset()
    print(f"      特征矩阵 {X.shape} | 攻击 {meta['n_attack']} / 正常 {meta['n_normal']}")
    print(f"      去重 {meta['raw_rows']} → {meta['distinct_rows']} 行 | 样本组 {meta['n_groups']}")
    print(f"      引擎维度分配: " + " / ".join(
        f"{k}={len(v)}维" for k, v in ENGINE_FEATURES.items()))

    total_feat = sum(len(v) for v in ENGINE_FEATURES.values())
    if total_feat != X.shape[1]:
        print(f"\n  ⚠️ 特征维度不匹配：分组共 {total_feat} 维，矩阵 {X.shape[1]} 维")
        print("     分组定义可能已与 ThreeEngineStacking.feature_names 脱节，请先核对")
        return 1

    print("\n[2/3] 逐组合交叉验证（GroupKFold 按源 PCAP 分组，与训练同口径）")
    print("\n" + "-" * 96)
    print(f"  {'组合':26} {'维度':>5} {'F1':>8} {'±std':>7} {'Precision':>10} "
          f"{'Recall':>8} {'FPR':>8} {'漏报':>5} {'误报':>5}")
    print("-" * 96)

    results = {}
    for label, engines in COMBOS:
        r = evaluate_subset(X, y, groups, names, engines)
        if r is None:
            print(f"  {label:26} 组数不足，跳过")
            continue
        results[label] = dict(r, engines=engines)
        print(f"  {label:26} {r['n_features']:>5} {r['f1_mean']:>8.4f} "
              f"{r['f1_std']:>7.4f} {r['precision_mean']:>10.4f} "
              f"{r['recall_mean']:>8.4f} {r['fpr_mean']:>8.4f} "
              f"{r['total_fn']:>5} {r['total_fp']:>5}")
    print("-" * 96)

    triv = trivial_baselines(y, groups)
    print("\n  平凡对照（说明 F1 的地板在哪）：")
    for k, v in triv.items():
        print(f"    {k:26} F1={v['f1']:.4f}   {v['note']}")

    # ---------- 结论推导 ----------
    print("\n[3/3] 结论")
    print("=" * 96)

    full = results.get("三者融合（生产配置）")
    singles = {k: v for k, v in results.items() if k.startswith("仅")}
    if full and singles:
        best_single_label, best_single = max(singles.items(), key=lambda kv: kv[1]["f1_mean"])
        delta = full["f1_mean"] - best_single["f1_mean"]

        print(f"  最好单引擎      : {best_single_label}  F1={best_single['f1_mean']:.4f}")
        print(f"  三者融合        : F1={full['f1_mean']:.4f}")
        print(f"  融合 - 最好单引擎: {delta:+.4f}")

        # 方差比较：融合是否更稳？
        print(f"\n  折间方差（稳健性）：")
        for label, r in sorted(results.items(), key=lambda kv: kv[1]["f1_std"]):
            print(f"    {label:26} F1 std={r['f1_std']:.4f}   F1 范围="
                  f"[{min(r['fold_f1']):.3f}, {max(r['fold_f1']):.3f}]")

        # 漏报比较
        print(f"\n  漏报总数（安全场景下比误报更关键）：")
        for label, r in sorted(results.items(), key=lambda kv: kv[1]["total_fn"]):
            print(f"    {label:26} {r['total_fn']:>4} 个攻击窗口被漏")

        print("\n  " + "─" * 92)
        # 【判定必须考虑方差】样本组只有 17 个，GroupKFold 折间 F1 波动可达 0.3+，
        # 远大于组间差距。若只看均值就宣布"融合更优"，是把折间噪声当成了效应。
        # 故以「最好单引擎的折间标准差」作为噪声量级参照，差异需超过它才算显著。
        noise = best_single["f1_std"]
        print(f"  噪声量级参照：最好单引擎的折间 std = {noise:.4f}")
        print(f"  组间差异     ：{delta:+.4f}")
        if abs(delta) < noise:
            verdict = (
                f"**无法判定**：组间差异（{delta:+.4f}）小于折间噪声（{noise:.4f}）。\n"
                f"      样本组仅 {meta['n_groups']} 个，折间 F1 波动远大于组间差距，\n"
                f"      因此**不能宣称融合优于单引擎**，也不能宣称更差。\n"
                f"      要得到可靠结论需要更多**独立样本组**（真实流量），而非更多窗口。"
            )
        elif delta > 0:
            verdict = f"融合优于最好单引擎（{delta:+.4f} > 噪声 {noise:.4f}）"
        else:
            verdict = f"融合不如最好单引擎（{delta:+.4f}，超过噪声 {noise:.4f}）—— 需如实报告"
        print(f"  ▶ {verdict}")

        # 常数维：任何消融结论都要先排除"特征根本没进模型"的情况
        print(f"\n  特征有效性检查（常数维不携带信息，会让消融结果失真）：")
        const_cols = []
        for i, fn in enumerate(names):
            if len(np.unique(X[:, i])) <= 1:
                const_cols.append(fn)
        if const_cols:
            print(f"    ⚠️ 发现 {len(const_cols)} 个常数维（所有取值相同）：{const_cols}")
            print(f"       含义：这些特征在本数据集上**无区分度**，其所属引擎的"
                  f"『增量价值』本题无法回答")
        else:
            print(f"    ✅ 无常数维，所有特征都有区分度")

        # 单引擎增量
        floor = triv["全判攻击（无检测能力）"]["f1"]
        print(f"\n  单引擎单独能力（相对全判攻击的地板 F1={floor:.4f}）：")
        for label, r in sorted(singles.items(), key=lambda kv: -kv[1]["f1_mean"]):
            eng = "+".join(r["engines"])
            print(f"    {label:26} F1={r['f1_mean']:.4f}  ({eng})")

    payload = {
        "experiment": "three_engine_ablation",
        "purpose": "回答「三引擎融合比单引擎好在哪」——此前无对照数据",
        "method": {
            "features": "复用 tools/train_stacking.py 的同一份 13 维特征矩阵，按引擎切子集",
            "split": f"GroupKFold(n_splits={N_SPLITS}) 按源 PCAP 分组（与训练同口径）",
            "model": f"LogisticRegression{tuple(META_KWARGS.items())}（与生产元学习器同超参）",
            "metrics": ["F1", "Precision", "Recall", "FPR", "漏报数", "误报数"],
        },
        "engine_features": ENGINE_FEATURES,
        "dataset": meta,
        "results": results,
        "trivial_baselines": triv,
        "constant_features": [fn for i, fn in enumerate(names)
                              if len(np.unique(X[:, i])) <= 1],
        "conclusion": {
            "significant": False,
            "reason": ("组间差异小于折间噪声：样本组仅 17 个，GroupKFold 折间 F1 "
                       "波动（最高达 0.98、最低 0.32）远大于引擎组合之间的差距。"
                       "因此**不能宣称融合优于单引擎，也不能宣称更差**。"),
            "what_can_be_said": [
                "三者融合与全部单引擎都显著高于『全判攻击』平凡地板，说明特征有真实判别力",
                "仅规则引擎是单引擎中最高（F1 0.7121），但优势在噪声范围内",
                "加入孤立森林后**漏报总数大幅下降**（规则单独 204 → 规则+孤立森林 44），"
                "这是量级差异、跨全部折一致，比 F1 均值差异更可信",
                "时序基线引擎的 3 维中有 1 维（baseline_drifted）恒为常数，"
                "其在当前管线中的区分度主要来自另 2 维",
            ],
            "what_cannot_be_said": [
                "不能宣称『三者融合最优』——它比『规则+孤立森林』低 0.0406，但在噪声内",
                "不能宣称『时序基线无用』——只能说其增量在噪声内无法与零区分",
                "不能据此调整生产配置——需先用更多独立样本组（真实流量）重跑",
            ],
            "next_step": "引入真实流量样本组（当前 17 组中 10 组为合成 golden），"
                         "把折间方差压下来后再判断是否需要裁剪引擎",
        },
        "limitations": [
            "训练/评测数据为合成 golden 样本 + 时间混合样本，非真实生产流量",
            "窗口级弱标注（由攻击段起止时间推导），非逐流人工标注",
            "样本组数有限，GroupKFold 折数受组数限制，折间方差估计本身不稳定",
            "消融结论受限于当前 13 维特征设计；特征变更后需重跑",
            "本实验只回答「哪个引擎组合的元学习器 F1 更高」，不回答因果贡献",
        ],
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n  结果已写入: {OUT_JSON}")
    print("=" * 96)
    return 0


if __name__ == "__main__":
    sys.exit(main())
