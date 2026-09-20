# -*- coding: utf-8 -*-
"""
融合架构对比（真实数据，无泄漏，可复现）

在 UNSW-NB15 上对比 5 种检测/融合方案的 F1：
  1. 仅监督模型 HistGradientBoosting
  2. 固定权重加权融合（0.5/0.2/0.15/0.15）
  3. GridSearch 网格搜索最优权重（真实搜索）
  4. Stacking（LogisticRegression 元学习器，真实训练）
  5. 级联 + Stacking（规则先裁决，剩余交 Stacking）

方法学（避免数据泄漏）：
  - 外层：分层 80/20，20% 作为最终 held-out，全程不参与任何拟合。
  - 开发 80%：5 折 StratifiedKFold 生成四个基引擎的 out-of-fold(OOF) 预测，
    用于训练 Stacking 元学习器与网格搜索权重。
  - 最终：基引擎在完整开发集上重训后预测 held-out，各融合方案据此评分。

基引擎：
  - 监督 HGB（全部 194 特征）
  - 孤立森林 IsolationForest（39 数值特征，OOF）
  - 时序基线：中位数 + MAD 的多变量 robust z（OOF）
  - 规则引擎：固定大流量阈值（复现其在 UNSW 上 recall≈0.0001）

产物：docs/fusion_architecture_comparison.png / .csv
      data/eval_perf/fusion_comparison_result.json
"""
import os
import sys
import json
import io
import itertools
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from scipy.stats import rankdata
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ENGINES = ["supervised", "rule_based", "baseline", "isolation_forest"]
FIXED_W = np.array([0.5, 0.2, 0.15, 0.15])
LARGE_BYTES = 1e7


def sup_model():
    return HistGradientBoostingClassifier(
        max_iter=200, min_samples_leaf=20, l2_regularization=1.0,
        early_stopping=True, random_state=42)


def rank01(x):
    """把连续异常分按经验排名归一化到 (0,1)。"""
    r = rankdata(x)
    return (r - 1.0) / max(len(x) - 1.0, 1.0)


def map_by_ref(x_new, ref_scores):
    """用开发集分数分布，把新分数映射到 (0,1)（保持与 OOF 同口径）。"""
    ref_sorted = np.sort(ref_scores)
    pos = np.searchsorted(ref_sorted, x_new)
    return np.clip(pos / len(ref_sorted), 0.0, 1.0)


def main():
    from tools.train_unsw_supervised import load_unsw, NUMERIC_FEATURES
    X, y, y_cat, names = load_unsw()
    n_num = len(NUMERIC_FEATURES)
    i_sbytes = NUMERIC_FEATURES.index("sbytes")
    i_dbytes = NUMERIC_FEATURES.index("dbytes")

    # 外层划分
    Xa, Xb, ya, yb = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"开发集 {Xa.shape}，held-out {Xb.shape}")

    # ---------- 开发集 OOF ----------
    oof_raw = {e: np.zeros(len(Xa)) for e in ENGINES}
    skf = StratifiedKFold(5, shuffle=True, random_state=42)
    for k, (tr, va) in enumerate(skf.split(Xa, ya)):
        Xan, Xvn = Xa[tr, :n_num], Xa[va, :n_num]
        # 监督
        clf = sup_model().fit(Xa[tr], ya[tr])
        oof_raw["supervised"][va] = clf.predict_proba(Xa[va])[:, 1]
        # 规则（固定阈值，无需训练）
        oof_raw["rule_based"][va] = (
            (Xvn[:, i_sbytes] > LARGE_BYTES) |
            (Xvn[:, i_dbytes] > LARGE_BYTES)).astype(float)
        # 孤立森林
        ifo = IsolationForest(n_estimators=80, random_state=42, n_jobs=-1)
        ifo.fit(Xan)
        oof_raw["isolation_forest"][va] = -ifo.score_samples(Xvn)
        # 时序基线：中位数 + MAD 多变量 robust z
        med = np.median(Xan, axis=0)
        mad = np.median(np.abs(Xan - med), axis=0) + 1e-9
        z = np.abs(0.6745 * (Xvn - med) / mad)
        oof_raw["baseline"][va] = np.max(z, axis=1)
        print(f"  OOF fold {k+1}/5")

    # 归一化为概率（监督/规则已在[0,1]；iso/base 用排名）
    oof = np.column_stack([
        oof_raw["supervised"],
        oof_raw["rule_based"],
        rank01(oof_raw["baseline"]),
        rank01(oof_raw["isolation_forest"]),
    ])

    # ---------- 在 OOF 上确定融合参数 ----------
    # GridSearch 权重（步长 0.1，和为 1）
    grid = [w for w in itertools.product(np.arange(0, 1.01, 0.1), repeat=3)
            if abs(sum(w) - 1.0) < 1e-9]
    best_f1, best_w = -1, None
    for w3 in grid:
        w = np.array([w3[0], w3[1], w3[2], 1.0 - sum(w3)])
        if w[-1] < -1e-9:
            continue
        w = np.clip(w, 0, 1)
        pred = (oof @ w > 0.5)
        f = f1_score(ya, pred)
        if f > best_f1:
            best_f1, best_w = f, w
    print(f"GridSearch 最优权重: {np.round(best_w,2)}（OOF F1={best_f1:.4f}）")

    # Stacking 元学习器
    meta = LogisticRegression(max_iter=500).fit(oof, ya)

    # ---------- 基引擎在完整开发集重训，预测 held-out ----------
    Xa_num, Xb_num = Xa[:, :n_num], Xb[:, :n_num]
    clf = sup_model().fit(Xa, ya)
    p_sup = clf.predict_proba(Xb)[:, 1]
    p_rule = ((Xb_num[:, i_sbytes] > LARGE_BYTES) |
              (Xb_num[:, i_dbytes] > LARGE_BYTES)).astype(float)
    ifo = IsolationForest(n_estimators=80, random_state=42, n_jobs=-1).fit(Xa_num)
    p_iso = map_by_ref(-ifo.score_samples(Xb_num), oof_raw["isolation_forest"])
    med = np.median(Xa_num, axis=0)
    mad = np.median(np.abs(Xa_num - med), axis=0) + 1e-9
    z_te = np.max(np.abs(0.6745 * (Xb_num - med) / mad), axis=1)
    p_base = map_by_ref(z_te, oof_raw["baseline"])

    P = np.column_stack([p_sup, p_rule, p_base, p_iso])

    # ---------- 5 方案 held-out F1 ----------
    f_sup = f1_score(yb, (p_sup > 0.5))
    f_fixed = f1_score(yb, (P @ FIXED_W > 0.5))
    f_grid = f1_score(yb, (P @ best_w > 0.5))
    stack_proba = meta.predict_proba(P)[:, 1]
    f_stack = f1_score(yb, (stack_proba > 0.5))
    # 级联 + Stacking：规则命中直接判攻击，否则交 Stacking
    casc = np.where(p_rule == 1, 1.0, stack_proba)
    f_casc = f1_score(yb, (casc > 0.5))

    labels = ["仅监督HGB", "固定权重\n加权", "GridSearch\n权重", "Stacking\n元学习器",
              "级联+Stacking"]
    vals = [f_sup, f_fixed, f_grid, f_stack, f_casc]
    print("\n=== held-out F1 ===")
    for l, v in zip(labels, vals):
        print(f"  {l.replace(chr(10),' ')}: {v:.4f}")

    fig, ax = plt.subplots(figsize=(11, 6))
    colors = ["#8FC1E3", "#57A0D3", "#2E6FB7", "#1F5A96", "#D9822B"]
    ax.bar(range(len(labels)), vals, color=colors, width=0.62)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("held-out F1", fontsize=12)
    ax.set_title("融合架构对比：不同检测/融合方案在 UNSW-NB15 上的 F1（真实数据，无泄漏）",
                 fontsize=13)
    ax.set_ylim(0.9, 1.0)
    for i, v in enumerate(vals):
        ax.text(i, v + 0.002, f"{v:.4f}", ha="center", fontsize=11)
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    docs = os.path.join(ROOT, "docs")
    plt.savefig(os.path.join(docs, "fusion_architecture_comparison.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("\n已保存 docs/fusion_architecture_comparison.png")

    import csv as csvmod
    with open(os.path.join(docs, "fusion_architecture_comparison.csv"), "w",
              newline="", encoding="utf-8-sig") as f:
        w = csvmod.writer(f)
        w.writerow(["scheme", "heldout_f1"])
        for l, v in zip(labels, vals):
            w.writerow([l.replace("\n", ""), round(v, 4)])

    result = {
        "grid_search_weights": dict(zip(ENGINES, [round(float(x), 3) for x in best_w])),
        "stacking_coefficients": dict(zip(
            ENGINES, [round(float(x), 3) for x in meta.coef_[0]])),
        "heldout_f1": {l.replace("\n", ""): round(float(v), 4)
                       for l, v in zip(labels, vals)},
    }
    out = os.path.join(ROOT, "data/eval_perf/fusion_comparison_result.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"已保存 {out}")


if __name__ == "__main__":
    main()
