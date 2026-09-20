# -*- coding: utf-8 -*-
"""
特征重要性可视化（真实数据）

HistGradientBoosting 不直接提供 feature_importances_，因此采用更严谨的
置换重要性（Permutation Importance）：在真实的 UNSW-NB15 测试集上，
逐个打乱某列特征，观察 F1 的下降幅度，下降越多说明该特征越关键。

产物：
  1. Top-20 特征置换重要性（带误差棒） -> docs/feature_importance.png
  2. 按特征类别聚合的重要性             -> docs/feature_category_importance.png
  3. 全部明细 CSV                        -> docs/feature_importance.csv

前置：先运行  python tools/train_unsw_supervised.py
"""
import os
import sys
import csv
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.inspection import permutation_importance

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
MODEL_PATH = os.path.join(ROOT, "models", "unsw_supervised_detector.joblib")
DOCS = os.path.join(ROOT, "docs")

TIME_SERIES = {"sinpkt", "dinpkt", "sjit", "djit", "tcprtt", "synack", "ackdat"}
CONNECTION = {"ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
              "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst"}

BLUE_MAIN = "#2E6FB7"
CATEGORY_COLORS = {
    "基础网络特征": "#2E6FB7",
    "时序/时延特征": "#57A0D3",
    "连接计数特征": "#8FC1E3",
    "协议类别one-hot": "#B8D8F0",
}


def classify(name: str) -> str:
    if name.startswith(("proto_", "service_", "state_")):
        return "协议类别one-hot"
    if name in TIME_SERIES:
        return "时序/时延特征"
    if name in CONNECTION:
        return "连接计数特征"
    return "基础网络特征"


def main():
    if not os.path.exists(MODEL_PATH):
        sys.exit("未找到模型，请先运行：python tools/train_unsw_supervised.py")

    # 真实数据：复用训练脚本的加载逻辑，并按同样的随机种子做分层划分，
    # 保证这里取出的是模型训练时未见过的真实测试集。
    from tools.train_unsw_supervised import load_unsw
    X, y, y_cat, names = load_unsw()
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)

    import joblib
    clf = joblib.load(MODEL_PATH)["model"]

    # 为控制置换耗时，对测试集做分层抽样取一个代表性子集（4000 条）。
    rng = np.random.RandomState(0)
    Xte_s, _, yte_s, _ = train_test_split(
        Xte, yte, train_size=4000, stratify=yte, random_state=0)
    print(f"在真实测试子集 {Xte_s.shape} 上计算置换重要性（n_repeats=3）...")

    res = permutation_importance(
        clf, Xte_s, yte_s, n_repeats=3, random_state=42,
        scoring="f1", n_jobs=-1)
    means = np.asarray(res.importances_mean)
    stds = np.asarray(res.importances_std)
    print(f"置换重要性计算完成，正值特征数: {int(np.sum(means > 0))}")

    order = np.argsort(means)[::-1]

    # ---------- 图1：Top-20 ----------
    top_n = 20
    top_idx = order[:top_n][::-1]
    top_names = [names[i] for i in top_idx]
    top_vals = means[top_idx]
    top_err = stds[top_idx]

    fig, ax = plt.subplots(figsize=(10, 7))
    ax.barh(range(top_n), top_vals, xerr=top_err, color=BLUE_MAIN,
            ecolor="#888", capsize=3)
    ax.set_yticks(range(top_n))
    ax.set_yticklabels(top_names, fontsize=10)
    ax.set_xlabel("置换重要性（打乱该特征后 F1 的下降幅度）", fontsize=11)
    ax.set_title("UNSW-NB15 监督模型 Top-20 特征置换重要性\n(真实测试集，n_repeats=3，误差棒为标准差)",
                 fontsize=13)
    ax.axvline(0, color="#999", linewidth=0.8)
    ax.grid(axis="x", linestyle="--", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(DOCS, "feature_importance.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("已保存 docs/feature_importance.png")

    # ---------- 图2：类别聚合 ----------
    cat_sum = {}
    for i, nm in enumerate(names):
        c = classify(nm)
        cat_sum[c] = cat_sum.get(c, 0.0) + max(means[i], 0.0)

    cat_order = ["基础网络特征", "时序/时延特征", "连接计数特征", "协议类别one-hot"]
    cat_vals = [cat_sum.get(c, 0.0) for c in cat_order]
    cat_colors = [CATEGORY_COLORS[c] for c in cat_order]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.bar(range(len(cat_order)), cat_vals, color=cat_colors, width=0.6)
    ax.set_xticks(range(len(cat_order)))
    ax.set_xticklabels(cat_order, fontsize=10)
    ax.set_ylabel("正向置换重要性合计", fontsize=11)
    ax.set_title("按特征类别聚合的重要性", fontsize=13)
    for i, v in enumerate(cat_vals):
        ax.text(i, v + max(cat_vals) * 0.01, f"{v:.3f}", ha="center", fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(DOCS, "feature_category_importance.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("已保存 docs/feature_category_importance.png")

    # ---------- CSV ----------
    with open(os.path.join(DOCS, "feature_importance.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["rank", "feature", "category", "perm_importance_mean", "perm_importance_std"])
        for rank, idx in enumerate(order, start=1):
            w.writerow([rank, names[idx], classify(names[idx]),
                        round(means[idx], 5), round(stds[idx], 5)])
    print("已保存 docs/feature_importance.csv")

    print("\nTop-10:")
    for idx in order[:10]:
        print(f"  {names[idx]:28s} {means[idx]:.4f} ± {stds[idx]:.4f}  [{classify(names[idx])}]")


if __name__ == "__main__":
    main()
