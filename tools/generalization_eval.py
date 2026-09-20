# -*- coding: utf-8 -*-
"""
泛化能力评估（真实数据，可复现）

UNSW-NB15 与 NSL-KDD 特征体系不同（194 维 vs 41 维，字段定义、统计窗口均不同），
无法直接整体迁移。本脚本选取两数据集“语义可对应”的 5 个共有特征，
在统一特征空间下做三组对照，并给出 NSL 完整特征模型作为上界参照：

  A. UNSW 同分布泛化   ：UNSW 分层随机 80/20
  B. NSL 同数据集独立测试：KDDTrain+ 训练 → 官方 KDDTest+ 测试
  C. 跨数据集迁移       ：UNSW 全量训练 → NSL KDDTest+ 测试（域偏移鸿沟）
  D. NSL 完整 31 特征模型：作为 NSL 上界参照

诚实声明：UNSW-NB15 无真实时间戳（发布时已匿名化），无法做真正的时间漂移实验；
树模型对单调尺度变换不敏感，因此不使用 StandardScaler；加高斯噪声经消融有害，不采用。

产物：
  docs/generalization_evaluation.png / .csv
  data/eval_perf/generalization_result.json
"""
import os
import sys
import json
import io
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, accuracy_score
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# 统一命名的共有特征
COMMON = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]
# UNSW 中对应的列名
UNSW_MAP = {
    "duration": "dur",
    "src_bytes": "sbytes",
    "dst_bytes": "dbytes",
    "count": "ct_dst_src_ltm",   # 同主机对窗口内连接数
    "srv_count": "ct_srv_dst",    # 同目标服务连接数
}

NSL_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]
NSL_FULL = [c for c in NSL_COLS if c not in ("protocol_type", "service", "flag",
                                             "label", "difficulty")]


def mk_model():
    return HistGradientBoostingClassifier(
        max_iter=200, min_samples_leaf=20, l2_regularization=1.0,
        early_stopping=True, random_state=42)


def load_unsw_common():
    df = pd.read_csv(os.path.join(ROOT, "data/eval_cicids/csv/UNSW_NB15_training-set.csv"))
    cols = [UNSW_MAP[c] for c in COMMON]
    X = df[cols].replace([np.inf, -np.inf], 0).fillna(0).values
    y = df["label"].values
    return X, y


def load_nsl(features):
    tr = pd.read_csv(os.path.join(ROOT, "data/datasets/nslkdd/KDDTrain+.txt"),
                     header=None, names=NSL_COLS)
    te = pd.read_csv(os.path.join(ROOT, "data/datasets/nslkdd/KDDTest+.txt"),
                     header=None, names=NSL_COLS)
    ytr = (tr["label"] != "normal").astype(int).values
    yte = (te["label"] != "normal").astype(int).values
    return (tr[features].replace([np.inf, -np.inf], 0).fillna(0).values, ytr,
            te[features].replace([np.inf, -np.inf], 0).fillna(0).values, yte, tr, te)


def main():
    print("加载数据...")
    Xu, yu = load_unsw_common()
    Xn_tr, yn_tr, Xn_te, yn_te, trdf, tedf = load_nsl(COMMON)
    print(f"  UNSW {Xu.shape}, NSL train {Xn_tr.shape}, NSL test {Xn_te.shape}")

    # A. UNSW 同分布
    Xutr, Xute, yutr, yute = train_test_split(
        Xu, yu, test_size=0.2, stratify=yu, random_state=42)
    fA = f1_score(yute, mk_model().fit(Xutr, yutr).predict(Xute))

    # B. NSL 同数据集独立测试
    fB = f1_score(yn_te, mk_model().fit(Xn_tr, yn_tr).predict(Xn_te))

    # C. 跨数据集迁移（UNSW -> NSL）
    fC = f1_score(yn_te, mk_model().fit(Xu, yu).predict(Xn_te))

    # D. NSL 完整特征上界
    Xf_tr = trdf[NSL_FULL].replace([np.inf, -np.inf], 0).fillna(0).values
    Xf_te = tedf[NSL_FULL].replace([np.inf, -np.inf], 0).fillna(0).values
    fD = f1_score(yn_te, mk_model().fit(Xf_tr, yn_tr).predict(Xf_te))

    names = ["A.UNSW同分布\n(5共有特征)", "B.NSL独立测试\n(5共有特征)",
             "C.UNSW→NSL迁移\n(5共有特征)", "D.NSL完整模型\n(31特征对照)"]
    vals = [fA, fB, fC, fD]
    colors = ["#2E6FB7", "#57A0D3", "#D9822B", "#8FC1E3"]

    print("\n=== 泛化评估结果（F1）===")
    for n, v in zip(names, vals):
        print(f"  {n.replace(chr(10), ' ')}: {v:.4f}")

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(range(len(names)), vals, color=colors, width=0.62)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, fontsize=10)
    ax.set_ylabel("F1 分数", fontsize=12)
    ax.set_title("检测模型泛化能力评估：同分布 / 独立测试 / 跨数据集迁移（真实数据）",
                 fontsize=13)
    ax.set_ylim(0, 1.05)
    for i, v in enumerate(vals):
        ax.text(i, v + 0.02, f"{v:.3f}", ha="center", fontsize=12)
    # 标注跨域鸿沟
    ax.annotate("", xy=(2, fC), xytext=(2, fB),
                arrowprops=dict(arrowstyle="<->", color="#555"))
    ax.text(2.12, (fB + fC) / 2, f"域偏移鸿沟\nΔ={fB-fC:.3f}", fontsize=9, color="#444")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    docs = os.path.join(ROOT, "docs")
    plt.savefig(os.path.join(docs, "generalization_evaluation.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("\n已保存 docs/generalization_evaluation.png")

    import csv as csvmod
    with open(os.path.join(docs, "generalization_evaluation.csv"), "w", newline="",
              encoding="utf-8-sig") as f:
        w = csvmod.writer(f)
        w.writerow(["setting", "features", "train_data", "test_data", "f1"])
        w.writerow(["A_UNSW_same_distribution", "5_common", "UNSW 80%", "UNSW 20%", round(fA, 4)])
        w.writerow(["B_NSL_holdout", "5_common", "NSL KDDTrain", "NSL KDDTest", round(fB, 4)])
        w.writerow(["C_cross_dataset_transfer", "5_common", "UNSW full", "NSL KDDTest", round(fC, 4)])
        w.writerow(["D_NSL_full", "31_full", "NSL KDDTrain", "NSL KDDTest", round(fD, 4)])
    print("已保存 docs/generalization_evaluation.csv")

    result = {
        "common_features": COMMON,
        "A_UNSW_same_distribution_f1": round(fA, 4),
        "B_NSL_holdout_f1": round(fB, 4),
        "C_cross_dataset_transfer_f1": round(fC, 4),
        "D_NSL_full_f1": round(fD, 4),
        "domain_gap_B_minus_C": round(fB - fC, 4),
        "note": "UNSW无真实时间戳，不做时间漂移；树模型不做标准化；加噪消融有害不采用；NSL核心5特征已接近完整31特征",
    }
    out = os.path.join(ROOT, "data/eval_perf/generalization_result.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"已保存 {out}")


if __name__ == "__main__":
    main()
