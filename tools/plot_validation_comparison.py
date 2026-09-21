# -*- coding: utf-8 -*-
"""
绘制监督检测器三种验证口径的 F1 对比（全部数字来自真实评测 JSON）：
  同分布（分层随机）  data/eval_perf/unsw_supervised_result.json
  时间外推 OOT        data/eval_perf/unsw_oot_result.json
  跨数据集 UNSW→NSL   data/eval_perf/generalization_result.json
输出 docs/validation_split_comparison.png / .csv
"""
import csv
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for f in ["Microsoft YaHei", "SimHei"]:
    try:
        font_manager.findfont(f, fallback_to_default=False)
        plt.rcParams["font.sans-serif"] = [f]
        break
    except Exception:
        continue
plt.rcParams["axes.unicode_minus"] = False

PERF = os.path.join(ROOT, "data", "eval_perf")
DOCS = os.path.join(ROOT, "docs")


def load(name):
    with open(os.path.join(PERF, name), encoding="utf-8") as f:
        return json.load(f)


same = load("unsw_supervised_result.json")["binary"]["f1"]
ootj = load("unsw_oot_result.json")
oot = ootj["oot"]["f1"]
cross = load("generalization_result.json")["C_cross_dataset_transfer_f1"]

labels = ["同分布\n(分层随机切分)", "时间外推 OOT\n(官方不同时间窗)", "跨数据集\n(UNSW→NSL)"]
vals = [same, oot, cross]
colors = ["#52C41A", "#5B8DEF", "#EA6668"]

fig, ax = plt.subplots(figsize=(8.4, 5.2))
bars = ax.bar(labels, vals, color=colors, width=0.56, edgecolor="white")
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}",
            ha="center", fontsize=13, fontweight="bold", color="#1A1B1C")
ax.set_ylim(0, 1.12)
ax.set_ylabel("F1 Score", fontsize=12)
ax.set_title("监督检测器在三种验证口径下的 F1 对比", fontsize=13, fontweight="bold")
ax.spines[["top", "right"]].set_visible(False)
ax.text(0.0, -0.21,
        "口径说明：同分布=同一时间窗随机切分（乐观上界）；OOT=官方 training 训练 / testing（另一时间窗）测试（真实时间泛化）；"
        "跨数据集=迁移到 NSL-KDD（域偏移下界）。",
        transform=ax.transAxes, fontsize=9, color="#555", wrap=True)
plt.tight_layout()
out_png = os.path.join(DOCS, "validation_split_comparison.png")
plt.savefig(out_png, dpi=150, bbox_inches="tight")

out_csv = os.path.join(DOCS, "validation_split_comparison.csv")
with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["验证口径", "F1", "说明"])
    w.writerow(["同分布(分层随机)", same, "同一时间窗随机切分，乐观上界"])
    w.writerow(["时间外推OOT", oot, "官方不同时间窗 train/test，真实时间泛化"])
    w.writerow(["跨数据集UNSW→NSL", cross, "不同数据集，域偏移下界"])
print("已保存:", out_png)
print("已保存:", out_csv)
