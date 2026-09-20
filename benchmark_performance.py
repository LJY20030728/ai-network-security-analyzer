# -*- coding: utf-8 -*-
"""
性能压测可视化（真实数据）

读取 tools/benchmark.py 用 time/tracemalloc 实测产出的
data/eval_perf/benchmark_result.json，绘制：
  左：各文件「解析 + 分析」耗时堆叠条形图
  右：各文件内存峰值条形图（>50MB 标橙，标识扩展瓶颈）
并导出 docs/performance_benchmark.csv。

本脚本只做可视化，不做任何 sleep 模拟。
前置：python tools/benchmark.py
"""
import os
import json
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(ROOT, "data", "eval_perf", "benchmark_result.json")
DOCS = os.path.join(ROOT, "docs")

C_PARSE = "#2E6FB7"
C_ANALYZE = "#8FC1E3"
C_PEAK_OK = "#2E6FB7"
C_PEAK_HOT = "#D9822B"


def main():
    with open(JSON_PATH, encoding="utf-8") as f:
        data = json.load(f)

    rows = [r for r in data["results"] if "error" not in r]
    rows.sort(key=lambda r: r["total_time_sec"])
    labels = [r["label"] for r in rows]
    parse_t = [r["parse_time_sec"] for r in rows]
    analyze_t = [r["analyze_time_sec"] for r in rows]
    peak = [r["total_peak_mb"] for r in rows]
    y = range(len(rows))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6.5))

    # 左：耗时堆叠
    ax1.barh(list(y), parse_t, color=C_PARSE, label="解析耗时")
    ax1.barh(list(y), analyze_t, left=parse_t, color=C_ANALYZE, label="分析耗时")
    ax1.set_yticks(list(y))
    ax1.set_yticklabels(labels, fontsize=10)
    ax1.set_xlabel("耗时（秒）", fontsize=11)
    ax1.set_title("各 PCAP 解析 + 分析耗时（实测）", fontsize=13)
    for i, r in enumerate(rows):
        ax1.text(r["total_time_sec"] + 0.3, i,
                 f"{r['total_time_sec']:.2f}s", va="center", fontsize=8)
    ax1.legend(loc="lower right", fontsize=10)
    ax1.grid(axis="x", linestyle="--", alpha=0.3)

    # 右：内存峰值
    colors = [C_PEAK_HOT if p > 50 else C_PEAK_OK for p in peak]
    ax2.barh(list(y), peak, color=colors)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels(labels, fontsize=10)
    ax2.set_xlabel("内存峰值（MB）", fontsize=11)
    ax2.set_title("各 PCAP 内存峰值（橙色为 >50MB 瓶颈点）", fontsize=13)
    for i, p in enumerate(peak):
        ax2.text(p + 1, i, f"{p:.1f}", va="center", fontsize=8)
    ax2.grid(axis="x", linestyle="--", alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(DOCS, "performance_benchmark.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("已保存 docs/performance_benchmark.png")

    # CSV
    with open(os.path.join(DOCS, "performance_benchmark.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["label", "file_size_mb", "total_packets", "total_flows",
                    "parse_time_sec", "analyze_time_sec", "total_time_sec",
                    "total_peak_mb", "packets_per_sec"])
        for r in rows:
            w.writerow([r["label"], r["file_size_mb"], r["total_packets"],
                        r["total_flows"], r["parse_time_sec"], r["analyze_time_sec"],
                        r["total_time_sec"], r["total_peak_mb"], r["packets_per_sec"]])
    print("已保存 docs/performance_benchmark.csv")

    s = data["summary"]
    print(f"\n实测汇总：{s['tested_files']} 文件，总包数 {s['total_packets_all']}")
    print(f"  平均耗时 {s['avg_total_time_sec']}s，平均内存峰值 {s['avg_peak_mb']}MB")
    print(f"  最慢 {s['max_time_sec']}s（{labels[-1]}）")


if __name__ == "__main__":
    main()
