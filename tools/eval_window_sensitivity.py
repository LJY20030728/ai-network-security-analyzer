# -*- coding: utf-8 -*-
"""P0-3 窗口敏感性实验：window_sec × σ 双因子网格
对黄金样本：normal 学习 → 各样本检测，统计
- TPR：基线专项样本(lightscan/burst) + 规则攻击样本 中被检出样本比例
- FPR：normal 自测偏差窗口占比
结论写入 data/eval_perf/window_sensitivity.json
"""
import json
import os
import sys
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from loguru import logger

logger.remove()

from scapy.all import rdpcap
from src.capture.packet_parser import PacketParser
from src.analysis.baseline import TrafficBaseline

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "samples", "golden")
ATTACK_SAMPLES = ["synflood", "portscan", "dnstunnel", "largeflow", "rststorm", "lightscan", "burst"]


def load(name):
    parser = PacketParser()
    return [parser.parse(spkt) for spkt in rdpcap(os.path.join(GOLDEN_DIR, f"{name}.pcap"))]


def main():
    samples = {n: load(n) for n in ["normal"] + ATTACK_SAMPLES}
    grid = list(product([5, 10, 30], [2.0, 3.0, 4.0]))

    rows = []
    for wsec, sigma in grid:
        base = TrafficBaseline(window_sec=wsec, sigma=sigma)
        base.learn(samples["normal"])
        gt_w = len(base._aggregate_windows(samples["normal"]))

        # FPR：normal 自测
        det_n = base.detect(samples["normal"])
        fp = len(det_n.get("deviations", []))
        fpr = fp / gt_w if gt_w else 0

        # TPR：攻击样本检出
        hit = 0
        per_sample = {}
        for n in ATTACK_SAMPLES:
            det = base.detect(samples[n])
            devs = len(det.get("deviations", []))
            per_sample[n] = devs
            if devs:
                hit += 1
        tpr = hit / len(ATTACK_SAMPLES)
        rows.append({
            "window_sec": wsec, "sigma": sigma,
            "normal_windows": gt_w, "fpr": round(fpr, 4),
            "tpr": round(tpr, 4), "hit_samples": hit,
            "per_sample": per_sample,
        })
        print(f"window={wsec:3d}s σ={sigma} → TPR={tpr:.2f} ({hit}/7) FPR={fpr:.4f} ({fp}/{gt_w})")

    # 汇总表
    print("\n========== 窗口敏感性网格 ==========")
    print(f"{'window_sec':<10} {'σ=2.0':<16} {'σ=3.0':<16} {'σ=4.0':<16}")
    for wsec in [5, 10, 30]:
        line = f"{wsec:<10}"
        for sigma in [2.0, 3.0, 4.0]:
            r = next(x for x in rows if x["window_sec"] == wsec and x["sigma"] == sigma)
            line += f"TPR{r['tpr']:.2f}/FPR{r['fpr']:.3f}  "
        print(line)

    os.makedirs("data/eval_perf", exist_ok=True)
    with open("data/eval_perf/window_sensitivity.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print("\n结果已写入 data/eval_perf/window_sensitivity.json")


if __name__ == "__main__":
    main()
