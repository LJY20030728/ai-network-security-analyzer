# -*- coding: utf-8 -*-
"""
学习并保存默认基线（v3.4.0）

用 baseline_demo_normal.pcap（2729包，含HTTP+DNS+UDP）学习基线，
保存为 data/baselines/default_baseline.json，随安装包分发。

用法：python tools/learn_default_baseline.py
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import rdpcap
from src.capture.packet_parser import PacketParser
from src.analysis.baseline import TrafficBaseline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "data", "samples", "golden")
BASELINE_DIR = os.path.join(ROOT, "data", "baselines")
DEFAULT_BASELINE = os.path.join(BASELINE_DIR, "default_baseline.json")


def main():
    os.makedirs(BASELINE_DIR, exist_ok=True)
    pcap_path = os.path.join(GOLDEN, "baseline_demo_normal.pcap")

    if not os.path.exists(pcap_path):
        print(f"错误：{pcap_path} 不存在")
        return 1

    print("=" * 60)
    print("学习默认基线")
    print("=" * 60)
    print(f"样本: {pcap_path}")

    parser = PacketParser()
    raw_packets = rdpcap(pcap_path)
    packets = parser.parse_list(raw_packets)
    print(f"解析包数: {len(packets)}")

    baseline = TrafficBaseline()
    baseline.learn(packets)
    print(f"学习结果: learned={baseline.learned}, "
          f"维度={list(baseline.profile.keys())}, "
          f"窗口数={len(baseline._train_windows)}")

    # 保存
    baseline.save(DEFAULT_BASELINE)
    size_kb = os.path.getsize(DEFAULT_BASELINE) / 1024
    print(f"已保存: {DEFAULT_BASELINE} ({size_kb:.1f} KB)")

    # 验证加载
    loaded = TrafficBaseline.load(DEFAULT_BASELINE)
    if loaded and loaded.learned:
        print(f"验证加载成功: learned={loaded.learned}, "
              f"window_sec={loaded.window_sec}")
    else:
        print("警告：加载验证失败")
        return 1

    print("\n完成。默认基线将随安装包分发，首次启动自动加载。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
