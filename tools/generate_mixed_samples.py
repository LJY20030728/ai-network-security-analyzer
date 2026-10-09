# -*- coding: utf-8 -*-
"""
生成时间混合训练样本（v3.4.0）

将正常流量pcap与攻击流量pcap按时间拼接，模拟真实环境中
"正常浏览中突然发起攻击"的场景。

生成的混合样本用于元学习器训练，增加样本多样性。

用法：python tools/generate_mixed_samples.py
"""
import os
import sys
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "data", "samples", "golden")
MIXED_DIR = os.path.join(ROOT, "data", "samples", "mixed")

# 混合方案：(正常样本, 攻击样本, 输出名, 攻击起始偏移秒)
MIX_PLANS = [
    ("baseline_demo_normal.pcap", "synflood.pcap", "mix_normal_synflood.pcap", 30),
    ("baseline_demo_normal.pcap", "portscan.pcap", "mix_normal_portscan.pcap", 30),
    ("baseline_demo_normal.pcap", "dnstunnel.pcap", "mix_normal_dnstunnel.pcap", 30),
    ("baseline_demo_normal.pcap", "rststorm.pcap", "mix_normal_rststorm.pcap", 30),
    ("normal.pcap", "synflood.pcap", "mix_short_normal_synflood.pcap", 15),
    ("normal.pcap", "portscan.pcap", "mix_short_normal_portscan.pcap", 15),
    ("baseline_demo_normal.pcap", "burst.pcap", "mix_normal_burst.pcap", 30),
]


def shift_packets(packets, offset_sec):
    """将包列表的时间戳整体偏移 offset_sec 秒"""
    for p in packets:
        p.time = p.time + offset_sec
    return packets


def main():
    os.makedirs(MIXED_DIR, exist_ok=True)
    print("=" * 60)
    print("生成时间混合训练样本")
    print("=" * 60)

    for normal_name, attack_name, out_name, offset in MIX_PLANS:
        normal_path = os.path.join(GOLDEN, normal_name)
        attack_path = os.path.join(GOLDEN, attack_name)
        out_path = os.path.join(MIXED_DIR, out_name)

        if not os.path.exists(normal_path):
            print(f"  [跳过] {normal_name} 不存在")
            continue
        if not os.path.exists(attack_path):
            print(f"  [跳过] {attack_name} 不存在")
            continue

        normal_pkts = rdpcap(normal_path)
        attack_pkts = rdpcap(attack_path)

        # 正常流量的最大时间戳
        if normal_pkts:
            normal_end = float(normal_pkts[-1].time)
        else:
            normal_end = 0.0

        # 攻击流量从正常流量结束后 offset 秒开始
        attack_start = normal_end + offset
        if attack_pkts:
            attack_base = float(attack_pkts[0].time)
            for p in attack_pkts:
                p.time = attack_start + (float(p.time) - attack_base)

        # 合并并按时间排序
        mixed = list(normal_pkts) + list(attack_pkts)
        mixed.sort(key=lambda p: float(p.time))

        wrpcap(out_path, mixed)
        size_kb = os.path.getsize(out_path) / 1024
        print(f"  {out_name:<40} {len(mixed):>6} 包 | {size_kb:>8.1f} KB "
              f"| 攻击起始于 +{offset}s")

    print(f"\n完成，混合样本保存在: {MIXED_DIR}")
    print(f"共生成 {len(os.listdir(MIXED_DIR))} 个混合样本")
    return 0


if __name__ == "__main__":
    sys.exit(main())
