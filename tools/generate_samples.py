# -*- coding: utf-8 -*-
"""
合成黄金样本生成器
===================
生成可回归的检测测试集（学习-检测两阶段用）：
- normal.pcap       : 正常流量（HTTP会话 + DNS查询 + UDP，时间均匀分布 1 小时）
- synflood.pcap     : SYN Flood（同源大量SYN无ACK）
- portscan.pcap     : 端口扫描（同源访问大量不同端口）
- dnstunnel.pcap    : DNS隧道（同源超长域名查询）
- largeflow.pcap    : 异常大流量（单流超大字节）
- rststorm.pcap     : RST风暴（同源大量RST包）

用法：
    python tools/generate_samples.py [--out data/samples/golden]
输出：golden 目录下的 6 个 pcap 文件 + samples.json 清单
"""
import argparse
import json
import os
import random
import time as time_mod
from typing import List

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap, PcapWriter


# 网络参数
SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
DNS_SERVER = "8.8.8.8"
START_TS = 1700000000.0  # 基准时间戳

random.seed(42)  # 可复现


def _set_time(pkt, ts: float):
    """设置包时间戳（scapy 写入 pcap 时保留）"""
    pkt.time = ts
    return pkt


def gen_normal_packets(n_sessions: int = 200, duration: int = 3600) -> List:
    """
    生成正常流量：
    - n_sessions 个 HTTP 会话（SYN→SYNACK→ACK→数据往返）
    - 30 个 DNS 查询 + 响应
    - 少量 UDP 通信
    时间均匀分布在 duration 秒内
    """
    pkts = []
    base = START_TS

    # HTTP 会话（模拟网页浏览）
    for i in range(n_sessions):
        t = base + (i / n_sessions) * duration
        src_port = 40000 + i
        # 握手 + 请求 + 响应数据
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=src_port, dport=80, flags="S", seq=1000 + i * 1000), t))
        pkts.append(_set_time(IP(src=SERVER_IP, dst=CLIENT_IP) /
                              TCP(sport=80, dport=src_port, flags="SA", seq=5000 + i, ack=1001 + i * 1000), t + 0.05))
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=src_port, dport=80, flags="A", seq=1001 + i * 1000, ack=5001 + i) /
                              Raw(load=f"GET /page/{i} HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n".encode()), t + 0.06))
        pkts.append(_set_time(IP(src=SERVER_IP, dst=CLIENT_IP) /
                              TCP(sport=80, dport=src_port, flags="PA", seq=5001 + i, ack=1002 + i * 1000) /
                              Raw(load=b"HTTP/1.1 200 OK\r\n\r\n" + b"<html>ok</html>" * 10), t + 0.1))
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=src_port, dport=80, flags="FA", seq=1002 + i * 1000, ack=5002 + i), t + 0.2))
        pkts.append(_set_time(IP(src=SERVER_IP, dst=CLIENT_IP) /
                              TCP(sport=80, dport=src_port, flags="FA", seq=5002 + i, ack=1003 + i * 1000), t + 0.25))
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=src_port, dport=80, flags="A", seq=1003 + i * 1000, ack=5003 + i), t + 0.3))

    # DNS 查询（正常域名）
    normal_domains = ["www.example.com", "mail.google.com", "api.github.com",
                      "cdn.cloudflare.com", "docs.python.org"]
    for i in range(30):
        t = base + random.uniform(0, duration)
        dport = 53
        q = normal_domains[i % len(normal_domains)]
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=DNS_SERVER) /
                              UDP(sport=50000 + i, dport=dport) /
                              DNS(id=i, qr=0, qd=DNSQR(qname=q)), t))
        pkts.append(_set_time(IP(src=DNS_SERVER, dst=CLIENT_IP) /
                              UDP(sport=dport, dport=50000 + i) /
                              DNS(id=i, qr=1, qd=DNSQR(qname=q), ancount=1), t + 0.02))

    # UDP 通信（少量）
    for i in range(20):
        t = base + random.uniform(0, duration)
        pkts.append(_set_time(IP(src=CLIENT_IP, dst="10.0.0.50") /
                              UDP(sport=60000 + i, dport=123) /
                              Raw(load=os.urandom(48)), t))

    # 按时间排序
    pkts.sort(key=lambda p: p.time)
    return pkts


def gen_synflood_packets(count: int = 200) -> List:
    """SYN Flood：同源向目标机发送大量 SYN（无 ACK），60 秒内集中"""
    pkts = []
    for i in range(count):
        t = START_TS + (i / count) * 60
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(0, 2**31)), t))
    return pkts


def gen_portscan_packets(n_ports: int = 50) -> List:
    """端口扫描：同源顺序探测大量不同端口（TCP SYN），60 秒内"""
    pkts = []
    for i in range(n_ports):
        t = START_TS + (i / n_ports) * 60
        port = 1 + i  # 1~50
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=40000 + i, dport=port, flags="S", seq=random.randint(0, 2**31)), t))
    return pkts


def gen_dnstunnel_packets(n_queries: int = 10) -> List:
    """DNS隧道：同源发送超长域名查询（>30字符）"""
    pkts = []
    for i in range(n_queries):
        t = START_TS + i * 2
        # 构造 40+ 字符的域名
        sub = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=35))
        qname = f"{sub}.tunnel.example.com"
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=DNS_SERVER) /
                              UDP(sport=50000 + i, dport=53) /
                              DNS(id=i + 100, qr=0, qd=DNSQR(qname=qname)), t))
    return pkts


def gen_largeflow_packets(target_mb: float = 11.0) -> List:
    """异常大流量：单流持续向目标发送大 payload（>10MB 阈值）"""
    pkts = []
    payload = os.urandom(1400)
    total = 0
    i = 0
    while total < target_mb * 1024 * 1024:
        t = START_TS + i * 0.001  # 约 1000 包/秒
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=40000, dport=21, flags="A", seq=1000 + i * 1400) /
                              Raw(load=payload), t))
        total += 1400
        i += 1
    return pkts


def gen_rststorm_packets(count: int = 80) -> List:
    """RST风暴：同源发送大量 RST 包"""
    pkts = []
    for i in range(count):
        t = START_TS + (i / count) * 60
        pkts.append(_set_time(IP(src=CLIENT_IP, dst=SERVER_IP) /
                              TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22, 21]),
                                  flags="R", seq=random.randint(0, 2**31)), t))
    return pkts


GENERATORS = {
    "normal": (gen_normal_packets, "正常流量（HTTP+DNS+UDP）"),
    "synflood": (gen_synflood_packets, "SYN Flood 攻击"),
    "portscan": (gen_portscan_packets, "端口扫描"),
    "dnstunnel": (gen_dnstunnel_packets, "DNS 隧道"),
    "largeflow": (gen_largeflow_packets, "异常大流量"),
    "rststorm": (gen_rststorm_packets, "RST 风暴"),
}


def main():
    parser = argparse.ArgumentParser(description="生成合成黄金样本")
    parser.add_argument("--out", default="data/samples/golden", help="输出目录")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    manifest = {}

    for name, (gen, desc) in GENERATORS.items():
        t0 = time_mod.time()
        pkts = gen()
        path = os.path.join(args.out, f"{name}.pcap")
        with PcapWriter(path, append=True, sync=True) as w:
            for p in pkts:
                w.write(p)
        elapsed = time_mod.time() - t0
        manifest[name] = {"description": desc, "packets": len(pkts), "file": path}
        print(f"[OK] {name:10s} | {desc:12s} | {len(pkts):>6} 包 | {elapsed:.1f}s")

    manifest_path = os.path.join(args.out, "samples.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"\n样本清单已写入: {manifest_path}")
    print("共生成 %d 个样本文件" % len(manifest))


if __name__ == "__main__":
    main()
