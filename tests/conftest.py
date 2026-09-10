# -*- coding: utf-8 -*-
"""pytest 共享 fixtures 与构造工具"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest
from datetime import datetime, timedelta

from src.capture.packet_parser import PacketInfo


def mk(ts, proto="TCP", src="1.1.1.1", dst="2.2.2.2", sport=1000, dport=80,
       flags="", length=100, dns_query=""):
    """构造一个 PacketInfo（ts 为秒偏移，自动转为时间戳字符串）"""
    t = (datetime(2024, 1, 1, 0, 0, 0) + timedelta(seconds=ts)).strftime("%Y-%m-%d %H:%M:%S.%f")
    return PacketInfo(
        timestamp=t, protocol=proto, src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport, flags=flags, length=length,
        dns_query=dns_query,
    )


def make_window_traffic(packets_per_window, windows, window_sec=10, **kw):
    """构造均匀流量：每窗口 packets_per_window 个包"""
    pkts = []
    for w in range(windows):
        for i in range(packets_per_window):
            pkts.append(mk(w * window_sec + i * 0.01, **kw))
    return pkts


@pytest.fixture
def normal_traffic():
    """正常流量：30 窗口 × 10 包，纯 ACK"""
    return make_window_traffic(10, 30, flags="ACK")


@pytest.fixture
def burst_traffic():
    """突发流量：30 窗口 × 80 包（8 倍突变）"""
    return make_window_traffic(80, 30, flags="ACK")
