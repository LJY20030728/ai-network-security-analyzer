# -*- coding: utf-8 -*-
"""解析层 + 路径工具单测（修正版：monkeypatch sys.frozen/_MEIPASS）"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest
from scapy.all import IP, TCP, UDP, ARP, DNS, DNSQR, DNSRR, Ether

from src.capture.packet_parser import PacketParser
from src.utils.paths import app_root, data_dir, asset_dir, seed_assets


@pytest.fixture
def parser():
    return PacketParser()


class TestPacketParser:
    def test_parse_tcp(self, parser):
        pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80, flags="S")
        info = parser.parse(pkt)
        assert info.protocol == "TCP"
        assert info.src_ip == "10.0.0.1"
        assert info.dst_port == 80
        assert "SYN" in info.flags

    def test_parse_udp(self, parser):
        pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=53, dport=53)
        info = parser.parse(pkt)
        assert info.protocol == "UDP"
        assert info.src_port == 53

    def test_parse_arp(self, parser):
        pkt = Ether()/ARP(psrc="10.0.0.1", pdst="10.0.0.2")
        info = parser.parse(pkt)
        assert info.protocol == "ARP"
        assert info.src_ip == "10.0.0.1"

    def test_timestamp_format(self, parser):
        pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1, dport=2)
        pkt.time = 1700000000.123
        info = parser.parse(pkt)
        assert info.timestamp.startswith("2023-")
        assert "." in info.timestamp  # 毫秒精度


class TestDnsParsing:
    """DNS 解析回归测试。

    背景（两个真实缺陷）：
      1. scapy 2.7 下 DNS 应答包的 ancount 可能为 None（字段未解析），
         原代码 `packet[DNS].ancount > 0` 会抛
         TypeError: '>' not supported between instances of 'NoneType' and 'int'，
         且该比较不在 try 保护范围内 → 整个 PCAP 解析中断。
      2. scapy 2.7 已把 qd/an/ns/ar 改为 PacketListField，`packet[DNS].an`
         是**列表**，原代码 `packet[DNS].an.rdata` 必然抛 AttributeError，
         被 try 静默吞掉 → 真实流量上 dns_response 永远为空。
    """

    def test_dns_query(self, parser):
        pkt = (Ether()/IP(src="10.0.0.1", dst="8.8.8.8")/UDP(sport=53000, dport=53) /
               DNS(id=1, qr=0, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
        pkt.time = 1700000000.0
        info = parser.parse(pkt)
        assert info.protocol == "DNS"
        assert "example.com" in info.dns_query
        assert info.dns_response == ""      # 查询包不应有应答内容

    def test_dns_response_extracts_rdata(self, parser):
        """应答记录必须能被提取（此前因 an 是列表而永远为空）"""
        pkt = (Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=53000) /
               DNS(id=0x1234, qr=1, rd=1, ra=1,
                   qd=DNSQR(qname="example.com", qtype="A"),
                   an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")))
        pkt.time = 1700000000.0
        info = parser.parse(pkt)
        assert info.protocol == "DNS"
        assert info.dns_response == "93.184.216.34"

    def test_dns_response_multiple_records(self, parser):
        """多条应答记录时取首条，且不得抛异常"""
        pkt = (Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=53000) /
               DNS(id=2, qr=1, rd=1, ra=1,
                   qd=DNSQR(qname="multi.com", qtype="A"),
                   an=DNSRR(rrname="multi.com", type="A", rdata="1.1.1.1") /
                      DNSRR(rrname="multi.com", type="A", rdata="2.2.2.2")))
        pkt.time = 1700000000.0
        info = parser.parse(pkt)
        assert info.dns_response == "1.1.1.1"

    def test_dns_ancount_none_does_not_crash(self, parser):
        """★ 核心回归：ancount 为 None 时不得抛 TypeError 中断解析"""
        pkt = (Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=53000) /
               DNS(id=3, qr=1, rd=1, ra=1,
                   qd=DNSQR(qname="none.com", qtype="A"),
                   an=DNSRR(rrname="none.com", type="A", rdata="9.9.9.9")))
        pkt.time = 1700000000.0
        # 模拟 scapy 未解析出 ancount 的情形
        pkt[DNS].ancount = None
        info = parser.parse(pkt)          # 修复前这里抛 TypeError
        assert info.protocol == "DNS"
        assert info.dns_response == "9.9.9.9"

    def test_dns_ancount_declared_but_an_empty(self, parser):
        """ancount 声称有应答但 an 段为空（本项目部分 golden 样本正是如此）：
        不得抛异常，dns_response 应为空字符串。"""
        pkt = (Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=53000) /
               DNS(id=6, qr=1, rd=1, ra=1, qd=DNSQR(qname="empty.com", qtype="A")))
        pkt.time = 1700000000.0
        pkt[DNS].ancount = 1          # 声明有 1 条，但没有实际记录
        info = parser.parse(pkt)
        assert info.protocol == "DNS"
        assert info.dns_response == ""

    def test_dns_response_without_an_section(self, parser):
        """qr=1 但没有 an 段（如 NXDOMAIN）不得抛异常"""
        pkt = (Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=53000) /
               DNS(id=4, qr=1, rd=1, ra=1, rcode=3,
                   qd=DNSQR(qname="nxdomain.com", qtype="A")))
        pkt.time = 1700000000.0
        info = parser.parse(pkt)
        assert info.protocol == "DNS"
        assert info.dns_response == ""

    def test_dns_non_ascii_qname_does_not_crash(self, parser):
        """畸形/非 UTF-8 域名不得中断解析"""
        pkt = (Ether()/IP(src="10.0.0.1", dst="8.8.8.8")/UDP(sport=53000, dport=53) /
               DNS(id=5, qr=0, rd=1, qd=DNSQR(qname=b"\xff\xfe\x00bad", qtype="A")))
        pkt.time = 1700000000.0
        info = parser.parse(pkt)          # decode(errors='ignore') 应兜住
        assert info.protocol == "DNS"


@pytest.fixture
def fake_frozen(tmp_path, monkeypatch):
    """模拟 PyInstaller 打包态：app_root = tmp_path"""
    exe = os.path.join(str(tmp_path), "app.exe")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", exe, raising=False)
    return tmp_path


class TestPaths:
    def test_app_root_dev(self):
        root = app_root()
        assert os.path.isdir(root)
        assert os.path.exists(os.path.join(root, "src"))

    def test_app_root_frozen(self, fake_frozen):
        assert app_root() == str(fake_frozen)

    def test_data_dir_under_root(self, fake_frozen):
        d = data_dir("baselines")
        assert d == os.path.join(str(fake_frozen), "data", "baselines")
        assert os.path.isdir(d)

    def test_asset_dir_meipass(self, tmp_path, monkeypatch):
        meipass = os.path.join(str(tmp_path), "_internal")
        monkeypatch.setattr(sys, "_MEIPASS", meipass, raising=False)
        assert asset_dir("models") == os.path.join(meipass, "models")

    def test_asset_dir_dev(self, tmp_path, monkeypatch):
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)
        assert asset_dir() == app_root()

    def test_seed_assets_copies(self, tmp_path, monkeypatch):
        """种子迁移：_MEIPASS 模式下内置基线复制到数据目录，且不覆盖已有"""
        meipass = tmp_path / "_internal"
        (meipass / "data" / "baselines").mkdir(parents=True)
        (meipass / "data" / "baselines" / "default.json").write_text(
            '{"name": "default"}', encoding="utf-8")
        exe = str(tmp_path / "app.exe")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", exe, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
        seed_assets()
        target = tmp_path / "data" / "baselines" / "default.json"
        assert target.exists()
        assert "default" in target.read_text(encoding="utf-8")

        # 已有文件不覆盖
        target.write_text('{"name": "custom"}', encoding="utf-8")
        seed_assets()
        assert "custom" in target.read_text(encoding="utf-8")
