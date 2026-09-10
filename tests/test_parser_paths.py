# -*- coding: utf-8 -*-
"""解析层 + 路径工具单测（修正版：monkeypatch sys.frozen/_MEIPASS）"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest
from scapy.all import IP, TCP, UDP, ARP, Ether

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
