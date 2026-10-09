# -*- coding: utf-8 -*-
"""
测试默认基线自动加载（v3.4.0 新增）

验证：
1. 默认基线文件存在
2. TrafficAnalyzer 初始化时自动加载默认基线
3. baseline_source = "default"
4. 用户手动学习后 baseline_source = "user"
5. 默认基线可用于检测
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.baseline import TrafficBaseline


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASELINE = os.path.join(ROOT, "data", "baselines", "default_baseline.json")


def test_default_baseline_file_exists():
    """默认基线文件应存在"""
    assert os.path.exists(DEFAULT_BASELINE), f"默认基线文件不存在: {DEFAULT_BASELINE}"
    assert os.path.getsize(DEFAULT_BASELINE) > 0


def test_default_baseline_loadable():
    """默认基线应可加载且已学习"""
    baseline = TrafficBaseline.load(DEFAULT_BASELINE)
    assert baseline is not None
    assert baseline.learned is True
    assert len(baseline.profile) == 4  # 4个维度


def test_auto_load_on_init():
    """TrafficAnalyzer 初始化时应自动加载默认基线"""
    analyzer = TrafficAnalyzer(use_baseline=True)
    assert analyzer.baseline is not None
    assert analyzer.baseline.learned is True
    assert analyzer.baseline_source == "default"


def test_no_auto_load_when_disabled():
    """use_baseline=False 时不应加载基线"""
    analyzer = TrafficAnalyzer(use_baseline=False)
    assert analyzer.baseline is None
    assert analyzer.baseline_source == "none"


def test_user_learn_overrides_default():
    """用户手动学习后 baseline_source 应为 user"""
    analyzer = TrafficAnalyzer(use_baseline=True)
    assert analyzer.baseline_source == "default"
    # 手动学习（用少量包，可能不满足最小窗口数，但 source 应更新）
    from src.capture.packet_parser import PacketInfo
    packets = [PacketInfo(
        timestamp="2026-01-01 00:00:00.000",
        protocol="TCP", src_ip="10.0.0.1", src_port=12345,
        dst_ip="10.0.0.2", dst_port=80, length=100, flags="S",
    ) for _ in range(50)]
    analyzer.learn_baseline(packets)
    # 即使学习失败（窗口不足），source 也应标记为 user
    assert analyzer.baseline_source == "user"


def test_default_baseline_usable_for_detection():
    """默认基线应可用于检测"""
    analyzer = TrafficAnalyzer(use_baseline=True)
    assert analyzer.baseline is not None
    assert analyzer.baseline.learned
    # 构造一个异常窗口（包数远超基线中位数）
    from src.capture.packet_parser import PacketInfo
    from src.analysis.baseline import WindowAccumulator
    packets = [PacketInfo(
        timestamp=f"2026-01-01 00:00:{i:02d}.000",
        protocol="TCP", src_ip="10.0.0.1", src_port=12345 + i,
        dst_ip="10.0.0.2", dst_port=80, length=100, flags="S",
    ) for i in range(60)]
    win_acc = WindowAccumulator(window_sec=10)
    for p in packets:
        win_acc.add(p)
    windows = win_acc.get_windows()
    if windows:
        result = analyzer.baseline.detect_windows(windows)
        assert "deviations" in result or "multi_dim_alerts" in result


if __name__ == "__main__":
    test_default_baseline_file_exists()
    test_default_baseline_loadable()
    test_auto_load_on_init()
    test_no_auto_load_when_disabled()
    test_user_learn_overrides_default()
    test_default_baseline_usable_for_detection()
    print("所有默认基线测试通过")
