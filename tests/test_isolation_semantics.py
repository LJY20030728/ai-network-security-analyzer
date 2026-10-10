# -*- coding: utf-8 -*-
"""
孤立森林告警语义 与 golden 样本不变性 的回归测试

锁定两个已确认缺陷：

1. 孤立森林是**双向**统计异常检测器，而安全语义**单向**（威胁 = 资源偏高）。
   此前高侧与低侧异常被同等计入告警，导致在正常流量上产生 5 条告警，
   其中 4 条是「流量比基线安静」——`verify_golden.py` 因此 exit 1。
   现改为：高侧 → 告警；低侧 → `behavioral_observations`（非告警）。

2. `tools/verify_baseline_value.py` 每次运行都会**删除并重建**
   `data/samples/golden/` 下的 burst.pcap / lightscan.pcap，静默改写了回归
   测试的输入数据。现改为默认写入 `data/samples/generated/`，
   仅在显式 `--update-golden` 时才改动 golden。

本文件为新增测试，不修改任何既有测试。
"""
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.isolation_detector import DIMENSIONS, IsolationDetector  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------
# 方向判定：高侧 / 低侧
# ----------------------------------------------------------------------

def _detector_with_medians(medians):
    det = IsolationDetector()
    det._medians = dict(medians)
    return det


def test_direction_high_when_above_median():
    det = _detector_with_medians({"window_packets": 10.0, "window_bytes": 500.0,
                                  "window_syn": 1.0, "window_dports": 2.0})
    assert det._deviation_direction({"window_packets": 50.0}, "window_packets") == "high"


def test_direction_low_when_below_median():
    det = _detector_with_medians({"window_packets": 10.0, "window_bytes": 500.0,
                                  "window_syn": 1.0, "window_dports": 2.0})
    assert det._deviation_direction({"window_packets": 1.0}, "window_packets") == "low"


def test_direction_zero_median_any_positive_is_high():
    """window_syn 常态中位数为 0：任何正值即为偏高。"""
    det = _detector_with_medians({"window_syn": 0.0})
    assert det._deviation_direction({"window_syn": 3.0}, "window_syn") == "high"
    assert det._deviation_direction({"window_syn": 0.0}, "window_syn") == "low"


# ----------------------------------------------------------------------
# detect_windows 输出必须带 direction，且低侧不给威胁级 severity
# ----------------------------------------------------------------------

def _learn_and_detect(windows_train, windows_test, contamination=0.1):
    det = IsolationDetector(contamination=contamination, random_state=42)
    det.learn_windows(windows_train)
    return det, det.detect_windows(windows_test)


def _win(packets, byte, syn, dports):
    return {"window_packets": packets, "window_bytes": byte,
            "window_syn": syn, "window_dports": dports}


def _real_normal_windows():
    """用真实 golden 正常样本聚合出窗口（比合成构造更能代表实际行为）。"""
    from src.analysis.baseline import WindowAccumulator
    from src.capture.pcap_parser import PcapParser

    path = os.path.join(ROOT, "data", "samples", "golden", "normal.pcap")
    if not os.path.isfile(path):
        return None
    pkts = PcapParser().parse_file(path)
    acc = WindowAccumulator(window_sec=10)
    for p in pkts:
        acc.add(p)
    return pkts, acc.get_windows()


@pytest.mark.skipif(not os.path.isfile(
    os.path.join(ROOT, "data", "samples", "golden", "normal.pcap")),
    reason="缺少 golden 正常样本")
def test_real_normal_traffic_is_not_flagged_as_threat():
    """核心回归：真实正常流量的 ML 异常不得再作为威胁告警暴露。

    修复前：正常流量产生 5 条 ML_ANOMALY 告警（其中 4 条为低侧），
    verify_golden.py 因此 exit 1。修复后：低侧全部归入行为观测。
    """
    from src.analysis.flow_extractor import TrafficAnalyzer

    pkts, _ = _real_normal_windows()
    ta = TrafficAnalyzer(use_baseline=True)
    ta.learn_baseline(pkts)

    iso = ta.isolation_detector
    assert iso is not None and iso.learned

    from src.analysis.baseline import WindowAccumulator
    acc = WindowAccumulator(window_sec=ta.baseline.window_sec)
    for p in pkts:
        acc.add(p)
    windows = acc.get_windows()

    res = iso.detect_windows(windows)
    anoms = res.get("anomalies", [])
    assert anoms, "合成/真实正常样本上应至少检出若干统计偏差（否则该断言无意义）"

    # 每个异常都必须带方向
    assert all(a.get("direction") in ("high", "low") for a in anoms)

    # 低侧必须为 INFO（非威胁级）
    for a in anoms:
        if a["direction"] == "low":
            assert a["severity"] == "INFO", a

    # 合并后：低侧不进入告警
    anomalies = {
        "total_alerts": 0, "alerts": [], "behavioral_observations": [],
        "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    merged = ta._merge_ml_anomalies(anomalies, res)
    highs = [a for a in merged["alerts"] if a["type"] == "ML_ANOMALY"]
    lows = merged["behavioral_observations"]
    assert merged["total_alerts"] == len(highs)
    assert merged["total_alerts"] <= 1, \
        f"正常流量仍产生 {merged['total_alerts']} 条 ML 威胁告警（修复前为 5）"
    assert len(lows) >= 1, "低侧偏差应被记录为行为观测"


# ----------------------------------------------------------------------
# 合并层：高侧进告警、低侧进 behavioral_observations
# ----------------------------------------------------------------------

def test_merge_routes_low_side_to_observations():
    from src.analysis.flow_extractor import TrafficAnalyzer

    ta = TrafficAnalyzer()
    anomalies = {
        "total_alerts": 0, "alerts": [], "behavioral_observations": [],
        "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    ml_result = {"anomalies": [
        {"window_index": 1, "dimension": "window_packets", "direction": "high",
         "anomaly_score": -0.3, "score_threshold": 0.0, "severity": "HIGH"},
        {"window_index": 2, "dimension": "window_packets", "direction": "low",
         "anomaly_score": -0.2, "score_threshold": 0.0, "severity": "INFO"},
    ]}
    out = ta._merge_ml_anomalies(anomalies, ml_result)

    assert out["total_alerts"] == 1, "低侧异常不得计入告警数"
    assert len(out["behavioral_observations"]) == 1
    assert out["behavioral_observations"][0]["direction"] == "low"
    assert out["ml_anomalies_added"] == 1
    assert out["ml_observations_added"] == 1
    # 低侧不得出现在 severity 统计里（INFO 不属于四档威胁级别）
    assert sum(out["severity_summary"].values()) == 1


def test_merge_all_low_side_yields_zero_alerts():
    from src.analysis.flow_extractor import TrafficAnalyzer

    ta = TrafficAnalyzer()
    anomalies = {
        "total_alerts": 0, "alerts": [], "behavioral_observations": [],
        "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    ml_result = {"anomalies": [
        {"window_index": i, "dimension": "window_packets", "direction": "low",
         "anomaly_score": -0.1 * i, "score_threshold": 0.0, "severity": "INFO"}
        for i in range(1, 4)
    ]}
    out = ta._merge_ml_anomalies(anomalies, ml_result)
    assert out["total_alerts"] == 0
    assert len(out["behavioral_observations"]) == 3


def test_merge_handles_empty_and_missing_direction():
    """旧数据可能没有 direction 字段：缺省按高侧处理，不得丢告警。"""
    from src.analysis.flow_extractor import TrafficAnalyzer

    ta = TrafficAnalyzer()
    anomalies = {
        "total_alerts": 0, "alerts": [], "behavioral_observations": [],
        "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    assert ta._merge_ml_anomalies(dict(anomalies), {"anomalies": []})["total_alerts"] == 0
    out = ta._merge_ml_anomalies(anomalies, {"anomalies": [
        {"window_index": 0, "dimension": "window_syn",
         "anomaly_score": -0.5, "score_threshold": 0.0, "severity": "HIGH"}]})
    assert out["total_alerts"] == 1


# ----------------------------------------------------------------------
# golden 样本不变性
# ----------------------------------------------------------------------

def test_verify_baseline_value_defaults_to_non_golden_output():
    """默认必须写到 generated/，只有 --update-golden 才动 golden。"""
    src = open(os.path.join(ROOT, "tools", "verify_baseline_value.py"),
               encoding="utf-8").read()
    assert "samples\", \"generated\"" in src or "samples/generated" in src, \
        "默认输出目录未指向 generated/"
    assert "--update-golden" in src, "缺少显式刷新开关"
    # _save 必须以 update_golden 为开关
    sig = inspect.signature(
        __import__("tools.verify_baseline_value", fromlist=["x"])._save)
    assert "update_golden" in sig.parameters


@pytest.mark.skipif(
    not os.path.isfile(os.path.join(ROOT, "data", "samples", "golden", "burst.pcap")),
    reason="缺少 golden 样本")
def test_golden_samples_are_not_modified_by_default_run():
    """默认运行不得改动 golden 下的 PCAP（按 mtime+size 判定）。"""
    import subprocess

    golden_dir = os.path.join(ROOT, "data", "samples", "golden")
    names = ["burst.pcap", "lightscan.pcap"]
    before = {}
    for n in names:
        p = os.path.join(golden_dir, n)
        if os.path.isfile(p):
            st = os.stat(p)
            before[n] = (st.st_size, st.st_mtime_ns)

    subprocess.run([sys.executable, "tools/verify_baseline_value.py"],
                   cwd=ROOT, capture_output=True, timeout=900)

    for n, prev in before.items():
        st = os.stat(os.path.join(golden_dir, n))
        assert (st.st_size, st.st_mtime_ns) == prev, f"golden 样本被改动: {n}"
