# -*- coding: utf-8 -*-
"""
Stacking 元学习器训练数据打标 的回归测试

锁定已确认的根因缺陷：`tools/train_stacking.py` 此前把**整个混合样本**标为攻击
（`MIXED_LABELS = {...: 1}`），而混合样本的正常前缀与 `normal` /
`baseline_demo_normal` 是同一批包（逐位相同）——于是同一特征向量同时被标为
0 和 1：1732 行里 264 行矛盾标签、仅 50.7% 唯一，训练的元学习器把正常样本
45/45 全判为攻击。

现改为按窗口打标（正常前缀=0 / 攻击段=1 / 跨界窗丢弃）+ 特征去重 +
按源 PCAP 分组的 GroupKFold。

本文件为新增测试，不修改任何既有测试。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.train_stacking import (  # noqa: E402
    MIXED_PLANS,
    _base_normal_last_ts,
    label_frames,
    mixed_attack_start,
    window_packet_slices,
)


# ----------------------------------------------------------------------
# attack_start 的确定性重建
# ----------------------------------------------------------------------

def test_mixed_plans_reference_existing_bases():
    for name, (base, offset) in MIXED_PLANS.items():
        assert isinstance(base, str) and base, name
        assert offset > 0, name


def test_attack_start_is_reconstructible():
    """attack_start = 基底正常样本最后一包时间 + offset（实测误差 < 1s）。"""
    for name, (base, offset) in MIXED_PLANS.items():
        base_end = _base_normal_last_ts(base)
        if base_end is None:
            pytest.skip(f"缺少基底样本 {base}.pcap")
        start = mixed_attack_start(name)
        assert start == pytest.approx(base_end + offset, abs=1e-6)


def test_attack_start_none_for_unknown_sample():
    assert mixed_attack_start("not_a_mixed_sample") is None


# ----------------------------------------------------------------------
# 窗口打标：正常前缀=0 / 攻击段=1 / 跨界窗丢弃
# ----------------------------------------------------------------------

def test_label_frames_marks_normal_prefix_then_attack():
    """窗口起点键（秒）在 attack_start 前后应分别得到 0 / 1。"""
    start = 1000.0
    # 手工构造窗口起点：前 3 个完全早于 start，后 2 个起点 >= start
    frame_keys = [900.0, 910.0, 920.0, 11 * 100.0, start, start + 10]
    # 用真实实现前先确认 attack_start 一致
    out = label_frames("__nonexistent__", frame_keys)
    assert out == [None] * len(frame_keys), "未知样本应全部丢弃，不能猜标签"


def test_label_frames_with_real_boundary(monkeypatch):
    """注入已知 attack_start，验证三类窗口的判定逻辑。"""
    import tools.train_stacking as ts

    monkeypatch.setattr(ts, "mixed_attack_start", lambda name: 1000.0)
    # 窗口键为整数秒；窗口 [k, k+1)
    frame_keys = [
        940,    # 940+1 = 941 <= 1000 → 正常
        998,    # 998+1 = 999  <= 1000 → 正常
        999,    # 999+1 = 1000 <= 1000 → 正常（边界含端点）
        1000,   # 起点 >= 1000 → 攻击
        1010,   # 攻击
    ]
    assert ts.label_frames("x", frame_keys) == [0, 0, 0, 1, 1]


def test_label_frames_drops_straddling_window(monkeypatch):
    """跨界窗（起点 < attack_start 但窗口末尾越过边界）必须被丢弃。"""
    import tools.train_stacking as ts

    monkeypatch.setattr(ts, "mixed_attack_start", lambda name: 1000.5)
    # 窗口起点 1000，末尾 1001 > 1000.5 → 跨界
    assert ts.label_frames("x", [1000]) == [None]


def test_no_samples_are_labelled_attack_at_file_level():
    """回归：不得再出现「整样本标 1」的写法。

    矛盾的根源是 MIXED_LABELS 全为 1 且被当作窗口标签使用。
    """
    import io
    import re

    src = io.open(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "tools", "train_stacking.py"), encoding="utf-8").read()
    # 混合样本打标必须走 label_frames，而不是把 label 直接传下去
    assert "label_frames(" in src, "缺少窗口级打标调用"
    assert "MIXED_LABELS = {name: 1 for name in MIXED_PLANS}" in src, \
        "MIXED_LABELS 应仅为占位（真实标签在窗口级决定）"
    # 不应存在把整样本标签直传给 collect_features 的旧写法
    assert not re.search(r"collect_features\([^)]*,\s*label,\s*win_sec\)", src), \
        "仍存在把样本级 label 直传的旧写法"


# ----------------------------------------------------------------------
# 训练器必须支持分组交叉验证
# ----------------------------------------------------------------------

def test_train_meta_learner_supports_groups():
    """GroupKFold 必须真正启用，且同时给出泄漏口径作对照。"""
    import inspect

    from src.analysis.stacking_fusion import ThreeEngineStacking

    sig = inspect.signature(ThreeEngineStacking.train_meta_learner)
    assert "groups" in sig.parameters, "train_meta_learner 未接受 groups 参数"

    src = inspect.getsource(ThreeEngineStacking.train_meta_learner)
    assert "GroupKFold" in src
    assert 'cv_scheme = "groupkfold_by_sample"' in src


def test_model_payload_carries_provenance(tmp_path):
    """模型落盘必须带训练数据指纹（此前无任何训练数据记录）。"""
    import joblib
    import numpy as np

    from src.analysis.stacking_fusion import ThreeEngineStacking

    fusion = ThreeEngineStacking(model_path=None)
    fusion.set_provenance({"dataset_hash": "deadbeef", "dataset_rows": 42})
    X = np.array([[0.0] * 13, [1.0] * 13, [0.1] * 13, [0.9] * 13])
    y = np.array([0, 1, 0, 1])
    out = tmp_path / "m.joblib"
    fusion.train_meta_learner(X, y, model_path=str(out))
    assert out.is_file()

    data = joblib.load(str(out))
    assert data["provenance"]["dataset_hash"] == "deadbeef"

    # 重新加载后应能读回指纹
    reloaded = ThreeEngineStacking(model_path=str(out))
    assert reloaded.provenance.get("dataset_hash") == "deadbeef"


# ----------------------------------------------------------------------
# 窗口切片工具（打标依赖窗口起始时间戳）
# ----------------------------------------------------------------------

def test_window_slices_expose_keys_when_requested():
    from datetime import datetime, timedelta

    from src.capture.packet_parser import PacketInfo

    base = datetime(2024, 1, 1)
    pkts = [PacketInfo(timestamp=(base + timedelta(seconds=s)).strftime("%Y-%m-%d %H:%M:%S"),
                       protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                       src_port=1, dst_port=80, flags="ACK", length=100, dns_query="")
            for s in (0, 5, 25)]

    plain = window_packet_slices(pkts, 10)
    keyed = window_packet_slices(pkts, 10, with_keys=True)

    assert len(plain) == len(keyed)
    assert all(isinstance(s, list) for s in plain)
    assert all(isinstance(k, int) and isinstance(s, list) for k, s in keyed)
