# -*- coding: utf-8 -*-
"""
三引擎归因（contributions）的回归测试

## 为什么要写这个文件

`test_isolation_13dim.py` 里原有的断言是：

    assert "isolation_forest" in result["contributions"]
    assert result["contributions"]["isolation_forest"] > 0

**这条断言拦不住任何实际错误** —— 一个恒返回 `{...: 0.34, ...: 0.33}` 的假实现
同样能通过。事实上原实现（对每组特征取算术平均再归一化）正是靠这条弱断言
存活了很久，而它给出的"贡献"与模型真实归因相差 3 倍、方向甚至相反。

## 因此本文件断言的是「归因的数学正确性」而非「键存在」

核心判据：LogisticRegression 的 logit 可精确分解为 `intercept + Σ wᵢxᵢ`。
所以对任意特征向量 x，本模块给出的分组占比**必须等于**独立算出的
`Σ_{i∈组} |wᵢxᵢ| / Σ_i |wᵢxᵢ|`。

这个等式是"新算法"与"旧算法"的**分水岭**：
    · 新算法（coef × feature）→ 必然满足
    · 旧算法（组内均值）      → 一般不等于，除非特征恰好各维相等

故本测试能真正防止回归。
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.helpers import force_utf8_stdout  # noqa: E402

force_utf8_stdout()

from src.analysis.stacking_fusion import (  # noqa: E402
    ENGINE_ORDER,
    THREE_ENGINE_FEATURE_NAMES,
    FALLBACK_WEIGHTS,
    ThreeEngineStacking,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "models", "stacking_meta_learner.joblib")

requires_model = pytest.mark.skipif(
    not os.path.exists(MODEL_PATH),
    reason="元学习器未训练（models/stacking_meta_learner.joblib 不存在）",
)

# 特征分组边界（与 THREE_ENGINE_FEATURE_NAMES 的顺序强耦合）
GROUP_SLICES = {
    "rule_based": slice(0, 4),
    "baseline": slice(4, 7),
    "isolation_forest": slice(7, 13),
}


def _fresh_stack():
    """加载一个独立的融合器实例（避免共享全局单例状态）"""
    return ThreeEngineStacking(model_path=MODEL_PATH)


# ----------------------------------------------------------------------
# 归因的数学正确性
# ----------------------------------------------------------------------

@requires_model
def test_attribution_equals_coefficient_decomposition():
    """归因必须等于 |wᵢxᵢ| 的分组占比 —— 独立重算后逐项对比。

    这是防回归的核心断言：旧实现（组内均值）在此必然失败。
    """
    f = _fresh_stack()
    assert f._coef_cache is not None, "系数未缓存，归因不可能来自模型"

    coef = f._coef_cache
    # 构造一个各维**互不相等**的特征向量：若实现退化为"组内均值"，
    # 结果会与 coef 分解不同（各维相等时两者巧合一致，故不能用全 1 向量）
    rng = np.random.default_rng(20261015)
    x = rng.random(len(THREE_ENGINE_FEATURE_NAMES))
    # 按特征量纲放大（rule_max_severity 取值 0~4），让量纲差异更明显
    x[2] *= 4.0

    # 独立重算期望值（不复用被测代码的算法）
    terms = np.abs(coef * x)
    expected_raw = {
        name: float(terms[sl].sum()) for name, sl in GROUP_SLICES.items()
    }
    total = sum(expected_raw.values())
    expected = {k: v / total for k, v in expected_raw.items()}

    got = f._engine_attribution(x)["contributions"]

    for name in ENGINE_ORDER:
        assert got[name] == pytest.approx(expected[name], abs=1e-4), (
            f"{name} 归因不符：得到 {got[name]}，期望 {expected[name]:.4f}。"
            f"若两者差异明显，说明归因实现退回了『组内均值』而非『系数分解』。"
        )


@requires_model
def test_attribution_differs_from_naive_group_mean():
    """反向断言：归因必须**不等于**"组内均值归一化"（旧算法的特征签名）。

    这条测试的意义：如果哪天有人把实现改回旧算法，它会立刻失败。
    它同时证明了本测试对两种算法有区分力（不是恒真断言）。
    """
    f = _fresh_stack()
    rng = np.random.default_rng(7)
    x = rng.random(len(THREE_ENGINE_FEATURE_NAMES))
    x[2] *= 4.0        # 量纲差异

    naive_raw = np.array([
        float(np.mean(x[GROUP_SLICES[n]])) for n in ENGINE_ORDER
    ])
    naive = naive_raw / naive_raw.sum()

    got = f._engine_attribution(x)["contributions"]
    got_vec = np.array([got[n] for n in ENGINE_ORDER])

    assert not np.allclose(got_vec, naive, atol=1e-3), (
        "归因结果与『组内均值归一化』一致 —— 实现可能被改回了旧算法"
    )


@requires_model
def test_contributions_sum_to_one():
    """三项占比之和必须为 1（允许舍入误差）"""
    f = _fresh_stack()
    rng = np.random.default_rng(1)
    for _ in range(5):
        x = rng.random(len(THREE_ENGINE_FEATURE_NAMES))
        c = f._engine_attribution(x)["contributions"]
        assert sum(c.values()) == pytest.approx(1.0, abs=1e-3), f"和={sum(c.values())}"


@requires_model
def test_logit_matches_manual_computation():
    """logit 必须等于 intercept + Σ wᵢxᵢ（精确，不是近似）"""
    f = _fresh_stack()
    rng = np.random.default_rng(42)
    x = rng.random(len(THREE_ENGINE_FEATURE_NAMES))
    attr = f._engine_attribution(x)
    assert attr["attribution_source"] == "model_coef"
    manual = f._intercept_cache + float(np.dot(f._coef_cache, x))
    assert attr["logit"] == pytest.approx(manual, abs=1e-4)


# ----------------------------------------------------------------------
# 归因来源标注（必须能区分"模型归因"与"兜底权重"）
# ----------------------------------------------------------------------

@requires_model
def test_predict_reports_attribution_source_model():
    """有模型时，predict 必须标注 attribution_source == model_coef"""
    f = _fresh_stack()
    r = f.predict(anomalies={"alerts": [{"type": "SYN_FLOOD", "severity": "HIGH"}]},
                  baseline_result={"drift": True},
                  ml_profile={"learned": True, "anomaly_windows": 3,
                              "total_windows": 10, "mean_anomaly_score": -0.2,
                              "max_anomaly_score": -0.3, "top_dimension": "window_syn",
                              "score_threshold": -0.05})
    assert r["attribution_source"] == "model_coef"
    assert r["confidence_source"] == "model"
    assert r["logit"] is not None
    assert sum(r["contributions"].values()) == pytest.approx(1.0, abs=1e-3)


def test_predict_reports_attribution_source_fallback_without_model():
    """无模型时必须如实标注 attribution_source == fallback_weights。

    这条很重要：兜底权重是**人工设定**的，不能冒充"模型归因"。
    """
    f = ThreeEngineStacking(model_path=None)
    assert f.meta_learner is None
    r = f.predict(anomalies={"alerts": [{"type": "X", "severity": "LOW"}]})
    assert r["attribution_source"] == "fallback_weights"
    assert r["logit"] is None
    assert r["intercept_logit"] is None
    # 兜底时应等于 FALLBACK_WEIGHTS 归一化后的占比
    total = sum(FALLBACK_WEIGHTS.values())
    for k in ENGINE_ORDER:
        assert r["contributions"][k] == pytest.approx(
            FALLBACK_WEIGHTS[k] / total, abs=1e-3)


@requires_model
def test_attribution_handles_all_zero_features_with_model():
    """有模型且特征全为 0 时：归因应全为 0（不得除零），来源仍标注 model_coef。

    注意这里必须**用有模型的实例**：无模型时会走兜底分支，
    返回的是人工权重而非 0（见下一个测试）。
    """
    f = _fresh_stack()
    assert f._coef_cache is not None
    out = f._engine_attribution(np.zeros(len(THREE_ENGINE_FEATURE_NAMES)))
    assert out["contributions"] == {k: 0.0 for k in ENGINE_ORDER}
    assert out["attribution_source"] == "model_coef"
    # 特征全 0 时 logit 退化为截距本身（注意返回值已 round 到 4 位，容差须匹配）
    assert out["logit"] == pytest.approx(float(f._intercept_cache), abs=1e-3)


def test_attribution_without_model_uses_fallback_weights():
    """无模型时不计较特征值，直接返回人工权重（并如实标注来源）"""
    f = ThreeEngineStacking(model_path=None)
    out = f._engine_attribution(np.zeros(len(THREE_ENGINE_FEATURE_NAMES)))
    assert out["attribution_source"] == "fallback_weights"
    total = sum(FALLBACK_WEIGHTS.values())
    for k in ENGINE_ORDER:
        assert out["contributions"][k] == pytest.approx(
            FALLBACK_WEIGHTS[k] / total, abs=1e-3)


# ----------------------------------------------------------------------
# 特征维度契约
# ----------------------------------------------------------------------

@requires_model
def test_coef_dimension_matches_feature_names():
    """系数维度必须与特征名数量一致（否则归因与判定都会错位）"""
    f = _fresh_stack()
    assert f._coef_cache is not None
    assert f._coef_cache.shape[0] == len(THREE_ENGINE_FEATURE_NAMES) == 13


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header"]))
