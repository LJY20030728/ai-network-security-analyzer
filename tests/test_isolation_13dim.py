# -*- coding: utf-8 -*-
"""
测试孤立森林13维特征提取（v3.4.0 新增）

验证：
1. 特征维度为13
2. 孤立森林6维特征（available/count/ratio/mean_score/max_score/top_dim_risk）正确提取
3. ml_profile 包含实际检测结果时特征非零
4. ml_profile 为空时孤立森林特征全零
"""
import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.stacking_fusion import ThreeEngineStacking, THREE_ENGINE_FEATURE_NAMES


def test_feature_dimension():
    """特征维度应为13"""
    assert len(THREE_ENGINE_FEATURE_NAMES) == 13
    f = ThreeEngineStacking(model_path=None)
    assert f.feature_dim == 13


def test_isolation_features_with_ml_profile():
    """ml_profile 包含实际检测结果时，孤立森林6维特征应非零"""
    f = ThreeEngineStacking(model_path=None)
    feats = f.extract_features(
        anomalies={"alerts": []},
        baseline_result={},
        ml_profile={
            "learned": True,
            "anomaly_windows": 5,
            "total_windows": 10,
            "mean_anomaly_score": -0.15,
            "max_anomaly_score": -0.25,
            "top_dimension": "window_syn",
            "score_threshold": -0.05,
        },
    )
    assert feats.shape == (13,)
    # 孤立森林特征索引 7-12
    assert feats[7] == 1.0   # isolation_available
    assert feats[8] > 0      # isolation_anomaly_count
    assert feats[9] > 0      # isolation_anomaly_ratio
    assert feats[10] > 0     # isolation_mean_score (归一化后)
    assert feats[11] > 0     # isolation_max_score
    assert feats[12] == 1.0  # isolation_top_dim_risk (syn=1.0)


def test_isolation_features_empty():
    """ml_profile 为空时，孤立森林特征应全零"""
    f = ThreeEngineStacking(model_path=None)
    feats = f.extract_features(
        anomalies={"alerts": []},
        baseline_result={},
        ml_profile=None,
    )
    assert feats[7] == 0.0   # isolation_available
    assert feats[8] == 0.0   # isolation_anomaly_count
    assert feats[9] == 0.0   # isolation_anomaly_ratio
    assert feats[10] == 0.0  # isolation_mean_score
    assert feats[11] == 0.0  # isolation_max_score
    assert feats[12] == 0.0  # isolation_top_dim_risk


def test_top_dim_risk_levels():
    """top_dimension 风险等级：syn/dports=1.0, packets/bytes=0.5, 其他=0.0"""
    f = ThreeEngineStacking(model_path=None)
    for dim, expected in [("window_syn", 1.0), ("window_dports", 1.0),
                          ("window_packets", 0.5), ("window_bytes", 0.5),
                          ("unknown", 0.0), ("", 0.0)]:
        feats = f.extract_features(
            anomalies={"alerts": []},
            baseline_result={},
            ml_profile={
                "learned": True, "anomaly_windows": 1, "total_windows": 10,
                "mean_anomaly_score": -0.1, "max_anomaly_score": -0.2,
                "top_dimension": dim, "score_threshold": -0.05,
            },
        )
        assert feats[12] == expected, f"dim={dim} expected={expected} got={feats[12]}"


def test_predict_with_13dim_model():
    """使用13维模型预测时不应回退到固定权重"""
    model_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "models", "stacking_meta_learner.joblib"
    )
    if not os.path.exists(model_path):
        return  # 模型未训练时跳过
    f = ThreeEngineStacking(model_path=model_path)
    assert f.meta_learner is not None
    result = f.predict(
        anomalies={"alerts": [{"type": "SYN_FLOOD", "severity": "HIGH"}]},
        baseline_result={"drift": True, "multi_dim_alerts": True},
        ml_profile={
            "learned": True, "anomaly_windows": 5, "total_windows": 10,
            "mean_anomaly_score": -0.15, "max_anomaly_score": -0.25,
            "top_dimension": "window_syn", "score_threshold": -0.05,
        },
    )
    assert result["confidence_source"] == "model"
    assert "isolation_forest" in result["contributions"]
    # 孤立森林贡献度应大于0（修复bug后）
    assert result["contributions"]["isolation_forest"] > 0


if __name__ == "__main__":
    test_feature_dimension()
    test_isolation_features_with_ml_profile()
    test_isolation_features_empty()
    test_top_dim_risk_levels()
    test_predict_with_13dim_model()
    print("所有孤立森林13维测试通过")
