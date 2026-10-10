# -*- coding: utf-8 -*-
"""
三引擎 Stacking 融合层（3.3.0）

三个引擎：
  rule_based        —— 阈值规则引擎（SYN洪水 / 端口扫描 / DNS隧道 / 大流量 / RST风暴）
  baseline          —— EWMA + 中位数/MAD 时序基线（4 维度，含漂移检测）
  isolation_forest  —— 孤立森林无监督异常检测（与基线同窗口输入）

meta_learner：LogisticRegression（轻量、可解释、打包友好）
输入：10 维特征（三个引擎输出的归一化）
输出：is_attack + attack_prob + confidence + 各引擎贡献度

【与早期版本的区别】
  早期版本包含第 4 个引擎"监督模型"（HistGradientBoosting，76 维 CIC 特征）。
  实测验证显示该模型在本项目样本上无有效增量且引入误报
  （见 docs/监督模型增量价值验证.md），故于 3.3.0 整体移除，
  融合层随之改为三引擎，元学习器已按三引擎重新训练。

【诚信约束】
  confidence_source 必须如实标注：
    · "model"              —— 仅由元学习器 predict_proba 得出
    · "weighted_fallback"  —— 元学习器不可用时的固定权重回退（非模型输出）
"""
import os
from typing import Dict, Any, Optional

import numpy as np

try:  # loguru 在运行环境一定存在；评测脚本单独导入时退化到标准库
    from loguru import logger
except Exception:  # pragma: no cover
    import logging
    logger = logging.getLogger(__name__)

# 三引擎特征名（顺序必须与元学习器 feature_order 严格一致）
THREE_ENGINE_FEATURE_NAMES = [
    # === 规则引擎（4 维）===
    "rule_has_alert",          # 是否有告警
    "rule_alert_count_norm",   # 告警总数（归一化，cap=10）
    "rule_max_severity",       # 最高严重度（0=无 1=LOW 2=MEDIUM 3=HIGH 4=CRITICAL）
    "rule_triggered_rules",    # 触发的不同规则数（归一化，cap=5）
    # === 时序基线（3 维）===
    "baseline_deviation_count",    # 基线偏差窗口数（归一化，cap=10）
    "baseline_multi_dim_triggered",# 是否出现多维度联合偏差（0/1）
    "baseline_drifted",            # 基线是否漂移（0/1）
    # === 孤立森林（6 维）===
    "isolation_available",         # 孤立森林是否可用（已学习）
    "isolation_anomaly_count",     # 异常窗口数（归一化，cap=10）
    "isolation_anomaly_ratio",     # 异常窗口占比（0-1）
    "isolation_mean_score",        # 异常窗口平均异常分（归一化，abs(score)/abs(threshold)）
    "isolation_max_score",         # 最异常窗口的异常分（归一化）
    "isolation_top_dim_risk",      # top贡献维度风险等级（syn/dports=1.0, packets/bytes=0.5）
]

ENGINE_ORDER = ("rule_based", "baseline", "isolation_forest")

# 元学习器不可用时的固定权重回退（人工设定，非训练所得）
FALLBACK_WEIGHTS = {"rule_based": 0.4, "baseline": 0.3, "isolation_forest": 0.3}

SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ThreeEngineStacking:
    """三引擎 Stacking 融合器（规则 + 基线 + 孤立森林）"""

    def __init__(self, model_path: Optional[str] = None):
        self.meta_learner = None
        self.model_path = model_path
        self.feature_names = THREE_ENGINE_FEATURE_NAMES
        self.feature_dim = len(THREE_ENGINE_FEATURE_NAMES)
        self.engine_order = list(ENGINE_ORDER)
        # 训练数据指纹（由训练脚本写入，随模型落盘，便于溯源「这个模型是谁训的」）
        self.provenance: Dict[str, Any] = {}
        if model_path and os.path.exists(model_path):
            self.load(model_path)

    # ------------------------------------------------------------------
    # 特征提取
    # ------------------------------------------------------------------
    def extract_features(self, anomalies: Dict[str, Any],
                         baseline_result: Optional[Dict[str, Any]] = None,
                         ml_profile: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        从三个引擎的输出提取 10 维特征向量。

        :param anomalies: 合并后的告警字典（含 alerts / total_alerts / severity_summary）
        :param baseline_result: 基线检测结果（含 drift / multi_dim_alerts）
        :param ml_profile: 孤立森林画像（IsolationDetector.to_dict()）
        """
        anomalies = anomalies or {}
        alerts = anomalies.get("alerts", []) or []

        # === 规则引擎（4 维）===
        alert_count = len(alerts)
        rule_has_alert = 1.0 if alert_count > 0 else 0.0
        rule_alert_count_norm = min(alert_count / 10.0, 1.0)

        max_severity = 0.0
        triggered = set()
        for a in alerts:
            max_severity = max(max_severity, SEVERITY_MAP.get(a.get("severity", "LOW"), 1))
            triggered.add(a.get("type", a.get("rule_type", "unknown")))
        rule_triggered_rules = min(len(triggered) / 5.0, 1.0)

        # === 时序基线（3 维）===
        baseline_result = baseline_result or {}
        b_dev_count = float(baseline_result.get("deviation_windows", 0) or 0)
        # 兼容多种字段名（不同版本/路径返回不同键）
        if not b_dev_count:
            b_dev_count = float(len(alerts_by_detector(alerts, "ewma-statistical-baseline")))
        baseline_deviation_count = min(b_dev_count / 10.0, 1.0)
        baseline_multi_dim = 1.0 if (baseline_result.get("multi_dim_alerts")
                                     or anomalies.get("baseline_multi_dim_alerts")) else 0.0
        drifted = baseline_result.get("drift") or anomalies.get("baseline_drift")
        baseline_drifted = 1.0 if drifted else 0.0

        # === 孤立森林（6 维）===
        ml_profile = ml_profile or {}
        iso_learned = bool(ml_profile.get("learned"))
        isolation_available = 1.0 if iso_learned else 0.0
        iso_count = float(ml_profile.get("anomaly_windows", 0) or 0)
        isolation_anomaly_count = min(iso_count / 10.0, 1.0)
        total_windows = float(ml_profile.get("total_windows", 0) or 0)
        isolation_anomaly_ratio = min(iso_count / total_windows, 1.0) if total_windows else 0.0

        # 新增3维：异常分统计 + top维度风险
        mean_score = float(ml_profile.get("mean_anomaly_score", 0.0) or 0.0)
        max_score = float(ml_profile.get("max_anomaly_score", 0.0) or 0.0)
        threshold = float(ml_profile.get("score_threshold", 0.0) or 0.0)
        # 归一化：异常分是负值，越小越异常。abs(score)/abs(threshold)，cap=1
        denom = abs(threshold) if abs(threshold) > 1e-6 else 1.0
        isolation_mean_score = min(abs(mean_score) / denom, 1.0) if iso_count > 0 else 0.0
        isolation_max_score = min(abs(max_score) / denom, 1.0) if iso_count > 0 else 0.0
        # top贡献维度风险：syn/dports 是高风险（扫描/洪水特征），packets/bytes 是中风险
        top_dim = ml_profile.get("top_dimension", "")
        if top_dim in ("window_syn", "window_dports"):
            isolation_top_dim_risk = 1.0
        elif top_dim in ("window_packets", "window_bytes"):
            isolation_top_dim_risk = 0.5
        else:
            isolation_top_dim_risk = 0.0

        return np.array([
            rule_has_alert, rule_alert_count_norm, max_severity, rule_triggered_rules,
            baseline_deviation_count, baseline_multi_dim, baseline_drifted,
            isolation_available, isolation_anomaly_count, isolation_anomaly_ratio,
            isolation_mean_score, isolation_max_score, isolation_top_dim_risk,
        ], dtype=np.float64)

    # ------------------------------------------------------------------
    # 预测
    # ------------------------------------------------------------------
    def predict(self, anomalies: Dict[str, Any],
                baseline_result: Optional[Dict[str, Any]] = None,
                ml_profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """三引擎融合预测"""
        features = self.extract_features(anomalies, baseline_result, ml_profile)
        meta_used = False

        if self.meta_learner is not None:
            try:
                if hasattr(self.meta_learner, "predict_proba"):
                    prob = float(self.meta_learner.predict_proba(features.reshape(1, -1))[0, 1])
                else:
                    prob = float(self.meta_learner.predict(features.reshape(1, -1))[0])
                meta_used = True
                confidence_source = "model"
            except Exception as e:
                logger.warning(f"Stacking 元学习器预测失败，回退固定权重: {e}")
                prob = self._weighted_fallback(features)
                confidence_source = "weighted_fallback"
        else:
            prob = self._weighted_fallback(features)
            confidence_source = "weighted_fallback"

        is_attack = prob >= 0.5
        confidence = abs(prob - 0.5) * 2  # 0-1

        # 引擎贡献度：按特征分组均值归一化为「占比」（三者和为 1）
        # 注意：特征本身不是概率（如 rule_max_severity 范围 0-4），
        # 直接求均值会得到 >100% 的无意义数字，必须归一化后再展示。
        raw = np.array([
            float(np.mean(features[0:4])),   # rule_based
            float(np.mean(features[4:7])),   # baseline
            float(np.mean(features[7:13])),  # isolation_forest
        ])
        total = float(raw.sum())
        share = raw / total if total > 0 else np.zeros_like(raw)
        contributions = {
            name: round(float(v), 4)
            for name, v in zip(ENGINE_ORDER, share)
        }

        return {
            "architecture": "three_engine_stacking",
            "engine_order": list(ENGINE_ORDER),
            "is_attack": bool(is_attack),
            "attack_prob": round(prob, 4),
            "confidence": round(confidence, 4),
            "confidence_source": confidence_source,
            "meta_learner_used": meta_used,
            "features": {n: float(v) for n, v in zip(self.feature_names, features)},
            "contributions": contributions,
        }

    def _weighted_fallback(self, features: np.ndarray) -> float:
        """元学习器不可用时的固定权重回退（明确标注为非模型输出）"""
        rule_score = min(features[0] * 0.5 + features[1] * 0.2 + features[2] / 4.0 * 0.2
                         + features[3] * 0.1, 1.0)
        base_score = min(features[4] * 0.6 + features[5] * 0.25 + features[6] * 0.15, 1.0)
        # 孤立森林6维：available(7) + count(8) + ratio(9) + mean_score(10) + max_score(11) + top_dim_risk(12)
        iso_score = min(features[8] * 0.35 + features[9] * 0.25
                        + features[10] * 0.15 + features[11] * 0.15
                        + features[12] * 0.10, 1.0)
        return float(
            FALLBACK_WEIGHTS["rule_based"] * rule_score
            + FALLBACK_WEIGHTS["baseline"] * base_score
            + FALLBACK_WEIGHTS["isolation_forest"] * iso_score
        )

    # ------------------------------------------------------------------
    # 模型加载/保存/训练
    # ------------------------------------------------------------------
    def load(self, model_path: str) -> bool:
        """加载 meta-learner；同时校验 feature_order 与当前三引擎一致"""
        import joblib
        try:
            data = joblib.load(model_path)
            if isinstance(data, dict) and "model" in data:
                order = data.get("feature_order") or data.get("engine_order")
                if order and tuple(order) != ENGINE_ORDER:
                    logger.error(
                        f"Stacking 元学习器引擎顺序不匹配：文件={order} 期望={list(ENGINE_ORDER)}。"
                        f"拒绝加载以免给出错误判定，请用 tools/train_stacking.py 重新训练。"
                    )
                    self.meta_learner = None
                    return False
                self.meta_learner = data["model"]
                self.provenance = data.get("provenance") or {}
            else:
                self.meta_learner = data
            logger.info(f"三引擎 Stacking 元学习器加载成功: {model_path}"
                        + (f" | 数据指纹={self.provenance.get('dataset_hash')}"
                           if self.provenance.get("dataset_hash") else " | 无数据指纹（旧模型）"))
            return True
        except Exception as e:
            logger.warning(f"meta-learner 加载失败，将使用固定权重回退: {e}")
            self.meta_learner = None
            return False

    def save(self, model_path: str) -> None:
        import joblib
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump({
            "model": self.meta_learner,
            "feature_names": self.feature_names,
            "feature_order": list(ENGINE_ORDER),
            "architecture": "three_engine_stacking",
            # 训练数据指纹：模型溯源（此前 joblib 无任何训练数据记录）
            "provenance": self.provenance or {},
        }, model_path)
        logger.info(f"三引擎 Stacking 元学习器保存成功: {model_path}")

    def set_provenance(self, provenance: Dict[str, Any]) -> None:
        """记录训练数据指纹（由训练脚本调用；随模型一同落盘）"""
        self.provenance = dict(provenance or {})

    def train_meta_learner(self, X: np.ndarray, y: np.ndarray,
                           model_path: Optional[str] = None,
                           groups: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """训练 meta-learner（逻辑回归）

        :param groups: 样本分组（通常是源 PCAP 名）。传入时使用 **GroupKFold**，
            保证同一样本的所有窗口落在同一折内——否则同一 PCAP 的近似重复窗口
            会同时出现在训练折与验证折，CV 分数被系统性高估。
        """
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import GroupKFold, StratifiedKFold, cross_val_score

        clf = LogisticRegression(C=1.0, max_iter=1000, random_state=42,
                                 class_weight="balanced")
        # 样本极少时 5 折不可行，按最小类别数/最少组数自适应
        n_min = int(np.bincount(y.astype(int)).min()) if len(y) else 0
        n_splits = max(2, min(5, n_min))
        cv_f1_mean = cv_f1_std = None
        cv_f1_ungrouped_mean = cv_f1_ungrouped_std = None
        cv_scheme = "stratified"

        if groups is not None and len(set(groups)) >= 2:
            n_groups = len(set(groups))
            n_splits = max(2, min(n_splits, n_groups))
            gkf = GroupKFold(n_splits=n_splits)
            cv = cross_val_score(clf, X, y, cv=gkf, groups=groups, scoring="f1")
            cv_f1_mean, cv_f1_std = float(np.mean(cv)), float(np.std(cv))
            cv_scheme = "groupkfold_by_sample"
            # 对照：普通分层 CV（存在样本内泄漏，仅用于展示差距）
            if n_min >= 2:
                skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
                cv_u = cross_val_score(clf, X, y, cv=skf, scoring="f1")
                cv_f1_ungrouped_mean = float(np.mean(cv_u))
                cv_f1_ungrouped_std = float(np.std(cv_u))
        elif n_min >= 2:
            skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            cv = cross_val_score(clf, X, y, cv=skf, scoring="f1")
            cv_f1_mean, cv_f1_std = float(np.mean(cv)), float(np.std(cv))

        clf.fit(X, y)
        self.meta_learner = clf

        result = {
            "cv_f1_mean": cv_f1_mean,
            "cv_f1_std": cv_f1_std,
            "cv_splits": n_splits,
            "cv_scheme": cv_scheme,
            "cv_f1_ungrouped_mean": cv_f1_ungrouped_mean,
            "cv_f1_ungrouped_std": cv_f1_ungrouped_std,
            "n_groups": int(len(set(groups))) if groups is not None else None,
            "feature_importance": {
                name: float(c) for name, c in zip(self.feature_names, clf.coef_[0])
            },
            "n_samples": int(len(y)),
            "n_attack": int(np.sum(y)),
            "n_normal": int(len(y) - np.sum(y)),
        }
        if model_path:
            self.save(model_path)
        logger.info(f"三引擎 Stacking 元学习器训练完成 | 样本 {len(y)} | "
                    f"{cv_scheme} F1={cv_f1_mean}")
        return result


def alerts_by_detector(alerts, detector_name):
    """按 detector 名筛选告警（兼容 detector 字段缺失）"""
    return [a for a in (alerts or []) if a.get("detector") == detector_name]


# 全局默认模型路径
DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "models", "stacking_meta_learner.joblib"
)


def get_three_engine_stacking(model_path: Optional[str] = None) -> ThreeEngineStacking:
    """获取三引擎 Stacking 融合器"""
    return ThreeEngineStacking(model_path or DEFAULT_MODEL_PATH)
