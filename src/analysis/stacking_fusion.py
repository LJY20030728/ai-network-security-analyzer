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
        # 元学习器系数缓存：用于把 logit 精确分解为各引擎的贡献
        # （见 _engine_attribution 的说明；None 表示元学习器不可用）
        self._coef_cache: Optional[np.ndarray] = None
        self._intercept_cache: Optional[float] = None
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
    # 引擎归因（contributions）
    # ------------------------------------------------------------------
    def _engine_attribution(self, features: np.ndarray) -> Dict[str, Any]:
        """计算三个引擎对本次判定的**真实贡献占比**。

        ## 为什么需要这个方法（修的是什么）

        原实现直接对每组特征取算术平均再归一化：

            raw = [mean(features[0:4]), mean(features[4:7]), mean(features[7:13])]
            share = raw / raw.sum()

        这在数学上是**错的**，原因有二：

        1. **丢弃了模型学到的系数**。LogisticRegression 的判定由
           `sigmoid(intercept + Σ wᵢxᵢ)` 决定，`wᵢ` 才决定"哪个引擎被信任"。
           原实现完全没用到 `wᵢ`，所以它算出的"贡献"与模型行为无关。
        2. **量纲不一致却直接平均**。`rule_max_severity` 取值 0~4，
           其余特征多为 0~1；组内求均值被这一个特征主导。

        实测对照（demo_attack 样本）：

            原实现报告      rule 0.5103 / baseline 0.3002 / iso 0.1895
            模型真实归因    rule 0.3153 / baseline 0.1119 / iso 0.5728
                                                  ↑ 相差 3 倍，方向甚至相反

        对一个以"可解释"为卖点的系统，展示错误的归因是硬伤。

        ## 现在的算法（线性模型下可精确分解）

        logistic 回归的 logit 可**精确**拆分为各特征项之和：

            logit = intercept + Σ wᵢxᵢ

        故第 i 个特征的**边际贡献**为 `wᵢxᵢ`（这本身就是模型对该样本
        预测值的分解，不是近似）。按引擎分组后取绝对值求和再归一化，
        即得"本次判定中各引擎的相对影响力"。

        用绝对值的原因：正负贡献都代表"该引擎影响了结论"，
        而我们报告的是**影响力大小**而非方向。

        :return: {"contributions": {...3 项和为 1...},
                  "attribution_source": "model_coef" | "fallback_weights",
                  "intercept_logit": float | None,
                  "logit": float | None}
        """
        w = self._coef_cache
        if w is None:
            # 元学习器不可用：只能用人工权重，且必须如实标注来源
            share = np.array([FALLBACK_WEIGHTS[k] for k in ENGINE_ORDER], dtype=np.float64)
            total = float(share.sum())
            return {
                "contributions": {k: round(float(v / total), 4)
                                  for k, v in zip(ENGINE_ORDER, share)},
                "attribution_source": "fallback_weights",
                "intercept_logit": None,
                "logit": None,
            }

        # 线性分解：每个特征的边际贡献 = w_i * x_i
        terms = np.abs(w * features)
        groups = {
            "rule_based": float(terms[0:4].sum()),
            "baseline": float(terms[4:7].sum()),
            "isolation_forest": float(terms[7:13].sum()),
        }
        total = float(sum(groups.values()))
        if total <= 1e-12:
            # 所有特征都为 0（无任何引擎响应）→ 影响力无从谈起
            share = {k: 0.0 for k in ENGINE_ORDER}
        else:
            share = {k: round(v / total, 4) for k, v in groups.items()}

        intercept = float(self._intercept_cache) if self._intercept_cache is not None else None
        logit = float(intercept + float(np.dot(w, features))) if intercept is not None else None
        return {
            "contributions": share,
            "attribution_source": "model_coef",
            "intercept_logit": round(intercept, 4) if intercept is not None else None,
            "logit": round(logit, 4) if logit is not None else None,
        }


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

        # 引擎归因：用模型系数把 logit 精确分解为各引擎的贡献。
        #
        # 【修复记录】原实现是"各组特征取算术平均再归一化"：
        #     raw = [mean(f[0:4]), mean(f[4:7]), mean(f[7:13])]; share = raw / raw.sum()
        # 这是错的 —— 它既丢弃了模型学到的系数 w（判定由 sigmoid(intercept+Σwx) 决定），
        # 又对不同量纲的特征直接平均（rule_max_severity 取值 0~4，其余多为 0~1）。
        # 实测该实现报告 rule 0.51 / iso 0.19，而模型真实归因是 rule 0.32 / iso 0.57，
        # 相差 3 倍且方向相反。归因错误对一个以「可解释」为卖点的系统是硬伤，故重写。
        attribution = self._engine_attribution(features)

        return {
            "architecture": "three_engine_stacking",
            "engine_order": list(ENGINE_ORDER),
            "is_attack": bool(is_attack),
            "attack_prob": round(prob, 4),
            "confidence": round(confidence, 4),
            "confidence_source": confidence_source,
            "meta_learner_used": meta_used,
            "features": {n: float(v) for n, v in zip(self.feature_names, features)},
            "contributions": attribution["contributions"],
            # 归因来源：model_coef = 由模型系数精确分解；fallback_weights = 人工权重
            # 使用者必须据此判断这个"贡献占比"是否可信（前者可信，后者只是兜底）
            "attribution_source": attribution["attribution_source"],
            "intercept_logit": attribution["intercept_logit"],
            "logit": attribution["logit"],
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
            # 缓存系数，供 _engine_attribution 把 logit 精确分解为各引擎贡献。
            # 只对线性模型有意义：树模型没有可分解的系数，此时置 None 让归因走兜底分支。
            self._cache_coef()
            logger.info(f"三引擎 Stacking 元学习器加载成功: {model_path}"
                        + (f" | 数据指纹={self.provenance.get('dataset_hash')}"
                           if self.provenance.get("dataset_hash") else " | 无数据指纹（旧模型）"))
            return True
        except Exception as e:
            logger.warning(f"meta-learner 加载失败，将使用固定权重回退: {e}")
            self.meta_learner = None
            self._coef_cache = None
            self._intercept_cache = None
            return False

    def _cache_coef(self) -> None:
        """把元学习器的系数与截距缓存到实例上（供归因分解使用）。

        仅在 `coef_` / `intercept_` 存在且维度与 13 维特征一致时缓存；
        否则置 None —— 归因会退回人工权重，并标注 attribution_source。
        """
        self._coef_cache = None
        self._intercept_cache = None
        m = self.meta_learner
        if m is None:
            return
        coef = getattr(m, "coef_", None)
        if coef is None:
            return
        coef = np.asarray(coef, dtype=np.float64).ravel()
        if coef.shape[0] != self.feature_dim:
            logger.warning(
                f"元学习器系数维度 {coef.shape[0]} 与特征维度 {self.feature_dim} 不一致，"
                f"归因将退回人工权重（判定本身不受影响）"
            )
            return
        self._coef_cache = coef
        intercept = getattr(m, "intercept_", None)
        if intercept is not None:
            inter = np.asarray(intercept, dtype=np.float64).ravel()
            self._intercept_cache = float(inter[0]) if inter.size else None

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
