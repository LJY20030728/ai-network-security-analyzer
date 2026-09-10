"""
孤立森林无监督异常检测引擎（L2）
====================================
与 EWMA 统计基线互补的第三轨检测：
- 统计基线（TrafficBaseline）：逐维度独立建模（z-score），捕捉单维度幅值突变
- 孤立森林（本模块）：对多维窗口特征**联合建模**，捕捉维度间耦合异常
  （如"包数正常但目的端口数突增"——单维度不显著、组合才异常的流量）

设计要点（简历叙事）：
1. 无监督：仅用正常流量窗口学习（与统计基线同输入），适配无标注安全场景
2. 同口径评测：与基线同窗口聚合、同训练/测试切分、同 TPR/FPR 指标
   （tools/eval_ml_engine.py 提供公平对比）
3. 可复现：固定 random_state；检测用连续 anomaly_score + 阈值而非 predict 标签，
   分数作为证据链量化依据（不依赖标签的二值输出）
4. 可解释：告警附 anomaly_score 与 top 贡献维度（特征粗定位，证据可溯源）
5. 轻量：纯 sklearn，训练/检测 O(n_samples log n)；模型仅内存驻留（学习数据
   来自用户提供的正常流量，无需预置权重文件）
"""
from typing import List, Dict, Any, Optional
from loguru import logger

from config.settings import settings

# 与 TrafficBaseline 完全一致的窗口特征维度（保证同输入同口径）
DIMENSIONS = ["window_packets", "window_bytes", "window_syn", "window_dports"]

# 异常分数阈值：IsolationForest decision_function 输出为负值越小越异常
# 默认取 contamination 分位数作为判定阈值（保持与模型先验一致）
DEFAULT_SCORE_THRESHOLD = 0.0


def _feature_matrix(windows: List[Dict[str, float]]) -> "np.ndarray":
    """窗口列表 → 特征矩阵（4 维，行序与输入一致）"""
    import numpy as np
    rows = []
    for w in windows:
        rows.append([float(w.get(d, 0.0)) for d in DIMENSIONS])
    return np.asarray(rows, dtype=np.float64).reshape(len(rows), len(DIMENSIONS))


class IsolationDetector:
    """孤立森林无监督异常检测器（窗口级，接口对齐 TrafficBaseline.learn_windows/detect_windows）"""

    def __init__(self,
                 contamination: Optional[float] = None,
                 random_state: Optional[int] = None,
                 max_samples: Optional[int] = None):
        from sklearn.ensemble import IsolationForest
        self.contamination = contamination if contamination is not None else settings.ml_contamination
        self.random_state = random_state if random_state is not None else settings.ml_random_state
        self.max_samples = max_samples if max_samples is not None else settings.ml_max_samples

        self.model: Optional[IsolationForest] = None
        self._learned = False
        self._train_windows: List[Dict[str, float]] = []
        self._train_scores: List[float] = []
        self._score_threshold: float = DEFAULT_SCORE_THRESHOLD
        # 归一化参考（用于报告可读性）
        self._medians: Dict[str, float] = {d: 0.0 for d in DIMENSIONS}
        self.name: str = "isolation-forest-unsupervised"
        self.created_at: str = ""

    # ---------- 学习阶段 ----------

    def learn_windows(self, windows: List[Dict[str, float]]) -> Dict[str, Any]:
        """从正常流量窗口序列训练孤立森林（与 TrafficBaseline.learn_windows 同输入）"""
        from sklearn.ensemble import IsolationForest
        if len(windows) < 10:
            logger.warning(f"ML 学习窗口不足（{len(windows)}），模型可能不稳定")

        X = _feature_matrix(windows)
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples=min(self.max_samples, max(2, len(windows))),
            n_estimators=100,
            n_jobs=-1,
        )
        self.model.fit(X)

        # 训练集自身的异常分数分布 → 判定阈值（按 contamination 分位数）
        train_scores = self.model.decision_function(X)
        self._train_scores = [float(s) for s in train_scores]
        self._score_threshold = float(
            sorted(train_scores)[max(0, int(len(train_scores) * self.contamination) - 1)]
        ) if len(train_scores) > 1 else DEFAULT_SCORE_THRESHOLD

        for d in DIMENSIONS:
            vals = [w[d] for w in windows]
            self._medians[d] = float(sorted(vals)[len(vals) // 2]) if vals else 0.0

        self._train_windows = windows
        self._learned = True
        if not self.created_at:
            from datetime import datetime
            self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"孤立森林学习完成 | 窗口数: {len(windows)} | contamination: {self.contamination} "
                    f"| score 阈值: {self._score_threshold:.4f}")
        return {
            "windows": len(windows),
            "contamination": self.contamination,
            "score_threshold": round(self._score_threshold, 4),
            "n_estimators": 100,
        }

    @property
    def learned(self) -> bool:
        return self._learned

    # ---------- 检测阶段 ----------

    def detect_windows(self, windows: List[Dict[str, float]]) -> Dict[str, Any]:
        """
        逐窗口异常评分 → 超阈值标记为 ML_ANOMALY 候选。
        返回结构对齐 TrafficBaseline.detect_windows：
        {total_anomalies, anomalies: [{window_index, dimension(top), score, severity, ...}]}
        """
        if not self._learned or self.model is None:
            return {"total_anomalies": 0, "anomalies": [], "error": "ML 模型未学习"}

        X = _feature_matrix(windows)
        scores = self.model.decision_function(X)

        anomalies = []
        for idx, (w, s) in enumerate(zip(windows, scores)):
            s = float(s)
            if s < self._score_threshold:
                top_dim, top_ratio = self._top_contributing_dimension(w)
                z_ratio = top_ratio
                severity = "HIGH" if s < self._score_threshold - 0.05 else "MEDIUM"
                anomalies.append({
                    "window_index": idx,
                    "dimension": top_dim,
                    "anomaly_score": round(s, 4),
                    "score_threshold": round(self._score_threshold, 4),
                    "top_dim_ratio": round(z_ratio, 2),   # 该维度相对中位数的倍数
                    "severity": severity,
                })

        logger.info(f"孤立森林检测完成 | {len(windows)} 窗口 | 异常窗口: {len(anomalies)}")
        return {"total_anomalies": len(anomalies), "anomalies": anomalies}

    def _top_contributing_dimension(self, w: Dict[str, float]) -> tuple:
        """粗定位贡献最大维度：取相对中位数偏差最大的维度（可解释性证据）"""
        best_dim, best_ratio = DIMENSIONS[0], 0.0
        for d in DIMENSIONS:
            med = self._medians.get(d, 0.0)
            v = float(w.get(d, 0.0))
            ratio = (v - med) / med if med > 0 else (v if v > 0 else 0.0)
            if abs(ratio) > abs(best_ratio):
                best_dim, best_ratio = d, ratio
        return best_dim, abs(best_ratio)

    # ---------- 持久化 ----------

    def to_dict(self) -> Dict[str, Any]:
        """导出元信息（模型不落盘——学习数据来自运行时正常流量，随会话重建）"""
        return {
            "name": self.name,
            "created_at": self.created_at,
            "learned": self._learned,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "train_windows": len(self._train_windows),
            "score_threshold": round(self._score_threshold, 4),
            "dimensions": DIMENSIONS,
        }
