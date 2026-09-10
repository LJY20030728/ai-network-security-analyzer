# -*- coding: utf-8 -*-
"""
P2-3: 轻量级时序分解（STL 思想，零依赖实现）
不依赖 statsmodels，纯 Python + 基础数学实现：
- 趋势提取：移动平均（可配置窗口）
- 季节性提取：基于周期的均值减法
- 残差异常检测：超出残差标准差阈值的点标记为异常

适用场景：网络流量时序数据（每窗口包数/字节数/SYN数等）
检测周期性异常：例如工作时间流量高、凌晨流量低，如果凌晨出现高流量则标记异常。
"""
import math
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


class TimeSeriesDecomposer:
    """
    轻量级时序分解器
    将时序数据分解为：趋势 + 季节性 + 残差
    """

    def __init__(self, period: int = 24, trend_window: int = 5,
                 residual_sigma: float = 3.0):
        """
        :param period: 季节性周期（窗口数，例如 24 表示 24 个窗口一个周期）
        :param trend_window: 趋势移动平均窗口大小
        :param residual_sigma: 残差异常检测的标准差倍数
        """
        self.period = max(period, 2)
        self.trend_window = max(trend_window, 3)
        self.residual_sigma = residual_sigma

    def decompose(self, values: List[float]) -> Dict[str, Any]:
        """
        时序分解
        :param values: 时序数据列表
        :return: {trend, seasonal, residual, anomalies, stats}
        """
        n = len(values)
        if n < self.period * 2:
            logger.warning(f"数据点不足（{n} < {self.period * 2}），无法进行可靠的季节性分解")
            # 回退到简单的移动平均异常检测
            return self._simple_anomaly_detection(values)

        # 1. 趋势提取：移动平均
        trend = self._moving_average(values, self.trend_window)

        # 2. 去趋势：原始值 - 趋势
        detrended = [values[i] - trend[i] for i in range(n)]

        # 3. 季节性提取：按周期取均值
        seasonal = self._extract_seasonal(detrended, self.period)

        # 4. 残差：去趋势值 - 季节性
        residual = [detrended[i] - seasonal[i] for i in range(n)]

        # 5. 残差异常检测
        anomalies = self._detect_residual_anomalies(residual, values)

        # 6. 统计信息
        stats = self._compute_stats(values, trend, seasonal, residual)

        return {
            "trend": trend,
            "seasonal": seasonal,
            "residual": residual,
            "anomalies": anomalies,
            "stats": stats,
            "method": "stl_lite",
            "period": self.period,
        }

    def _moving_average(self, values: List[float], window: int) -> List[float]:
        """移动平均（居中窗口，边界用可用数据）"""
        n = len(values)
        result = []
        half = window // 2
        for i in range(n):
            start = max(0, i - half)
            end = min(n, i + half + 1)
            result.append(sum(values[start:end]) / (end - start))
        return result

    def _extract_seasonal(self, detrended: List[float], period: int) -> List[float]:
        """提取季节性成分：按周期位置取均值"""
        n = len(detrended)
        # 计算每个周期位置的均值
        period_means = [0.0] * period
        period_counts = [0] * period
        for i in range(n):
            pos = i % period
            period_means[pos] += detrended[i]
            period_counts[pos] += 1
        for i in range(period):
            if period_counts[i] > 0:
                period_means[i] /= period_counts[i]

        # 扩展到完整长度
        return [period_means[i % period] for i in range(n)]

    def _detect_residual_anomalies(self, residual: List[float],
                                     original: List[float]) -> List[Dict[str, Any]]:
        """检测残差异常点"""
        n = len(residual)
        if n == 0:
            return []

        # 计算残差的均值和标准差
        mean_r = sum(residual) / n
        variance = sum((r - mean_r) ** 2 for r in residual) / n
        std_r = math.sqrt(variance) if variance > 0 else 1.0

        anomalies = []
        threshold = self.residual_sigma * std_r

        for i in range(n):
            z_score = abs(residual[i] - mean_r) / std_r if std_r > 0 else 0
            if abs(residual[i] - mean_r) > threshold:
                direction = "high" if residual[i] > mean_r else "low"
                anomalies.append({
                    "index": i,
                    "value": original[i],
                    "residual": residual[i],
                    "z_score": round(z_score, 2),
                    "direction": direction,
                    "severity": "CRITICAL" if z_score > 5 else "HIGH" if z_score > 4 else "MEDIUM",
                })

        return anomalies

    def _compute_stats(self, values: List[float], trend: List[float],
                       seasonal: List[float], residual: List[float]) -> Dict[str, Any]:
        """计算分解统计信息"""
        n = len(values)
        if n == 0:
            return {}

        # 各成分的方差占比（解释度）
        total_var = sum((v - sum(values) / n) ** 2 for v in values)
        trend_var = sum((t - sum(trend) / n) ** 2 for t in trend) if n > 1 else 0
        seasonal_var = sum((s - sum(seasonal) / n) ** 2 for s in seasonal) if n > 1 else 0
        residual_var = sum((r - sum(residual) / n) ** 2 for r in residual) if n > 1 else 0

        def safe_ratio(v):
            return round(v / total_var, 3) if total_var > 0 else 0

        return {
            "n_points": n,
            "mean": round(sum(values) / n, 2),
            "std": round(math.sqrt(sum((v - sum(values) / n) ** 2 for v in values) / n), 2),
            "trend_explained": safe_ratio(trend_var),
            "seasonal_explained": safe_ratio(seasonal_var),
            "residual_explained": safe_ratio(residual_var),
            "seasonal_amplitude": round(max(seasonal) - min(seasonal), 2),
            "trend_slope": round((trend[-1] - trend[0]) / n, 4) if n > 1 else 0,
        }

    def _simple_anomaly_detection(self, values: List[float]) -> Dict[str, Any]:
        """简单回退：数据不足时用 z-score 异常检测"""
        n = len(values)
        if n == 0:
            return {"trend": [], "seasonal": [], "residual": [], "anomalies": [],
                    "stats": {}, "method": "zscore_fallback"}

        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std = math.sqrt(variance) if variance > 0 else 1.0

        anomalies = []
        for i, v in enumerate(values):
            z = abs(v - mean) / std if std > 0 else 0
            if z > self.residual_sigma:
                anomalies.append({
                    "index": i,
                    "value": v,
                    "z_score": round(z, 2),
                    "direction": "high" if v > mean else "low",
                    "severity": "CRITICAL" if z > 5 else "HIGH" if z > 4 else "MEDIUM",
                })

        return {
            "trend": [mean] * n,
            "seasonal": [0.0] * n,
            "residual": [v - mean for v in values],
            "anomalies": anomalies,
            "stats": {"n_points": n, "mean": round(mean, 2), "std": round(std, 2),
                      "method": "zscore_fallback"},
            "method": "zscore_fallback",
        }


def detect_seasonal_anomalies(window_series: List[Dict[str, Any]],
                                metric: str = "packets",
                                period: int = 24) -> Dict[str, Any]:
    """
    便捷函数：对窗口序列进行季节性异常检测
    :param window_series: 窗口数据列表（每个窗口是 dict，含 metric 字段）
    :param metric: 要检测的指标名（packets/bytes/syn/dports）
    :param period: 季节性周期（窗口数）
    :return: 分解结果 + 异常告警
    """
    values = []
    for w in window_series:
        if isinstance(w, dict):
            values.append(float(w.get(metric, 0)))
        else:
            values.append(float(getattr(w, metric, 0)))

    decomposer = TimeSeriesDecomposer(period=period)
    result = decomposer.decompose(values)

    # 转换为告警格式
    alerts = []
    for a in result.get("anomalies", []):
        alerts.append({
            "type": "SEASONAL_ANOMALY",
            "window_index": a["index"],
            "metric": metric,
            "value": a["value"],
            "z_score": a["z_score"],
            "direction": a["direction"],
            "severity": a["severity"],
            "message": f"窗口 {a['index']} {metric} {a['direction']}于季节性预期 "
                       f"(z={a['z_score']})",
        })

    result["alerts"] = alerts
    return result
