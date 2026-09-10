# -*- coding: utf-8 -*-
"""
P2-4: 检测引擎策略模式 + 工厂模式
设计模式应用：
- Strategy（策略模式）：定义统一的检测接口，不同检测算法可互换
- Factory（工厂模式）：根据配置创建对应的检测器实例
- Context（上下文）：持有策略引用，统一调度检测流程

设计目标：
- 开闭原则：新增检测算法只需实现接口，不修改现有代码
- 单一职责：每个检测器只负责一种检测算法
- 依赖倒置：高层模块依赖抽象接口，不依赖具体实现
"""
import abc
from typing import Any, Dict, List, Optional

from loguru import logger


# ============================================================
# 策略接口
# ============================================================

class DetectionStrategy(abc.ABC):
    """检测策略抽象接口 — 所有检测引擎必须实现"""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """检测器名称"""
        pass

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """检测器版本"""
        pass

    @abc.abstractmethod
    def detect(self, packets: List[Any], flows: Optional[List[Any]] = None,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        执行检测
        :param packets: 包列表
        :param flows: 流列表（可选）
        :param context: 上下文信息（基线、配置等）
        :return: 检测结果 {alerts, summary, stats}
        """
        pass

    def validate_input(self, packets: List[Any]) -> bool:
        """输入校验（默认实现，子类可覆盖）"""
        if not packets:
            logger.warning(f"[{self.name}] 输入为空，跳过检测")
            return False
        return True

    def _empty_result(self) -> Dict[str, Any]:
        """返回空结果"""
        return {
            "detector": self.name,
            "version": self.version,
            "alerts": [],
            "summary": {"total_alerts": 0, "by_severity": {}},
            "stats": {"packets_processed": 0, "time_ms": 0},
        }


# ============================================================
# 具体策略实现（适配器模式：包装现有检测器）
# ============================================================

class RuleBasedStrategy(DetectionStrategy):
    """规则引擎检测策略（包装现有规则检测）"""

    @property
    def name(self) -> str:
        return "rule_based"

    @property
    def version(self) -> str:
        return "1.0.0"

    def detect(self, packets: List[Any], flows: Optional[List[Any]] = None,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.validate_input(packets):
            return self._empty_result()
        try:
            # 包装现有规则检测逻辑
            from src.analysis.flow_extractor import TrafficAnalyzer
            analyzer = context.get("analyzer") if context else None
            if analyzer and hasattr(analyzer, "_rule_detect"):
                result = analyzer._rule_detect(packets)
                return {
                    "detector": self.name,
                    "version": self.version,
                    "alerts": result.get("alerts", []),
                    "summary": result.get("summary", {}),
                    "stats": result.get("stats", {}),
                }
            return self._empty_result()
        except Exception as e:
            logger.error(f"[{self.name}] 检测失败: {e}")
            return self._empty_result()


class BaselineStrategy(DetectionStrategy):
    """时序基线检测策略（包装现有基线检测）"""

    @property
    def name(self) -> str:
        return "baseline"

    @property
    def version(self) -> str:
        return "2.0.0"

    def detect(self, packets: List[Any], flows: Optional[List[Any]] = None,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.validate_input(packets):
            return self._empty_result()
        try:
            baseline = context.get("baseline") if context else None
            if baseline and hasattr(baseline, "detect_windows"):
                # 窗口聚合后检测
                from src.analysis.baseline import WindowAccumulator
                acc = WindowAccumulator(window_sec=baseline.window_sec)
                for p in packets:
                    acc.add(p)
                windows = acc.get_windows()
                result = baseline.detect_windows(windows)
                return {
                    "detector": self.name,
                    "version": self.version,
                    "alerts": result.get("alerts", []),
                    "summary": result.get("summary", {}),
                    "stats": {"windows": len(windows)},
                }
            return self._empty_result()
        except Exception as e:
            logger.error(f"[{self.name}] 检测失败: {e}")
            return self._empty_result()


class SupervisedStrategy(DetectionStrategy):
    """监督模型检测策略（包装现有监督检测器）"""

    @property
    def name(self) -> str:
        return "supervised"

    @property
    def version(self) -> str:
        return "1.0.0"

    def detect(self, packets: List[Any], flows: Optional[List[Any]] = None,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.validate_input(packets):
            return self._empty_result()
        try:
            from src.analysis.supervised_detector import SupervisedDetector
            detector = SupervisedDetector()
            result = detector.detect_pcap(packets)
            return {
                "detector": self.name,
                "version": self.version,
                "alerts": result.get("aggregate_alert", []),
                "summary": {
                    "is_attack": result.get("is_attack", False),
                    "confidence": result.get("confidence", 0),
                    "attack_flows": result.get("attack_flows", 0),
                },
                "stats": result.get("category_distribution", {}),
            }
        except Exception as e:
            logger.error(f"[{self.name}] 检测失败: {e}")
            return self._empty_result()


class IsolationForestStrategy(DetectionStrategy):
    """孤立森林检测策略（包装现有孤立森林检测）"""

    @property
    def name(self) -> str:
        return "isolation_forest"

    @property
    def version(self) -> str:
        return "1.0.0"

    def detect(self, packets: List[Any], flows: Optional[List[Any]] = None,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.validate_input(packets):
            return self._empty_result()
        try:
            from src.analysis.isolation_detector import IsolationForestDetector
            detector = IsolationForestDetector()
            result = detector.detect(packets)
            return {
                "detector": self.name,
                "version": self.version,
                "alerts": result.get("alerts", []),
                "summary": result.get("summary", {}),
                "stats": result.get("stats", {}),
            }
        except Exception as e:
            logger.error(f"[{self.name}] 检测失败: {e}")
            return self._empty_result()


# ============================================================
# 工厂模式
# ============================================================

class DetectorFactory:
    """检测器工厂 — 根据配置创建对应的检测器实例"""

    _registry = {
        "rule_based": RuleBasedStrategy,
        "baseline": BaselineStrategy,
        "supervised": SupervisedStrategy,
        "isolation_forest": IsolationForestStrategy,
    }

    @classmethod
    def register(cls, name: str, strategy_cls: type):
        """注册新的检测策略（开闭原则：新增算法只需注册，不修改工厂）"""
        cls._registry[name] = strategy_cls
        logger.info(f"注册检测策略: {name} -> {strategy_cls.__name__}")

    @classmethod
    def create(cls, name: str, **kwargs) -> DetectionStrategy:
        """
        创建检测器实例
        :param name: 检测器名称
        :param kwargs: 传递给检测器构造函数的参数
        :return: 检测策略实例
        """
        if name not in cls._registry:
            raise ValueError(f"未知的检测器: {name}，可用: {list(cls._registry.keys())}")
        return cls._registry[name](**kwargs)

    @classmethod
    def create_all(cls, names: Optional[List[str]] = None) -> List[DetectionStrategy]:
        """
        批量创建检测器
        :param names: 检测器名称列表，None 表示创建所有已注册的
        :return: 检测器实例列表
        """
        if names is None:
            names = list(cls._registry.keys())
        return [cls.create(name) for name in names if name in cls._registry]

    @classmethod
    def available_detectors(cls) -> Dict[str, str]:
        """列出所有可用的检测器及其版本"""
        return {name: cls._registry[name]().version for name in cls._registry}


# ============================================================
# 上下文（统一调度）
# ============================================================

class DetectionEngine:
    """
    检测引擎上下文 — 统一调度多个检测策略，集成投票
    持有策略引用，运行时可动态切换策略
    """

    def __init__(self, strategies: Optional[List[DetectionStrategy]] = None,
                 weights: Optional[Dict[str, float]] = None):
        """
        :param strategies: 检测策略列表
        :param weights: 各策略的投票权重
        """
        self._strategies = strategies or []
        self._weights = weights or {
            "supervised": 0.5,
            "rule_based": 0.2,
            "baseline": 0.15,
            "isolation_forest": 0.15,
        }

    def add_strategy(self, strategy: DetectionStrategy, weight: float = 0.2):
        """动态添加检测策略"""
        self._strategies.append(strategy)
        self._weights[strategy.name] = weight

    def remove_strategy(self, name: str):
        """动态移除检测策略"""
        self._strategies = [s for s in self._strategies if s.name != name]
        self._weights.pop(name, None)

    def detect_all(self, packets: List[Any], flows: Optional[List[Any]] = None,
                   context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        执行所有检测策略，集成投票
        :return: {results_by_detector, ensemble_vote, total_alerts}
        """
        results = {}
        all_alerts = []

        for strategy in self._strategies:
            try:
                result = strategy.detect(packets, flows, context)
                results[strategy.name] = result
                alerts = result.get("alerts", [])
                all_alerts.extend(alerts)
                logger.info(f"[{strategy.name}] 检测完成: {len(alerts)} 条告警")
            except Exception as e:
                logger.error(f"[{strategy.name}] 检测异常: {e}")
                results[strategy.name] = {"error": str(e), "alerts": []}

        # 集成投票
        ensemble = self._ensemble_vote(results)

        return {
            "results_by_detector": results,
            "ensemble_vote": ensemble,
            "total_alerts": len(all_alerts),
            "detectors_used": [s.name for s in self._strategies],
        }

    def _ensemble_vote(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """集成投票：加权汇总各检测器的攻击判定"""
        attack_score = 0.0
        total_weight = 0.0
        details = {}

        for name, result in results.items():
            weight = self._weights.get(name, 0.1)
            total_weight += weight

            # 判断该检测器是否认为有攻击
            is_attack = False
            confidence = 0.0
            summary = result.get("summary", {})
            if summary.get("is_attack"):
                is_attack = True
                confidence = summary.get("confidence", 0.5)
            elif result.get("alerts"):
                # 有告警也视为检测到异常
                is_attack = True
                confidence = min(0.3 + len(result["alerts"]) * 0.05, 0.9)

            if is_attack:
                attack_score += weight * confidence

            details[name] = {
                "weight": weight,
                "is_attack": is_attack,
                "confidence": confidence,
                "weighted_score": weight * confidence if is_attack else 0,
            }

        final_score = attack_score / total_weight if total_weight > 0 else 0
        is_attack = final_score > 0.3  # 阈值

        return {
            "is_attack": is_attack,
            "confidence": round(final_score, 3),
            "threshold": 0.3,
            "details": details,
        }


# ============================================================
# 便捷函数
# ============================================================

def create_default_engine() -> DetectionEngine:
    """创建默认的检测引擎（四引擎集成）"""
    strategies = DetectorFactory.create_all()
    return DetectionEngine(strategies=strategies)
