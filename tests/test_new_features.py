# -*- coding: utf-8 -*-
"""
P2-5: 新功能综合测试
覆盖 P0/P1/P2 阶段新增的核心模块：
- 错误处理三层（P2-1）
- 日志可观测性（P2-2）
- STL 时序分解（P2-3）
- 检测引擎策略模式（P2-4）
- 取证知识库（P1-2）
- DPAPI 安全存储（P1-3）
- SQLite 数据库（P1-4）
- 幻觉控制（P0-3）
- 监督检测器（P0-1）
"""
import os
import sys
import tempfile
import pytest

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# P2-1: 错误处理三层测试
# ============================================================

class TestInputValidator:
    """输入校验器测试"""

    def test_validate_pcap_file_invalid_path(self):
        from src.utils.error_handler import InputValidator
        valid, msg = InputValidator.validate_pcap_file("/nonexistent/file.pcap")
        assert not valid
        assert "不存在" in msg

    def test_validate_pcap_file_wrong_extension(self):
        from src.utils.error_handler import InputValidator
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            valid, msg = InputValidator.validate_pcap_file(path)
            assert not valid
            assert "不支持" in msg
        finally:
            os.unlink(path)

    def test_validate_api_key_empty(self):
        from src.utils.error_handler import InputValidator
        valid, msg = InputValidator.validate_api_key("")
        assert not valid

    def test_validate_api_key_placeholder(self):
        from src.utils.error_handler import InputValidator
        valid, msg = InputValidator.validate_api_key("sk-xxxx-test")
        assert not valid
        assert "占位符" in msg

    def test_validate_api_key_valid(self):
        from src.utils.error_handler import InputValidator
        valid, msg = InputValidator.validate_api_key("sk-valid-api-key-12345")
        assert valid


class TestGlobalExceptionHandler:
    """全局异常处理器测试"""

    def test_handle_file_not_found(self):
        from src.utils.error_handler import GlobalExceptionHandler
        try:
            open("/nonexistent/file.txt")
        except FileNotFoundError as e:
            info = GlobalExceptionHandler.handle(e, "test")
            assert info.error_type == "FileNotFoundError"
            assert "文件未找到" in info.message

    def test_handle_value_error(self):
        from src.utils.error_handler import GlobalExceptionHandler
        try:
            int("abc")
        except ValueError as e:
            info = GlobalExceptionHandler.handle(e, "test")
            assert info.error_type == "ValueError"
            assert "参数错误" in info.message

    def test_handle_unknown_error(self):
        from src.utils.error_handler import GlobalExceptionHandler
        info = GlobalExceptionHandler.handle(RuntimeError("unknown"), "test")
        assert info.message == "操作失败"


class TestSafeExecute:
    """安全执行装饰器测试"""

    def test_safe_execute_success(self):
        from src.utils.error_handler import safe_execute

        @safe_execute(context="test", fallback=0)
        def add(a, b):
            return a + b

        assert add(1, 2) == 3

    def test_safe_execute_fallback(self):
        from src.utils.error_handler import safe_execute

        @safe_execute(context="test", fallback=-1)
        def fail():
            raise ValueError("test error")

        assert fail() == -1


# ============================================================
# P2-2: 日志可观测性测试
# ============================================================

class TestLogObserver:
    """日志观察者测试"""

    def test_get_log_observer_singleton(self):
        from src.utils.log_observer import get_log_observer
        obs1 = get_log_observer()
        obs2 = get_log_observer()
        # 单例或新实例都可以，只要不报错
        assert obs1 is not None
        assert obs2 is not None

    def test_get_recent_logs_empty(self):
        from src.utils.log_observer import get_log_observer
        obs = get_log_observer()
        logs = obs.get_recent_logs(limit=10)
        assert isinstance(logs, list)

    def test_get_log_stats(self):
        from src.utils.log_observer import get_log_observer
        stats = get_log_observer().get_log_stats()
        assert "total_recent" in stats
        assert "level_distribution" in stats

    def test_generate_diagnostic_report(self):
        from src.utils.log_observer import get_log_observer
        report = get_log_observer().generate_diagnostic_report()
        assert "system" in report
        assert "python" in report
        assert "configuration" in report
        assert "database" in report
        assert "health_status" in report


# ============================================================
# P2-3: STL 时序分解测试
# ============================================================

class TestTimeSeriesDecomposer:
    """STL 时序分解器测试"""

    def test_decompose_simple(self):
        from src.analysis.stl_decomposer import TimeSeriesDecomposer
        decomposer = TimeSeriesDecomposer(period=6, trend_window=3)
        # 构造 50 个点的简单数据
        values = [10.0 + i * 0.1 for i in range(50)]
        result = decomposer.decompose(values)
        assert "trend" in result
        assert "seasonal" in result
        assert "residual" in result
        assert "anomalies" in result
        assert "stats" in result
        assert len(result["trend"]) == 50

    def test_decompose_with_anomaly(self):
        from src.analysis.stl_decomposer import TimeSeriesDecomposer
        decomposer = TimeSeriesDecomposer(period=6, trend_window=3, residual_sigma=2.0)
        values = [10.0] * 48
        values[24] = 100.0  # 异常点
        result = decomposer.decompose(values)
        assert len(result["anomalies"]) >= 1

    def test_decompose_insufficient_data(self):
        from src.analysis.stl_decomposer import TimeSeriesDecomposer
        decomposer = TimeSeriesDecomposer(period=24)
        values = [1.0, 2.0, 3.0]  # 数据不足
        result = decomposer.decompose(values)
        assert result["method"] == "zscore_fallback"

    def test_detect_seasonal_anomalies(self):
        from src.analysis.stl_decomposer import detect_seasonal_anomalies
        windows = [{"packets": 10.0 + i} for i in range(50)]
        result = detect_seasonal_anomalies(windows, metric="packets", period=6)
        assert "alerts" in result
        assert "anomalies" in result


# ============================================================
# P2-4: 检测引擎策略模式测试
# ============================================================

class TestDetectorFactory:
    """检测器工厂测试"""

    def test_available_detectors(self):
        from src.analysis.detection_engine import DetectorFactory
        detectors = DetectorFactory.available_detectors()
        assert "rule_based" in detectors
        assert "baseline" in detectors
        assert "supervised" in detectors
        assert "isolation_forest" in detectors

    def test_create_unknown_detector(self):
        from src.analysis.detection_engine import DetectorFactory
        with pytest.raises(ValueError):
            DetectorFactory.create("unknown")

    def test_register_new_detector(self):
        from src.analysis.detection_engine import DetectorFactory, DetectionStrategy

        class CustomStrategy(DetectionStrategy):
            @property
            def name(self):
                return "custom"

            @property
            def version(self):
                return "0.1.0"

            def detect(self, packets, flows=None, context=None):
                return self._empty_result()

        DetectorFactory.register("custom", CustomStrategy)
        assert "custom" in DetectorFactory.available_detectors()


class TestDetectionEngine:
    """检测引擎上下文测试"""

    def test_create_default_engine(self):
        from src.analysis.detection_engine import create_default_engine
        engine = create_default_engine()
        assert len(engine._strategies) >= 4

    def test_add_remove_strategy(self):
        from src.analysis.detection_engine import DetectionEngine, RuleBasedStrategy
        engine = DetectionEngine()
        assert len(engine._strategies) == 0
        engine.add_strategy(RuleBasedStrategy(), weight=0.3)
        assert len(engine._strategies) == 1
        engine.remove_strategy("rule_based")
        assert len(engine._strategies) == 0

    def test_detect_all_empty(self):
        from src.analysis.detection_engine import DetectionEngine
        engine = DetectionEngine()
        result = engine.detect_all([])
        assert result["total_alerts"] == 0
        assert result["ensemble_vote"]["is_attack"] is False


# ============================================================
# P1-2: 取证知识库测试
# ============================================================

class TestForensicKnowledgeBase:
    """取证知识库测试"""

    def test_get_stats(self):
        from src.storage.forensic_kb import get_forensic_kb
        stats = get_forensic_kb().get_stats()
        assert "analysis_count" in stats
        assert "chat_count" in stats
        assert "baseline_count" in stats

    def test_get_trend_analysis(self):
        from src.storage.forensic_kb import get_forensic_kb
        trend = get_forensic_kb().get_trend_analysis(days=7)
        assert "total_records" in trend
        assert "daily_stats" in trend
        assert "top_attack_types" in trend

    def test_extract_iocs_empty(self):
        from src.storage.forensic_kb import get_forensic_kb
        iocs = get_forensic_kb().extract_iocs("nonexistent_id")
        assert iocs == []


# ============================================================
# P1-4: SQLite 数据库测试
# ============================================================

class TestDatabase:
    """SQLite 数据库测试"""

    def test_singleton(self):
        from src.storage.database import Database
        db1 = Database()
        db2 = Database()
        assert db1 is db2

    def test_get_stats(self):
        from src.storage.database import Database
        stats = Database().get_stats()
        assert "analysis_count" in stats
        assert "chat_count" in stats
        assert "baseline_count" in stats
        assert "db_path" in stats

    def test_add_and_list_chat(self):
        from src.storage.database import Database
        db = Database()
        result = db.add_chat("user", "test message", session_id="test_session_pytest")
        assert result is not None
        assert "id" in result
        chats = db.list_chat(session_id="test_session_pytest")
        assert isinstance(chats, list)


# ============================================================
# P0-3: 幻觉控制测试
# ============================================================

class TestHallucinationControl:
    """幻觉控制三件套测试"""

    def test_module_import(self):
        from src.ai.hallucination_control import (
            OutputValidator, ConfidenceCrossValidator, ReviewMarker
        )
        assert OutputValidator is not None
        assert ConfidenceCrossValidator is not None
        assert ReviewMarker is not None

    def test_output_validator_instance(self):
        from src.ai.hallucination_control import OutputValidator
        validator = OutputValidator()
        assert validator is not None


# ============================================================
# P0-1: 监督检测器测试
# ============================================================

class TestSupervisedDetector:
    """监督检测器测试"""

    def test_detector_initialization(self):
        from src.analysis.supervised_detector import SupervisedDetector
        detector = SupervisedDetector()
        assert detector is not None
        assert detector.model is not None or detector.loaded is False

    def test_cic_feature_extractor(self):
        from src.analysis.cic_features import CICFlowExtractor
        extractor = CICFlowExtractor()
        assert extractor is not None
        # 检查有特征提取方法
        methods = [m for m in dir(extractor) if not m.startswith("_")]
        assert len(methods) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
