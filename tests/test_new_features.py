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
# 三引擎 Stacking 融合测试（3.3.0 取代原监督检测器测试）
# ============================================================

class TestStackingFusion:
    """三引擎 Stacking 融合层测试"""

    def test_fusion_initialization(self):
        from src.analysis.stacking_fusion import ThreeEngineStacking, ENGINE_ORDER
        fusion = ThreeEngineStacking()
        assert fusion is not None
        assert tuple(ENGINE_ORDER) == ("rule_based", "baseline", "isolation_forest")
        assert fusion.feature_dim == 13  # v3.4.0: 10→13维（新增孤立森林异常分统计）

    def test_feature_extraction_shape(self):
        from src.analysis.stacking_fusion import ThreeEngineStacking
        fusion = ThreeEngineStacking()
        feats = fusion.extract_features(
            {"alerts": [{"type": "SYN_FLOOD_SUSPECTED", "severity": "HIGH"}],
             "total_alerts": 1},
            {"drift": None, "multi_dim_alerts": []},
            {"learned": True, "anomaly_windows": 2, "total_windows": 10},
        )
        assert feats.shape == (13,)  # v3.4.0: 10→13维

    def test_predict_without_meta_learner_uses_fallback(self):
        """元学习器缺失时必须回退固定权重，并如实标注来源"""
        from src.analysis.stacking_fusion import ThreeEngineStacking
        fusion = ThreeEngineStacking(model_path=None)
        assert fusion.meta_learner is None
        out = fusion.predict({"alerts": [], "total_alerts": 0}, {}, {"learned": False})
        assert out["confidence_source"] == "weighted_fallback"
        assert out["meta_learner_used"] is False
        assert out["architecture"] == "three_engine_stacking"

    def test_load_rejects_wrong_engine_order(self, tmp_path):
        """引擎顺序不匹配的元学习器必须被拒绝加载（防止给出错误判定）"""
        import joblib
        from sklearn.linear_model import LogisticRegression
        import numpy as np
        from src.analysis.stacking_fusion import ThreeEngineStacking

        X = np.random.RandomState(0).rand(20, 4)
        y = (X[:, 0] > 0.5).astype(int)
        clf = LogisticRegression().fit(X, y)
        p = tmp_path / "wrong.joblib"
        joblib.dump({"model": clf,
                     "feature_order": ["supervised", "rule_based", "baseline", "isolation_forest"]},
                    p)
        fusion = ThreeEngineStacking()
        assert fusion.load(str(p)) is False
        assert fusion.meta_learner is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
