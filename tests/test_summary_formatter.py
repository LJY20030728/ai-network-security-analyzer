"""
摘要格式化模块单元测试（src/report/summary_formatter.py）

这些逻辑原先内联在 gradio_app 的回调闭包里，无法单测。抽离后在此覆盖。

其中最重要的断言是「诚信约束」：置信度来源必须如实呈现，
不得把固定权重回退（weighted_fallback）展示成元学习器输出。
"""
from src.report.summary_formatter import (
    CONFIDENCE_SOURCE_LABELS,
    format_analysis_summary,
    format_anomaly_summary,
    format_hallucination_block,
    format_stacking_verdict,
    format_traffic_overview,
)


def _report(**over):
    base = {
        "summary": {
            "total_packets": 200, "total_flows": 198, "total_bytes": 2048,
            "time_range": {"start": "2026-01-01 00:00:00.000", "end": "2026-01-01 00:00:10.000"},
        },
        "protocol_distribution": {"TCP": 150, "UDP": 50},
        "anomaly_detection": {
            "total_alerts": 3,
            "severity_summary": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0},
        },
        "stacking_fusion": {
            "architecture": "three_engine_stacking",
            "engine_order": ["rule_based", "baseline", "isolation_forest"],
            "is_attack": True, "attack_prob": 0.83, "confidence": 0.66,
            "confidence_source": "model", "meta_learner_used": True,
            "contributions": {"rule_based": 0.5, "baseline": 0.3, "isolation_forest": 0.2},
        },
    }
    base.update(over)
    return base


class TestTrafficOverview:
    def test_basic_fields(self):
        text = format_traffic_overview(_report())
        assert "总数据包数: 200" in text
        assert "网络流数量: 198" in text
        assert "TCP: 150 包 (75.0%)" in text
        assert "UDP: 50 包 (25.0%)" in text

    def test_zero_packets_no_division_error(self):
        """total_packets=0 时不得抛 ZeroDivisionError（原先内联代码会崩）"""
        r = _report(summary={"total_packets": 0, "total_flows": 0, "total_bytes": 0,
                             "time_range": {}})
        text = format_traffic_overview(r)
        assert "总数据包数: 0" in text

    def test_missing_sections_tolerated(self):
        assert format_traffic_overview({}) != ""


class TestStackingVerdict:
    def test_none_returns_empty(self):
        assert format_stacking_verdict(None) == ""
        assert format_stacking_verdict({}) == ""

    def test_basic_render(self):
        text = format_stacking_verdict({
            "is_attack": True, "confidence": 0.8, "attack_prob": 0.9,
            "confidence_source": "model", "meta_learner_used": True,
        })
        assert "三引擎融合判定" in text
        assert "🔴 攻击" in text
        assert "攻击概率: 0.9000" in text

    def test_meta_learner_used_is_disclosed(self):
        used = format_stacking_verdict({
            "is_attack": True, "confidence": 0.8,
            "confidence_source": "model", "meta_learner_used": True})
        assert "元学习器: 已使用" in used

        fallback = format_stacking_verdict({
            "is_attack": False, "confidence": 0.2,
            "confidence_source": "weighted_fallback", "meta_learner_used": False})
        assert "未加载（固定权重回退）" in fallback

    def test_fallback_source_is_not_presented_as_model(self):
        """诚信约束：固定权重回退必须明示「非模型输出」"""
        text = format_stacking_verdict({
            "is_attack": True, "confidence": 0.55,
            "confidence_source": "weighted_fallback", "meta_learner_used": False,
        })
        assert "固定权重回退（非模型输出）" in text
        # 不得出现"元学习器输出"
        assert "元学习器输出（Stacking）" not in text

    def test_engine_contributions_rendered(self):
        text = format_stacking_verdict({
            "is_attack": True, "confidence": 0.5,
            "contributions": {"rule_based": 0.6, "baseline": 0.0, "isolation_forest": 0.4},
        })
        assert "引擎贡献" in text
        assert "rule_based:60%" in text
        assert "isolation_forest:40%" in text
        # 0 值贡献不展示
        assert "baseline" not in text

    def test_confidence_source_labels_cover_known_values(self):
        """所有可能出现的来源都应有中文标签，避免 UI 露出英文枚举"""
        for key in ("model", "weighted_fallback"):
            assert key in CONFIDENCE_SOURCE_LABELS


class TestAnomalySummary:
    def test_counts_and_severities(self):
        text = format_anomaly_summary({"total_alerts": 3,
                                       "severity_summary": {"HIGH": 2, "MEDIUM": 1, "LOW": 0}})
        assert "共 3 条告警" in text
        assert "HIGH: 2 条" in text
        assert "MEDIUM: 1 条" in text
        assert "LOW" not in text          # 0 条不展示

    def test_empty_returns_empty(self):
        assert format_anomaly_summary({}) == ""


class TestAnalysisSummary:
    def test_composes_all_sections(self):
        text = format_analysis_summary(_report())
        assert "流量分析概览" in text
        assert "三引擎融合判定" in text
        assert "异常检测" in text


class TestHallucinationBlock:
    def test_full_block(self):
        text = format_hallucination_block({
            "output_validation": {"score": 0.8, "level": "pass", "issues": ["a"]},
            "cross_validation": {"consensus": "attack", "agreement": 0.67},
            "hallucination_risk": "medium",
            "review_marker": {"needs_review": True, "priority": "high",
                              "reasons": ["r1", "r2", "r3", "r4"]},
        })
        assert "幻觉控制校验" in text
        assert "输出校验分: 0.8" in text
        assert "多引擎共识: attack" in text
        assert "67%" in text
        assert "需人工复核: high优先级" in text
        assert text.count("    - ") == 3          # 最多展示 3 条原因

    def test_empty_and_missing_keys(self):
        assert format_hallucination_block({}) == ""
        assert format_hallucination_block(None) == ""
        # 缺字段不得抛异常
        assert "幻觉控制校验" in format_hallucination_block({"hallucination_risk": "low"})
