# -*- coding: utf-8 -*-
"""L3 多采样投票单元测试：多数投票 / 一致性 / 票合并 / 全部失败降级"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.ai.threat_analyzer import ThreatAnalyzer


def make_structured(is_threat, conf, attacks=None, refs=None, actions=None):
    return {
        "overview": "overview-x",
        "is_threat": is_threat,
        "overall_confidence": conf,
        "attacks": attacks or [],
        "recommended_actions": actions or [],
        "knowledge_references": refs or [],
    }


class TestVotingMerge:
    def test_vote_union_dedup_preserves_order(self):
        out = ThreatAnalyzer._vote_union([["a", "b"], ["b", "c"], []])
        assert out == ["a", "b", "c"]

    def test_merge_vote_attacks_majority(self):
        a1 = make_structured(True, 0.9, attacks=[{"alert_type": "端口扫描", "evidence": "ev1",
                                                  "is_true_positive": True, "confidence": 0.9,
                                                  "recommended_actions": ["隔离"]}])
        a2 = make_structured(True, 0.8, attacks=[{"alert_type": "端口扫描", "evidence": "ev1",
                                                  "is_true_positive": False, "confidence": 0.6,
                                                  "recommended_actions": ["监控"]}])
        a3 = make_structured(True, 0.7, attacks=[{"alert_type": "端口扫描", "evidence": "ev1",
                                                  "is_true_positive": True, "confidence": 0.8,
                                                  "recommended_actions": ["隔离"]}])
        merged = ThreatAnalyzer._merge_vote_attacks([a1, a2, a3])
        attacks = merged["attacks"]
        assert len(attacks) == 1
        assert attacks[0]["is_true_positive"] is True      # 2/3 多数
        assert "隔离" in attacks[0]["recommended_actions"]
        assert "监控" in attacks[0]["recommended_actions"]  # 并集

    def test_merge_vote_attacks_separates_different_alerts(self):
        a1 = make_structured(True, 0.9, attacks=[{"alert_type": "A", "evidence": "e1",
                                                  "is_true_positive": True, "confidence": 0.9,
                                                  "recommended_actions": []}])
        a2 = make_structured(True, 0.9, attacks=[{"alert_type": "B", "evidence": "e2",
                                                  "is_true_positive": False, "confidence": 0.4,
                                                  "recommended_actions": []}])
        merged = ThreatAnalyzer._merge_vote_attacks([a1, a2])
        assert len(merged["attacks"]) == 2


class TestVoteFlow:
    def test_vote_majority_true(self, monkeypatch):
        analyzer = ThreatAnalyzer()
        # 2 票真 1 票假 → 最终真，agreement=0.667
        def fake_structured(*a, **k):
            calls = fake_structured.n
            fake_structured.n += 1
            is_t = calls < 2
            return {"ok": True, "structured": make_structured(is_t, 0.8 + 0.05 * calls),
                    "raw_text": "", "evidence_match": []}
        fake_structured.n = 0
        monkeypatch.setattr(analyzer, "analyze_threats_structured", fake_structured)
        r = analyzer.analyze_threats_structured_vote({"alerts": []}, n_samples=3,
                                                     temperatures="0.1,0.4,0.7")
        assert r["ok"] is True
        assert r["structured"]["is_threat"] is True
        assert r["agreement"] == pytest.approx(0.667, abs=0.01)
        assert len(r["votes"]) == 3

    def test_vote_all_fail_degrades(self, monkeypatch):
        analyzer = ThreatAnalyzer()
        def fake_structured(*a, **k):
            return {"ok": False, "structured": None, "raw_text": "x"}
        monkeypatch.setattr(analyzer, "analyze_threats_structured", fake_structured)
        r = analyzer.analyze_threats_structured_vote({"alerts": []}, n_samples=3)
        assert r["ok"] is False
        assert "全部解析失败" in r["raw_text"]

    def test_vote_confidence_penalized_by_low_agreement(self, monkeypatch):
        analyzer = ThreatAnalyzer()
        # 2 真 1 假：置信度应低于平均置信度（一致性加权）
        def fake_structured(*a, **k):
            calls = fake_structured.n
            fake_structured.n += 1
            return {"ok": True, "structured": make_structured(calls < 2, 0.9),
                    "raw_text": "", "evidence_match": []}
        fake_structured.n = 0
        monkeypatch.setattr(analyzer, "analyze_threats_structured", fake_structured)
        r = analyzer.analyze_threats_structured_vote({"alerts": []}, n_samples=3)
        assert r["structured"]["overall_confidence"] < 0.9  # 一致性加权后下降
        assert r["structured"]["overall_confidence"] > 0.5

    def test_vote_uses_settings_default_temps(self, monkeypatch):
        analyzer = ThreatAnalyzer()
        seen = []
        def fake_structured(*a, **k):
            return {"ok": True, "structured": make_structured(True, 0.8),
                    "raw_text": "", "evidence_match": []}
        monkeypatch.setattr(analyzer, "analyze_threats_structured", fake_structured)
        r = analyzer.analyze_threats_structured_vote({"alerts": []})
        assert len(r["votes"]) == 3
        temps = [v["temperature"] for v in r["votes"]]
        assert temps == [0.1, 0.4, 0.7]
