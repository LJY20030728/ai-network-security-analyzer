# -*- coding: utf-8 -*-
"""L4 证据比对匹配器单元测试：特征提取 / 匹配度 / 检索失败降级"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.ai.evidence_matcher import EvidenceMatcher, ALERT_TYPE_PROFILE


class FakeRag:
    """桩 RAG：返回预置知识条目（含流量特征指纹）"""
    def __init__(self, results=None):
        self._results = results or []

    def search(self, query, top_k=3, use_hybrid=True):
        return self._results


SYN_ALERT = {
    "type": "SYN_FLOOD_SUSPECTED", "severity": "HIGH",
    "src_ip": "10.0.0.5", "syn_count": 600, "unanswered_syn": 590,
    "description": "源IP 10.0.0.5 发出 600 个SYN，未完成握手 590 个，疑似SYN洪水攻击",
}

MITRE_SYN_DOC = {
    "content": ("攻击者通过发送大量SYN包实施拒绝服务攻击，常见SYN洪水特征："
                "短时间内大量SYN无ACK响应；端口80/443常见于Web服务。"),
    "metadata": {"title": "MITRE ATT&CK T1498 - 网络拒绝服务", "source": "knowledge_base"},
    "similarity": 0.85,
}


class TestEvidenceMatcher:
    def test_alert_numeric_fields_extracts_counts(self):
        nums = EvidenceMatcher._alert_numeric_fields(SYN_ALERT)
        assert 600 in nums and 590 in nums

    def test_alert_plain_text_contains_type_and_ip(self):
        text = EvidenceMatcher._alert_plain_text(SYN_ALERT)
        assert "SYN_FLOOD_SUSPECTED" in text and "10.0.0.5" in text

    def test_match_alert_hits_keywords(self):
        matcher = EvidenceMatcher(rag=FakeRag([MITRE_SYN_DOC]))
        r = matcher.match_alert(SYN_ALERT)
        assert r["match_score"] > 0
        assert "T1498" in r["knowledge_title"]
        assert r["matched_keywords"], "应命中期望关键词"
        assert "启发式" in r["note"]

    def test_match_alert_no_results_returns_zero(self):
        matcher = EvidenceMatcher(rag=FakeRag([]))
        r = matcher.match_alert(SYN_ALERT)
        assert r["match_score"] == 0.0
        assert "未命中" in r["note"]

    def test_unknown_alert_type_does_not_crash(self):
        matcher = EvidenceMatcher(rag=FakeRag([MITRE_SYN_DOC]))
        r = matcher.match_alert({"type": "WEIRD_TYPE", "src_ip": "1.2.3.4"})
        assert r["alert_type"] == "WEIRD_TYPE"

    def test_rag_exception_degrades_to_zero(self):
        class BoomRag:
            def search(self, *a, **k):
                raise RuntimeError("boom")
        matcher = EvidenceMatcher(rag=BoomRag())
        r = matcher.match_alert(SYN_ALERT)
        assert r["match_score"] == 0.0

    def test_match_alerts_preserves_order(self):
        matcher = EvidenceMatcher(rag=FakeRag([MITRE_SYN_DOC]))
        out = matcher.match_alerts([SYN_ALERT, {"type": "RST_STORM", "rst_count": 80}])
        assert len(out) == 2
        assert out[0]["alert_type"] == "SYN_FLOOD_SUSPECTED"

    def test_alert_type_profile_covers_detection_types(self):
        for t in ("SYN_FLOOD_SUSPECTED", "PORT_SCAN_SUSPECTED", "DNS_TUNNEL_SUSPECTED",
                  "LARGE_DATA_TRANSFER", "RST_STORM", "BASELINE_DEVIATION", "ML_ANOMALY"):
            assert t in ALERT_TYPE_PROFILE, f"缺少 {t} 的比对档案"
