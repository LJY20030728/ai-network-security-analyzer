# -*- coding: utf-8 -*-
"""API 审计日志单测：写入 / 查询 / 过滤 / 统计 / 失败降级"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest

from src.api.audit import AuditLogger


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(os.path.join(str(tmp_path), "audit.db"))


class TestAudit:
    def test_log_and_query(self, audit):
        audit.log("GET", "/api/healthz", 200, 5.2, "127.0.0.1", "pytest")
        rows = audit.query(limit=10)
        assert len(rows) == 1
        assert rows[0]["method"] == "GET"
        assert rows[0]["status_code"] == 200
        assert rows[0]["duration_ms"] == 5.2

    def test_status_filter(self, audit):
        audit.log("GET", "/api/a", 200, 1.0)
        audit.log("GET", "/api/b", 401, 2.0)
        audit.log("GET", "/api/c", 500, 3.0)
        assert len(audit.query(status=401)) == 1
        assert len(audit.query(status=200)) == 1

    def test_path_filter(self, audit):
        audit.log("POST", "/api/pcap/analyze", 200, 10.0)
        audit.log("GET", "/api/knowledge/stats", 200, 11.0)
        assert len(audit.query(path_kw="pcap")) == 1
        assert len(audit.query(path_kw="knowledge")) == 1

    def test_stats_aggregation(self, audit):
        audit.log("GET", "/api/a", 200, 10.0)
        audit.log("GET", "/api/a", 200, 30.0)
        audit.log("GET", "/api/b", 500, 20.0)
        s = audit.stats()
        assert s["total_requests"] == 3
        assert s["error_count"] == 1
        assert s["error_rate"] == pytest.approx(1 / 3, abs=0.001)
        assert s["avg_duration_ms"] == pytest.approx(20.0, abs=0.1)
        assert s["top_endpoints"][0]["path"] == "/api/a"

    def test_log_failure_degrades(self, audit):
        """DB 异常时写入降级跳过，不影响调用方"""
        audit._conn.close()
        audit.log("GET", "/api/x", 200, 1.0)  # 不应抛异常
