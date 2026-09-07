# -*- coding: utf-8 -*-
"""P1-2 API 端到端测试：鉴权 / 审计 / 知识库 / 基线 / PCAP 流式分析全链路"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from src.api.main import app
from config.settings import settings

GOLDEN = os.path.join("data", "samples", "golden")
TOKEN = settings.api_auth_token

client = TestClient(app)


def _auth():
    return {"X-API-Token": TOKEN}


# ---------- 鉴权与审计 ----------

def test_health_no_auth():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok" or "status" in body


def test_api_requires_token():
    r = client.get("/api/knowledge/stats")
    assert r.status_code == 401


def test_unauthorized_attempt_is_audited():
    """未授权访问留痕（审计可追溯）"""
    client.get("/api/knowledge/stats")  # 401 触发
    r = client.get("/api/audit/logs", headers=_auth())
    assert r.status_code == 200
    logs = r.json()
    logs_list = logs.get("logs", logs if isinstance(logs, list) else [])
    assert any(l.get("status_code") == 401 for l in logs_list if isinstance(l, dict))


def test_audit_stats():
    r = client.get("/api/audit/stats", headers=_auth())
    assert r.status_code == 200
    assert "total_requests" in r.json()
    assert "error_rate" in r.json()


# ---------- 知识库 ----------

def test_knowledge_stats():
    r = client.get("/api/knowledge/stats", headers=_auth())
    assert r.status_code == 200
    assert r.json().get("total_docs", r.json().get("total", 0)) >= 0


def test_knowledge_search():
    r = client.post("/api/knowledge/search",
                    data={"query": "SQL注入", "top_k": 3}, headers=_auth())
    assert r.status_code == 200
    assert "results" in r.json()


# ---------- 基线管理 ----------

@pytest.fixture(scope="module")
def learned_baseline():
    pcap = os.path.join(GOLDEN, "normal.pcap")
    with open(pcap, "rb") as f:
        r = client.post("/api/baseline/learn",
                        files={"file": ("normal.pcap", f, "application/octet-stream")},
                        data={"name": "e2e_baseline"}, headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "success"
    assert body.get("packet_count", 0) > 0
    assert "profile" in body
    return body


def test_baseline_list(learned_baseline):
    r = client.get("/api/baseline/list", headers=_auth())
    assert r.status_code == 200
    names = [b["name"] for b in r.json().get("baselines", [])]
    assert "e2e_baseline" in names


# ---------- PCAP 流式分析端到端 ----------

@pytest.mark.parametrize("fname,expected_type", [
    ("synflood.pcap", "SYN_FLOOD_SUSPECTED"),
    ("portscan.pcap", "PORT_SCAN_SUSPECTED"),
    ("dnstunnel.pcap", "DNS_TUNNEL_SUSPECTED"),
])
def test_pcap_analyze_stream_e2e(fname, expected_type):
    pcap = os.path.join(GOLDEN, fname)
    with open(pcap, "rb") as f:
        r = client.post("/api/pcap/analyze",
                        files={"file": (fname, f, "application/octet-stream")},
                        data={"enable_ai": "false"}, headers=_auth())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("status") == "success"
    assert body.get("packet_count", 0) > 0
    report = body["analysis_report"]
    assert report.get("streaming") is True  # 流式路径
    types = {a["type"] for a in report["anomaly_detection"]["alerts"]}
    assert expected_type in types
    assert "source_sha256" in body.get("evidence", {})  # 证据溯源


def test_pcap_analyze_rejects_non_pcap():
    r = client.post("/api/pcap/analyze",
                    files={"file": ("x.txt", b"not a pcap", "text/plain")},
                    data={"enable_ai": "false"}, headers=_auth())
    assert r.status_code in (400, 415)
