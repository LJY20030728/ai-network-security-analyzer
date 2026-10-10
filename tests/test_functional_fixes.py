# -*- coding: utf-8 -*-
"""
功能正确性批次（B15–B18）的回归测试

B15 多温度投票是虚构的：`analyze_threats_structured` 内部把 temperature 硬编码
    为 0.2，且响应缓存 key 只含 messages+temp+max_tokens → n 次"独立"采样实际
    只发生 1 次调用、拿到同一结果，投票恒为全体一致。
B16 混合检索上报**伪造**相似度：`distances.get(doc_id, 0.5)` 给 BM25-only 命中
    凭空赋 0.5（高于真实 dist=0.6 → 0.40）；且映射非单调（dist 1.9 → 0.3448
    > dist 1.0 → 0.0），`_rerank` 据此排序会出错。
B17 `expand_terms` 用朴素子串替换，`HTTP` 先于 `HTTPS` 命中，把 `HTTPS` 改写成
    `HTTP 超文本传输S`；`rewrite_query` 的正则第 2 组吃掉"有什么"，拆出
    `CSRF有什么是什么`。
B18 `list_analysis` 不 SELECT `raw_json`，而 `forensic_kb` 读 `rec["raw"]`
    → 取证攻击趋势恒为空；`rag_engine.clear()` 不复位 BM25 索引与播种标记
    → 重建知识库后返回空内容幽灵结果。

本文件为新增测试，不修改任何既有测试。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------
# B15：多温度投票必须真的产生 N 次不同温度的调用
# ----------------------------------------------------------------------

class _FakeCompletions:
    def __init__(self, log):
        self.log = log

    def create(self, model, messages, temperature, max_tokens):
        import json as _json
        self.log.append(temperature)

        class _M:
            content = _json.dumps({"is_threat": True, "overall_confidence": 0.8,
                                   "overview": "ok", "attacks": [],
                                   "recommended_actions": []})

        class _C:
            message = _M()

        class _R:
            choices = [_C()]
            usage = type("U", (), {"prompt_tokens": 1, "completion_tokens": 1})()

        return _R()


def _threat_analyzer_with_fake_llm(temps_log):
    from src.ai.llm_client import get_llm_client, reset_llm_client
    import src.ai.threat_analyzer as TA

    reset_llm_client()
    llm = get_llm_client()
    llm.client = type("FC", (), {"chat": type("CH", (), {
        "completions": _FakeCompletions(temps_log)})()})()
    llm.api_key = "test-key"

    ta = TA.get_threat_analyzer()
    ta.llm = llm

    class _FakeRag:
        def search(self, *a, **k):
            return []

    ta.rag = _FakeRag()
    return ta


def test_vote_makes_n_real_calls_with_distinct_temperatures():
    """核心回归：3 次采样必须是 3 次真实调用，且温度各不相同。"""
    log = []
    ta = _threat_analyzer_with_fake_llm(log)
    res = ta.analyze_threats_structured_vote(
        {"total_alerts": 1, "alerts": [{"type": "SYN_FLOOD_SUSPECTED", "severity": "HIGH"}]},
        n_samples=3, temperatures="0.1,0.4,0.7")

    assert len(log) == 3, f"应为 3 次独立调用，实际 {len(log)}（此前恒为 1）"
    assert log == [0.1, 0.4, 0.7], f"温度未真正传递: {log}"
    assert [v["temperature"] for v in res["votes"]] == [0.1, 0.4, 0.7]


def test_vote_not_swallowed_by_response_cache():
    """第二次投票不得被缓存短路。"""
    log = []
    ta = _threat_analyzer_with_fake_llm(log)
    payload = {"total_alerts": 1, "alerts": [{"type": "SYN_FLOOD_SUSPECTED", "severity": "HIGH"}]}
    ta.analyze_threats_structured_vote(payload, n_samples=3, temperatures="0.1,0.4,0.7")
    log.clear()
    ta.analyze_threats_structured_vote(payload, n_samples=3, temperatures="0.1,0.4,0.7")
    assert len(log) == 3, f"投票被缓存短路，仅 {len(log)} 次调用"


def test_non_vote_path_still_uses_cache():
    """非投票场景不应被过度禁用缓存。"""
    from src.ai.llm_client import get_llm_client, reset_llm_client
    log = []
    reset_llm_client()
    llm = get_llm_client()
    llm.client = type("FC", (), {"chat": type("CH", (), {
        "completions": _FakeCompletions(log)})()})()
    llm.api_key = "k"
    msgs = [{"role": "user", "content": "hello-cache-test"}]
    llm.chat(msgs, temperature=0.2)
    llm.chat(msgs, temperature=0.2)
    assert len(log) == 1, "相同请求第二次应命中缓存"


def test_vote_respects_configured_temperatures(monkeypatch):
    from config.settings import settings
    log = []
    ta = _threat_analyzer_with_fake_llm(log)
    monkeypatch.setattr(settings, "llm_vote_temperatures", "0.0,0.5,0.9")
    ta.analyze_threats_structured_vote({"total_alerts": 0, "alerts": []}, n_samples=3)
    assert log == [0.0, 0.5, 0.9]


def test_language_injection_does_not_mutate_caller_messages():
    """`_inject_language_instruction` 不得原地修改调用方的 messages。"""
    from src.ai.llm_client import LLMClient
    original = [{"role": "user", "content": "hi"}]
    snapshot = [dict(m) for m in original]
    LLMClient()._inject_language_instruction(original)
    assert original == snapshot, "调用方 messages 被就地修改"


# ----------------------------------------------------------------------
# B16：相似度映射必须单调，且不得伪造缺失值
# ----------------------------------------------------------------------

def test_similarity_mapping_is_monotonic():
    from src.ai.rag_engine import RAGEngine
    vals = [RAGEngine.distance_to_similarity(d)
            for d in (0.0, 0.2, 0.5, 1.0, 1.5, 1.9, 2.0)]
    assert vals == sorted(vals, reverse=True), f"非单调: {vals}"
    # 明确回归：dist 1.9 不得高于 dist 1.0
    assert RAGEngine.distance_to_similarity(1.9) < RAGEngine.distance_to_similarity(1.0)


def test_similarity_mapping_range():
    from src.ai.rag_engine import RAGEngine
    assert RAGEngine.distance_to_similarity(0.0) == 1.0
    assert RAGEngine.distance_to_similarity(2.0) == 0.0
    assert RAGEngine.distance_to_similarity(-5) == 1.0     # 裁剪
    assert RAGEngine.distance_to_similarity(9) == 0.0


def test_missing_distance_is_not_fabricated():
    """无真实距离的条目标记为 unavailable，不再凭空 0.5。"""
    from src.ai.rag_engine import RAGEngine

    class _Coll:
        def get(self, ids, include=None):
            return {"ids": ids, "documents": ["d" + i for i in ids],
                    "metadatas": [{"title": "t" + i} for i in ids]}

    eng = RAGEngine.__new__(RAGEngine)
    eng.collection = _Coll()
    res = eng._format_results(["a", "b"], {"a": 0.4})

    assert res[0]["similarity"] == pytest.approx(0.8)
    assert res[0]["distance_source"] == "vector"
    assert res[1]["similarity"] is None, "仍伪造了相似度"
    assert res[1]["distance"] is None, "仍伪造了距离"
    assert res[1]["distance_source"] == "unavailable"


def test_no_default_05_distance_default_in_source():
    """不得再用 0.5 之类假值填充缺失距离。

    用 AST 检查**代码**（docstring 里说明旧实现用的是正确内容，不应被误判）。
    """
    import ast
    import io

    src = io.open(os.path.join(ROOT, "src", "ai", "rag_engine.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    # 收集所有 dict.get(..., 0.5) 与字典推导中的 0.5 常量
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "get" and len(node.args) >= 2:
            default = node.args[1]
            if isinstance(default, ast.Constant) and default.value == 0.5:
                pytest.fail(f"行 {node.lineno}: dict.get 仍用 0.5 作默认值")
    # 不允许 {doc_id: 0.5 for ...} 这种伪造兜底
    assert "doc_id: 0.5 for doc_id" not in _strip_docstrings(src), \
        "异常分支仍返回伪造 0.5"


def _strip_docstrings(src: str) -> str:
    """移除所有 docstring 后的源码（用于字符串级断言，避免注释误伤）"""
    import ast
    import io
    tree = ast.parse(src)
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                spans.append((body[0].lineno, body[0].end_lineno))
    lines = src.splitlines()
    for a, b in sorted(spans, reverse=True):
        del lines[a - 1:b]
    return "\n".join(lines)


def test_rerank_normalizes_similarity_and_handles_none():
    """排序对 None 相似度不得崩溃，也不得系统性惩罚 BM25-only 条目。"""
    from src.ai.rag_engine import RAGEngine
    eng = RAGEngine.__new__(RAGEngine)
    eng.embedding_function = None
    results = [
        {"content": "syn flood attack", "metadata": {"title": "SYN Flood"},
         "similarity": 0.9, "distance_source": "vector"},
        {"content": "syn flood", "metadata": {"title": "SYN Flood"},
         "similarity": None, "distance_source": "unavailable"},
    ]
    out = eng._rerank("SYN Flood", results)
    assert all("rerank_score" in r for r in out)


# ----------------------------------------------------------------------
# B17：查询改写
# ----------------------------------------------------------------------

@pytest.mark.parametrize("query,must_not_contain", [
    ("HTTPS流量如何检测", "超文本传输S"),
    ("HTTP和HTTPS的区别", "超文本传输S"),
])
def test_expand_terms_does_not_corrupt_https(query, must_not_contain):
    from src.ai.retrieval_hybrid import expand_terms
    out = expand_terms(query)
    assert must_not_contain not in out, f"HTTPS 被 HTTP 吃掉: {out!r}"


@pytest.mark.parametrize("text", ["HTTPServer", "myHTTPx", "HTTPSServer"])
def test_expand_terms_respects_boundaries(text):
    from src.ai.retrieval_hybrid import expand_terms
    assert expand_terms(text) == text, f"误改写更长标识符: {expand_terms(text)!r}"


def test_expand_terms_still_expands_standalone_terms():
    from src.ai.retrieval_hybrid import expand_terms
    assert "网络服务扫描" in expand_terms("T1046是什么")
    assert "安全外壳" in expand_terms("SSH暴力破解")


@pytest.mark.parametrize("query,expected", [
    ("XSS和CSRF有什么区别", ["XSS是什么", "CSRF是什么"]),
    ("XSS和CSRF有什么不同", ["XSS是什么", "CSRF是什么"]),
    ("TCP和UDP有什么区别", ["TCP是什么", "UDP是什么"]),
    ("这只是一句普通问题", ["这只是一句普通问题"]),
])
def test_rewrite_query_splits_cleanly(query, expected):
    from src.ai.retrieval_hybrid import rewrite_query
    assert rewrite_query(query) == expected


def test_rewrite_query_keeps_shared_question_tail():
    from src.ai.retrieval_hybrid import rewrite_query
    out = rewrite_query("DNS放大攻击和DNS投毒的区别，检测上关注什么？")
    assert len(out) == 2
    for sub in out:
        assert "检测上关注什么" in sub
        assert "，，" not in sub, f"标点重复: {sub!r}"


# ----------------------------------------------------------------------
# B18：取证趋势 + BM25 失效
# ----------------------------------------------------------------------

def test_list_analysis_includes_raw():
    """list_analysis 必须返回 raw（forensic_kb 的统计与趋势依赖它）。"""
    import inspect
    from src.storage.database import Database
    src = inspect.getsource(Database.list_analysis)
    assert "raw_json" in src, "SELECT 未包含 raw_json"
    assert 'd["raw"]' in src, "未解析为 raw 字段"


def test_list_analysis_tolerates_corrupt_json(tmp_path, monkeypatch):
    """单行 JSON 损坏不得让整批查询失败。

    直接写入损坏的 severity 字符串（绕过 add_analysis 的 json.dumps 归一化，
    以模拟真实的脏数据/旧版本写入）。
    """
    import threading
    from src.storage.database import Database

    db = Database()
    monkeypatch.setattr(db, "_db_path", str(tmp_path / "t.db"), raising=False)
    monkeypatch.setattr(db, "_local", threading.local(), raising=False)
    db._init_tables()
    db.add_analysis({
        "id": "broken-1", "ts": "2026-01-01 00:00:00", "file": "x.pcap",
        "packets": 1, "flows": 1, "bytes": 1, "alerts": 1,
        "severity": {"HIGH": 1}, "summary_text": "s", "raw": {"a": 1},
    })
    # 用原始 SQL 写入一个损坏的 severity 与 raw_json
    conn = db._get_conn()
    conn.execute("UPDATE analysis_history SET severity = ?, raw_json = ? WHERE id = ?",
                 ("{not valid json", "[[[", "broken-1"))
    conn.commit()

    rows = db.list_analysis()          # 不得抛异常
    assert rows, "损坏行导致列表为空"
    assert isinstance(rows[0]["severity"], dict), rows[0]["severity"]
    assert isinstance(rows[0]["raw"], dict), rows[0]["raw"]


def test_forensic_trend_reads_raw_alerts(tmp_path, monkeypatch):
    """取证统计的攻击类型应能真正读到告警（此前恒为空）。"""
    import threading
    from src.storage.database import Database

    db = Database()
    monkeypatch.setattr(db, "_db_path", str(tmp_path / "t2.db"), raising=False)
    monkeypatch.setattr(db, "_local", threading.local(), raising=False)
    db._init_tables()
    db.add_analysis({
        "id": "a1", "ts": "2026-01-01 00:00:00", "file": "x.pcap",
        "packets": 1, "flows": 1, "bytes": 1, "alerts": 1,
        "severity": {"HIGH": 1}, "summary_text": "s",
        "raw": {"anomaly_detection": {"alerts": [{"type": "PORT_SCAN_SUSPECTED"}]}},
    })
    rows = db.list_analysis()
    alerts = rows[0]["raw"].get("anomaly_detection", {}).get("alerts", [])
    assert alerts and alerts[0]["type"] == "PORT_SCAN_SUSPECTED"


def test_rag_clear_resets_bm25_and_seed_flag():
    """clear() 必须复位 BM25 索引与播种标记，否则重建后出现幽灵结果。"""
    import inspect
    from src.ai.rag_engine import RAGEngine
    src = inspect.getsource(RAGEngine.clear)
    assert "_invalidate_bm25_index" in src, "clear() 未复位 BM25 索引"
    assert "_seeded = False" in src, "clear() 未复位播种标记"


def test_add_texts_invalidates_bm25():
    """新增文档后必须让 BM25 失效，否则新内容无法被关键词臂召回。"""
    import inspect
    from src.ai.rag_engine import RAGEngine
    src = inspect.getsource(RAGEngine.add_texts)
    assert "_invalidate_bm25_index" in src, "add_texts 未使 BM25 索引失效"
