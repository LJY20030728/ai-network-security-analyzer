# -*- coding: utf-8 -*-
"""
`get_trend_analysis` 的返回契约（空态与有数据态必须同构）

## 它防的是什么

`get_trend_analysis()` 曾在两个分支返回**结构不同**的字典：

    无历史数据 →  {"total": 0, "message": "无历史数据"}          # 2 个字段
    有历史数据 →  {total_records, attack_records, ..., high_risk_count}  # 12 个字段

后果不是"测试红了"，而是**产品行为随数据存在与否而变**：
  · 开发机有历史数据 → 本地测试全绿
  · 全新安装（= CI 干净 checkout）→ `data/db` 不存在 → 无记录 → 走空态分支
    → UI 的趋势分析端点拿不到 `total_records`/`daily_stats`/`top_attack_types`
  · 于是"新装用户第一次点趋势分析"就是异常路径，而开发时永远看不到

这类缺陷的共性是**测试依赖了本机残留状态**，因此这里显式构造"空库"场景，
而不是借用真实 `data/db`。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.database import Database  # noqa: E402
from src.storage.forensic_kb import ForensicKnowledgeBase  # noqa: E402

# 有数据分支返回的完整字段集（契约基准）
EXPECTED_FIELDS = [
    "total_records",
    "attack_records",
    "normal_records",
    "attack_rate",
    "total_alerts",
    "avg_alerts_per_record",
    "daily_stats",
    "severity_trend",
    "verdict_trend",
    "top_attack_types",
    "needs_review_count",
    "high_risk_count",
]


def _kb_with_empty_db() -> ForensicKnowledgeBase:
    """构造一个指向**空内存数据库**的 ForensicKnowledgeBase（不碰真实 data/db，避免防病毒拦截SQLite文件写入）。"""
    Database.reset_for_testing()
    db = Database(":memory:")
    assert db.list_analysis(limit=10) == [], "测试前提：该库必须为空"

    kb = ForensicKnowledgeBase.__new__(ForensicKnowledgeBase)
    kb._db = db
    return kb


@pytest.mark.parametrize("field", EXPECTED_FIELDS)
def test_empty_db_returns_all_contract_fields(field):
    """★ 核心断言：空库也必须返回全部 12 个字段。"""
    kb = _kb_with_empty_db()
    trend = kb.get_trend_analysis(days=7)
    assert field in trend, (
        f"空态缺少字段 '{field}' —— 返回结构随数据存在与否而变。\n"
        f"  实际返回键: {sorted(trend)}\n"
        f"  后果: 全新安装（CI 干净 checkout）调用趋势分析会字段缺失，\n"
        f"        而开发机因有历史数据永远看不到这个问题。"
    )


def test_empty_db_values_are_zero_not_missing():
    """空态取值应为零值/空容器，而不是 None 或缺失。"""
    kb = _kb_with_empty_db()
    t = kb.get_trend_analysis(days=7)
    assert t["total_records"] == 0
    assert t["attack_records"] == 0
    assert t["normal_records"] == 0
    assert t["attack_rate"] == 0
    assert t["total_alerts"] == 0
    assert t["daily_stats"] == {}
    assert t["severity_trend"] == {}
    assert t["verdict_trend"] == {}
    assert t["top_attack_types"] == []


def test_empty_and_populated_have_identical_key_sets():
    """两种状态的**键集合必须完全一致**（同构契约）。"""
    kb = _kb_with_empty_db()
    empty_keys = set(kb.get_trend_analysis(days=7)) - {"message"}

    # 造一条记录，让函数走"有数据"分支
    kb._db.add_analysis({
        "id": "contract-1", "ts": "2026-01-01 00:00:00", "file": "f.pcap",
        "packets": 10, "flows": 2, "bytes": 100, "alerts": 1,
        "severity": {"HIGH": 1}, "summary_text": "s",
        "raw": {"anomaly_detection": {"alerts": [{"type": "X"}]}},
    })
    populated_keys = set(kb.get_trend_analysis(days=7))

    assert empty_keys == populated_keys, (
        f"键集合不一致：\n"
        f"  仅空态有: {sorted(empty_keys - populated_keys)}\n"
        f"  仅有数据态有: {sorted(populated_keys - empty_keys)}"
    )


def test_message_only_appears_in_empty_state():
    """`message` 是空态的提示性附加字段；有数据时不应出现（避免误导）。"""
    kb = _kb_with_empty_db()
    assert kb.get_trend_analysis(days=7).get("message") == "无历史数据"

    kb._db.add_analysis({
        "id": "contract-2", "ts": "2026-01-01 00:00:00", "file": "f.pcap",
        "packets": 10, "flows": 2, "bytes": 100, "alerts": 1,
        "severity": {"HIGH": 1}, "summary_text": "s",
        "raw": {"anomaly_detection": {"alerts": [{"type": "X"}]}},
    })
    assert "message" not in kb.get_trend_analysis(days=7)
