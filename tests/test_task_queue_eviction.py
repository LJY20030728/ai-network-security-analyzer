# -*- coding: utf-8 -*-
"""
TaskQueue 淘汰策略测试（TTL + 容量双限）

## 为什么需要

原实现的任务表**只增不减**：每个成功任务把完整结果常驻内存
（report JSON ≈ 38 KB / AnalysisOutcome ≈ 89 KB，实测）。
1000 个任务 ≈ 40~90 MB，且永不释放。

但"随时可取回结果"是 API 的设计意图，所以不能无脑删。本测试锁定：

  1. TTL 生效：超期任务被淘汰
  2. 容量生效：超过 max_tasks 时淘汰最旧的已完成任务
  3. **绝不淘汰 pending / running**（违反会让 worker 回写 KeyError）
  4. 被淘汰的任务返回 `status="expired"`，而非 404（可区分"过期"与"不存在"）
  5. 未删未超期的任务仍可正常取回
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.helpers import force_utf8_stdout  # noqa: E402

force_utf8_stdout()

from src.api.task_queue import TaskQueue  # noqa: E402


def _wait_status(q, task_id, statuses, timeout=10.0):
    """轮询直到任务进入指定状态之一"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = q.get(task_id)
        if t and t["status"] in statuses:
            return t
        time.sleep(0.02)
    return q.get(task_id)


def _submit_finished(q, value=1):
    """提交一个立即完成的任务并等待终态"""
    tid = q.submit(lambda: value)
    t = _wait_status(q, tid, ("success", "error"))
    assert t is not None and t["status"] == "success"
    return tid


# ----------------------------------------------------------------------
# 容量淘汰
# ----------------------------------------------------------------------

def test_capacity_limit_evicts_oldest_finished():
    """任务数超过 max_tasks 时必须淘汰，且总数被压回上限内"""
    q = TaskQueue(max_workers=4, result_ttl_sec=3600, max_tasks=5)
    ids = [_submit_finished(q, i) for i in range(12)]

    assert q.stats()["total"] <= 5, (
        f"任务表未被压回上限：total={q.stats()['total']} > max_tasks=5")
    assert q.stats()["evicted_total"] >= 7

    # 最新的任务必须仍可取回（淘汰的是最旧的）
    assert q.get(ids[-1])["status"] == "success"
    # 最旧的任务应已过期
    oldest = q.get(ids[0])
    assert oldest is not None and oldest["status"] == "expired", (
        f"最旧任务应标记为 expired，实际 {oldest}")


def test_evicted_task_returns_expired_not_none():
    """被淘汰的任务返回 status='expired'；从未存在的返回 None。

    这个区分很重要：都返回 404/None 会让调用方以为是 task_id 写错，
    从而错误地重试或报错，而不是提示"结果已过期"。
    """
    q = TaskQueue(max_workers=4, result_ttl_sec=3600, max_tasks=2)
    ids = [_submit_finished(q, i) for i in range(6)]

    evicted = None
    for tid in ids:
        t = q.get(tid)
        if t and t["status"] == "expired":
            evicted = tid
            break
    assert evicted is not None, "应有任务被淘汰并可查询到 expired 状态"

    # 从未存在的 id → None
    assert q.get("nonexistent123") is None


# ----------------------------------------------------------------------
# TTL 淘汰
# ----------------------------------------------------------------------

def test_ttl_evicts_expired_results():
    """TTL 极短时，已完成任务应被淘汰"""
    q = TaskQueue(max_workers=4, result_ttl_sec=1, max_tasks=1000)
    tid = _submit_finished(q)
    assert q.get(tid)["status"] == "success"

    # 等过 TTL，再触发一次淘汰（新提交会顺带清理）
    time.sleep(1.2)
    _submit_finished(q)          # 触发 _evict_locked

    t = q.get(tid)
    assert t is not None and t["status"] == "expired", (
        f"TTL 到期后应淘汰，实际 {t}")


def test_ttl_zero_disables_time_based_eviction():
    """result_ttl_sec=0 应关闭时间淘汰（只保留容量限制）"""
    q = TaskQueue(max_workers=4, result_ttl_sec=0, max_tasks=1000)
    tid = _submit_finished(q)
    time.sleep(0.3)
    assert q.get(tid)["status"] == "success"


# ----------------------------------------------------------------------
# 安全约束：绝不淘汰运行中的任务
# ----------------------------------------------------------------------

def test_running_task_is_never_evicted():
    """正在运行的任务不得被淘汰 —— 否则 worker 回写时会 KeyError。

    构造一个阻塞任务，在它运行期间塞满任务表并触发淘汰，
    然后确认它仍存在于表中、且能正常走到 success。
    """
    import threading

    gate = threading.Event()

    def slow():
        gate.wait(timeout=10)
        return "done"

    # max_tasks=1：只要再提交一个终态任务，就会触发出淘汰压力
    q = TaskQueue(max_workers=4, result_ttl_sec=0, max_tasks=1)
    slow_id = q.submit(slow)
    t = _wait_status(q, slow_id, ("running", "success"), timeout=5)
    assert t is not None

    # 在 slow 运行期间塞入大量已完成的快任务，制造淘汰压力
    for _ in range(8):
        _submit_finished(q, 0)

    # 运行中的任务必须仍在表中（可能仍 running）
    still = q.get(slow_id)
    assert still is not None, "运行中的任务被淘汰了（会导致 KeyError）"
    assert still["status"] in ("running", "success")

    gate.set()
    final = _wait_status(q, slow_id, ("success", "error"), timeout=10)
    assert final["status"] == "success", f"任务未能正常完成: {final}"


def test_pending_task_not_evicted():
    """pending 状态的任务也不得被淘汰"""
    import threading
    gate = threading.Event()

    q = TaskQueue(max_workers=1, result_ttl_sec=0, max_tasks=1)
    # 第一个任务占住唯一的 worker，第二个会停留在 pending
    gate_id = q.submit(lambda: gate.wait(timeout=10))
    _wait_status(q, gate_id, ("running",), timeout=5)
    pending_id = q.submit(lambda: "later")
    time.sleep(0.1)

    # 制造淘汰压力
    for _ in range(5):
        # 这些会排队，不会立即完成；仅用于把表撑大
        q.submit(lambda: "x")

    t = q.get(pending_id)
    assert t is not None, "pending 任务被淘汰了"
    gate.set()


# ----------------------------------------------------------------------
# 统计与观测
# ----------------------------------------------------------------------

def test_stats_expose_eviction_config():
    """stats 应暴露容量/TTL/累计淘汰量，便于观测是否真的在淘汰"""
    q = TaskQueue(max_workers=2, result_ttl_sec=60, max_tasks=10)
    s = q.stats()
    assert s["max_tasks"] == 10
    assert s["result_ttl_sec"] == 60
    assert s["evicted_total"] == 0
    for _ in range(15):
        _submit_finished(q)
    assert q.stats()["evicted_total"] > 0


def test_bounded_expired_id_memory():
    """过期 id 的记忆必须有界（否则它自己又成了新的泄漏源）"""
    q = TaskQueue(max_workers=8, result_ttl_sec=0, max_tasks=1)
    for _ in range(80):
        _submit_finished(q)
    # deque 有 maxlen，长度不会超过设定上限
    assert len(q._expired_ids) <= 200


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header"]))
