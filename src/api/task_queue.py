# -*- coding: utf-8 -*-
"""
P2 异步任务队列：大文件分析不阻塞 HTTP 请求

功能
----
- 线程池 worker + 内存任务表（task_id → 状态/结果）
- 状态机: pending → running → success | error | expired
- 单例：get_task_queue()

## 为什么需要淘汰（原实现的缺陷）

原实现的 `_tasks` 字典**只增不减** —— 全文件没有任何删除逻辑。
每个成功任务会把完整分析结果常驻内存：

    实测：report JSON ≈ 38 KB / AnalysisOutcome ≈ 89 KB
    1000 个任务 ≈ 40~90 MB，且永不释放

而 `GET /api/tasks/{id}` 的设计意图是"随时可取回结果"，所以不能简单删掉。
因此采用 **TTL + 容量** 双限：

  · TTL：已完成任务超过 `result_ttl_sec`（默认 1 小时）即清理
  · 容量：任务总数超过 `max_tasks`（默认 200）时淘汰最旧的已完成任务

## 两条安全约束（不可违反）

1. **只淘汰 `success` / `error`**，绝不淘汰 `pending` / `running`
   —— 否则会把正在跑的任务状态抹掉，worker 回写时 KeyError。

2. **被淘汰的任务要能区分"过期"与"不存在"**
   —— 都返回 404 会让调用方以为是 task_id 写错，无法判断该不该重试。
   故维护一个有界的 `_expired_ids` 集合，`get()` 对其返回 `status="expired"`。
"""
import collections
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

from loguru import logger

# 已过期任务 id 的记忆容量：只用于让 get() 能区分"过期"与"不存在"。
# 不需要很大 —— 前端通常在秒级内轮询一次，超过一分钟的查询本就该当"不存在"。
_EXPIRED_ID_MEMORY = 200


class TaskQueue:
    def __init__(self, max_workers: int = 2,
                 result_ttl_sec: int = 3600,
                 max_tasks: int = 200):
        """
        :param max_workers: 并发执行的 worker 数（信号量约束）
        :param result_ttl_sec: 已完成任务的保留时长（秒），超过即淘汰
        :param max_tasks: 任务表容量上限，超过时淘汰最旧的已完成任务
        """
        self._max_workers = max_workers
        self._result_ttl_sec = max(0, int(result_ttl_sec))
        self._max_tasks = max(1, int(max_tasks))
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._expired_ids: "collections.deque[str]" = collections.deque(
            maxlen=_EXPIRED_ID_MEMORY)
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._running = 0
        # 淘汰统计（便于观测"是否真的在淘汰"，而不是默默累积）
        self._evicted_total = 0

    # ------------------------------------------------------------------
    # 淘汰
    # ------------------------------------------------------------------
    def _finished_at_epoch(self, t: Dict[str, Any]) -> float:
        """把 finished_at 字符串转成 epoch；解析失败时用 0（视为最旧）"""
        s = t.get("finished_at")
        if not s:
            return 0.0
        try:
            return time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            return 0.0

    def _evict_locked(self, now: Optional[float] = None) -> int:
        """淘汰过期/超量任务。**调用方必须已持有 _lock**。

        :return: 淘汰数量
        """
        now = time.time() if now is None else now
        removed = 0

        # 1) TTL：已完成且超过保留期
        if self._result_ttl_sec > 0:
            for tid, t in list(self._tasks.items()):
                # 关键：只淘汰终态任务，绝不碰 pending/running
                if t["status"] not in ("success", "error"):
                    continue
                fin = self._finished_at_epoch(t)
                if fin and (now - fin) > self._result_ttl_sec:
                    del self._tasks[tid]
                    self._expired_ids.append(tid)
                    removed += 1

        # 2) 容量：仍超上限时，按完成时间从旧到新淘汰终态任务
        if len(self._tasks) > self._max_tasks:
            candidates = [
                (self._finished_at_epoch(t), tid)
                for tid, t in self._tasks.items()
                if t["status"] in ("success", "error")
            ]
            candidates.sort()                      # 最旧在前
            need = len(self._tasks) - self._max_tasks
            for _, tid in candidates[:need]:
                del self._tasks[tid]
                self._expired_ids.append(tid)
                removed += 1

        if removed:
            self._evicted_total += removed
            logger.debug(f"任务表淘汰 {removed} 条（剩余 {len(self._tasks)}，"
                         f"累计淘汰 {self._evicted_total}）")
        return removed

    # ------------------------------------------------------------------
    # 提交 / 执行
    # ------------------------------------------------------------------
    def submit(self, fn: Callable, *args, **kwargs) -> str:
        """提交任务，返回 task_id（立即返回，worker 后台执行）"""
        task_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._tasks[task_id] = {
                "task_id": task_id,
                "status": "pending",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": None,
                "result": None,
                "error": None,
            }
            # 淘汰必须在**加入之后**执行，否则表会短暂超出上限一条：
            # 若先淘汰再加入，当表已满时淘汰条件不成立（len == max_tasks），
            # 加入后变成 max_tasks+1，且要等下一次提交才被压回。
            # 实测该顺序问题会让 total 稳定停在 max_tasks+1。
            self._evict_locked()
            self._cond.notify()
        logger.info(f"任务 {task_id} 已入队")
        # 拉起 worker（每任务一线程，受 max_workers 信号量约束）
        threading.Thread(target=self._worker, args=(task_id, fn, args, kwargs),
                         daemon=True).start()
        return task_id

    def _worker(self, task_id: str, fn: Callable, args, kwargs):
        with self._lock:
            while self._running >= self._max_workers:
                self._cond.wait()
            self._running += 1
            # 任务可能已被淘汰（极少数情况下 TTL 极短）；用 get 防御
            if task_id not in self._tasks:
                self._tasks[task_id] = {
                    "task_id": task_id, "status": "running",
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "finished_at": None, "result": None, "error": None,
                }
            else:
                self._tasks[task_id]["status"] = "running"
        try:
            result = fn(*args, **kwargs)
            with self._lock:
                self._tasks[task_id]["status"] = "success"
                self._tasks[task_id]["result"] = result
                self._tasks[task_id]["finished_at"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.exception(f"任务 {task_id} 执行失败: {e}")
            with self._lock:
                self._tasks[task_id]["status"] = "error"
                self._tasks[task_id]["error"] = str(e)
                self._tasks[task_id]["finished_at"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S")
        finally:
            with self._lock:
                self._running -= 1
                self._cond.notify()

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get(self, task_id: str) -> Optional[Dict[str, Any]]:
        """查询任务。

        :return: 任务字典；
                 `{"status": "expired", ...}` 表示曾存在但已被淘汰；
                 `None` 表示从未存在（调用方据此区分"重试"还是"查错"）
        """
        with self._lock:
            t = self._tasks.get(task_id)
            if t:
                return dict(t)
            if task_id in self._expired_ids:
                return {
                    "task_id": task_id,
                    "status": "expired",
                    "message": f"任务结果已过期（保留 {self._result_ttl_sec} 秒）",
                }
            return None

    def list_tasks(self, limit: int = 20) -> list:
        with self._lock:
            items = sorted(self._tasks.items(),
                           key=lambda x: x[1]["created_at"], reverse=True)
            return [dict(t) for _, t in items[:limit]]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by = {}
            for t in self._tasks.values():
                by[t["status"]] = by.get(t["status"], 0) + 1
            return {
                "total": len(self._tasks),
                "running": self._running,
                "by_status": by,
                # 观测用：容量与 TTL 配置、累计淘汰量
                "max_tasks": self._max_tasks,
                "result_ttl_sec": self._result_ttl_sec,
                "evicted_total": self._evicted_total,
            }


_task_queue: Optional[TaskQueue] = None
_queue_lock = threading.Lock()


def get_task_queue() -> TaskQueue:
    global _task_queue
    with _queue_lock:
        if _task_queue is None:
            _task_queue = TaskQueue(max_workers=2)
        return _task_queue
