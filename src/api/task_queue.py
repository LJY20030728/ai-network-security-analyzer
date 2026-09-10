# -*- coding: utf-8 -*-
"""
P2 异步任务队列：大文件分析不阻塞 HTTP 请求
- 线程池 worker + 内存任务表（task_id → 状态/结果）
- 状态机: pending → running → success | error
- 单例：get_task_queue()
"""
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

from loguru import logger


class TaskQueue:
    def __init__(self, max_workers: int = 2):
        self._max_workers = max_workers
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._running = 0

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
            self._tasks[task_id]["status"] = "running"
        try:
            result = fn(*args, **kwargs)
            with self._lock:
                self._tasks[task_id]["status"] = "success"
                self._tasks[task_id]["result"] = result
                self._tasks[task_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.exception(f"任务 {task_id} 执行失败: {e}")
            with self._lock:
                self._tasks[task_id]["status"] = "error"
                self._tasks[task_id]["error"] = str(e)
                self._tasks[task_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        finally:
            with self._lock:
                self._running -= 1
                self._cond.notify()

    def get(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tasks.get(task_id)
            return dict(t) if t else None

    def list_tasks(self, limit: int = 20) -> list:
        with self._lock:
            items = sorted(self._tasks.items(), key=lambda x: x[1]["created_at"], reverse=True)
            return [dict(t) for _, t in items[:limit]]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by = {}
            for t in self._tasks.values():
                by[t["status"]] = by.get(t["status"], 0) + 1
            return {"total": len(self._tasks), "running": self._running, "by_status": by}


_task_queue: Optional[TaskQueue] = None
_queue_lock = threading.Lock()


def get_task_queue() -> TaskQueue:
    global _task_queue
    with _queue_lock:
        if _task_queue is None:
            _task_queue = TaskQueue(max_workers=2)
        return _task_queue
