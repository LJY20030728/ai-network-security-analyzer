# -*- coding: utf-8 -*-
"""
API 审计日志（SQLite 持久化）
=============================
- 记录每次 /api 请求的方法 / 路径 / 状态码 / 耗时 / 客户端 IP / UA（请求体不落库，避免敏感数据）
- WAL 模式 + 线程锁，写入阻塞 <100ms，常驻内存增量 <5MB
- 提供分页查询与统计（供安全审计与面试演示）
"""
import os
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status_code);
"""


class AuditLogger:
    """SQLite 审计日志单例（线程安全，WAL 模式）"""

    _instance: Optional["AuditLogger"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, timeout=0.1, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._write_lock = threading.Lock()
        logger.info(f"审计日志就绪: {db_path}")

    @classmethod
    def get(cls, db_path: str) -> "AuditLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
        return cls._instance

    def log(self, method: str, path: str, status_code: int,
            duration_ms: float, client_ip: str = "", user_agent: str = "",
            note: str = "") -> None:
        """写一条审计记录（同步写，短超时失败即降级丢弃，不阻塞请求）"""
        try:
            with self._write_lock:
                self._conn.execute(
                    "INSERT INTO audit_log (ts, method, path, status_code, duration_ms,"
                    " client_ip, user_agent, note) VALUES (?,?,?,?,?,?,?,?)",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                     method, path, status_code, round(duration_ms, 2),
                     client_ip or "", user_agent or "", note),
                )
                self._conn.commit()
        except Exception as e:  # noqa: BLE001 审计失败不得影响业务
            logger.warning(f"审计日志写入失败（降级跳过）: {e}")

    def query(self, limit: int = 50, offset: int = 0,
              status: Optional[int] = None, path_kw: str = "") -> List[Dict[str, Any]]:
        """分页查询审计日志"""
        sql = "SELECT id, ts, method, path, status_code, duration_ms, client_ip, user_agent, note FROM audit_log WHERE 1=1"
        args: List[Any] = []
        if status is not None:
            sql += " AND status_code = ?"
            args.append(status)
        if path_kw:
            sql += " AND path LIKE ?"
            args.append(f"%{path_kw}%")
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args += [min(max(limit, 1), 500), max(offset, 0)]
        rows = self._conn.execute(sql, args).fetchall()
        cols = ["id", "ts", "method", "path", "status_code", "duration_ms",
                "client_ip", "user_agent", "note"]
        return [dict(zip(cols, r)) for r in rows]

    def stats(self) -> Dict[str, Any]:
        """审计统计：总量 / 错误率 / 平均耗时 / 端点 TOP"""
        total = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        errors = self._conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE status_code >= 400").fetchone()[0]
        avg_ms = self._conn.execute(
            "SELECT AVG(duration_ms) FROM audit_log").fetchone()[0] or 0.0
        top = self._conn.execute(
            "SELECT path, COUNT(*) c, ROUND(AVG(duration_ms),1) avg_ms FROM audit_log"
            " GROUP BY path ORDER BY c DESC LIMIT 10").fetchall()
        return {
            "total_requests": total,
            "error_count": errors,
            "error_rate": round(errors / total, 4) if total else 0.0,
            "avg_duration_ms": round(avg_ms, 2),
            "top_endpoints": [{"path": r[0], "count": r[1], "avg_ms": r[2]} for r in top],
        }
