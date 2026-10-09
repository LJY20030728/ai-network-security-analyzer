# -*- coding: utf-8 -*-
"""
P1-4: SQLite 数据库存储层
历史记录 + 基线从 JSON 迁移到 SQLite，支持：
- 分析历史 CRUD
- 对话历史 CRUD
- 基线管理 CRUD
- 从旧 JSON 数据自动导入（向后兼容）
- 线程安全（连接池 + 锁）
"""
import json
import os
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional

from loguru import logger

from src.utils.paths import data_dir
from src.utils.helpers import ensure_dir, get_timestamp_str


class Database:
    """SQLite 数据库单例（线程安全）"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True
        self._db_path = db_path or os.path.join(data_dir("db"), "analyzer.db")
        ensure_dir(os.path.dirname(self._db_path))
        self._local = threading.local()
        self._init_tables()
        logger.info(f"SQLite 数据库初始化完成: {self._db_path}")

    def _get_conn(self) -> sqlite3.Connection:
        """获取线程本地连接"""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_tables(self):
        """初始化表结构"""
        conn = self._get_conn()
        conn.executescript("""
            -- 分析历史表
            CREATE TABLE IF NOT EXISTS analysis_history (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                file TEXT,
                packets INTEGER DEFAULT 0,
                flows INTEGER DEFAULT 0,
                bytes INTEGER DEFAULT 0,
                alerts INTEGER DEFAULT 0,
                severity TEXT DEFAULT '{}',
                stacking_verdict INTEGER DEFAULT 0,
                stacking_confidence REAL DEFAULT 0.0,
                hallucination_risk TEXT DEFAULT 'unknown',
                needs_review INTEGER DEFAULT 0,
                summary_text TEXT,
                ai_summary TEXT,
                html_report TEXT,
                raw_json TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            );

            -- 对话历史表
            CREATE TABLE IF NOT EXISTS chat_history (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                session_id TEXT DEFAULT 'default',
                metadata TEXT DEFAULT '{}',
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            );

            -- 基线管理表
            CREATE TABLE IF NOT EXISTS baselines (
                name TEXT PRIMARY KEY,
                window_sec INTEGER DEFAULT 5,
                learned INTEGER DEFAULT 0,
                total_packets INTEGER DEFAULT 0,
                total_windows INTEGER DEFAULT 0,
                profile_json TEXT DEFAULT '{}',
                description TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                updated_at TEXT DEFAULT (datetime('now', 'localtime'))
            );

            -- 索引
            CREATE INDEX IF NOT EXISTS idx_analysis_ts ON analysis_history(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_analysis_file ON analysis_history(file);
            CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id, ts);
            CREATE INDEX IF NOT EXISTS idx_baselines_name ON baselines(name);
        """)
        conn.commit()
        self._migrate_columns(conn)

    def _migrate_columns(self, conn) -> None:
        """
        轻量 schema 迁移（幂等）。

        3.3.0 移除了监督模型引擎，融合判定改由三引擎 Stacking 产出，
        因此历史表列名由 supervised_* 更名为 stacking_*。
        对已存在的旧库执行 ALTER TABLE RENAME COLUMN，保留历史数据。
        """
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(analysis_history)").fetchall()}
        except Exception as e:
            logger.warning(f"读取 analysis_history 表结构失败，跳过迁移: {e}")
            return

        renames = [
            ("stacking_verdict", "stacking_verdict"),
            ("stacking_confidence", "stacking_confidence"),
        ]
        for old, new in renames:
            if old in cols and new not in cols:
                try:
                    conn.execute(f"ALTER TABLE analysis_history RENAME COLUMN {old} TO {new}")
                    conn.commit()
                    logger.info(f"数据库迁移：analysis_history.{old} → {new}")
                except Exception as e:
                    logger.warning(f"列重命名失败 {old} → {new}: {e}")
        # 新库直接建表时也确保列存在（旧库可能两列都没有）
        cols = {r[1] for r in conn.execute("PRAGMA table_info(analysis_history)").fetchall()}
        for col, ddl in (("stacking_verdict", "INTEGER DEFAULT 0"),
                         ("stacking_confidence", "REAL DEFAULT 0.0")):
            if col not in cols:
                try:
                    conn.execute(f"ALTER TABLE analysis_history ADD COLUMN {col} {ddl}")
                    conn.commit()
                    logger.info(f"数据库迁移：新增列 analysis_history.{col}")
                except Exception as e:
                    logger.warning(f"新增列失败 {col}: {e}")

    # ---------- 分析历史 ----------

    def add_analysis(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """添加分析历史"""
        rec = {
            "id": uuid.uuid4().hex[:12],
            "ts": get_timestamp_str(),
            **record,
        }
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO analysis_history
            (id, ts, file, packets, flows, bytes, alerts, severity,
             stacking_verdict, stacking_confidence, hallucination_risk, needs_review,
             summary_text, ai_summary, html_report, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rec["id"], rec["ts"],
            rec.get("file", ""), rec.get("packets", 0), rec.get("flows", 0),
            rec.get("bytes", 0), rec.get("alerts", 0),
            json.dumps(rec.get("severity", {}), ensure_ascii=False),
            1 if rec.get("stacking_verdict") else 0,
            rec.get("stacking_confidence", 0.0),
            rec.get("hallucination_risk", "unknown"),
            1 if rec.get("needs_review") else 0,
            rec.get("summary_text", ""), rec.get("ai_summary", ""),
            rec.get("html_report", ""),
            json.dumps(rec.get("raw", {}), ensure_ascii=False, default=str),
        ))
        conn.commit()
        return rec

    # 允许通过 update_analysis 更新的列（白名单，防止 SQL 拼接被注入）
    _UPDATABLE_COLUMNS = (
        "file", "packets", "flows", "bytes", "alerts", "severity",
        "stacking_verdict", "stacking_confidence", "hallucination_risk",
        "needs_review", "summary_text", "ai_summary", "html_report", "raw_json",
    )

    def update_analysis(self, analysis_id: str, updates: Dict[str, Any]) -> bool:
        """
        局部更新一条分析历史（白名单列 + 参数化占位符）。

        用途：报告文件被删除后"重新分析"时，回写新的 PCAP 路径与报告路径，
        避免整行重写导致 ts/summary 等信息丢失。

        :param analysis_id: 记录 id
        :param updates: 待更新字段（键必须在白名单内，未知键忽略）
        :return: 是否至少更新了一行
        """
        if not analysis_id or not updates:
            return False

        sets = []
        params: List[Any] = []
        for key, value in updates.items():
            col = key if key in self._UPDATABLE_COLUMNS else {
                "raw": "raw_json", "severity_json": "severity",
            }.get(key)
            if col is None or col not in self._UPDATABLE_COLUMNS:
                logger.debug(f"update_analysis 忽略未知字段: {key}")
                continue
            # 类型规整（与 add_analysis 保持一致）
            if col in ("severity", "raw_json"):
                value = value if isinstance(value, str) else json.dumps(
                    value if value is not None else {}, ensure_ascii=False, default=str)
            elif col in ("stacking_verdict", "needs_review"):
                value = 1 if value else 0
            elif col in ("packets", "flows", "bytes", "alerts"):
                value = int(value or 0)
            elif col == "stacking_confidence":
                value = float(value or 0.0)
            sets.append(f"{col} = ?")
            params.append(value)

        if not sets:
            return False

        conn = self._get_conn()
        params.append(analysis_id)
        cur = conn.execute(
            f"UPDATE analysis_history SET {', '.join(sets)} WHERE id = ?",  # noqa: S608 (列名来自白名单)
            tuple(params),
        )
        conn.commit()
        updated = cur.rowcount > 0
        if updated:
            logger.info(f"分析历史已更新: {analysis_id} | 字段={[s.split(' = ')[0] for s in sets]}")
        else:
            logger.warning(f"分析历史更新未命中记录: {analysis_id}")
        return updated

    def list_analysis(self, limit: int = 60, offset: int = 0) -> List[Dict[str, Any]]:
        """列出分析历史"""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT id, ts, file, packets, flows, bytes, alerts, severity,
                   stacking_verdict, stacking_confidence, hallucination_risk, needs_review,
                   summary_text, ai_summary, html_report
            FROM analysis_history
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["severity"] = json.loads(d.get("severity", "{}"))
            d["stacking_verdict"] = bool(d.get("stacking_verdict", 0))
            d["needs_review"] = bool(d.get("needs_review", 0))
            result.append(d)
        return result

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """获取单条分析历史"""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM analysis_history WHERE id = ?", (analysis_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["severity"] = json.loads(d.get("severity", "{}"))
        d["raw"] = json.loads(d.get("raw_json", "{}"))
        d["stacking_verdict"] = bool(d.get("stacking_verdict", 0))
        d["needs_review"] = bool(d.get("needs_review", 0))
        return d

    def delete_analysis(self, analysis_id: str) -> bool:
        """删除分析历史"""
        conn = self._get_conn()
        conn.execute("DELETE FROM analysis_history WHERE id = ?", (analysis_id,))
        conn.commit()
        return True

    def count_analysis(self) -> int:
        """统计分析历史数量"""
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0]

    # ---------- 对话历史 ----------

    def add_chat(self, role: str, content: str, session_id: str = "default",
                 metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """添加对话历史"""
        rec = {
            "id": uuid.uuid4().hex[:12],
            "ts": get_timestamp_str(),
            "role": role,
            "content": content,
            "session_id": session_id,
        }
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO chat_history (id, ts, role, content, session_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (rec["id"], rec["ts"], role, content, session_id,
              json.dumps(metadata or {}, ensure_ascii=False)))
        conn.commit()
        return rec

    def list_chat(self, session_id: str = "default", limit: int = 100) -> List[Dict[str, Any]]:
        """列出对话历史"""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT id, ts, role, content, session_id, metadata
            FROM chat_history
            WHERE session_id = ?
            ORDER BY ts ASC
            LIMIT ?
        """, (session_id, limit)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["metadata"] = json.loads(d.get("metadata", "{}"))
            result.append(d)
        return result

    def clear_chat(self, session_id: str = "default") -> bool:
        """清空对话历史"""
        conn = self._get_conn()
        conn.execute("DELETE FROM chat_history WHERE session_id = ?", (session_id,))
        conn.commit()
        return True

    # ---------- 基线管理 ----------

    def save_baseline(self, name: str, profile: Dict[str, Any], window_sec: int = 5,
                      total_packets: int = 0, total_windows: int = 0,
                      description: Optional[str] = None) -> bool:
        """保存基线"""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO baselines
            (name, window_sec, learned, total_packets, total_windows, profile_json, description, updated_at)
            VALUES (?, ?, 1, ?, ?, ?, ?, datetime('now', 'localtime'))
        """, (name, window_sec, total_packets, total_windows,
              json.dumps(profile, ensure_ascii=False), description))
        conn.commit()
        return True

    def list_baselines(self) -> List[Dict[str, Any]]:
        """列出所有基线"""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT name, window_sec, learned, total_packets, total_windows,
                   description, created_at, updated_at
            FROM baselines
            ORDER BY updated_at DESC
        """).fetchall()
        return [dict(row) for row in rows]

    def get_baseline(self, name: str) -> Optional[Dict[str, Any]]:
        """获取基线"""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM baselines WHERE name = ?", (name,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["profile"] = json.loads(d.get("profile_json", "{}"))
        d["learned"] = bool(d.get("learned", 0))
        return d

    def delete_baseline(self, name: str) -> bool:
        """删除基线"""
        conn = self._get_conn()
        conn.execute("DELETE FROM baselines WHERE name = ?", (name,))
        conn.commit()
        return True

    # ---------- JSON 导入（向后兼容） ----------

    def import_from_json(self, analysis_json_path: Optional[str] = None,
                         chat_json_path: Optional[str] = None) -> Dict[str, int]:
        """从旧 JSON 文件导入数据（向后兼容）"""
        imported = {"analysis": 0, "chat": 0}

        # 导入分析历史
        if analysis_json_path and os.path.exists(analysis_json_path):
            try:
                with open(analysis_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                records = data if isinstance(data, list) else data.get("records", [])
                for rec in records:
                    self.add_analysis(rec)
                    imported["analysis"] += 1
                logger.info(f"从 JSON 导入分析历史: {imported['analysis']} 条")
            except Exception as e:
                logger.warning(f"导入分析历史失败: {e}")

        # 导入对话历史
        if chat_json_path and os.path.exists(chat_json_path):
            try:
                with open(chat_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                records = data if isinstance(data, list) else data.get("records", [])
                for rec in records:
                    self.add_chat(
                        role=rec.get("role", "user"),
                        content=rec.get("content", ""),
                        session_id=rec.get("session_id", "default"),
                    )
                    imported["chat"] += 1
                logger.info(f"从 JSON 导入对话历史: {imported['chat']} 条")
            except Exception as e:
                logger.warning(f"导入对话历史失败: {e}")

        return imported

    def get_stats(self) -> Dict[str, Any]:
        """获取数据库统计"""
        conn = self._get_conn()
        return {
            "analysis_count": conn.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0],
            "chat_count": conn.execute("SELECT COUNT(*) FROM chat_history").fetchone()[0],
            "baseline_count": conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0],
            "db_path": self._db_path,
            "db_size_mb": round(os.path.getsize(self._db_path) / (1024 * 1024), 2)
            if os.path.exists(self._db_path) else 0,
        }
