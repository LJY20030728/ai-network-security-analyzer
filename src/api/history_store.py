# -*- coding: utf-8 -*-
"""
历史记录持久化模块（P1-4 SQLite 迁移版）
- 分析历史：每次 PCAP 分析完成后落盘，供「📜 分析历史」Tab 回看
- 对话历史：安全问答助手多轮对话落盘，刷新页面不丢失
- 存储引擎：SQLite（默认），启动时自动从旧 JSON 导入（向后兼容）
线程安全（SQLite 连接池 + 锁）
"""
import json
import os
import threading
import uuid
from typing import Any, Dict, List, Optional

from loguru import logger

from src.utils.paths import data_dir
from src.utils.helpers import ensure_dir, get_timestamp_str
from src.storage.database import Database

MAX_ANALYSIS = 60          # 分析历史最多保留 60 条
MAX_CHAT_ROUNDS = 100      # 对话历史最多保留 100 轮


class HistoryStore:
    """分析历史 + 对话历史统一存储（SQLite 后端）"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._db = Database()
        self._migrated = False
        # 旧 JSON 路径（用于迁移）
        hist_dir = data_dir("history")
        ensure_dir(hist_dir)
        self._analysis_json_path = os.path.join(hist_dir, "analysis_history.json")
        self._chat_json_path = os.path.join(hist_dir, "chat_history.json")
        # 启动时自动迁移
        self._auto_migrate()

    def _auto_migrate(self):
        """启动时自动从 JSON 导入旧数据（仅当 SQLite 为空时）"""
        if self._migrated:
            return
        with self._lock:
            if self._migrated:
                return
            try:
                analysis_count = self._db.count_analysis()
                if analysis_count == 0:
                    imported = self._db.import_from_json(
                        analysis_json_path=self._analysis_json_path,
                        chat_json_path=self._chat_json_path,
                    )
                    if imported["analysis"] > 0 or imported["chat"] > 0:
                        logger.info(f"历史数据自动迁移完成: 分析{imported['analysis']}条, 对话{imported['chat']}条")
                        # 迁移后备份旧 JSON 文件
                        for path in [self._analysis_json_path, self._chat_json_path]:
                            if os.path.exists(path):
                                backup = path + ".bak"
                                try:
                                    os.rename(path, backup)
                                    logger.info(f"旧 JSON 已备份: {backup}")
                                except Exception:
                                    pass
            except Exception as e:
                logger.warning(f"历史数据自动迁移失败: {e}")
            finally:
                self._migrated = True

    # ---------- 分析历史 ----------

    def add_analysis(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """追加一条分析历史，返回带 id 的记录"""
        with self._lock:
            rec = self._db.add_analysis(record)
            # 超过最大保留数时删除最旧的
            count = self._db.count_analysis()
            if count > MAX_ANALYSIS:
                # 删除最旧的（按 ts 升序取前 count-MAX_ANALYSIS 条）
                conn = self._db._get_conn()
                old_ids = conn.execute(
                    "SELECT id FROM analysis_history ORDER BY ts ASC LIMIT ?",
                    (count - MAX_ANALYSIS,)
                ).fetchall()
                for row in old_ids:
                    conn.execute("DELETE FROM analysis_history WHERE id = ?", (row["id"],))
                conn.commit()
        return rec

    def list_analysis(self) -> List[Dict[str, Any]]:
        """列出分析历史（按时间倒序）"""
        with self._lock:
            return self._db.list_analysis(limit=MAX_ANALYSIS)

    def get_analysis(self, aid: str) -> Optional[Dict[str, Any]]:
        """获取单条分析历史"""
        with self._lock:
            return self._db.get_analysis(aid)

    def clear_analysis(self) -> int:
        """清空分析历史，返回删除数量"""
        with self._lock:
            count = self._db.count_analysis()
            conn = self._db._get_conn()
            conn.execute("DELETE FROM analysis_history")
            conn.commit()
            return count

    # ---------- 对话历史 ----------

    def add_chat_round(self, user_msg: str, assistant_msg: str) -> None:
        """追加一轮问答"""
        with self._lock:
            self._db.add_chat("user", user_msg)
            self._db.add_chat("assistant", assistant_msg)
            # 超过最大保留数时删除最旧的
            conn = self._db._get_conn()
            count = conn.execute("SELECT COUNT(*) FROM chat_history").fetchone()[0]
            if count > MAX_CHAT_ROUNDS * 2:
                old_ids = conn.execute(
                    "SELECT id FROM chat_history ORDER BY ts ASC LIMIT ?",
                    (count - MAX_CHAT_ROUNDS * 2,)
                ).fetchall()
                for row in old_ids:
                    conn.execute("DELETE FROM chat_history WHERE id = ?", (row["id"],))
                conn.commit()

    def load_chat(self) -> List[Dict[str, str]]:
        """读取全部对话，转换为 Gradio messages 格式"""
        with self._lock:
            records = self._db.list_chat(limit=MAX_CHAT_ROUNDS * 2)
        messages: List[Dict[str, str]] = []
        for r in records:
            messages.append({"role": r["role"], "content": r["content"]})
        return messages

    def clear_chat(self) -> int:
        """清空对话历史，返回删除数量"""
        with self._lock:
            conn = self._db._get_conn()
            count = conn.execute("SELECT COUNT(*) FROM chat_history").fetchone()[0]
            conn.execute("DELETE FROM chat_history")
            conn.commit()
            return count

    def get_stats(self) -> Dict[str, Any]:
        """获取存储统计"""
        with self._lock:
            return self._db.get_stats()


# 全局单例
_history_store: Optional[HistoryStore] = None


def get_history_store() -> HistoryStore:
    """获取历史存储单例"""
    global _history_store
    if _history_store is None:
        _history_store = HistoryStore()
    return _history_store
