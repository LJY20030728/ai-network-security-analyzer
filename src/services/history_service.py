"""
历史记录服务

负责：
- 分析历史记录的增删改查
- 对话历史管理
- 历史记录格式化（用于UI展示）
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

from src.core.exceptions import (
    HistoryError,
    HistoryNotFoundError,
)

logger = logging.getLogger(__name__)


class HistoryService:
    """历史记录服务"""
    
    def __init__(self):
        self._store = None
    
    def _get_store(self):
        """懒加载历史存储"""
        if self._store is None:
            from src.api.history_store import get_history_store
            self._store = get_history_store()
        return self._store
    
    def list_analysis(self) -> List[Dict[str, Any]]:
        """列出所有分析记录"""
        try:
            return self._get_store().list_analysis()
        except Exception as e:
            logger.error(f"获取历史记录失败: {e}")
            raise HistoryError(message=f"获取历史记录失败: {str(e)}") from e
    
    def get_analysis(self, record_id: str) -> Dict[str, Any]:
        """获取单条分析记录"""
        records = self._get_store().list_analysis()
        for record in records:
            if record.get("id") == record_id:
                return record
        raise HistoryNotFoundError(message=f"历史记录不存在: {record_id}")
    
    def add_analysis(self, record: Dict[str, Any]) -> str:
        """添加分析记录，返回记录ID"""
        try:
            return self._get_store().add_analysis(record)
        except Exception as e:
            logger.error(f"添加历史记录失败: {e}")
            raise HistoryError(message=f"添加历史记录失败: {str(e)}") from e
    
    def update_analysis(self, record_id: str, updates: Dict[str, Any]) -> bool:
        """更新分析记录"""
        try:
            return self._get_store().update_analysis(record_id, updates)
        except Exception as e:
            logger.error(f"更新历史记录失败: {e}")
            raise HistoryError(message=f"更新历史记录失败: {str(e)}") from e
    
    def clear_analysis(self) -> int:
        """清空全部分析记录，返回删除数量"""
        try:
            return self._get_store().clear_analysis()
        except Exception as e:
            logger.error(f"清空历史记录失败: {e}")
            raise HistoryError(message=f"清空历史记录失败: {str(e)}") from e
    
    def get_table_rows(self) -> List[List[Any]]:
        """
        获取历史记录表格行数据（用于UI展示）
        
        Returns:
            表格行列表，每行：[时间, 文件名, 包数, 流数, 告警数, 严重度, 摘要]
        """
        try:
            records = self.list_analysis()
            rows = []
            for r in records:
                rows.append([
                    r.get("timestamp", ""),
                    r.get("filename", ""),
                    r.get("packet_count", 0),
                    r.get("flow_count", 0),
                    r.get("alert_count", 0),
                    r.get("max_severity", ""),
                    (r.get("summary", "") or "")[:50],
                ])
            return rows
        except Exception as e:
            logger.error(f"格式化历史表格失败: {e}")
            return []
    
    def get_dropdown_choices(self) -> List[str]:
        """获取历史记录下拉框选项"""
        try:
            records = self.list_analysis()
            return [f"{r.get('timestamp', '')} | {r.get('filename', '')}" for r in records]
        except Exception as e:
            logger.error(f"获取历史下拉选项失败: {e}")
            return []
    
    def get_record_by_dropdown_label(self, label: str) -> Optional[Dict[str, Any]]:
        """根据下拉框标签获取记录"""
        records = self.list_analysis()
        for r in records:
            choice = f"{r.get('timestamp', '')} | {r.get('filename', '')}"
            if choice == label:
                return r
        return None
    
    # ===== 对话历史 =====
    
    def load_chat_history(self) -> List[Dict[str, str]]:
        """加载对话历史"""
        try:
            return self._get_store().load_chat()
        except Exception as e:
            logger.error(f"加载对话历史失败: {e}")
            return []
    
    def add_chat_round(self, user_msg: str, assistant_msg: str):
        """添加一轮对话"""
        try:
            self._get_store().add_chat_round(user_msg, assistant_msg)
        except Exception as e:
            logger.error(f"保存对话失败: {e}")
    
    def clear_chat(self):
        """清空对话历史"""
        try:
            self._get_store().clear_chat()
        except Exception as e:
            logger.error(f"清空对话历史失败: {e}")


# 全局服务单例
_history_service: Optional[HistoryService] = None


def get_history_service() -> HistoryService:
    """获取历史记录服务单例"""
    global _history_service
    if _history_service is None:
        _history_service = HistoryService()
    return _history_service
