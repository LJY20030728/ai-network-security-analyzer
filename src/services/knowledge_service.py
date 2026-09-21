"""
知识库服务

负责：
- RAG知识库初始化（MITRE ATT&CK等内置知识）
- 知识库统计
- 知识库搜索
- 文档导入
"""

import os
import logging
from typing import Dict, Any, List, Optional

from src.core.exceptions import (
    KnowledgeBaseError,
    KnowledgeNotInitializedError,
    KnowledgeSearchError,
    FileTooLargeError,
    InvalidFileTypeError,
)

logger = logging.getLogger(__name__)

# 知识文档大小限制（5MB）
MAX_KNOWLEDGE_MB = 5
ALLOWED_KNOWLEDGE_EXTENSIONS = {".txt", ".md", ".markdown", ".json"}


class KnowledgeService:
    """知识库服务"""
    
    def __init__(self):
        self._rag_engine = None
        self._initialized = False
    
    def _get_rag_engine(self):
        """懒加载RAG引擎"""
        if self._rag_engine is None:
            from src.ai.rag_engine import get_rag_engine
            self._rag_engine = get_rag_engine()
        return self._rag_engine
    
    @property
    def is_initialized(self) -> bool:
        """知识库是否已初始化"""
        return self._initialized
    
    def initialize(self) -> Dict[str, Any]:
        """
        初始化知识库（加载MITRE ATT&CK等内置知识）
        
        Returns:
            初始化结果
        """
        try:
            rag = self._get_rag_engine()
            from src.knowledge.mitre_attck import get_all_knowledge

            # 幂等：先清空旧集合再全量重建，避免重复点击导致片段翻倍
            rag.clear()
            rag._seeded = False
            knowledge_items = get_all_knowledge()
            count = rag.add_knowledge_base(knowledge_items)
            rag._seeded = True

            self._initialized = True
            
            return {
                "status": "success",
                "message": f"知识库初始化完成，共添加 {count} 个文档块",
                "knowledge_items": len(knowledge_items),
                "chunks_added": count,
                "stats": rag.get_stats(),
            }
        except Exception as e:
            logger.error(f"知识库初始化失败: {e}")
            raise KnowledgeBaseError(message=f"知识库初始化失败: {str(e)}") from e
    
    def get_stats(self) -> Dict[str, Any]:
        """获取知识库统计"""
        try:
            rag = self._get_rag_engine()
            return rag.get_stats()
        except Exception as e:
            logger.error(f"获取知识库统计失败: {e}")
            raise KnowledgeBaseError(message=f"获取知识库统计失败: {str(e)}") from e
    
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        搜索知识库
        
        Args:
            query: 搜索查询
            top_k: 返回结果数量
            
        Returns:
            搜索结果列表
        """
        try:
            rag = self._get_rag_engine()
            results = rag.search(query, top_k=top_k)
            return results
        except Exception as e:
            logger.error(f"知识库搜索失败: {e}")
            raise KnowledgeSearchError(message=f"知识库搜索失败: {str(e)}") from e
    
    def validate_knowledge_file(self, filename: str, size: int):
        """校验知识文件"""
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_KNOWLEDGE_EXTENSIONS:
            raise InvalidFileTypeError(
                message=f"不支持的文件类型 {ext}，仅支持 .txt/.md/.json"
            )
        
        max_bytes = MAX_KNOWLEDGE_MB * 1024 * 1024
        if size > max_bytes:
            raise FileTooLargeError(
                message=f"知识文档超过大小限制（{MAX_KNOWLEDGE_MB}MB）"
            )
    
    def add_document(self, filepath: str, filename: str) -> Dict[str, Any]:
        """
        导入文档到知识库
        
        Args:
            filepath: 临时文件路径
            filename: 原始文件名
            
        Returns:
            导入结果
        """
        try:
            rag = self._get_rag_engine()
            chunks = rag.add_file(filepath, source=f"user_import:{filename}")
            
            return {
                "status": "success",
                "filename": filename,
                "chunks_added": chunks,
                "stats": rag.get_stats(),
            }
        except Exception as e:
            logger.error(f"知识导入失败: {e}")
            raise KnowledgeBaseError(message=f"知识导入失败: {str(e)}") from e
    
    def chat(self, question: str, context: str = "") -> str:
        """
        安全知识问答（基于RAG）
        
        Args:
            question: 用户问题
            context: 上下文（可选）
            
        Returns:
            回答文本
        """
        from src.ai.threat_analyzer import get_threat_analyzer
        
        threat_analyzer = get_threat_analyzer()
        answer = threat_analyzer.chat_about_security(question, context)
        
        # 错误与正常响应分离
        if answer.startswith("[大模型调用失败]") or answer.startswith("[LLM"):
            from src.core.exceptions import LLMAPIError
            raise LLMAPIError(message=answer)
        
        return answer


# 全局服务单例
_knowledge_service: Optional[KnowledgeService] = None


def get_knowledge_service() -> KnowledgeService:
    """获取知识库服务单例"""
    global _knowledge_service
    if _knowledge_service is None:
        _knowledge_service = KnowledgeService()
    return _knowledge_service
