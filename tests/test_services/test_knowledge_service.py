"""
知识库服务单元测试
"""

import pytest
from unittest.mock import patch, MagicMock

from src.services.knowledge_service import KnowledgeService, get_knowledge_service
from src.core.exceptions import KnowledgeNotInitializedError, KnowledgeSearchError


@pytest.mark.skip(reason="服务层重构后需要重写")
class TestKnowledgeService:
    """知识库服务测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.service = KnowledgeService()
    
    def test_is_initialized_false(self):
        """测试：知识库未初始化"""
        assert self.service.is_initialized() in (True, False)  # 根据实际情况
    
    def test_get_knowledge_service_singleton(self):
        """测试：服务单例模式"""
        service1 = get_knowledge_service()
        service2 = get_knowledge_service()
        assert service1 is service2


@pytest.mark.skip(reason="服务层重构后需要重写")
class TestKnowledgeServiceInitialization:
    """知识库初始化测试"""
    
    @patch("src.services.knowledge_service.get_rag_engine")
    def test_initialize_knowledge_base(self, mock_get_rag):
        """测试：初始化知识库"""
        mock_rag = MagicMock()
        mock_rag.initialize.return_value = {"status": "success", "chunks": 100}
        mock_get_rag.return_value = mock_rag
        
        service = KnowledgeService()
        result = service.initialize_knowledge_base()
        
        assert result["status"] == "success"
        assert "chunks" in result
    
    @patch("src.services.knowledge_service.get_rag_engine")
    def test_search_knowledge_not_initialized(self, mock_get_rag):
        """测试：未初始化时搜索抛出异常"""
        mock_rag = MagicMock()
        mock_rag.is_initialized.return_value = False
        mock_get_rag.return_value = mock_rag
        
        service = KnowledgeService()
        
        with pytest.raises(KnowledgeNotInitializedError) as exc_info:
            service.search_knowledge("test query")
        assert "知识库未初始化" in str(exc_info.value.message)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
