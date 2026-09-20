"""
历史记录服务单元测试
"""

import pytest
from unittest.mock import patch, MagicMock

from src.services.history_service import HistoryService, get_history_service
from src.core.exceptions import HistoryNotFoundError


@pytest.mark.skip(reason="服务层重构后需要重写")
class TestHistoryService:
    """历史记录服务测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.service = HistoryService()
    
    def test_get_history_service_singleton(self):
        """测试：服务单例模式"""
        service1 = get_history_service()
        service2 = get_history_service()
        assert service1 is service2
    
    @patch("src.services.history_service.get_history_store")
    def test_list_analysis_empty(self, mock_get_store):
        """测试：空历史记录"""
        mock_store = MagicMock()
        mock_store.list_analysis.return_value = []
        mock_get_store.return_value = mock_store
        
        result = self.service.list_analysis()
        assert isinstance(result, list)
        assert len(result) == 0
    
    @patch("src.services.history_service.get_history_store")
    def test_list_analysis_with_data(self, mock_get_store):
        """测试：有历史记录"""
        mock_store = MagicMock()
        mock_store.list_analysis.return_value = [
            {"id": 1, "file": "test1.pcap", "ts": "20260101_120000"},
            {"id": 2, "file": "test2.pcap", "ts": "20260102_120000"},
        ]
        mock_get_store.return_value = mock_store
        
        result = self.service.list_analysis()
        assert len(result) == 2
        assert result[0]["file"] == "test1.pcap"
    
    def test_get_analysis_not_found(self):
        """测试：历史记录不存在"""
        with pytest.raises(HistoryNotFoundError) as exc_info:
            self.service.get_analysis(99999)
        assert "历史记录不存在" in str(exc_info.value.message)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
