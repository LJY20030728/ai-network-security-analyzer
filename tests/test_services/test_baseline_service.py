"""
基线管理服务单元测试
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.services.baseline_service import BaselineService, get_baseline_service
from src.core.exceptions import BaselineNotFoundError, BaselineTrainingError


class TestBaselineService:
    """基线管理服务测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.service = BaselineService()
    
    def test_baseline_path_safe(self):
        """测试：基线文件名安全化"""
        path = self.service._baseline_path("test-baseline_123")
        assert "test-baseline_123.json" in path
    
    def test_baseline_path_unsafe_name(self):
        """测试：不安全的文件名被清理"""
        path = self.service._baseline_path("test/../baseline")
        # 应该只保留安全字符
        assert ".." not in path
    
    @patch("src.services.baseline_service.Database")
    def test_list_baselines_empty(self, mock_db_class):
        """测试：空基线列表"""
        mock_db = MagicMock()
        mock_db.list_baselines.return_value = []
        mock_db_class.return_value = mock_db
        
        result = self.service.list_baselines()
        assert isinstance(result, list)
        assert len(result) == 0
    
    @patch("src.services.baseline_service.Database")
    def test_list_baselines_with_data(self, mock_db_class):
        """测试：有基线数据"""
        mock_db = MagicMock()
        mock_db.list_baselines.return_value = [
            {"name": "baseline1", "created_at": "2026-01-01"},
            {"name": "baseline2", "created_at": "2026-01-02"},
        ]
        mock_db.get_baseline.side_effect = lambda name: {
            "name": name,
            "profile": {"profile": {"median_packets": 100}}
        }
        mock_db_class.return_value = mock_db
        
        result = self.service.list_baselines()
        assert len(result) == 2
        assert result[0]["name"] == "baseline1"
    
    def test_get_baseline_not_found(self):
        """测试：基线不存在"""
        with pytest.raises(BaselineNotFoundError) as exc_info:
            self.service.get_baseline("nonexistent")
        assert "基线不存在" in str(exc_info.value.message)
    
    @patch("src.services.baseline_service.Database")
    def test_delete_baseline(self, mock_db_class):
        """测试：删除基线"""
        mock_db = MagicMock()
        mock_db.delete_baseline.return_value = True
        mock_db_class.return_value = mock_db
        
        # 不应该抛出异常
        self.service.delete_baseline("test_baseline")
    
    def test_get_baseline_service_singleton(self):
        """测试：服务单例模式"""
        service1 = get_baseline_service()
        service2 = get_baseline_service()
        assert service1 is service2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
