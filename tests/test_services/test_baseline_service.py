"""
基线管理服务单元测试
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.services.baseline_service import BaselineService
from src.core.exceptions import BaselineNotFoundError


class TestBaselineService:
    """基线管理服务测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.service = BaselineService()
    
    def test_baseline_path_safe(self):
        """测试：基线文件名安全化"""
        self.service._baseline_dir = "/tmp/test_baselines"
        path = self.service._baseline_path("test-baseline_123")
        assert "test-baseline_123.json" in path
    
    def test_baseline_path_empty_name(self):
        """测试：空文件名用默认名"""
        self.service._baseline_dir = "/tmp/test_baselines"
        path = self.service._baseline_path("")
        assert "baseline.json" in path
    
    def test_list_baselines(self):
        """测试：列出基线"""
        with patch("src.storage.database.Database") as mock_db_class:
            mock_db = MagicMock()
            mock_db.list_baselines.return_value = [{"name": "test1"}, {"name": "test2"}]
            mock_db_class.return_value = mock_db
            
            result = self.service.list_baselines()
            assert len(result) == 2
    
    def test_delete_baseline(self):
        """测试：删除基线"""
        with patch("src.storage.database.Database") as mock_db_class:
            mock_db = MagicMock()
            mock_db.delete_baseline.return_value = True
            mock_db_class.return_value = mock_db
            
            result = self.service.delete_baseline("test_baseline")
            assert result["status"] == "success"
            assert result["deleted"] == "test_baseline"
