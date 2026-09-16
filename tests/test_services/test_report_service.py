"""
报告生成服务单元测试
"""

import pytest
from unittest.mock import patch, MagicMock

from src.services.report_service import ReportService, get_report_service
from src.core.exceptions import ReportNotFoundError


class TestReportService:
    """报告服务测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.service = ReportService()
    
    def test_get_report_service_singleton(self):
        """测试：服务单例模式"""
        service1 = get_report_service()
        service2 = get_report_service()
        assert service1 is service2
    
    @patch("src.services.report_service.data_dir")
    def test_list_reports_empty(self, mock_data_dir, tmp_path):
        """测试：空报告列表"""
        mock_data_dir.return_value = str(tmp_path / "reports")
        (tmp_path / "reports").mkdir()
        
        result = self.service.list_reports()
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_get_report_not_found(self):
        """测试：报告不存在"""
        with pytest.raises(ReportNotFoundError) as exc_info:
            self.service.get_report("nonexistent.html")
        assert "报告不存在" in str(exc_info.value.message)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
