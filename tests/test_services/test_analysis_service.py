"""
分析服务单元测试
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.services.analysis_service import AnalysisService, get_analysis_service
from src.core.exceptions import (
    PCAPParseError,
    FileTooLargeError,
    InvalidFileTypeError,
    LLMAPIError,
)


@pytest.mark.skip(reason="服务层重构后需要重写")
class TestAnalysisService:
    """分析服务测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.service = AnalysisService()
    
    def test_validate_upload_file_valid(self):
        """测试：有效文件类型和大小"""
        # 不应该抛出异常
        self.service.validate_upload_file("test.pcap", 1024 * 1024)
    
    def test_validate_upload_file_invalid_type(self):
        """测试：无效文件类型"""
        with pytest.raises(InvalidFileTypeError) as exc_info:
            self.service.validate_upload_file("test.txt", 1024)
        assert "不支持的文件类型" in str(exc_info.value.message)
    
    def test_validate_upload_file_too_large(self):
        """测试：文件过大"""
        from config.settings import settings
        large_size = settings.max_upload_mb * 1024 * 1024 + 1
        with pytest.raises(FileTooLargeError) as exc_info:
            self.service.validate_upload_file("test.pcap", large_size)
        assert "文件超过大小限制" in str(exc_info.value.message)
    
    def test_calculate_file_sha256(self, tmp_path):
        """测试：计算文件SHA256"""
        # 创建临时文件
        test_file = tmp_path / "test.pcap"
        test_file.write_bytes(b"test content")
        
        sha256 = self.service.calculate_file_sha256(str(test_file))
        
        # 验证SHA256格式（64位十六进制）
        assert len(sha256) == 64
        assert all(c in "0123456789abcdef" for c in sha256)
    
    def test_calculate_file_sha256_file_not_found(self):
        """测试：文件不存在时返回空字符串"""
        sha256 = self.service.calculate_file_sha256("nonexistent.pcap")
        assert sha256 == ""
    
    @patch("src.services.analysis_service.PcapParser")
    @patch.object(AnalysisService, "_get_traffic_analyzer")
    def test_analyze_pcap_success(self, mock_analyzer, mock_parser_class, tmp_path):
        """测试：PCAP分析成功"""
        # 创建临时PCAP文件
        test_file = tmp_path / "test.pcap"
        test_file.write_bytes(b"fake pcap content")
        
        # Mock流量分析器
        mock_analyzer_instance = MagicMock()
        mock_analyzer_instance.analyze_stream.return_value = {
            "summary": {"total_packets": 100, "total_flows": 10, "total_bytes": 10000},
            "protocol_distribution": {"TCP": 50, "UDP": 50},
            "anomaly_detection": {"alerts": [], "total_alerts": 0},
            "top_talkers": [],
        }
        mock_analyzer.return_value = mock_analyzer_instance
        
        # Mock PCAP解析器
        mock_parser_instance = MagicMock()
        mock_parser_instance.iter_packets.return_value = iter([])
        mock_parser_class.return_value = mock_parser_instance
        
        # 执行分析
        result = self.service.analyze_pcap(str(test_file), enable_ai=False)
        
        # 验证结果
        assert result["status"] == "success"
        assert result["packet_count"] == 100
        assert "analysis_report" in result
        assert "evidence" in result
    
    @patch("src.services.analysis_service.PcapParser")
    @patch.object(AnalysisService, "_get_traffic_analyzer")
    def test_analyze_pcap_empty_file(self, mock_analyzer, mock_parser_class, tmp_path):
        """测试：空PCAP文件抛出异常"""
        # 创建空文件
        test_file = tmp_path / "empty.pcap"
        test_file.write_bytes(b"")
        
        # Mock流量分析器返回空结果
        mock_analyzer_instance = MagicMock()
        mock_analyzer_instance.analyze_stream.return_value = {
            "summary": {"total_packets": 0},
        }
        mock_analyzer.return_value = mock_analyzer_instance
        
        # Mock PCAP解析器
        mock_parser_instance = MagicMock()
        mock_parser_instance.iter_packets.return_value = iter([])
        mock_parser_class.return_value = mock_parser_instance
        
        # 应该抛出PCAPParseError
        with pytest.raises(PCAPParseError) as exc_info:
            self.service.analyze_pcap(str(test_file), enable_ai=False)
        assert "PCAP文件解析失败或为空" in str(exc_info.value.message)
    
    def test_get_analysis_service_singleton(self):
        """测试：服务单例模式"""
        service1 = get_analysis_service()
        service2 = get_analysis_service()
        assert service1 is service2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
