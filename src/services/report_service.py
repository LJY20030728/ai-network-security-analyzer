"""
报告生成服务

负责：
- HTML取证报告生成
- 安全事件响应报告生成
- 报告文件管理
"""

import os
import logging
from typing import Dict, Any, Optional

from src.core.exceptions import (
    ReportError,
    ReportNotFoundError,
    LLMAPIError,
)

logger = logging.getLogger(__name__)


class ReportService:
    """报告生成服务"""
    
    def __init__(self):
        self._report_dir = None
    
    @property
    def report_dir(self) -> str:
        """报告存储目录"""
        if self._report_dir is None:
            from src.utils.paths import data_dir
            self._report_dir = data_dir("reports")
        return self._report_dir
    
    def generate_html_report(
        self,
        analysis_report: Dict[str, Any],
        evidence: Dict[str, Any],
        ai_analysis: Optional[str] = None,
        ai_traffic_summary: Optional[str] = None,
        structured_report: Optional[Dict] = None,
    ) -> str:
        """
        生成HTML取证报告
        
        Args:
            analysis_report: 分析报告数据
            evidence: 证据信息
            ai_analysis: AI威胁分析文本
            ai_traffic_summary: AI流量概览
            structured_report: 结构化报告
            
        Returns:
            HTML文件路径
        """
        try:
            from src.report.html_report import save_html_report
            
            html_path = save_html_report(
                analysis_report,
                evidence,
                ai_analysis=ai_analysis,
                ai_traffic_summary=ai_traffic_summary,
                structured_report=structured_report,
                report_dir=self.report_dir,
            )
            return html_path
        except Exception as e:
            logger.error(f"HTML报告生成失败: {e}")
            raise ReportError(message=f"HTML报告生成失败: {str(e)}") from e
    
    def get_report_path(self, filename: str) -> str:
        """
        获取报告文件完整路径
        
        Args:
            filename: 报告文件名
            
        Returns:
            完整路径
        """
        # 安全检查：防止路径遍历
        safe_name = os.path.basename(filename)
        path = os.path.join(self.report_dir, safe_name)
        
        if not os.path.exists(path):
            raise ReportNotFoundError(message=f"报告不存在: {safe_name}")
        
        return path
    
    def list_reports(self, limit: int = 50) -> list:
        """
        列出所有报告文件
        
        Args:
            limit: 返回数量限制
            
        Returns:
            报告列表
        """
        try:
            reports = []
            if not os.path.exists(self.report_dir):
                return reports
            
            for fn in sorted(os.listdir(self.report_dir), reverse=True)[:limit]:
                if fn.endswith(".html"):
                    path = os.path.join(self.report_dir, fn)
                    stat = os.stat(path)
                    reports.append({
                        "filename": fn,
                        "size_bytes": stat.st_size,
                        "created_at": stat.st_ctime,
                    })
            
            return reports
        except Exception as e:
            logger.error(f"获取报告列表失败: {e}")
            raise ReportError(message=f"获取报告列表失败: {str(e)}") from e
    
    def generate_incident_report(self, incident_data: Dict[str, Any]) -> str:
        """
        生成安全事件响应报告（AI辅助）
        
        Args:
            incident_data: 事件数据
            
        Returns:
            报告文本
        """
        from src.ai.llm_client import get_llm_client
        from src.ai.threat_analyzer import get_threat_analyzer
        
        llm = get_llm_client()
        if not llm.is_available():
            raise LLMAPIError(message="未配置大模型API Key")
        
        threat_analyzer = get_threat_analyzer()
        report = threat_analyzer.generate_incident_report(incident_data)
        
        if report.startswith("[大模型调用失败]") or report.startswith("[LLM"):
            raise LLMAPIError(message=report)
        
        return report


# 全局服务单例
_report_service: Optional[ReportService] = None


def get_report_service() -> ReportService:
    """获取报告服务单例"""
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service
