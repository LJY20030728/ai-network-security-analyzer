"""
PCAP分析服务

负责：
- PCAP文件解析与特征提取
- 四引擎检测流程（规则+监督+基线+孤立森林）
- AI威胁研判
- 分析结果生成与存储
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, Optional, List

from config.settings import settings
from src.core.exceptions import (
    AnalysisError,
    PCAPParseError,
    LLMAPIError,
    FileTooLargeError,
    InvalidFileTypeError,
)

logger = logging.getLogger(__name__)

# 允许的PCAP文件扩展名
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap.gz"}


class AnalysisService:
    """PCAP分析服务"""
    
    def __init__(self):
        self._traffic_analyzer = None
        self._threat_analyzer = None
    
    def _get_traffic_analyzer(self):
        """懒加载流量分析器"""
        if self._traffic_analyzer is None:
            from src.analysis.detection_engine import TrafficAnalyzer
            self._traffic_analyzer = TrafficAnalyzer()
        return self._traffic_analyzer
    
    def _get_threat_analyzer(self):
        """懒加载威胁分析器"""
        if self._threat_analyzer is None:
            from src.ai.threat_analyzer import get_threat_analyzer
            self._threat_analyzer = get_threat_analyzer()
        return self._threat_analyzer
    
    def validate_upload_file(self, filename: str, size: int):
        """校验上传文件类型与大小"""
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_PCAP_EXTENSIONS:
            raise InvalidFileTypeError(
                message=f"不支持的文件类型 {ext}，仅允许: {', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))}"
            )
        
        max_bytes = settings.max_upload_mb * 1024 * 1024
        if size > max_bytes:
            raise FileTooLargeError(
                message=f"文件超过大小限制（{settings.max_upload_mb}MB）"
            )
    
    def calculate_file_sha256(self, filepath: str) -> str:
        """计算文件 SHA-256（证据溯源）"""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.warning(f"计算文件哈希失败: {e}")
            return ""
    
    def analyze_pcap(
        self,
        filepath: str,
        enable_ai: bool = True,
        baseline_name: str = "",
    ) -> Dict[str, Any]:
        """
        执行完整PCAP分析
        
        流程：
        1. 文件解析（流式）
        2. 四引擎检测
        3. AI威胁研判（可选）
        4. 生成HTML报告
        
        Args:
            filepath: PCAP文件路径
            enable_ai: 是否启用AI分析
            baseline_name: 基线名称（可选）
            
        Returns:
            分析结果字典
        """
        # 1. 计算文件哈希（证据溯源）
        sha256 = self.calculate_file_sha256(filepath)
        
        # 2. 流式解析与分析
        from src.capture.pcap_parser import PcapParser
        parser = PcapParser()
        traffic_analyzer = self._get_traffic_analyzer()
        
        # 加载基线（如果指定）
        if baseline_name:
            self._load_baseline(traffic_analyzer, baseline_name)
        
        analysis_report = None
        try:
            analysis_report = traffic_analyzer.analyze_stream(
                parser.iter_packets(filepath), sample_count=50
            )
        except Exception as e:
            logger.error(f"流式分析失败: {e}")
            raise PCAPParseError(message=f"PCAP文件解析失败或为空: {str(e)}") from e
        
        packet_count = analysis_report.get("summary", {}).get("total_packets", 0) if analysis_report else 0
        samples = (analysis_report or {}).pop("_samples", [])
        
        if packet_count == 0:
            raise PCAPParseError(message="PCAP文件解析失败或为空")
        
        # 3. 构建基础结果
        from src.utils.time_utils import get_timestamp_str
        result = {
            "status": "success",
            "packet_count": packet_count,
            "analysis_report": analysis_report,
            "evidence": {
                "source_file": os.path.basename(filepath),
                "source_sha256": sha256,
                "analyzed_at": get_timestamp_str(),
                "rule_version": "2.0.0",
            },
        }
        
        # 4. AI威胁分析（可选）
        if enable_ai:
            self._run_ai_analysis(result, analysis_report, samples)
        
        # 5. 生成HTML报告
        self._generate_html_report(result, analysis_report)
        
        return result
    
    def _load_baseline(self, traffic_analyzer, baseline_name: str):
        """加载基线到分析器"""
        try:
            from src.services.baseline_service import BaselineService
            baseline_service = BaselineService()
            baseline_service.load_baseline_into(traffic_analyzer, baseline_name)
            logger.info(f"已加载基线: {baseline_name}")
        except Exception as e:
            logger.warning(f"加载基线失败: {e}")
    
    def _run_ai_analysis(self, result: Dict[str, Any], analysis_report: Dict, samples: List):
        """执行AI威胁分析"""
        try:
            from src.ai.llm_client import get_llm_client
            llm = get_llm_client()
            
            if not llm.is_available():
                result["ai_warning"] = "未配置大模型API Key，跳过AI分析"
                return
            
            logger.info("开始AI威胁分析...")
            threat_analyzer = self._get_threat_analyzer()
            
            # 转换样本格式
            samples_dict = []
            if samples:
                from src.capture.packet_parser import PacketParser
                pp = PacketParser()
                pp.captured_packets = samples
                samples_dict = pp.to_dict_list()
            
            # 威胁研判
            structured = threat_analyzer.analyze_threats_structured(
                analysis_report["anomaly_detection"],
                packet_samples=samples_dict
            )
            ai_analysis = structured["raw_text"]
            result["ai_threat_analysis"] = ai_analysis
            result["ai_threat_structured"] = structured["structured"]
            result["ai_threat_structured_ok"] = structured["ok"]
            
            if ai_analysis.startswith("[大模型调用失败]") or ai_analysis.startswith("[LLM"):
                result["ai_analysis_failed"] = True
                raise LLMAPIError(message=ai_analysis)
            
            # AI流量概览
            ai_traffic_summary = threat_analyzer.analyze_traffic_summary(
                analysis_report["summary"],
                analysis_report["protocol_distribution"],
                analysis_report["top_talkers"]
            )
            result["ai_traffic_summary"] = ai_traffic_summary
            
        except LLMAPIError:
            raise
        except Exception as e:
            logger.error(f"AI分析失败: {e}")
            result["ai_warning"] = f"AI分析失败: {str(e)}"
    
    def _generate_html_report(self, result: Dict[str, Any], analysis_report: Dict):
        """生成HTML报告"""
        try:
            from src.report.html_report import save_html_report
            from src.utils.paths import data_dir
            
            html_path = save_html_report(
                analysis_report,
                result["evidence"],
                ai_analysis=result.get("ai_threat_analysis"),
                ai_traffic_summary=result.get("ai_traffic_summary"),
                structured_report=result.get("ai_threat_structured"),
                report_dir=data_dir("reports"),
            )
            result["report_html"] = html_path
        except Exception as e:
            logger.warning(f"HTML报告生成失败（不影响分析结果）: {e}")
            result["report_html"] = ""
    
    def save_analysis_result(self, result: Dict[str, Any], timestamp: str) -> str:
        """保存分析结果到JSON文件"""
        from src.utils.paths import data_dir
        report_path = os.path.join(data_dir("samples"), f"report_{timestamp}.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        return report_path


# 全局服务单例
_analysis_service: Optional[AnalysisService] = None


def get_analysis_service() -> AnalysisService:
    """获取分析服务单例"""
    global _analysis_service
    if _analysis_service is None:
        _analysis_service = AnalysisService()
    return _analysis_service
