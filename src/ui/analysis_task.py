"""
PCAP 分析任务封装

将 gradio_app.py 中的 _analyze_pcap_task 拆分为独立模块。
本函数只做「服务结果 → API 契约」的字段映射，流水线逻辑委托 src/services/analysis_service.py。
"""
from typing import Dict, Any
from fastapi import HTTPException

from src.services.analysis_service import run_analysis as _run_analysis


def analyze_pcap_task(filepath: str, enable_ai: bool, baseline_name: str = "") -> Dict[str, Any]:
    """在后台线程执行完整分析——委托 src/services/analysis_service.py（唯一实现）

    本函数只做「服务结果 → API 契约」的字段映射，不再持有流水线逻辑。
    此前这里与 UI 路径是两份副本，kwargs 与是否跑幻觉控制都不一致。
    """
    try:
        outcome = _run_analysis(
            filepath,
            enable_ai=enable_ai,
            baseline_name=baseline_name,
            ai_mode="structured",   # API 路径：非流式，含流量概览
            run_hallucination=True,  # 与 UI 路径统一（此前 API 不跑）
            generate_report=True,
        )
    except ValueError as e:
        # 解析失败/空文件 → 客户端错误
        raise HTTPException(status_code=400, detail=str(e)) from e

    result: Dict[str, Any] = {
        "status": "success",
        "packet_count": outcome.packet_count,
        "analysis_report": outcome.report,
        "evidence": outcome.evidence,
        "report_html": outcome.html_path,
        "case_id": outcome.case_id,
    }
    if enable_ai:
        result["ai_threat_analysis"] = outcome.ai_text
        result["ai_threat_structured"] = outcome.ai_structured
        result["ai_threat_structured_ok"] = outcome.ai_structured_ok
        if outcome.ai_failed:
            result["ai_analysis_failed"] = True
        if outcome.ai_traffic_summary is not None:
            result["ai_traffic_summary"] = outcome.ai_traffic_summary
        if outcome.ai_warning:
            result["ai_warning"] = outcome.ai_warning
    if outcome.hallucination:
        result["hallucination_control"] = outcome.hallucination

    return result
