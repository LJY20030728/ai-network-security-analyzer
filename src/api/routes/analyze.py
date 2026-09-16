"""
PCAP分析相关路由
"""

import os
import json
import logging
from typing import Dict, Any

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.concurrency import run_in_threadpool

from config.settings import settings
from src.services.analysis_service import get_analysis_service
from src.services.history_service import get_history_service
from src.core.exceptions import AppError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pcap", tags=["pcap"])


@router.post("/analyze")
async def analyze_pcap(
    file: UploadFile = File(...),
    enable_ai: bool = Form(True),
    baseline_name: str = Form("")
):
    """
    上传PCAP文件并分析
    支持 .pcap / .pcapng 格式（Wireshark导出的文件）
    可选指定已学习的基线名称做时序对照检测
    """
    try:
        analysis_service = get_analysis_service()
        
        # 读取上传内容
        max_bytes = settings.max_upload_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")
        
        # 校验文件
        safe_name = os.path.basename(file.filename or "upload.pcap")
        analysis_service.validate_upload_file(safe_name, len(content))
        
        # 保存上传的文件
        from src.utils.time_utils import get_timestamp_str
        from src.utils.paths import data_dir, ensure_dir
        
        timestamp = get_timestamp_str()
        filename = f"upload_{timestamp}_{safe_name}"
        filepath = os.path.join(data_dir("uploads"), filename)
        ensure_dir(os.path.dirname(filepath))
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        logger.info(f"收到PCAP文件: {safe_name} ({len(content)} bytes)")
        
        # 后台执行分析
        result = await run_in_threadpool(
            analysis_service.analyze_pcap,
            filepath, enable_ai, baseline_name
        )
        
        from src.utils.formatters import format_bytes
        result["file_size"] = format_bytes(len(content))
        result["filename"] = safe_name
        
        # 保存分析结果
        report_path = analysis_service.save_analysis_result(result, timestamp)
        result["report_saved"] = report_path
        
        # 添加到历史记录
        try:
            history_service = get_history_service()
            history_service.add_analysis({
                "filename": safe_name,
                "packet_count": result.get("packet_count", 0),
                "flow_count": len(result.get("analysis_report", {}).get("flows", [])),
                "alert_count": len(result.get("analysis_report", {}).get("anomaly_detection", {}).get("alerts", [])),
                "max_severity": result.get("analysis_report", {}).get("anomaly_detection", {}).get("max_severity", "INFO"),
                "summary": result.get("ai_traffic_summary", "")[:100],
                "file_path": filepath,
                "html_report": result.get("report_html", ""),
                "timestamp": timestamp,
            })
        except Exception as e:
            logger.warning(f"添加历史记录失败: {e}")
        
        return result
        
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PCAP分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"PCAP分析失败: {e}")


@router.post("/analyze_async")
async def analyze_pcap_async(
    file: UploadFile = File(...),
    enable_ai: bool = Form(True),
    baseline_name: str = Form("")
):
    """
    异步分析：大文件任务入队后立即返回 task_id，轮询 GET /api/tasks/{task_id}
    """
    try:
        analysis_service = get_analysis_service()
        
        max_bytes = settings.max_upload_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")
        
        safe_name = os.path.basename(file.filename or "upload.pcap")
        analysis_service.validate_upload_file(safe_name, len(content))
        
        from src.utils.time_utils import get_timestamp_str
        from src.utils.paths import data_dir, ensure_dir
        
        timestamp = get_timestamp_str()
        filename = f"async_{timestamp}_{safe_name}"
        filepath = os.path.join(data_dir("uploads"), filename)
        ensure_dir(os.path.dirname(filepath))
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        # 提交异步任务
        from src.api.task_queue import get_task_queue
        task_id = get_task_queue().submit(
            analysis_service.analyze_pcap, filepath, enable_ai, baseline_name
        )
        
        logger.info(f"异步分析任务已入队: {task_id} ({safe_name})")
        return {"status": "accepted", "task_id": task_id, "filename": safe_name}
        
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"异步任务提交失败: {e}")
        raise HTTPException(status_code=500, detail=f"任务提交失败: {e}")
