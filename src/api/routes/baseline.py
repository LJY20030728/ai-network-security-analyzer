"""
基线管理相关路由
"""

import os
import logging
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from config.settings import settings
from src.services.baseline_service import get_baseline_service
from src.core.exceptions import AppError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/baseline", tags=["baseline"])


@router.post("/learn")
async def baseline_learn(
    file: UploadFile = File(...),
    name: str = Form("default")
):
    """
    上传正常流量 pcap 学习基线画像，保存为 JSON。
    检测阶段可引用该基线对照统计偏差。
    """
    try:
        baseline_service = get_baseline_service()
        
        max_bytes = settings.max_upload_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")
        
        from src.utils.time_utils import get_timestamp_str
        from src.utils.paths import data_dir, ensure_dir
        
        tmp_path = os.path.join(
            data_dir("uploads"),
            f"baseline_learn_{get_timestamp_str()}.pcap"
        )
        ensure_dir(os.path.dirname(tmp_path))
        with open(tmp_path, 'wb') as f:
            f.write(content)
        
        # 学习基线
        result = baseline_service.learn_baseline(tmp_path, name)
        
        return result
        
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"基线学习失败: {e}")
        raise HTTPException(status_code=500, detail=f"基线学习失败: {e}")


@router.get("/list")
async def baseline_list():
    """列出所有基线"""
    try:
        baseline_service = get_baseline_service()
        return {
            "baselines": baseline_service.list_baselines(),
            "directory": baseline_service.baseline_dir,
        }
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取基线列表失败: {e}")


@router.get("/get")
async def baseline_get(name: str):
    """获取单个基线画像详情"""
    try:
        baseline_service = get_baseline_service()
        return baseline_service.get_baseline(name)
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取基线失败: {e}")


@router.post("/delete")
async def baseline_delete(name: str = Form(...)):
    """删除基线"""
    try:
        baseline_service = get_baseline_service()
        return baseline_service.delete_baseline(name)
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除基线失败: {e}")
