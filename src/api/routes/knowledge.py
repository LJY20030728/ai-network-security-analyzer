"""
知识库管理相关路由
"""

import os
import logging

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.concurrency import run_in_threadpool

from src.services.knowledge_service import get_knowledge_service
from src.core.exceptions import AppError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


@router.post("/init")
async def init_knowledge_base():
    """初始化安全知识库（加载MITRE ATT&CK等内置知识）"""
    try:
        knowledge_service = get_knowledge_service()
        return knowledge_service.initialize()
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        logger.error(f"知识库初始化失败: {e}")
        raise HTTPException(status_code=500, detail=f"知识库初始化失败: {e}")


@router.get("/stats")
async def knowledge_stats():
    """获取知识库统计"""
    try:
        knowledge_service = get_knowledge_service()
        return knowledge_service.get_stats()
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取知识库统计失败: {e}")


@router.post("/search")
async def search_knowledge(
    query: str = Form(...),
    top_k: int = Form(5)
):
    """搜索知识库"""
    try:
        knowledge_service = get_knowledge_service()
        results = knowledge_service.search(query, top_k=top_k)
        return {"query": query, "results": results}
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"知识库搜索失败: {e}")


@router.post("/add")
async def add_knowledge(file: UploadFile = File(...)):
    """导入文档到知识库（.txt/.md 等纯文本）"""
    try:
        knowledge_service = get_knowledge_service()
        
        max_bytes = 5 * 1024 * 1024  # 知识文档上限 5MB
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail="知识文档超过大小限制（5MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")
        
        filename = file.filename or "doc.txt"
        knowledge_service.validate_knowledge_file(filename, len(content))
        
        from src.utils.time_utils import get_timestamp_str
        from src.utils.paths import data_dir, ensure_dir
        
        tmp_path = os.path.join(
            data_dir("knowledge"),
            f"import_{get_timestamp_str()}_{os.path.basename(filename)}"
        )
        ensure_dir(os.path.dirname(tmp_path))
        with open(tmp_path, "wb") as f:
            f.write(content)
        
        result = await run_in_threadpool(
            knowledge_service.add_document, tmp_path, filename
        )
        
        return result
        
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"知识导入失败: {e}")
        raise HTTPException(status_code=500, detail=f"知识导入失败: {e}")
