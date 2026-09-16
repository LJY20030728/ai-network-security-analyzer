"""
健康检查和通用路由
"""

import logging
from fastapi import APIRouter

from config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system"])


@router.get("/api/health")
async def health_check():
    """健康检查"""
    from src.ai.llm_client import get_llm_client
    
    llm = get_llm_client()
    
    return {
        "status": "healthy",
        "project": settings.project_name,
        "version": settings.version,
        "llm_model": settings.llm_model,
        "llm_available": llm.is_available(),
        "debug": settings.debug,
    }
