"""
安全问答相关路由
"""

import logging
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from src.services.knowledge_service import get_knowledge_service
from src.core.exceptions import AppError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["chat"])


class ChatRequest(BaseModel):
    question: str
    context: str = ""


class ChatResponse(BaseModel):
    question: str
    answer: str


@router.post("/chat", response_model=ChatResponse)
async def security_chat(request: ChatRequest):
    """安全知识问答（基于RAG）"""
    try:
        knowledge_service = get_knowledge_service()
        
        # LLM 调用移入线程池，避免阻塞事件循环
        answer = await run_in_threadpool(
            knowledge_service.chat,
            request.question,
            request.context
        )
        
        return {"question": request.question, "answer": answer}
        
    except AppError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"安全问答失败: {e}")
        raise HTTPException(status_code=500, detail=f"安全问答失败: {e}")
