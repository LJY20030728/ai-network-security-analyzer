"""
全局中间件和错误处理器

功能：
- 统一异常处理
- 请求日志记录
- 请求ID追踪
- CORS配置
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import logging

from .exceptions import AppError
from .errors import ErrorCode

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """请求日志中间件"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id
        
        start_time = time.time()
        logger.info(f"[{request_id}] → {request.method} {request.url.path}")
        
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            logger.info(
                f"[{request_id}] ← {response.status_code} "
                f"{request.method} {request.url.path} ({duration:.3f}s)"
            )
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"[{request_id}] ✗ {request.method} {request.url.path} "
                f"({duration:.3f}s) - {type(e).__name__}: {str(e)}"
            )
            raise


def setup_middleware(app):
    """配置中间件"""
    
    # CORS配置
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 请求日志中间件
    app.add_middleware(RequestLoggingMiddleware)


def setup_exception_handlers(app):
    """配置全局异常处理器"""
    
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        """处理应用异常"""
        request_id = getattr(request.state, "request_id", "unknown")
        logger.warning(
            f"[{request_id}] AppError: {exc.error_code.value} - {exc.message}"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
        )
    
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """处理未捕获的异常"""
        request_id = getattr(request.state, "request_id", "unknown")
        logger.error(
            f"[{request_id}] Unhandled exception: {type(exc).__name__}: {str(exc)}",
            exc_info=True
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR.value,
                    "message": "服务器内部错误",
                    "detail": {
                        "type": type(exc).__name__,
                        "request_id": request_id,
                    }
                }
            }
        )
