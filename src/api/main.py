"""
FastAPI 主服务（精简版）

架构：
- 路由层：src/api/routes/（业务路由）
- 服务层：src/services/（业务逻辑）
- 核心层：src/core/（异常+中间件）
- UI层：Gradio界面（从原main_v1_backup.py导入）
"""

import os
import sys
import logging

# 确保项目根目录在path中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
from src.utils.helpers import ensure_dir
from src.utils.paths import data_dir, seed_assets

# 注意：日志初始化由main_v1_backup.py中的setup_logging统一处理
# 这里不再重复初始化，避免日志配置冲突

logger = logging.getLogger(__name__)

# 首次启动种子数据迁移
seed_assets()

# 创建FastAPI应用
app = FastAPI(
    title=settings.project_name,
    description="基于流行为检测与LLM辅助研判的网络异常分析系统",
    version=settings.version
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== 全局异常处理器 =====
# 新架构：使用src/core/middleware中的统一异常处理
from src.core.middleware import setup_middleware, setup_exception_handlers

# 注册新架构中间件和异常处理器
setup_middleware(app)
setup_exception_handlers(app)

# 保留旧的异常处理器（兼容Gradio UI和现有API）
from fastapi import Request as _Request
from fastapi.responses import JSONResponse as _JSONResponse
from src.utils.error_handler import GlobalExceptionHandler

@app.exception_handler(Exception)
async def global_exception_handler(request: _Request, exc: Exception):
    """全局异常处理器 — 所有未捕获异常都返回友好的中文错误信息"""
    error_info = GlobalExceptionHandler.handle(exc, context=f"{request.method} {request.url.path}")
    return _JSONResponse(
        status_code=500 if not error_info.recoverable else 200,
        content={
            "status": "error",
            "error": error_info.to_dict(),
        },
    )

# ===== 注册路由 =====
from src.api.routes import analyze, baseline, knowledge, chat, system

app.include_router(analyze.router)
app.include_router(baseline.router)
app.include_router(knowledge.router)
app.include_router(chat.router)
app.include_router(system.router)

logger.info("API路由注册完成")

# ===== Gradio UI 集成 =====
# 从原备份文件导入Gradio UI创建函数
# 后续逐步把UI代码迁移到 src/ui/gradio_app.py
try:
    import gradio as gr
    
    # 导入Gradio UI创建函数（从最新备份文件）
    from src.ui.gradio_app import create_gradio_interface, GRADIO_AVAILABLE
    
    if GRADIO_AVAILABLE:
        gradio_app = create_gradio_interface()
        try:
            gradio_app.queue()
        except Exception:
            pass
        
        # Gradio 6.x 文件下载路由需白名单
        from src.utils.paths import data_dir as _data_dir
        
        # 导入Gradio UI相关的挂载参数（theme + css）
        from src.ui.gradio_app import _UI_KWARGS, _GRADIO_MAJOR
        
        # Gradio 6.x 需要在mount时传递theme和css
        _mount_kwargs = {}
        if _GRADIO_MAJOR >= 6:
            _mount_kwargs.update(_UI_KWARGS)
        _mount_kwargs["allowed_paths"] = [_data_dir("reports"), _data_dir("uploads"), _data_dir("history")]
        
        app = gr.mount_gradio_app(app, gradio_app, path="/", **_mount_kwargs)
        logger.info("Gradio Web UI 已挂载到 /")
        
except ImportError:
    GRADIO_AVAILABLE = False
    logger.info("gradio 未安装，仅启动API服务")
except Exception as e:
    logger.warning(f"Gradio UI 挂载失败（不影响API使用）: {e}")


# ===== 系统初始化 =====
@app.on_event("startup")
async def startup_event():
    """应用启动时初始化"""
    logger.info("=" * 60)
    logger.info(f"{settings.project_name} 启动中...")
    logger.info("=" * 60)
    
    # 确保数据目录存在
    ensure_dir(data_dir("samples"))
    ensure_dir(data_dir("knowledge"))
    ensure_dir(data_dir("chroma_db"))
    ensure_dir(data_dir("uploads"))
    
    # 初始化LLM客户端
    from src.ai.llm_client import get_llm_client
    llm = get_llm_client()
    if llm.is_available():
        logger.info("✓ 大模型API已配置")
    else:
        logger.warning("⚠ 未配置大模型API Key，AI分析功能将不可用")
    
    logger.info("系统初始化完成")


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时"""
    logger.info("系统正在关闭...")


def main():
    """启动服务"""
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    logger.info(f"启动服务: http://127.0.0.1:{port}")
    logger.info(f"API文档: http://127.0.0.1:{port}/docs")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
