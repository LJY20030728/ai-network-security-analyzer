"""
FastAPI 主服务
提供REST API接口，供前端或其他系统调用
同时集成Gradio Web UI（无需单独前端，降低使用门槛）

安全设计：
- /api/* 接口由本地访问令牌（X-API-Token）保护，Gradio UI 进程内调用不受影响
- PCAP 上传限制大小与类型
- 分析结果附源文件 SHA-256 哈希（证据溯源）
"""
import os
import re
import sys
import json
import secrets
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from src.api import schemas
from loguru import logger

# 可选导入gradio（未安装时仅使用API）
try:
    import gradio as gr
    GRADIO_AVAILABLE = True
except ImportError:
    GRADIO_AVAILABLE = False
    gr = None

# i18n 国际化支持（自研轻量方案，兼容 Gradio 6.x）
try:
    from src.ui.i18n_manager import I18nManager
    I18N_AVAILABLE = True
except ImportError:
    I18N_AVAILABLE = False
    I18nManager = None

# 翻译函数：恒等返回（组件创建时使用中文原文，运行时通过 I18nManager 批量切换）
def _(text):
    return text

# Tab 组件专用翻译函数：创建时直接使用翻译后的文本
# 原因：Gradio 6.x 中 Tab 的 label 无法通过 gr.update 事件更新
def _tab(text):
    global _i18n
    if _i18n is not None:
        return _i18n.tr(text)
    return text

# 全局 i18n 管理器实例（在 build_ui 中初始化）
_i18n: Optional[I18nManager] = None

# 确保项目根目录在path中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings, find_env_file
from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.baseline import TrafficBaseline
from src.ai.llm_client import get_llm_client
from src.ai.rag_engine import get_rag_engine
from src.ai.threat_analyzer import get_threat_analyzer
from src.knowledge import get_all_knowledge
from src.report.html_report import save_html_report
from src.report.summary_formatter import format_analysis_summary, format_hallucination_block
from src.utils.helpers import (
    setup_logging, ensure_dir, format_bytes, get_timestamp_str,
    calculate_file_sha256, validate_upload_file,
)
from src.utils.paths import data_dir, seed_assets
from src.api.audit import AuditLogger
from src.api.history_store import get_history_store
from src.api.task_queue import get_task_queue
# 图表构建已抽到 src/ui/charts.py（所有插值在模块内统一 html.escape）
# 名称规范绑定到本地，调用点无需改动
from src.ui.charts import _build_baseline_compare_svg, _build_baseline_profile_svg
from src.storage.baseline_name import safe_baseline_name, validate_baseline_name
# 分析流水线已抽到服务层（唯一实现，UI/API 共用），见 §4c 重构
from src.services.analysis_service import (
    load_baseline_into as _load_baseline_into,
    quick_sha256 as _quick_sha256,
    run_analysis as _run_analysis,
)

# 初始化日志（同时输出到控制台和文件，文件路径与 LogObserver 一致）
import os as _os
_log_dir = data_dir("logs")
ensure_dir(_log_dir)
_log_file = _os.path.join(_log_dir, "analyzer.log")
setup_logging(settings.log_level, log_file=_log_file)

# 首次启动种子数据迁移（打包版：把内置预置基线复制到数据目录）
seed_assets()

# 创建FastAPI应用（版本号统一取自 settings.version，单一来源）
app = FastAPI(
    title=settings.project_name,
    description="基于流行为检测与LLM辅助研判的网络异常分析系统",
    version=settings.version
)

# CORS配置（仅允许本机访问，收紧默认全开策略）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== P2-1: 全局异常处理器（三层错误处理）=====
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

@app.exception_handler(HTTPException)
async def http_exception_handler(request: _Request, exc: HTTPException):
    """HTTP 异常处理器 — 保留状态码，添加友好提示"""
    return _JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error": {
                "error_type": "HTTPError",
                "message": exc.detail,
                "detail": "",
                "suggestion": "请检查请求参数和权限",
                "recoverable": exc.status_code < 500,
            },
        },
    )

# 全局状态
_system_initialized = False
_knowledge_loaded = False

# ===== 本地 API 鉴权 =====


def _generate_and_persist_token() -> str:
    """生成随机访问令牌并写入 .env（保留原有配置项）"""
    token = secrets.token_hex(16)
    # 与 settings 使用同一探测逻辑（exe同级 → cwd → 项目根）
    env_path = find_env_file()
    lines = []
    env_existed = os.path.exists(env_path)
    read_ok = True
    if env_existed:
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            # 【数据安全】原实现此处 lines = [] 并继续向下写回文件，
            # 效果是：.env 无法读取时（编码/权限/被占用），
            # 整个 .env 会被覆盖成只剩 API_AUTH_TOKEN 一行，
            # 用户的 LLM_API_KEY / BASE_URL / MODEL 全部丢失。
            # 且因为 token 已生成、鉴权看起来正常，故障被自我掩盖。
            read_ok = False
            lines = []
            logger.error(
                f"⚠️ 读取 .env 失败（{type(e).__name__}: {e}）。"
                f"为避免覆盖并丢失现有配置，本次跳过令牌落盘。"
            )
    replaced = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key == "API_AUTH_TOKEN":
                lines[i] = f"API_AUTH_TOKEN={token}\n"
                replaced = True
                break
    if not replaced:
        lines.append(f"API_AUTH_TOKEN={token}\n")

    # 仅当"文件本来不存在"或"成功读取了原内容"时才写回，避免破坏用户配置
    if env_existed and not read_ok:
        logger.error(
            "已跳过写入 .env：原文件存在但读取失败。"
            "本次生成的 API_AUTH_TOKEN 仅在本次运行内存中有效，"
            "请修复 .env 权限/编码后重启应用以持久化。"
        )
        return token
    try:
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        logger.warning(f"无法写入 API 令牌到 .env: {e}")
    return token


_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """延迟初始化审计日志（首次 /api 请求时创建，DB 落在用户数据目录）"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger.get(os.path.join(data_dir("audit"), "audit.db"))
    return _audit_logger


def _is_loopback_host(host: str) -> bool:
    """主机名/IP 是否为回环地址"""
    import ipaddress

    h = (host or "").strip().lower()
    if not h:
        return False
    if h in ("localhost", "::1", "[::1]"):
        return True
    try:
        return ipaddress.ip_address(h.strip("[]")).is_loopback
    except ValueError:
        return False


def _request_is_local(request: Request) -> bool:
    """请求是否来自本机（回环）。

    同时检查客户端地址与 Host 头：Docker 端口映射下，局域网请求的客户端 IP 会是
    网桥地址（非回环），但如果只看客户端 IP，某些反代/宿主场景会误判为本地；
    反向检查 Host 头能兜住这种情况——真正的本机访问 Host 一定是 127.0.0.1/localhost。

    设计依据：项目默认绑定 127.0.0.1（desktop_app.py 与本机 API 启动方式），
    此时局域网本就无法访问，回环访问无需 token 以保证桌面版与浏览器直访体验；
    而 Docker / 显式绑 0.0.0.0 的场景必须携带 token。
    """
    client_host = request.client.host if request.client else ""
    host_header = request.headers.get("host", "")
    # 用 urlsplit 解析 Host 头，正确处理 "127.0.0.1:8080" 与 "[::1]:8080"
    # （不能用 host_header.count(":") == 1，IPv6 字面量含多个冒号）
    from urllib.parse import urlsplit

    try:
        host_only = urlsplit(f"//{host_header}").hostname or ""
    except ValueError:
        host_only = ""
    return _is_loopback_host(client_host) and _is_loopback_host(host_only)


def require_token_for_external_access(request: Request) -> Optional[str]:
    """Gradio `auth_dependency`：非回环访问必须携带正确 token。

    【Gradio 6 约定】该依赖必须 **返回用户 ID 字符串** 表示认证通过、
    返回 `None` 表示未通过（Gradio 自己会抛 401 "Not authenticated"）。
    此处**不能**自己抛 HTTPException——那会被 Gradio 视为依赖异常。

    【安全背景】此前的 token 中间件只覆盖 `/api/*`，而 Gradio UI 挂载在 `/`，
    于是 UI 的全部事件回调（打开文件、写配置、触发分析）在对外暴露时均可被
    无鉴权调用。本依赖挂在 Gradio 挂载点上，覆盖 UI 整体。

    - 回环访问：返回 "local"（桌面版 pywebview 与本机浏览器无需 token）。
    - 非回环：校验 X-API-Token 头（或 ?token= 查询参数），通过则返回用户标识。
    """
    if _request_is_local(request):
        return "local"

    token = settings.api_auth_token
    if not token:
        # 未配置 token 却对外暴露：fail closed（拒绝而非放行）
        logger.error("服务对外暴露但未配置 API_AUTH_TOKEN，已拒绝非回环 UI 访问")
        return None

    provided = request.headers.get("x-api-token") or request.query_params.get("token") or ""
    # 常量时间比较，避免逐字节时间侧信道
    import hmac

    if not hmac.compare_digest(str(provided), str(token)):
        try:
            get_audit_logger().log(
                method=request.method, path=request.url.path, status_code=401,
                duration_ms=0.0,
                client_ip=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent", "")[:200],
                note="unauthorized UI access attempt")
        except Exception as e:
            logger.error(f"⚠️ 审计日志写入失败（UI 鉴权拒绝未能留痕）: {e}")
        return None
    return "api-token"


# 供 mount_gradio_app(auth_dependency=...) 使用（与上面的包装保持同一实现）
_require_token_for_external_access = require_token_for_external_access


def _open_path_with_shell(path: str) -> tuple:
    """用系统默认程序打开文件/目录——**默认禁用**，需显式开启。

    【安全】`os.startfile()` 会以当前用户身份用 shell 打开任意路径。此前它在
    4 个 UI 回调中被无条件调用，而这些回调在应用对外暴露时可能被无鉴权触发；
    再叠加"递归搜索文件系统找文件再打开"的逻辑，等于把本机 shell 的执行入口
    交给了调用方。安全工具不应自带这种能力。

    现在：
      · 默认**拒绝**执行，只返回路径与提示，由 UI 展示「复制路径」供用户自行打开；
      · 仅当设置 `AI_NSA_ALLOW_OPEN_PATH=1` 时才真正调用 startfile；
      · 无论如何都校验路径必须位于本程序的数据目录（data/reports 等）之内，
        避免被诱导打开任意文件。

    :return: (是否已打开, 给用户的提示文本)
    """
    import os as _os

    try:
        real = _os.path.realpath(path)
    except Exception as e:
        return False, f"❌ 路径无效：{e}"

    # 路径必须落在项目 data/ 目录内
    try:
        data_root = _os.path.realpath(data_dir(""))
        if _os.path.commonpath([real, data_root]) != data_root:
            logger.warning(f"拒绝打开 data 目录之外的路径: {real}")
            return False, f"❌ 出于安全考虑，仅允许打开程序数据目录内的文件：`{real}`"
    except Exception as e:
        return False, f"❌ 路径校验失败：{e}"

    if not _os.path.exists(real):
        return False, f"❌ 文件不存在：`{real}`"

    if _os.environ.get("AI_NSA_ALLOW_OPEN_PATH", "").strip().lower() not in ("1", "true", "yes"):
        # 默认路径：不执行，只给出可复制的路径
        return False, (
            f"ℹ️ 已跳过自动打开（默认禁用，设置 `AI_NSA_ALLOW_OPEN_PATH=1` 可启用）。\n"
            f"📌 路径：`{real}`"
        )

    try:
        if hasattr(_os, "startfile"):        # Windows
            _os.startfile(real)
        elif sys.platform == "darwin":        # macOS
            import subprocess
            subprocess.Popen(["open", real])
        else:                                 # Linux
            import subprocess
            subprocess.Popen(["xdg-open", real])
        return True, f"✅ 已用系统默认程序打开：`{real}`"
    except Exception as e:
        logger.warning(f"打开路径失败: {e}")
        return False, f"❌ 打开失败：{e}\n📌 路径：`{real}`"


@app.middleware("http")
async def api_token_middleware(request: Request, call_next):
    """鉴权 + API 审计日志（健康检查豁免鉴权与审计噪声；请求体不落库）"""
    import time as _time
    path = request.url.path
    start = _time.perf_counter()
    is_api = path.startswith("/api/")
    status_code = 200
    if is_api and path != "/api/health":
        token = settings.api_auth_token
        if token:
            provided = request.headers.get("x-api-token", "")
            if provided != token:
                status_code = 401
                try:
                    get_audit_logger().log(
                        method=request.method, path=path, status_code=401,
                        duration_ms=(_time.perf_counter() - start) * 1000,
                        client_ip=request.client.host if request.client else "",
                        user_agent=request.headers.get("user-agent", "")[:200],
                        note="unauthorized access attempt")
                except Exception as e:
                    # 审计写入失败必须可见：这是安全证据链，静默丢失等于无记录
                    logger.error(
                        f"⚠️ 审计日志写入失败（401 鉴权拒绝未能留痕）| {path}: {e}"
                    )
                return JSONResponse({"detail": "unauthorized: invalid or missing X-API-Token"}, status_code=401)
    try:
        response = await call_next(request)
        status_code = response.status_code
    except Exception:
        status_code = 500
        raise
    finally:
        # 审计记录（排除健康检查心跳噪声）
        if is_api and path != "/api/health":
            try:
                get_audit_logger().log(
                    method=request.method, path=path, status_code=status_code,
                    duration_ms=(_time.perf_counter() - start) * 1000,
                    client_ip=request.client.host if request.client else "",
                    user_agent=request.headers.get("user-agent", "")[:200])
            except Exception as e:
                # 审计写入失败必须可见：静默丢失会让"谁在什么时候调用了什么"
                # 这段证据链出现空洞，事后审计无法还原
                logger.error(
                    f"⚠️ 审计日志写入失败（{request.method} {path} -> {status_code} 未留痕）: {e}"
                )
    return response


# ===== Pydantic 请求模型 =====

class AnalyzeRequest(BaseModel):
    """分析请求"""
    packets: List[Dict[str, Any]]
    enable_ai_analysis: bool = True


class ChatRequest(BaseModel):
    """安全问答请求"""
    question: str
    context: Optional[str] = None


# ===== 系统初始化 =====

@app.on_event("startup")
async def startup_event():
    """应用启动时初始化"""
    global _system_initialized
    logger.info("=" * 60)
    logger.info(f"{settings.project_name} 启动中...")
    logger.info("=" * 60)

    # 确保数据目录存在
    ensure_dir(data_dir("samples"))
    ensure_dir(data_dir("knowledge"))
    ensure_dir(data_dir("chroma_db"))
    ensure_dir(data_dir("uploads"))

    # 本地 API 令牌：为空则自动生成（保护 /api/* 外部调用）
    if not settings.api_auth_token:
        token = _generate_and_persist_token()
        settings.api_auth_token = token  # 同步到运行实例，middleware 立即生效
        logger.warning(f"已自动生成本地 API 访问令牌并写入 .env（外部调用需携带 X-API-Token: {token[:4]}...）")
    else:
        logger.info("本地 API 访问令牌已配置")

    # 初始化LLM客户端（检查API Key）
    llm = get_llm_client()
    if llm.is_available():
        logger.info("✓ 大模型API已配置")
    else:
        logger.warning("⚠ 未配置大模型API Key，AI分析功能将不可用")

    _system_initialized = True
    logger.info("系统初始化完成")


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时"""
    logger.info("系统正在关闭...")


# ===== 健康检查 =====

# ===== API 审计日志接口 =====


@app.get("/api/audit/logs")
async def audit_logs(limit: int = 50, offset: int = 0,
                     status: Optional[int] = None, path_kw: str = "") -> Dict[str, Any]:
    """分页查询 API 审计日志（需 X-API-Token）"""
    return {
        "total": len(get_audit_logger().query(limit=100000)),
        "logs": get_audit_logger().query(limit=limit, offset=offset,
                                           status=status, path_kw=path_kw),
    }


@app.get("/api/audit/stats")
async def audit_stats() -> Dict[str, Any]:
    """审计统计：请求量 / 错误率 / 平均耗时 / 端点 TOP"""
    return get_audit_logger().stats()


@app.get("/api/health", response_model=schemas.HealthResponse)
async def health_check():
    """健康检查接口"""
    llm_available = get_llm_client().is_available()
    return {
        "status": "healthy",
        "project": settings.project_name,
        "version": settings.version,
        "llm_available": llm_available,
        "llm_model": settings.llm_model,
    }


# ===== 知识库管理 =====

@app.post("/api/knowledge/init")
async def init_knowledge_base():
    """初始化安全知识库（加载MITRE ATT&CK等内置知识）"""
    global _knowledge_loaded
    try:
        rag = get_rag_engine()
        knowledge_items = get_all_knowledge()
        count = rag.add_knowledge_base(knowledge_items)
        _knowledge_loaded = True
        return {
            "status": "success",
            "message": f"知识库初始化完成，共添加 {count} 个文档块",
            "knowledge_items": len(knowledge_items),
            "stats": rag.get_stats()
        }
    except Exception as e:
        logger.error(f"知识库初始化失败: {e}")
        raise HTTPException(status_code=500, detail=f"知识库初始化失败: {e}")


@app.get("/api/knowledge/stats")
async def knowledge_stats():
    """获取知识库统计"""
    try:
        rag = get_rag_engine()
        return rag.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取知识库统计失败: {e}")


@app.post("/api/knowledge/search")
async def search_knowledge(query: str = Form(...), top_k: int = Form(5)):
    """搜索知识库"""
    try:
        rag = get_rag_engine()
        results = rag.search(query, top_k=top_k)
        return {"query": query, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"知识库搜索失败: {e}")


@app.post("/api/knowledge/add")
async def add_knowledge(file: UploadFile = File(...)):
    """导入文档到知识库（.txt/.md 等纯文本）"""
    try:
        max_bytes = 5 * 1024 * 1024  # 知识文档上限 5MB
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail="知识文档超过大小限制（5MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")

        # 【P2优化】支持多种文档格式：TXT/MD/PDF/Word/JSON
        filename = file.filename or "doc.txt"
        ext = os.path.splitext(filename)[1].lower()
        supported_exts = (".txt", ".md", ".markdown", ".json", ".pdf", ".docx", ".doc")
        if ext not in supported_exts:
            raise HTTPException(status_code=400, detail=f"不支持的文件类型 {ext}，支持格式：.txt/.md/.json/.pdf/.docx")

        # 保存临时文件
        tmp_path = os.path.join(data_dir("knowledge"), f"import_{get_timestamp_str()}_{os.path.basename(filename)}")
        ensure_dir(os.path.dirname(tmp_path))
        with open(tmp_path, "wb") as f:
            f.write(content)

        def _add_task():
            rag = get_rag_engine()
            
            # 根据文件类型提取文本
            text_content = ""
            if ext == ".pdf":
                # PDF文件：用PyPDF2提取文本
                try:
                    import PyPDF2
                    with open(tmp_path, "rb") as f:
                        reader = PyPDF2.PdfReader(f)
                        for page in reader.pages:
                            text_content += page.extract_text() + "\n"
                except ImportError:
                    raise Exception("PDF支持需要安装PyPDF2，请运行: pip install PyPDF2")
                # 把提取的文本写入临时txt文件
                txt_path = tmp_path.replace(".pdf", ".txt")
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(text_content)
                chunks = rag.add_file(txt_path, source=f"user_import:{filename}")
            elif ext in (".docx", ".doc"):
                # Word文件：用python-docx提取文本
                try:
                    from docx import Document
                    doc = Document(tmp_path)
                    for para in doc.paragraphs:
                        text_content += para.text + "\n"
                except ImportError:
                    raise Exception("Word支持需要安装python-docx，请运行: pip install python-docx")
                # 把提取的文本写入临时txt文件
                txt_path = tmp_path.replace(".docx", ".txt").replace(".doc", ".txt")
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(text_content)
                chunks = rag.add_file(txt_path, source=f"user_import:{filename}")
            else:
                # 纯文本文件：直接添加
                chunks = rag.add_file(tmp_path, source=f"user_import:{filename}")
            
            return chunks

        chunks = await run_in_threadpool(_add_task)
        return {"status": "success", "filename": filename, "chunks_added": chunks,
                "stats": get_rag_engine().get_stats()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"知识导入失败: {e}")
        raise HTTPException(status_code=500, detail=f"知识导入失败: {e}")


# ===== 基线管理（EWMA 时序基线：学习-检测两阶段）=====

BASELINE_DIR = data_dir("baselines")


def _baseline_path(name: str) -> str:
    """基线文件名安全化 + 路径

    复用 `validate_baseline_name` 的字符策略（消除此前「内联过滤规则」与
    「名称校验规则」两套并存的漂移），但文件名额外不允许空格与点。
    """
    safe = "".join(ch for ch in (name or "") if ch.isalnum() or ch in "-_")
    if not safe:
        safe = "baseline"
    return os.path.join(BASELINE_DIR, f"{safe[:64]}.json")


def _list_baselines() -> List[Dict[str, Any]]:
    """列出所有已保存基线（P1-4: SQLite 为主，JSON 为兼容备份）"""
    from src.storage.database import Database
    db = Database()
    items = db.list_baselines()
    if not items:
        # SQLite 为空时从 JSON 导入（向后兼容）
        ensure_dir(BASELINE_DIR)
        for fn in sorted(os.listdir(BASELINE_DIR)):
            if fn.endswith(".json"):
                path = os.path.join(BASELINE_DIR, fn)
                b = TrafficBaseline.load(path)
                if b and b.learned:
                    # JSON 文件的 name 属不可信输入（文件可被手工编辑），
                    # 非法名回退到文件名 stem；仍非法则跳过该条并记日志，
                    # 不能让整个列表页因一条脏数据挂掉。
                    raw_name = b.name or os.path.splitext(fn)[0]
                    safe_name = safe_baseline_name(raw_name, fallback="")
                    if not safe_name:
                        safe_name = safe_baseline_name(os.path.splitext(fn)[0], fallback="")
                    if not safe_name:
                        logger.warning(f"跳过名称非法的基线文件: {fn}（name={raw_name!r}）")
                        continue
                    if safe_name != raw_name:
                        logger.warning(f"基线名称非法，已回退为安全名: {raw_name!r} → {safe_name!r}")
                    db.save_baseline(
                        name=safe_name,
                        profile=b.to_dict().get("profile", {}),
                        window_sec=b.window_sec,
                        total_packets=getattr(b, "packets_used", 0),
                        description=getattr(b, "description", None),
                    )
        items = db.list_baselines()
    # 转换为 UI 需要的格式
    result = []
    for item in items:
        bl = db.get_baseline(item["name"])
        profile_summary = {}
        if bl and bl.get("profile"):
            prof = bl["profile"].get("profile", bl["profile"])
            if isinstance(prof, dict):
                profile_summary = {k: {"median": v.get("median"), "mad": v.get("mad")}
                                   for k, v in prof.items() if isinstance(v, dict)}
        result.append({
            "name": item["name"],
            "file": f"{item['name']}.json",
            "created_at": item.get("created_at", ""),
            "packets_used": item.get("total_packets", 0),
            "window_sec": item.get("window_sec", 5),
            "profile": profile_summary,
        })
    return result


def _baseline_names() -> List[str]:
    """所有已保存基线名称（UI 下拉框选项）"""
    return [b["name"] for b in _list_baselines()]



@app.post("/api/baseline/learn")
async def baseline_learn(file: UploadFile = File(...), name: str = Form("default")):
    """
    上传正常流量 pcap 学习基线画像，保存为 JSON。
    检测阶段可引用该基线对照统计偏差。
    """
    try:
        # 名称校验必须早于任何落盘动作（否则非法名会先写进 data/baselines/）
        try:
            name = validate_baseline_name(name)
        except ValueError as name_err:
            raise HTTPException(status_code=400, detail=str(name_err)) from name_err

        max_bytes = settings.max_upload_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")

        tmp_path = os.path.join(data_dir("uploads"), f"baseline_learn_{get_timestamp_str()}.pcap")
        ensure_dir(os.path.dirname(tmp_path))
        with open(tmp_path, 'wb') as f:
            f.write(content)

        def _learn_task():
            parser = PcapParser()
            packets = parser.parse_file(tmp_path)
            if not packets:
                raise HTTPException(status_code=400, detail="PCAP解析失败或为空，无法学习基线")
            baseline = TrafficBaseline()
            baseline.name = name
            baseline.learn(packets)
            return baseline, len(packets)

        baseline, packet_count = await run_in_threadpool(_learn_task)

        save_path = _baseline_path(name)
        ensure_dir(BASELINE_DIR)
        if not baseline.save(save_path):
            raise HTTPException(status_code=500, detail="基线保存失败")
        # P1-4: 同时保存到 SQLite
        try:
            from src.storage.database import Database
            db = Database()
            db.save_baseline(
                name=name,
                profile=baseline.to_dict().get("profile", {}),
                window_sec=baseline.window_sec,
                total_packets=packet_count,
                description=f"从 {file.filename} 学习",
            )
        except Exception as e:
            logger.warning(f"基线保存到 SQLite 失败（不影响 JSON 保存）: {e}")

        return {
            "status": "success",
            "name": name,
            "packet_count": packet_count,
            "saved_to": save_path,
            "profile": baseline.to_dict(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"基线学习失败: {e}")
        raise HTTPException(status_code=500, detail=f"基线学习失败: {e}")


@app.get("/api/baseline/list")
async def baseline_list():
    """列出所有基线"""
    try:
        return {"baselines": _list_baselines(), "directory": BASELINE_DIR}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取基线列表失败: {e}")


@app.get("/api/baseline/get")
async def baseline_get(name: str):
    """获取单个基线画像详情"""
    try:
        b = TrafficBaseline.load(_baseline_path(name))
        if not b or not b.learned:
            raise HTTPException(status_code=404, detail=f"基线不存在或未学习: {name}")
        return b.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取基线失败: {e}")


@app.post("/api/baseline/delete")
async def baseline_delete(name: str = Form(...)):
    """删除基线（P1-4: 同时删除 SQLite 和 JSON）"""
    try:
        # 删除 SQLite
        try:
            from src.storage.database import Database
            Database().delete_baseline(name)
        except Exception as e:
            logger.warning(f"从 SQLite 删除基线失败: {e}")
        # 删除 JSON
        path = _baseline_path(name)
        if os.path.exists(path):
            os.remove(path)
            return {"status": "success", "deleted": name}
        raise HTTPException(status_code=404, detail=f"基线不存在: {name}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除基线失败: {e}")


# ===== PCAP文件分析 =====

# 允许的上传文件类型
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap.gz"}


def _check_upload_file(filename: str, size: int):
    """校验上传文件类型与大小——委托 src.utils.helpers，由 UI 层决定如何提示"""
    err = validate_upload_file(filename, size, max_mb=settings.max_upload_mb)
    if err:
        status = 413 if "大小限制" in err else 400
        raise HTTPException(status_code=status, detail=err)


def _analyze_pcap_task(filepath: str, enable_ai: bool, baseline_name: str = "") -> Dict[str, Any]:
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


@app.post("/api/pcap/analyze")
async def analyze_pcap(file: UploadFile = File(...), enable_ai: bool = Form(True),
                        baseline_name: str = Form("")):
    """
    上传PCAP文件并分析
    支持 .pcap / .pcapng 格式（Wireshark导出的文件）
    可选指定已学习的基线名称做时序对照检测
    """
    try:
        # 读取上传内容（限制大小）
        max_bytes = settings.max_upload_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")

        _check_upload_file(file.filename or "unknown.pcap", len(content))

        # 保存上传的文件
        timestamp = get_timestamp_str()
        safe_name = os.path.basename(file.filename or "upload.pcap")
        filename = f"upload_{timestamp}_{safe_name}"
        filepath = os.path.join(data_dir("uploads"), filename)
        ensure_dir(os.path.dirname(filepath))

        with open(filepath, 'wb') as f:
            f.write(content)

        logger.info(f"收到PCAP文件: {safe_name} ({len(content)} bytes)")

        # 重活（解析+分析+AI）放入线程池，避免阻塞事件循环
        result = await run_in_threadpool(_analyze_pcap_task, filepath, enable_ai, baseline_name)
        result["file_size"] = format_bytes(len(content))
        result["filename"] = safe_name

        # 保存分析报告（JSON 快照）
        report_path = os.path.join(data_dir("samples"), f"report_{timestamp}.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        result["report_saved"] = report_path

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PCAP分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"PCAP分析失败: {e}")


@app.post("/api/pcap/analyze_async")
async def analyze_pcap_async(file: UploadFile = File(...), enable_ai: bool = Form(True),
                             baseline_name: str = Form("")):
    """
    P2 异步分析：大文件任务入队后立即返回 task_id，轮询 GET /api/tasks/{task_id}
    """
    try:
        max_bytes = settings.max_upload_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")
        if not content:
            raise HTTPException(status_code=400, detail="上传文件为空")
        _check_upload_file(file.filename or "unknown.pcap", len(content))

        timestamp = get_timestamp_str()
        safe_name = os.path.basename(file.filename or "upload.pcap")
        filename = f"async_{timestamp}_{safe_name}"
        filepath = os.path.join(data_dir("uploads"), filename)
        ensure_dir(os.path.dirname(filepath))
        with open(filepath, 'wb') as f:
            f.write(content)

        task_id = get_task_queue().submit(_analyze_pcap_task, filepath, enable_ai, baseline_name)
        logger.info(f"异步分析任务已入队: {task_id} ({safe_name})")
        return {"status": "accepted", "task_id": task_id, "filename": safe_name}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"异步任务提交失败: {e}")
        raise HTTPException(status_code=500, detail=f"任务提交失败: {e}")


@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    """查询异步任务状态与结果"""
    t = get_task_queue().get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    return t


@app.get("/api/tasks")
async def list_tasks(limit: int = 20):
    """任务列表 + 队列统计"""
    return {"tasks": get_task_queue().list_tasks(limit),
            "stats": get_task_queue().stats()}


# ===== 安全问答 =====

@app.post("/api/chat", response_model=schemas.ChatResponse)
async def security_chat(request: ChatRequest):
    """安全知识问答（基于RAG）"""
    try:
        llm = get_llm_client()
        if not llm.is_available():
            raise HTTPException(status_code=400, detail="未配置大模型API Key")

        threat_analyzer = get_threat_analyzer()
        # P1-3：LLM 调用移入线程池，避免阻塞事件循环（问答 20s 级延迟不再卡住其他请求）
        answer = await run_in_threadpool(
            threat_analyzer.chat_about_security, request.question, request.context)

        # 错误与正常响应分离：LLM调用失败返回502
        if answer.startswith("[大模型调用失败]") or answer.startswith("[LLM"):
            raise HTTPException(status_code=502, detail=answer)

        return {"question": request.question, "answer": answer}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"安全问答失败: {e}")
        raise HTTPException(status_code=500, detail=f"安全问答失败: {e}")


# ===== 事件报告生成 =====

# ===== P2-2: 日志可观测性 API =====

@app.get("/api/logs")
async def get_logs(limit: int = 100, level: str = "", keyword: str = ""):
    """获取最近日志（UI 日志查看器）"""
    try:
        from src.utils.log_observer import get_log_observer
        observer = get_log_observer()
        logs = observer.get_recent_logs(
            limit=min(limit, 500),
            level=level or None,
            keyword=keyword or None,
        )
        return {"total": len(logs), "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取日志失败: {e}")


@app.get("/api/logs/stats")
async def get_log_stats():
    """获取日志统计信息"""
    try:
        from src.utils.log_observer import get_log_observer
        return get_log_observer().get_log_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取日志统计失败: {e}")


@app.get("/api/diagnostic")
async def get_diagnostic_report():
    """一键诊断报告（系统信息+配置状态+最近错误+性能指标）"""
    try:
        from src.utils.log_observer import get_log_observer
        return get_log_observer().generate_diagnostic_report()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"生成诊断报告失败: {e}")


@app.post("/api/logs/clear")
async def clear_logs():
    """清空日志文件"""
    try:
        from src.utils.log_observer import get_log_observer
        success = get_log_observer().clear_logs()
        return {"status": "success" if success else "failed", "message": "日志已清空" if success else "清空失败"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清空日志失败: {e}")


# ===== P1-3: 配置向导 API（DPAPI 加密存储）=====

@app.get("/api/config/status")
async def config_status():
    """获取配置状态（API Key 是否已配置、是否加密存储）"""
    try:
        from config.settings import settings
        has_key = bool(settings.llm_api_key and "xxxx" not in settings.llm_api_key)
        secure_available = False
        secure_keys = []
        try:
            import sys
            if sys.platform == "win32":
                from src.security.secure_store import get_secure_store
                ss = get_secure_store()
                secure_available = ss.dpapi_available
                secure_keys = ss.list_keys()
        except Exception as e:
            # 静默失败会让本接口谎报 "dpapi_available=false / 无已存 Key"，
            # 使用户误以为加密存储没生效。必须记录原因。
            logger.warning(
                f"读取 DPAPI 安全存储状态失败，本响应中的 dpapi_available/secure_keys "
                f"可能不准确: {e}"
            )
        return {
            "api_key_configured": has_key,
            "api_key_masked": (settings.llm_api_key[:6] + "..." + settings.llm_api_key[-4:])
            if has_key else "",
            "base_url": settings.llm_base_url,
            "model": settings.llm_model,
            "dpapi_available": secure_available,
            "secure_keys": secure_keys,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取配置状态失败: {e}")


def _assert_safe_llm_base_url(base_url: str) -> str:
    """校验 LLM Base URL，拒绝 SSRF 目标，返回规范化后的 URL。

    【安全】原实现直接把用户传入的 `base_url` 拼上 `/chat/completions` 发请求，
    并把 `Authorization: Bearer <用户的真实 API Key>` 一同送出，仅检查了"非空"。
    这意味着任意能调用该接口的人都可以：
      · 让服务器向内网/云元数据地址发起请求（SSRF）；
      · 把用户的真实 LLM Key 外带到自己的服务器（凭据泄露）。

    本函数只允许 https、禁止回环/私网/链路本地/保留地址、禁止非标准端口，
    并拒绝明显的内网主机名。
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    raw = (base_url or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="base_url 不能为空")

    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="仅允许 https:// 的 Base URL（拒绝 http/其他协议，避免明文传输 API Key）",
        )
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise HTTPException(status_code=400, detail="Base URL 缺少主机名")

    # 主机名黑名单（内网常用名与云元数据别名）
    if host in {"localhost", "metadata", "metadata.google.internal"} or \
            host.endswith((".local", ".internal", ".localhost")):
        raise HTTPException(status_code=400, detail=f"Base URL 主机名不被允许: {host}")

    # 端口：仅允许标准 HTTPS 端口
    if parsed.port not in (None, 443):
        raise HTTPException(status_code=400,
                            detail=f"仅允许 443 端口（当前 {parsed.port}）")

    # 解析主机名并检查所有解析结果，阻断内网 / 回环 / 链路本地 / 保留地址
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Base URL 主机名无法解析: {e}") from e

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(
                status_code=400,
                detail=f"Base URL 解析到内网/保留地址（{ip}），已拒绝以避免 SSRF",
            )

    return raw.rstrip("/")


@app.post("/api/config/validate")
async def config_validate(api_key: str = Form(...), base_url: str = Form(""),
                           model: str = Form("")):
    """校验 API Key 有效性（发送一个简单的测试请求）

    【安全】base_url 必须通过 SSRF 校验；且**不回显上游响应正文**——
    原实现会把响应体前 200 字符返回给调用方，等于把探测结果当作回显通道。
    """
    if not api_key or "xxxx" in api_key:
        return {"valid": False, "message": "API Key 为空或仍是占位符"}
    try:
        import httpx
        safe_base = _assert_safe_llm_base_url(base_url or "")
        url = safe_base + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model or "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 5,
        }
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                return {"valid": True, "message": "API Key 校验通过", "status_code": 200}
            # 不回显响应正文（可能含上游内部信息），只给状态码与截断原因
            reason = ""
            try:
                body = resp.json()
                if isinstance(body, dict):
                    err = body.get("error") or {}
                    reason = str(err.get("message") or err.get("type") or "")[:120]
            except Exception:
                reason = ""
            return {"valid": False,
                    "message": f"校验失败: HTTP {resp.status_code}"
                               + (f"（{reason}）" if reason else ""),
                    "status_code": resp.status_code}
    except HTTPException as e:
        return {"valid": False, "message": f"配置被拒绝: {e.detail}"}
    except Exception as e:
        return {"valid": False, "message": f"校验异常: {e}"}


@app.post("/api/config/save_secure")
async def config_save_secure(api_key: str = Form(...), base_url: str = Form(""),
                              model: str = Form("")):
    """保存配置到 DPAPI 加密存储（P1-3）"""
    if not api_key or "xxxx" in api_key:
        raise HTTPException(status_code=400, detail="API Key 为空或仍是占位符")
    try:
        import sys
        if sys.platform != "win32":
            raise HTTPException(status_code=400, detail="DPAPI 仅支持 Windows")
        from src.security.secure_store import get_secure_store
        ss = get_secure_store()
        ss.set("LLM_API_KEY", api_key.strip())
        ss.set("LLM_BASE_URL", base_url.strip())
        ss.set("LLM_MODEL", model.strip())
        # 重置 LLM 客户端
        try:
            from src.ai.llm_client import reset_llm_client
            reset_llm_client()
        except Exception as e:
            # 静默失败会让旧 Key 继续生效，而接口却返回"已保存成功" —— 属于谎报
            logger.error(
                f"⚠️ 重置 LLM 客户端失败，新配置可能不会立即生效（需重启应用）: {e}"
            )
        return {"status": "success", "message": "已保存到 DPAPI 加密存储",
                "dpapi_encrypted": ss.is_encrypted("LLM_API_KEY")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"保存失败: {e}")


# ===== P1-2: 取证知识库 API =====

@app.get("/api/forensic/stats")
async def forensic_stats():
    """取证知识库统计"""
    try:
        from src.storage.forensic_kb import get_forensic_kb
        return get_forensic_kb().get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取取证统计失败: {e}")


@app.get("/api/forensic/trend")
async def forensic_trend(days: int = 30):
    """攻击趋势分析"""
    try:
        from src.storage.forensic_kb import get_forensic_kb
        return get_forensic_kb().get_trend_analysis(days=days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"趋势分析失败: {e}")


@app.get("/api/forensic/related/{analysis_id}")
async def forensic_related(analysis_id: str, max_related: int = 10):
    """跨样本关联分析（路径参数为单花括号；双花括号会被当成字面量导致 404）"""
    try:
        from src.storage.forensic_kb import get_forensic_kb
        related = get_forensic_kb().find_related_samples(analysis_id, max_related)
        return {"analysis_id": analysis_id, "related_count": len(related), "related": related}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"关联分析失败: {e}")


@app.get("/api/forensic/iocs/{analysis_id}")
async def forensic_iocs(analysis_id: str):
    """从分析记录提取 IOC（路径参数为单花括号）"""
    try:
        from src.storage.forensic_kb import get_forensic_kb
        iocs = get_forensic_kb().extract_iocs(analysis_id)
        return {"analysis_id": analysis_id, "ioc_count": len(iocs), "iocs": iocs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC提取失败: {e}")


@app.post("/api/incident/report")
async def generate_incident_report(incident_data: Dict[str, Any]):
    """生成安全事件响应报告"""
    try:
        llm = get_llm_client()
        if not llm.is_available():
            raise HTTPException(status_code=400, detail="未配置大模型API Key")

        threat_analyzer = get_threat_analyzer()
        report = threat_analyzer.generate_incident_report(incident_data)

        if report.startswith("[大模型调用失败]") or report.startswith("[LLM"):
            raise HTTPException(status_code=502, detail=report)

        return {"status": "success", "report": report}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"事件报告生成失败: {e}")
        raise HTTPException(status_code=500, detail=f"事件报告生成失败: {e}")


# ===== Gradio Web UI 集成 =====

# ---- 界面美化：蓝色 × 二次元主题（v1.3.0，与应用图标同风格） ----
_GRADIO_CSS = """
body {
    background:
        radial-gradient(circle at 18% 8%, rgba(96,165,250,0.14), transparent 42%),
        radial-gradient(circle at 82% 92%, rgba(147,197,253,0.18), transparent 45%),
        radial-gradient(circle at 55% 45%, rgba(219,234,254,0.35), transparent 60%),
        linear-gradient(160deg, #eaf2ff 0%, #f7faff 50%, #eaf6ff 100%) !important;
    background-attachment: fixed !important;
}
body::before {
    content: "";
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
        radial-gradient(rgba(59,130,246,0.10) 1px, transparent 1.6px),
        radial-gradient(rgba(147,197,253,0.16) 1px, transparent 1.6px);
    background-size: 34px 34px, 51px 51px;
    background-position: 0 0, 17px 17px;
}
.gradio-container { max-width: 1280px !important; }
#app-hero {
    display: flex; align-items: center; gap: 16px;
    padding: 18px 24px; margin: 6px 0 14px;
    background: linear-gradient(120deg, #1d4ed8 0%, #2563eb 45%, #3b82f6 75%, #60a5fa 100%);
    border-radius: 18px; color: #fff;
    box-shadow: 0 8px 24px rgba(37,99,235,0.28), inset 0 1px 0 rgba(255,255,255,0.25);
}
#app-hero .hero-logo {
    width: 64px; height: 64px; border-radius: 50%; flex: none;
    border: 3px solid rgba(255,255,255,0.92);
    box-shadow: 0 0 0 5px rgba(255,255,255,0.18), 0 6px 16px rgba(0,0,0,0.25);
    object-fit: cover;
}
#app-hero .hero-title { font-size: 21px; font-weight: 800; letter-spacing: 1px; text-shadow: 0 2px 8px rgba(0,0,0,0.18); }
#app-hero .hero-sub { font-size: 12px; opacity: 0.95; margin-top: 3px; letter-spacing: 0.3px; }
#app-hero .hero-star { font-size: 13px; opacity: 0.9; margin-top: 2px; }
.tabs { border-radius: 14px; }
.gr-button-primary {
    background: linear-gradient(135deg, #2563eb, #60a5fa) !important;
    border: none !important;
    box-shadow: 0 4px 12px rgba(37,99,235,0.25) !important;
}
.gr-button-primary:hover { filter: brightness(1.06); }
"""


def _render_app_header() -> str:
    """顶部 Hero：应用图标 + 标题（蓝色二次元风格，图标与快捷方式同源）"""
    import base64
    logo_b64 = None
    cands = []
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cands.append(os.path.join(root, 'assets', 'app_logo.png'))
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        cands.append(os.path.join(meipass, 'assets', 'app_logo.png'))
        cands.append(os.path.join(os.path.dirname(meipass), 'assets', 'app_logo.png'))
    cands.append(os.path.join(os.getcwd(), 'assets', 'app_logo.png'))
    for p in cands:
        try:
            if os.path.exists(p):
                with open(p, 'rb') as f:
                    logo_b64 = 'data:image/png;base64,' + base64.b64encode(f.read()).decode('utf-8')
                    break
        except Exception as e:
            # 仅影响界面 logo（纯装饰），失败时回退到内置图标；留痕便于排查资源问题
            logger.debug(f"加载界面 logo 失败，已回退内置图标: {p} ({type(e).__name__}: {e})")
            continue
    if logo_b64:
        logo_html = '<img class="hero-logo" src="' + logo_b64 + '" alt="logo"/>'
    else:
        logo_html = '<div class="hero-logo" style="display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,0.3);font-size:30px;">🛡️</div>'
    return (
        '<div id="app-hero">' + logo_html
        + '<div><div class="hero-title">AI 网络安全智能分析系统</div>'
        + '<div class="hero-sub">流行为检测 × LLM 研判 × 证据溯源 ｜ 上传 PCAP，AI 自动分析威胁</div>'
        + '<div class="hero-star">✦ 蓝白星光主题 · 桌面应用版 ✦</div></div></div>'
    )



def _load_custom_css() -> str:
    """P2-6: 加载自定义 CSS（内联基础样式 + 外部蓝色二次元风格文件）"""
    css = _GRADIO_CSS
    try:
        import os
        css_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "ui", "custom_style.css")
        if os.path.exists(css_path):
            with open(css_path, "r", encoding="utf-8") as f:
                css += "\n\n/* ===== 外部自定义样式 ===== */\n" + f.read()
    except Exception as e:
        logger.warning(f"加载自定义 CSS 失败: {e}")
    return css


# 【重要】以下两项必须惰性求值，不能放在模块级：
# 无 gradio 环境下 `gr` 为 None，模块级 `gr.themes.Soft(...)` 会抛
# AttributeError，导致本模块（以及 re-export 它的 src/api/main.py）
# 整体导入失败——"gradio 未安装时仅启动 API 服务"这条降级路径随之失效。
_GRADIO_MAJOR: int = 0
_UI_KWARGS: Dict[str, Any] = {}


def _init_gradio_ui_kwargs() -> None:
    """在确认 gradio 可用后初始化 UI kwargs（幂等）。"""
    global _GRADIO_MAJOR, _UI_KWARGS
    if _UI_KWARGS:
        return
    _GRADIO_MAJOR = int(getattr(gr, "__version__", "4").split(".")[0])
    _UI_KWARGS = {"theme": gr.themes.Soft(primary_hue=gr.themes.colors.blue),
                  "css": _load_custom_css()}


def create_gradio_interface():
    """创建Gradio Web界面（简单易用，无需前端开发）"""
    global _i18n

    # 无 gradio 时给出明确错误，而不是让调用方撞上 NoneType 属性错误
    if not GRADIO_AVAILABLE:
        raise RuntimeError(
            "gradio 未安装，无法创建 Web UI。请 `pip install -r requirements.txt`，"
            "或仅使用 API 服务（不调用本函数）。"
        )
    # gradio 可用后再初始化依赖 gr 的 kwargs（模块级不能做，否则破坏"gradio 可选"）
    _init_gradio_ui_kwargs()

    # 初始化 i18n 管理器
    _default_lang = "zh"
    if I18N_AVAILABLE:
        _trans_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "translations.json")
        _config_path = os.path.join(data_dir("config"), "ui_settings.json")
        _default_lang = I18nManager.load_preference(_config_path, "zh")
        _i18n = I18nManager(_trans_path, default_lang=_default_lang)
        # 同步设置 LLM 输出语言
        try:
            from src.ai.llm_client import LLMClient
            LLMClient.set_language(_default_lang)
        except Exception as _e:
            logger.warning(f"同步 LLM 语言失败: {_e}")
        logger.info(f"i18n 管理器已初始化，默认语言: {_default_lang}")

    # P2-6: Gradio 6.x 也加载自定义 CSS
    _blocks_kwargs = {"css": _load_custom_css()} if _GRADIO_MAJOR >= 6 else _UI_KWARGS
    with gr.Blocks(title="AI网络安全分析系统", **_blocks_kwargs) as demo:
        gr.HTML(_render_app_header())

        with gr.Tabs():
            # Tab 1: PCAP分析
            with gr.Tab(_tab("📊 PCAP流量分析")):
                gr.Markdown(_("上传Wireshark抓包文件（.pcap/.pcapng），系统将自动进行流量分析和AI威胁研判"))
                with gr.Row():
                    pcap_file = gr.File(label=_("上传PCAP文件"), file_types=[".pcap", ".pcapng", ".cap"])
                    enable_ai = gr.Checkbox(label=_("启用AI分析"), value=True)
                baseline_dropdown = gr.Dropdown(
                    label=_("时序基线（可选）"), choices=_baseline_names(), interactive=True,
                    info=_("选择已学习的正常流量基线，分析时将对照时序偏差检测")
                )
                analyze_btn = gr.Button(_("🔍 开始分析"), variant="primary")
                process_output = gr.Markdown(label=_("🧠 分析过程"), value=_("🕐 等待上传 PCAP 开始分析"))
                with gr.Row():
                    summary_output = gr.Textbox(
                                                label=_("📋 流量概览"), lines=15, max_lines=25)
                    threat_output = gr.Textbox(
                                                label=_("⚠️ AI威胁分析"), lines=15, max_lines=25)
                with gr.Row():
                    toggle_raw_btn = gr.Button(
                        _("📖 展开完整报告"), size="sm")
                raw_output = gr.Code(
                    label=_("📊 完整分析报告（JSON）"),
                    language="json", lines=12, max_lines=15,
                    elem_id="raw-code-collapsed")
                raw_output_full = gr.Code(
                    label=_("📊 完整分析报告（JSON）· 展开视图"),
                    language="json", lines=30, max_lines=40, visible=False,
                    elem_id="raw-code-full")
                raw_content_state = gr.State("")
                raw_expanded_state = gr.State(False)
                # 下载报告区域：按钮在上，进度条和操作按钮在下
                report_download = gr.DownloadButton(
                    label=_("📄 下载取证型HTML报告"), value=None, visible=True)
                download_progress = gr.HTML(value="", visible=True)
                with gr.Row():
                    tab1_open_report_btn = gr.Button(_("📄 打开报告文件"), size="sm", visible=False)
                    tab1_open_report_dir_btn = gr.Button(_("📂 打开报告所在文件夹"), size="sm", visible=False)
                baseline_chart_output = gr.HTML(label=_("📈 流量 vs 基线对比图（选基线分析时显示）"))
                report_feedback = gr.Markdown(_("💡 分析完成后点击「下载取证型HTML报告」，进度条显示下载状态，完成后可直接打开报告"))
                analysis_done = gr.State(False)  # 标记当前会话是否已完成至少一次分析
                # 本会话生成的报告路径。此前下载按钮用「目录里最新的 .html」定位报告，
                # 多标签页/多用户/报告生成失败时会取到**别的案件**的报告；改为随分析
                # 结果写入本会话状态，下载只认自己这一份。
                report_path_state = gr.State(None)

                def refresh_baselines():
                    try:
                        bl = _list_baselines()
                        return gr.Dropdown(choices=[b["name"] for b in bl])
                    except Exception:
                        return gr.Dropdown(choices=[])

                baseline_dropdown.focus(refresh_baselines, outputs=baseline_dropdown)

                def on_report_download_click(done, report_path):
                    """点击下载：使用**本会话**生成的报告路径，设置下载按钮 value 触发浏览器下载"""
                    if not done or not report_path:
                        return (gr.update(value=None),
                                "⚠️ 尚未生成报告：请先上传 PCAP 文件并点击「开始分析」\n"
                                "（若分析已完成仍看到此提示，说明报告生成失败，请查看上方错误信息）",
                                "",
                                gr.update(visible=False), gr.update(visible=False))
                    try:
                        # 只认本会话产生的报告，不再扫描目录取最新文件：
                        # 此前用 max(mtime) 会在多标签页/多用户时取到别的案件的报告
                        newest = report_path
                        if not os.path.isfile(newest):
                            return (gr.update(value=None),
                                    f"❌ 报告文件不存在或已被移动：{newest}", "",
                                    gr.update(visible=False), gr.update(visible=False))
                        sz = os.path.getsize(newest) / 1024
                        # 【P1优化】更真实的分阶段进度反馈
                        progress_html = f"""
                        <div style="margin:10px 0;padding:16px;background:linear-gradient(135deg,#e8f4fd,#f0f8ff);border-radius:12px;border:1px solid #b3d9f2;">
                            <div style="font-size:14px;color:#1a5276;margin-bottom:10px;font-weight:600;">📥 报告下载</div>
                            
                            <!-- 阶段1：文件准备 -->
                            <div style="margin-bottom:8px;display:flex;align-items:center;gap:8px;">
                                <div style="width:20px;height:20px;border-radius:50%;background:#27ae60;color:white;display:flex;align-items:center;justify-content:center;font-size:12px;">✓</div>
                                <div style="font-size:13px;color:#2c3e50;">定位报告文件</div>
                            </div>
                            
                            <!-- 阶段2：文件读取 -->
                            <div style="margin-bottom:8px;display:flex;align-items:center;gap:8px;">
                                <div style="width:20px;height:20px;border-radius:50%;background:#27ae60;color:white;display:flex;align-items:center;justify-content:center;font-size:12px;">✓</div>
                                <div style="font-size:13px;color:#2c3e50;">读取文件内容（{sz:.1f} KB）</div>
                            </div>
                            
                            <!-- 阶段3：下载完成 -->
                            <div style="margin-bottom:12px;display:flex;align-items:center;gap:8px;">
                                <div style="width:20px;height:20px;border-radius:50%;background:#27ae60;color:white;display:flex;align-items:center;justify-content:center;font-size:12px;">✓</div>
                                <div style="font-size:13px;color:#2c3e50;">生成下载链接</div>
                            </div>
                            
                            <!-- 进度条 -->
                            <div style="width:100%;height:24px;background:#e0e0e0;border-radius:12px;overflow:hidden;margin-bottom:10px;">
                                <div style="width:100%;height:100%;background:linear-gradient(90deg,#3498db,#2980b9);border-radius:12px;display:flex;align-items:center;justify-content:center;color:white;font-size:12px;font-weight:600;">100%</div>
                            </div>
                            
                            <!-- 完成提示 -->
                            <div style="padding:10px;background:#d5f5e3;border-radius:8px;border-left:4px solid #27ae60;">
                                <div style="font-size:13px;color:#1e8449;font-weight:600;margin-bottom:4px;">✅ 下载完成！</div>
                                <div style="font-size:12px;color:#27ae60;">📄 报告文件：{os.path.basename(newest)}</div>
                                <div style="font-size:12px;color:#27ae60;margin-top:2px;">📦 文件大小：{sz:.1f} KB</div>
                                <div style="font-size:12px;color:#2980b9;margin-top:6px;">💡 点击下方按钮可直接打开报告或所在文件夹</div>
                            </div>
                        </div>
                        """
                        return (gr.update(value=newest),
                                f"✅ 报告已下载：{os.path.basename(newest)}（{sz:.1f} KB）\n"
                                f"📌 保存位置：`{newest}`\n"
                                f"💡 可点击下方按钮直接打开报告",
                                progress_html,
                                gr.update(visible=True), gr.update(visible=True))
                    except Exception as e:
                        return (gr.update(value=None), f"❌ 载入报告失败：{e}", "",
                                gr.update(visible=False), gr.update(visible=False))

                def analyze_pcap_gradio(file, ai_enabled, baseline_name):
                    """生成器版：分阶段输出分析过程 + AI 流式研判 + 写入历史记录"""
                    if not file:
                        yield ("❌ 请先上传PCAP文件", "请先上传PCAP文件", "", "", None,
                               gr.update(value=_history_table_value()), gr.update(value=None),
                               False, None)
                        return
                    try:
                        # 阶段 1-4：解析、检测、AI 研判、幻觉控制、报告生成
                        # 全部委托 src/services/analysis_service.py（与 API 路径同一实现）。
                        # 用队列把服务层的进度/AI 分片回传到本生成器，保持真实流式展示。
                        import queue as _queue
                        import threading as _threading

                        _q: "_queue.Queue" = _queue.Queue()

                        # 服务层在阶段 1 结束时才知道摘要，通过闭包回传，供进度事件展示
                        _ui_state = {"summary": "⏳ 分析中..."}

                        def _on_progress(msg):
                            _q.put(("progress", msg))

                        def _on_ai_chunk(text):
                            _q.put(("ai", text))

                        def _on_summary_ready(summary_text):
                            _ui_state["summary"] = summary_text

                        _box = {}

                        def _worker():
                            try:
                                _box["outcome"] = _run_analysis(
                                    file.name,
                                    enable_ai=ai_enabled,
                                    baseline_name=baseline_name,
                                    ai_mode="stream",
                                    run_hallucination=True,
                                    generate_report=True,
                                    on_progress=_on_progress,
                                    on_ai_chunk=_on_ai_chunk,
                                    on_summary_ready=_on_summary_ready,
                                )
                            except BaseException as err:  # noqa: BLE001 原样回传
                                _box["error"] = err
                            finally:
                                _q.put(("done", None))

                        _threading.Thread(target=_worker, daemon=True).start()

                        outcome = None
                        ai_threat = ""
                        while True:
                            kind, payload = _q.get()
                            if kind == "done":
                                break
                            if kind == "progress":
                                yield (payload, _ui_state["summary"], ai_threat, "", None,
                                       gr.update(value=_history_table_value()),
                                       gr.update(value=None), False, None)
                            elif kind == "ai":
                                ai_threat = payload
                                yield ("🧠 阶段 3/4：AI 威胁研判中（流式输出）...",
                                       _ui_state["summary"], ai_threat, "", None,
                                       gr.update(value=_history_table_value()),
                                       gr.update(value=None), False, None)

                        if "error" in _box:
                            raise _box["error"]
                        outcome = _box["outcome"]

                        report = outcome.report
                        summary = outcome.summary
                        report_json = outcome.report_json
                        html_path = outcome.html_path
                        # 幻觉控制已由服务层统一执行（API 路径同样执行）
                        hallucination_result = outcome.hallucination
                        evidence = outcome.evidence

                        # 复制PCAP文件到项目目录（确保持久化，重新分析时源文件一定存在）
                        import shutil as _shutil
                        persisted_pcap_path = os.path.abspath(file.name)
                        try:
                            analyzed_dir = data_dir("samples", "analyzed")
                            os.makedirs(analyzed_dir, exist_ok=True)
                            src_path = os.path.abspath(file.name)
                            if os.path.exists(src_path):
                                # 使用时间戳+原文件名，避免重名覆盖
                                import time as _t2
                                ts_prefix = _t2.strftime("%Y%m%d_%H%M%S")
                                dst_name = f"{ts_prefix}_{os.path.basename(src_path)}"
                                dst_path = os.path.join(analyzed_dir, dst_name)
                                _shutil.copy2(src_path, dst_path)
                                persisted_pcap_path = dst_path
                                logger.info(f"PCAP文件已持久化复制到: {dst_path}")
                        except Exception as copy_err:
                            logger.warning(f"PCAP文件持久化复制失败，使用原路径: {copy_err}")
                        
                        # 写入分析历史（供「📜 分析历史」Tab 回看）
                        try:
                            get_history_store().add_analysis({
                                "file": os.path.basename(file.name),
                                "file_path": persisted_pcap_path,  # 持久化后的PCAP路径，用于重新分析
                                "packets": report["summary"]["total_packets"],
                                "flows": report["summary"]["total_flows"],
                                "bytes": report["summary"]["total_bytes"],
                                "alerts": report["anomaly_detection"]["total_alerts"],
                                "severity": report["anomaly_detection"]["severity_summary"],
                                "stacking_verdict": (report.get("stacking_fusion") or {}).get("is_attack", False),
                                "stacking_confidence": (report.get("stacking_fusion") or {}).get("confidence", 0),
                                "hallucination_risk": hallucination_result.get("hallucination_risk", "unknown") if hallucination_result else "unknown",
                                "needs_review": hallucination_result.get("review_marker", {}).get("needs_review", False) if hallucination_result else False,
                                "summary_text": summary,
                                "ai_summary": (ai_threat or "")[:400],
                                "raw": report,
                                "html_report": html_path,
                            })
                        except Exception as e:
                            logger.warning(f"写入分析历史失败: {e}")

                        yield (f"✅ 分析完成（{get_timestamp_str()}）",
                               summary, ai_threat, report_json, html_path,
                               gr.update(value=_history_table_value()),
                               _build_baseline_compare_svg(report.get("window_series"),
                                                           report.get("baseline_profile")),
                               True, html_path)  # analysis_done=True + 本会话报告路径

                    except Exception as e:
                        logger.error(f"分析失败: {e}")
                        yield (f"❌ 分析失败: {str(e)}", "分析失败", "", "", None,
                               gr.update(value=_history_table_value()), gr.update(value=None),
                               False, None)  # 分析失败保持 analysis_done=False，清空报告路径

                # 注：analyze_btn 的事件注册在「📜 分析历史」Tab 定义之后（需引用 history_dropdown）

            # Tab 2: 分析历史（v1.5.1：表格列表 + 行点击查看详情）
            with gr.Tab(_tab("📜 分析历史")):
                def _fmt_time(ts):
                    """历史时间戳 → 可读格式：20260908_231447 → 2026/9/8 23:14"""
                    ts = ts or ""
                    m = re.match(r"^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})", ts)
                    if m:
                        y, mo, d, h, mi = m.groups()
                        return f"{int(y)}/{int(mo)}/{int(d)} {int(h)}:{mi}"
                    m2 = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})", ts)
                    if m2:
                        y, mo, d, h, mi = m2.groups()
                        return f"{int(y)}/{int(mo)}/{int(d)} {int(h)}:{mi}"
                    return ts or "?"

                def _history_count_text():
                    try:
                        n = len(get_history_store().list_analysis())
                        return _("📊 当前 **{n}** 条分析记录").replace("{n}", str(n))
                    except Exception:
                        return _("📊 当前 **0** 条分析记录")

                def _history_table_value():
                    """历史记录 → 表格行（时间/文件/包/流/告警/严重度/摘要）"""
                    try:
                        hs = get_history_store().list_analysis()
                    except Exception:
                        return []
                    rows = []
                    for h in hs:
                        sev = h.get('severity', {})
                        sev_str = ""
                        if isinstance(sev, dict):
                            parts = [f"{k}:{v}" for k, v in sev.items() if v]
                            sev_str = " | ".join(parts) if parts else "正常"
                        summary = (h.get('summary_text') or "").replace("\n", " ").replace("\r", "")[:45]
                        rows.append([_fmt_time(h.get('ts', '')), h.get('file', '?'),
                                     h.get('packets', 0), h.get('flows', 0),
                                     h.get('alerts', 0), sev_str, summary])
                    return rows

                gr.Markdown(_("每次 PCAP 分析完成后自动记录。**点击表格任意一行**查看该次分析的详情、摘要与报告（最多保留 60 条）"))
                history_count = gr.Markdown(value=_history_count_text())
                history_table = gr.Dataframe(
                    value=_history_table_value(),
                    label=_("历史分析记录（点击行查看详情）"),
                    headers=[_("时间"), _("文件"), _("包数"), _("流数"), _("告警数"), _("严重度"), _("摘要")],
                    datatype=["str", "str", "number", "number", "number", "str", "str"],
                    interactive=False, row_count=(5, "dynamic"), column_count=7, wrap=True)
                # 下拉框选择记录（更可靠，不依赖表格点击的状态同步）

                def _search_pcap_file(filename):
                    """在**项目数据目录内**搜索同名 PCAP，返回完整路径或 None。

                    【安全】原实现会把 `~/Desktop`、`~/Downloads` 与当前工作目录
                    一并递归遍历。这有两个问题：
                      1. 越权访问用户个人目录（用户从未授权本程序读取桌面）；
                      2. 遍历结果最终会被交给 `os.startfile()` 打开——即
                         "在文件系统里找一个文件然后用 shell 打开它"，
                         这是典型的危险组合（可被诱导打开非预期文件）。
                    现仅搜索本程序自己管理的 `data/samples`（PCAP 持久化目录）。
                    """
                    if not filename:
                        return None
                    import os as _os

                    # 文件名必须是纯文件名（拒绝任何路径分隔符与上跳）
                    if _os.path.basename(filename) != filename or filename in (".", ".."):
                        logger.warning(f"拒绝搜索含路径成分的文件名: {filename!r}")
                        return None

                    try:
                        samples_dir = data_dir("samples")
                    except Exception as e:
                        logger.warning(f"定位 samples 目录失败，无法搜索 PCAP: {e}")
                        return None
                    if not _os.path.isdir(samples_dir):
                        return None

                    for root, dirs, files in _os.walk(samples_dir):
                        dirs[:] = [d for d in dirs
                                   if d not in ('.git', 'venv', 'node_modules', '__pycache__')]
                        for f in files:
                            if f.lower() == filename.lower():
                                return _os.path.join(root, f)
                    return None
                
                def _history_dropdown_choices():
                    """生成下拉框选项：值=记录ID，显示=时间 | 文件名 | 告警数"""
                    try:
                        hs = get_history_store().list_analysis()
                    except Exception:
                        hs = []
                    choices = []
                    for h in hs:
                        rid = h.get("id", "")
                        ts = _fmt_time(h.get("ts", ""))
                        fname = h.get("file", "?")
                        alerts = h.get("alerts", 0)
                        label = f"{ts} | {fname} | {alerts}条告警"
                        choices.append((label, str(rid)))
                    return choices
                
                history_select_dropdown = gr.Dropdown(
                    choices=_history_dropdown_choices(),
                    label=_("📌 选择要操作的记录（推荐：用下拉框精确选择，避免表格点击状态不同步）"),
                    interactive=True,
                    allow_custom_value=False
                )
                with gr.Row():
                    refresh_history_btn = gr.Button(_("🔄 刷新列表"))
                    load_history_btn = gr.Button(_("📂 加载到分析结果"), variant="primary")
                    open_report_btn = gr.Button(_("📄 打开选中记录的报告"), variant="primary")
                    clear_history_btn = gr.Button(_("🗑 清空全部历史"))
                
                # 重新分析确认区域（默认隐藏，按钮紧下方，更醒目）
                with gr.Row(visible=False) as regen_confirm_row:
                    regen_confirm_msg = gr.Markdown(
                        _("### ⚠️ 报告已删除，是否重新分析？\n\n"
                          "点击「✅ 确认重新分析」后，系统将在后台重新执行完整PCAP分析（含AI研判），\n"
                          "分3阶段显示进度，完成后自动打开报告。**此操作不影响Tab1的PCAP分析页面。**"),
                        scale=3)
                    with gr.Column(scale=1):
                        confirm_regen_btn = gr.Button(_("✅ 确认重新分析"), variant="primary")
                        cancel_regen_btn = gr.Button(_("❌ 取消"))
                
                # 重新分析进度显示（默认隐藏，确认区域下方）
                regen_progress = gr.Markdown("", visible=False)
                
                history_detail = gr.Markdown(value=_("点击表格任意一行查看记录详情"), label=_("记录详情（点击行后展示）"))
                history_feedback = gr.Markdown(
                    _("💡 **用法**：点击表格任意行 → 下方查看详情；\n"
                      "「加载到分析结果」= 把该次分析回填到上方 Tab1 结果区；\n"
                      "「打开报告」= 在浏览器打开该次 HTML 取证报告"))
                
                selected_history = gr.State(None)
                pending_regen_id = gr.State(None)  # 待重新分析的记录ID

                def refresh_history_ui():
                    return (gr.update(value=_history_table_value()), _history_count_text(),
                            "🔄 列表已刷新（下拉框选项已同步更新）",
                            gr.update(choices=_history_dropdown_choices()))
                
                def confirm_regen_report_ui(record_id):
                    """确认重新分析：后台执行完整PCAP分析，生成报告，更新历史记录，打开报告"""
                    if not record_id:
                        yield "⚠️ 没有待重新分析的记录", gr.update(visible=False), gr.update(value="", visible=False)
                        return
                    
                    # 从数据库获取记录
                    h = None
                    try:
                        all_records = get_history_store().list_analysis()
                        for r in all_records:
                            if str(r.get("id", "")) == str(record_id):
                                h = r
                                break
                    except Exception as e:
                        # 静默失败会让用户看到"未找到该记录"，而真实原因是读取异常 —— 会误导排查方向
                        logger.error(f"读取历史记录失败（记录 id={record_id}）: {e}")
                    
                    if not h:
                        yield "❌ 未找到该记录", gr.update(visible=False), gr.update(value="", visible=False)
                        return
                    
                    actual_id = h.get("id", record_id)
                    file_path = h.get("file_path", "")
                    fname = h.get("file", "unknown")
                    
                    # 如果 file_path 不存在或文件已删除，自动在常见目录搜索同名PCAP文件
                    if not file_path or not os.path.exists(file_path):
                        logger.info(f"记录 {actual_id} 的 file_path 不存在或无效: {file_path}，开始自动搜索...")
                        searched = _search_pcap_file(fname)
                        if searched:
                            file_path = searched
                            logger.info(f"自动搜索到PCAP文件: {file_path}")
                            # 更新历史记录中的 file_path
                            try:
                                get_history_store().update_analysis(record_id, {"file_path": file_path})
                            except Exception as e:
                                # 回写失败会导致下次仍需重新搜索，但不影响本次分析
                                logger.warning(f"回写 file_path 到历史记录失败（本次分析不受影响）: {e}")
                        else:
                            logger.warning(f"未找到PCAP文件: {fname}")
                    
                    if not file_path or not os.path.exists(file_path):
                        yield (f"❌ PCAP源文件不存在：`{file_path or '未保存路径'}`\n\n"
                               f"📋 记录文件名：`{fname}`\n"
                               f"🔍 已自动搜索：data/samples/、桌面、下载目录，均未找到\n\n"
                               f"💡 请切换到Tab1重新上传该PCAP文件进行分析",
                               gr.update(visible=False), gr.update(value="", visible=False))
                        return
                    
                    # 隐藏确认区域，显示进度
                    yield "", gr.update(visible=False), gr.update(value=f"🔄 正在后台重新分析 `{fname}`，请稍候...（阶段1/3：解析PCAP+特征提取+规则检测）", visible=True)
                    
                    try:
                        # 后台执行完整分析（复用底层同步函数）
                        import time as _t
                        t0 = _t.time()
                        result = _analyze_pcap_task(file_path, enable_ai=True, baseline_name="")
                        elapsed = _t.time() - t0
                        
                        yield "", gr.update(visible=False), gr.update(value=f"🔄 分析完成（耗时 {elapsed:.1f}秒），正在生成报告...（阶段2/3）", visible=True)
                        
                        html_path = result.get("report_html", "")
                        if not html_path:
                            yield "❌ 报告生成失败", gr.update(visible=False), gr.update(value="", visible=False)
                            return
                        
                        # 更新历史记录中的报告路径
                        try:
                            get_history_store().update_analysis(record_id, {"html_report": html_path})
                        except Exception as e:
                            # 回写失败会让历史记录里的报告路径与实际不符（打开旧报告）
                            logger.warning(
                                f"回写报告路径到历史记录失败（报告已生成，但历史记录可能仍指向旧路径）: {e}"
                            )
                        
                        yield "", gr.update(visible=False), gr.update(value=f"✅ 报告已生成，正在打开...（阶段3/3）", visible=True)
                        
                        # 打开报告（默认禁用，见 _open_path_with_shell 的安全说明）
                        _opened, _open_msg = _open_path_with_shell(html_path)
                        if not _opened:
                            logger.info(f"未自动打开报告：{_open_msg}")
                        
                        final_msg = (f"✅ **重新分析完成，报告{'已打开' if _opened else '已生成'}**\n"
                               f"📋 记录：{fname}\n"
                               f"📦 包数：{result.get('packet_count', 0)}\n"
                               f"⏱ 耗时：{elapsed:.1f}秒\n"
                               f"📂 报告：`{os.path.basename(html_path)}`\n"
                               + ("" if _opened else "     （自动打开失败，请手动打开上述文件）\n")
                               + f"\n💡 重新分析在后台执行，Tab1的PCAP分析页面不受影响")
                        yield "", gr.update(visible=False), gr.update(value=final_msg, visible=True)
                        
                    except Exception as e:
                        import traceback
                        logger.error(f"重新分析失败: {e}\n{traceback.format_exc()}")
                        err_msg = (f"❌ 重新分析失败：{type(e).__name__}: {e}\n\n"
                               f"💡 建议：切换到Tab1重新上传该PCAP文件进行分析")
                        yield "", gr.update(visible=False), gr.update(value=err_msg, visible=True)
                
                def cancel_regen_ui():
                    """取消重新分析"""
                    return "已取消重新分析", gr.update(visible=False), gr.update(value="", visible=False), None

                def on_history_row_click(evt: gr.SelectData):
                    """点击表格行 → 展示该记录详情 + 回填结果区 + 记录选中状态"""
                    idx = evt.index
                    row = idx[0] if isinstance(idx, (list, tuple)) else idx
                    try:
                        hs = get_history_store().list_analysis()
                    except Exception as e:
                        # 静默降级为空列表会让界面提示"记录已不存在或已被清空"，
                        # 而真实原因是存储读取异常 —— 会误导用户去清空历史。
                        logger.error(f"读取历史记录列表失败: {e}")
                        return (f"❌ 读取历史记录失败：{type(e).__name__}: {e}", "", "", "", None)
                    if row is None or not hs or row >= len(hs):
                        return ("⚠️ 记录已不存在或已被清空", "", "", "", None)
                    h = hs[row]
                    
                    # 【P1优化】用更友好的Markdown格式展示详情
                    file_name = h.get("file", "未知文件")
                    ts = h.get("ts", "未知时间")
                    alerts = h.get("alerts", 0)
                    status = h.get("status", "未知")
                    
                    # 格式化时间
                    from datetime import datetime
                    try:
                        if isinstance(ts, (int, float)):
                            ts_str = datetime.fromtimestamp(ts).strftime("%Y/%m/%d %H:%M")
                        else:
                            ts_str = str(ts)
                    except:
                        ts_str = str(ts)
                    
                    detail_md = f"""
### 📋 分析记录详情

| 字段 | 内容 |
|------|------|
| **文件名** | `{file_name}` |
| **分析时间** | {ts_str} |
| **告警数量** | {alerts} 条 |
| **分析状态** | {status} |

**💡 提示：** 点击下方「📂 加载到分析结果」按钮，可在Tab1查看完整的可视化分析结果。
"""
                    
                    raw_json = json.dumps(h.get("raw", {}), ensure_ascii=False, indent=2, default=str)
                    return (detail_md, h.get("summary_text", ""), h.get("ai_summary", ""),
                            raw_json, h)

                def load_history_ui(sel):
                    """将当前选中的历史记录回填到 Tab1 结果区（并在本 Tab 显示明确反馈）"""
                    h = sel
                    if not h:
                        return ("⚠️ 请先在表格中点击选择一条记录", "",
                                "", "", "", None)
                    detail = {k: v for k, v in h.items() if k not in ('summary_text', 'ai_summary', 'raw')}
                    # 将 dict 转换为 Markdown 表格格式（history_detail 是 Markdown 组件）
                    detail_md = "### 📋 记录详情\n\n"
                    detail_md += "| 字段 | 值 |\n|------|-----|\n"
                    for k, v in detail.items():
                        val_str = str(v) if v is not None else "—"
                        if len(val_str) > 80:
                            val_str = val_str[:77] + "..."
                        detail_md += f"| {k} | {val_str} |\n"
                    detail_md += "\n✅ **已回填到「PCAP流量分析」结果区**"
                    brief = (h.get("summary_text") or "").replace("\n", " ")[:60]
                    return (f"✅ **已回填到「🔍 PCAP流量分析」结果区**（请切换到第一个 Tab 查看）\n"
                            f"文件：`{h.get('file', '?')}` | 告警 {h.get('alerts', 0)} 条\n摘要：{brief}…",
                            detail_md, h.get("summary_text", ""), h.get("ai_summary", ""),
                            json.dumps(h.get("raw", {}), ensure_ascii=False, indent=2, default=str), h)

                def open_selected_report_ui(dropdown_val, sel):
                    """打开选中记录的报告；若报告文件不存在，显示确认区域询问用户是否重新分析"""
                    import traceback
                    
                    # 【P0修复】优先使用表格选中的记录（用户点击表格行的意图更明确）
                    # 只有当表格没有选中记录时，才回退到下拉框
                    record_id = None
                    h = None
                    
                    # 优先级1：表格点击选中的记录
                    if sel and isinstance(sel, dict) and len(sel) > 0 and sel.get("id"):
                        record_id = sel.get("id")
                        h = sel  # 直接用已有的记录对象，避免再次查询
                        logger.info(f"使用表格选中的记录ID: {record_id} (文件: {sel.get('file', '?')})")
                    # 优先级2：下拉框选择的记录
                    elif dropdown_val:
                        record_id = str(dropdown_val)
                        logger.info(f"使用下拉框选择的记录ID: {record_id}")
                    
                    # 严格的空值检查
                    if not record_id:
                        return ("⚠️ 请先选择一条记录：\n"
                                "✅ **推荐方式**：在上方下拉框中选择一条记录\n"
                                "或：点击表格中任意一行（行高亮）→ 再点「打开报告」",
                                gr.update(visible=False), gr.update(value="", visible=False), None)
                    
                    # 根据记录ID从数据库获取完整记录（如果h还没设置的话）
                    if h is None:
                        try:
                            all_records = get_history_store().list_analysis()
                            for r in all_records:
                                if str(r.get("id", "")) == str(record_id):
                                    h = r
                                    break
                        except Exception as db_err:
                            logger.warning(f"从数据库获取记录失败: {db_err}")
                        
                        # 如果数据库中找不到，使用传入的sel作为后备
                        if h is None:
                            if sel and isinstance(sel, dict):
                                h = sel
                            else:
                                return (f"⚠️ 未找到ID为 {record_id} 的记录，请刷新列表后重试",
                                        gr.update(visible=False), gr.update(value="", visible=False), None)
                            logger.info(f"数据库中未找到记录ID={record_id}，使用传入状态数据")
                    
                    rp = h.get("html_report")
                    raw = h.get("raw") or {}
                    fname = h.get("file", "unknown")
                    ts = h.get("ts", "unknown")
                    actual_id = h.get("id", record_id)
                    
                    logger.info(f"打开报告请求: id={actual_id}, file={fname}, ts={ts}, saved_report={rp}, exists={os.path.exists(rp) if rp else False}")
                    
                    # 如果报告路径不存在或文件已删除，显示确认区域询问用户是否重新分析
                    if not rp or not os.path.exists(rp):
                        file_path = h.get("file_path", "")
                        file_exists = os.path.exists(file_path) if file_path else False
                        if file_exists:
                            # 检查是否是项目内持久化的文件
                            is_persisted = "samples\\analyzed" in file_path or "samples/analyzed" in file_path
                            persist_tag = "✅ 已持久化" if is_persisted else "⚠️ 原始路径（建议重新分析后会自动持久化）"
                            confirm_msg = (f"⚠️ 该记录的报告文件已删除。\n\n"
                                           f"📋 记录：{fname} | {ts}\n"
                                           f"📂 PCAP文件：`{file_path}`\n"
                                           f"📦 状态：{persist_tag}\n\n"
                                           f"是否重新执行PCAP分析生成报告？\n"
                                           f"（重新分析在后台执行，分3阶段显示进度，完成后自动打开报告，不影响Tab1）")
                        else:
                            confirm_msg = (f"⚠️ 该记录的报告文件已删除，且PCAP源文件也找不到了。\n\n"
                                           f"📋 记录：{fname} | {ts}\n"
                                           f"📂 原PCAP路径：`{file_path or '未保存'}`\n\n"
                                           f"❌ 无法重新分析（源文件不存在）。\n"
                                           f"💡 建议：切换到Tab1重新上传该PCAP文件进行分析")
                        return (confirm_msg, gr.update(visible=True), gr.update(value="", visible=False), actual_id)
                    else:
                        # 报告存在，尝试打开（默认禁用，仅返回可复制路径）
                        logger.info(f"报告文件: {rp} (大小: {os.path.getsize(rp) if os.path.exists(rp) else 'N/A'} bytes)")
                        _ok, _msg = _open_path_with_shell(rp)
                        return (f"{_msg}\n"
                                f"📌 对应记录：{fname} | {ts}\n"
                                f"📂 报告路径：`{rp}`",
                                gr.update(visible=False), gr.update(value="", visible=False), None)

                def clear_history_ui():
                    n = get_history_store().clear_analysis()
                    return (gr.update(value=[]), "📊 当前 **0** 条分析记录",
                            f"🗑 已清空全部历史记录（{n} 条）", "", None,
                            gr.update(choices=[], value=None))

                history_table.select(on_history_row_click,
                                     outputs=[history_detail, summary_output, threat_output,
                                              raw_content_state, selected_history])
                refresh_history_btn.click(refresh_history_ui,
                                          outputs=[history_table, history_count, history_feedback,
                                                   history_select_dropdown])
                confirm_regen_btn.click(confirm_regen_report_ui, inputs=[pending_regen_id],
                                         outputs=[history_feedback, regen_confirm_row, regen_progress])
                cancel_regen_btn.click(cancel_regen_ui,
                                        outputs=[history_feedback, regen_confirm_row, regen_progress, pending_regen_id])
                load_history_btn.click(load_history_ui, inputs=[selected_history],
                                       outputs=[history_feedback, history_detail, summary_output,
                                                threat_output, raw_content_state, selected_history])
                open_report_btn.click(open_selected_report_ui, inputs=[history_select_dropdown, selected_history],
                                      outputs=[history_feedback, regen_confirm_row, regen_progress, pending_regen_id])
                clear_history_btn.click(clear_history_ui,
                                        outputs=[history_table, history_count, history_feedback,
                                                 history_detail, selected_history,
                                                 history_select_dropdown])
                demo.load(refresh_history_ui, outputs=[history_table, history_count, history_feedback,
                                                         history_select_dropdown])

                def open_report_dir_ui():
                    try:
                        d = data_dir("reports")
                        os.makedirs(d, exist_ok=True)
                        _ok, _msg = _open_path_with_shell(d)
                        return _msg
                    except Exception as e:
                        return f"❌ 打开失败: {e}"

                def open_report_file_ui():
                    """打开最新生成的报告文件（默认禁用自动打开，仅返回路径）"""
                    try:
                        d = data_dir("reports")
                        fs = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".html")] if os.path.isdir(d) else []
                        if not fs:
                            return "❌ 尚无报告文件，请先完成一次PCAP分析"
                        newest = max(fs, key=os.path.getmtime)
                        _ok, _msg = _open_path_with_shell(newest)
                        return _msg
                    except Exception as e:
                        return f"❌ 打开失败: {e}"

                tab1_open_report_dir_btn.click(open_report_dir_ui, outputs=process_output)
                tab1_open_report_btn.click(open_report_file_ui, outputs=process_output)
                
                def sync_raw_content(raw):
                    """内容State变化 → 同步到收起/展开两个Code组件（保持各自visible）"""
                    return gr.update(value=raw), gr.update(value=raw)

                raw_content_state.change(
                    sync_raw_content, inputs=[raw_content_state],
                    outputs=[raw_output, raw_output_full])

                def toggle_raw_output(expanded):
                    """切换完整报告框的展开/收起（只改visible，内容保留）"""
                    if expanded:
                        # 当前展开 → 收起
                        return (gr.update(visible=True), gr.update(visible=False),
                                "📖 展开完整报告", False)
                    else:
                        # 当前收起 → 展开
                        return (gr.update(visible=False), gr.update(visible=True),
                                "📕 收起报告", True)

                toggle_raw_btn.click(
                    toggle_raw_output,
                    inputs=[raw_expanded_state],
                    outputs=[raw_output, raw_output_full, toggle_raw_btn,
                             raw_expanded_state])

                report_download.click(on_report_download_click,
                                      inputs=[analysis_done, report_path_state],
                                      outputs=[report_download, report_feedback, download_progress,
                                               tab1_open_report_btn, tab1_open_report_dir_btn])

                # analyze_btn 事件注册（此处 history_dropdown 已定义）
                analyze_btn.click(
                    analyze_pcap_gradio,
                    inputs=[pcap_file, enable_ai, baseline_dropdown],
                    outputs=[process_output, summary_output, threat_output, raw_content_state,
                             report_download, history_table, baseline_chart_output,
                             analysis_done, report_path_state]
                )
                # 分析完成后刷新下拉框选项（通过一个隐藏的辅助按钮触发）
                def _refresh_dropdown_only():
                    return gr.update(choices=_history_dropdown_choices())

            # Tab 3: 安全问答（v1.4.0：流式输出 + 对话历史持久化 + RAG 检索依据展示）
            with gr.Tab(_tab("💬 安全知识问答")):
                gr.Markdown(_("基于MITRE ATT&CK知识库的安全问答助手 —— 回答逐字流式显示，对话自动保存（刷新不丢失）"))
                chatbot = gr.Chatbot(label=_("安全助手"))
                msg_input = gr.Textbox(label=_("输入问题"), placeholder=_("例如：什么是DNS隧道？如何检测端口扫描？"))
                with gr.Row():
                    send_btn = gr.Button(_("发送"), variant="primary")
                    clear_btn = gr.Button(_("清空对话"))

                def _norm_chat_history(history):
                    """兼容新旧 Chatbot 历史格式 → messages 格式"""
                    if not history:
                        return []
                    if isinstance(history, list) and history and isinstance(history[0], dict):
                        return [{"role": m.get("role", "user"), "content": m.get("content", "")}
                                for m in history if isinstance(m, dict)]
                    out = []
                    for item in history:
                        if isinstance(item, (list, tuple)) and len(item) >= 2:
                            out.append({"role": "user", "content": str(item[0])})
                            out.append({"role": "assistant", "content": str(item[1])})
                    return out

                def chat_response_stream(message, history):
                    """生成器：RAG 检索依据 → LLM 流式回答 → 持久化对话"""
                    if not message:
                        yield history
                        return
                    msgs = _norm_chat_history(history)
                    llm = get_llm_client()
                    if not llm.is_available():
                        msgs.append({"role": "user", "content": message})
                        msgs.append({"role": "assistant",
                                     "content": "⚠️ 未配置大模型API Key，请在「⚙️ 设置」中配置LLM_API_KEY"})
                        yield msgs
                        return

                    msgs.append({"role": "user", "content": message})
                    msgs.append({"role": "assistant", "content": "🔎 正在检索安全知识库..."})
                    yield msgs

                    threat_analyzer = get_threat_analyzer()
                    answer = ""
                    try:
                        for evt in threat_analyzer.chat_about_security_stream(message, chat_history=msgs[:-2]):
                            if evt["stage"] == "retrieval":
                                ev = evt.get("evidence") or []
                                if ev:
                                    ev_lines = "　".join(
                                        f"《{e['title']}》(相似度 "
                                        f"{e['similarity'] if e.get('similarity') is not None else '未知'})"
                                        for e in ev[:3])
                                    more = f"（另有 {len(ev)-3} 条）" if len(ev) > 3 else ""
                                    msgs[-1]["content"] = (
                                        f"🔎 知识库检索到 {len(ev)} 条依据：{ev_lines}{more}\n\n"
                                        f"✍️ 正在生成回答...")
                                else:
                                    msgs[-1]["content"] = "🔎 未检索到直接依据，将基于安全知识回答。\n\n✍️ 正在生成回答..."
                                yield msgs
                            else:
                                answer += evt["chunk"]
                                msgs[-1]["content"] = answer
                                yield msgs
                        try:
                            get_history_store().add_chat_round(message, answer)
                        except Exception as e:
                            logger.warning(f"对话历史保存失败: {e}")
                    except Exception as e:
                        logger.error(f"问答助手异常: {e}")
                        msgs[-1]["content"] = f"❌ 问答失败: {str(e)}"
                        yield msgs

                def clear_chat_ui():
                    try:
                        get_history_store().clear_chat()
                    except Exception as e:
                        # 静默失败会让界面清空，但数据库里对话仍在 —— 刷新后又出现，
                        # 用户会以为是"没清干净"的诡异 bug
                        logger.error(f"清空对话历史失败（界面已清空，但存储中的数据可能仍存在）: {e}")
                    return []

                def chat_and_clear(message, history):
                    """包装：问答生成 + 最后清空输入框"""
                    final_history = history
                    for result in chat_response_stream(message, history):
                        final_history = result
                        yield result, gr.update(value="")
                    # 最后再确保清空一次
                    yield final_history, gr.update(value="")

                send_btn.click(chat_and_clear, inputs=[msg_input, chatbot],
                               outputs=[chatbot, msg_input])
                msg_input.submit(chat_and_clear, inputs=[msg_input, chatbot],
                                 outputs=[chatbot, msg_input])
                clear_btn.click(clear_chat_ui, outputs=chatbot)
                # 页面加载时恢复历史对话
                demo.load(lambda: get_history_store().load_chat(), outputs=chatbot)

            # Tab 3: 知识库管理
            with gr.Tab(_tab("📚 知识库管理")):
                gr.Markdown(_("管理安全知识库（MITRE ATT&CK、处置手册、协议知识）"))
                # 第一行：两个操作按钮同高
                with gr.Row(equal_height=True):
                    init_btn = gr.Button(_("🔄 初始化/重建知识库"), variant="primary", size="lg")
                    import_btn = gr.Button(_("📥 导入到知识库"), variant="secondary", size="lg")
                # 第二行：文件上传（全宽）
                kb_file = gr.File(label=_("导入知识文档（.txt/.md/.json/.pdf/.docx）"), file_types=[".txt", ".md", ".json", ".pdf", ".docx"])
                # 第三行：两个结果内容框同高
                with gr.Row(equal_height=True):
                    stats_output = gr.Markdown(label=_("📊 知识库统计"), value=_("尚未初始化，请点击「初始化知识库」"))
                    import_output = gr.Markdown(label=_("📥 导入结果"), value=_("请选择文件后点击「导入到知识库」"))
                # 第四行：搜索
                with gr.Row():
                    search_input = gr.Textbox(label=_("搜索知识库"), placeholder=_("输入关键词搜索..."), scale=4)
                    search_btn = gr.Button(_("🔍 搜索"), scale=1)
                search_output = gr.Markdown(label=_("搜索结果"), value=_("输入关键词后点击搜索"))

                def _format_kb_stats(stats):
                    """将知识库统计字典格式化为友好的Markdown"""
                    if not stats or not isinstance(stats, dict):
                        return "暂无数据"
                    if "error" in stats:
                        return f"❌ **错误**: {stats['error']}"
                    
                    lines = []
                    lines.append("### 📊 知识库状态")
                    lines.append("")
                    
                    if "status" in stats:
                        lines.append(f"**状态**: {stats['status']}")
                    if "progress" in stats:
                        lines.append(f"**进度**: {stats['progress']}")
                    if "chunks" in stats:
                        lines.append(f"**文档块数**: {stats['chunks']}")
                    if "documents" in stats:
                        lines.append(f"**文档数**: {stats['documents']}")
                    if "items_count" in stats:
                        lines.append(f"**知识条目数**: {stats['items_count']}")
                    if "chunks_added" in stats:
                        lines.append(f"**新增块数**: {stats['chunks_added']}")
                    
                    return "\n".join(lines)

                def init_kb():
                    """生成器版：分阶段输出初始化进度，避免长时间无响应"""
                    try:
                        yield _format_kb_stats({"status": "正在清除旧知识库...", "progress": "10%"})
                        rag = get_rag_engine()
                        rag.clear()
                        yield _format_kb_stats({"status": "正在加载知识条目...", "progress": "30%"})
                        items = get_all_knowledge()
                        yield _format_kb_stats({"status": f"已加载 {len(items)} 条知识，正在向量化嵌入...", "progress": "50%", "items_count": len(items)})
                        count = rag.add_knowledge_base(items)
                        yield _format_kb_stats({"status": f"嵌入完成，共 {count} 个文档块，正在统计...", "progress": "90%", "chunks_added": count})
                        stats = rag.get_stats()
                        stats["status"] = "✅ 知识库初始化完成"
                        stats["progress"] = "100%"
                        yield _format_kb_stats(stats)
                    except Exception as e:
                        yield _format_kb_stats({"error": str(e), "status": "❌ 初始化失败"})

                def search_kb(query):
                    if not query:
                        return "请输入搜索关键词"
                    rag = get_rag_engine()
                    results = rag.search(query, top_k=5)
                    if not results:
                        return "暂无结果"
                    lines = [f"### 🔍 搜索结果（{len(results)}条）", ""]
                    for i, r in enumerate(results[:5], 1):
                        if isinstance(r, dict):
                            content = r.get("content", r.get("text", str(r)))[:200]
                            source = r.get("source", "未知来源")
                            lines.append(f"**{i}. {source}**")
                            lines.append(f"  > {content}...")
                            lines.append("")
                    return "\n".join(lines)

                def import_kb(file):
                    if not file:
                        return "请先选择文档"
                    try:
                        rag = get_rag_engine()
                        chunks = rag.add_file(file.name, source=f"user_import:{os.path.basename(file.name)}")
                        stats = rag.get_stats()
                        lines = ["### ✅ 导入成功", ""]
                        lines.append(f"**新增文档块**: {chunks}")
                        lines.append(f"**总文档块**: {stats.get('total_documents', 'N/A')}")
                        return "\n".join(lines)
                    except Exception as e:
                        return f"❌ **导入失败**: {str(e)}"

                init_btn.click(init_kb, outputs=stats_output)
                import_btn.click(import_kb, inputs=kb_file, outputs=import_output)
                search_btn.click(search_kb, inputs=search_input, outputs=search_output)

            # Tab 4: 基线管理
            with gr.Tab(_tab("📈 基线管理")):
                gr.Markdown(_("""
                **时序基线（EWMA 学习-检测两阶段）**
                上传一份**正常流量** pcap，系统学习该网络的"日常画像"（每时间窗的包数/字节/SYN/端口数中位数），
                之后分析可疑流量时可对照该基线，偏差超 σ 即告警。预置基线 `default`（学习自 normal.pcap）可直接使用。
                """))
                
                # === 已有基线列表（放在最前面，用户进入即可看到）===
                gr.Markdown(_("### 📋 已保存基线"))
                def _baseline_table_value():
                    rows = []
                    for b in _list_baselines():
                        rows.append([b["name"], b["packets_used"], b["window_sec"],
                                     b.get("sigma", 3.0), b["created_at"], b["file"]])
                    return rows

                baseline_table = gr.Dataframe(
                    value=_baseline_table_value(),
                    headers=[_("名称"), _("学习包数"), _("窗口(s)"), _("σ"), _("创建时间"), _("文件")],
                    label=_("已保存基线（点击行查看画像图表）"),
                    interactive=False)
                baseline_feedback = gr.Markdown(_("💡 点击表格任意一行查看该基线的画像图表"))
                
                # === 基线画像图表（紧跟表格，点击行立即可见）===
                with gr.Row():
                    baseline_profile_output = gr.JSON(label=_("选中基线画像数据"))
                    baseline_chart = gr.HTML(label=_("📊 基线画像图表（4维度中位数±MAD）"))
                
                # 页面加载时自动显示默认基线图表（如果有default基线）
                def _load_default_baseline_chart():
                    try:
                        for b in _list_baselines():
                            if b["name"] == "default":
                                chart = _build_baseline_profile_svg(b.get("profile"), "default")
                                if chart:
                                    return b["profile"], "✅ 已加载默认基线「default」画像图表，点击其他行可切换", b, chart
                        # 没有default基线，显示第一个
                        bl = _list_baselines()
                        if bl:
                            b = bl[0]
                            chart = _build_baseline_profile_svg(b.get("profile"), b["name"])
                            if chart:
                                return b["profile"], f"✅ 已加载基线「{b['name']}」画像图表", b, chart
                    except Exception as e:
                        # 静默失败会显示"暂无基线"，而真实原因可能是基线损坏或渲染异常
                        logger.warning(f"加载默认基线画像图表失败（界面将显示为「暂无基线」）: {e}")
                    return {}, "💡 暂无基线，下方学习一份即可看到图表示例", None, ""
                
                baseline_selected = gr.State(None)
                
                # === 学习新基线 ===
                gr.Markdown(_("### 🧠 学习新基线"))
                with gr.Row():
                    baseline_file = gr.File(label=_("上传正常流量PCAP"), file_types=[".pcap", ".pcapng", ".cap"])
                    baseline_name_input = gr.Textbox(label=_("基线名称"), value="my-network",
                                                     placeholder=_("如: office-network"))
                learn_btn = gr.Button(_("🧠 一键学习基线"), variant="primary")
                learn_feedback = gr.Markdown(_("💡 上传正常流量 pcap → 命名 → 点「一键学习」→ 结果与列表即时刷新"))
                learn_output = gr.JSON(label=_("学习结果（基线画像）"))
                
                # === 操作按钮 ===
                with gr.Row():
                    refresh_baseline_btn = gr.Button(_("🔄 刷新列表"))
                    delete_baseline_btn = gr.Button(_("🗑 删除选中基线"), variant="stop")

                def learn_baseline_ui(file, name):
                    if not file:
                        return "❌ 请先上传正常流量PCAP", None, gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names())
                    try:
                        import time as _t
                        t0 = _t.time()
                        parser = PcapParser()
                        packets = parser.parse_file(file.name)
                        if not packets:
                            return "❌ PCAP解析失败或为空，无法学习基线", None, gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names())
                        name = (name or "default").strip()
                        # 名称校验必须早于落盘（baseline.save 会先写 JSON 文件）
                        try:
                            name = validate_baseline_name(name)
                        except ValueError as name_err:
                            return f"❌ {name_err}", None, gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names())
                        baseline = TrafficBaseline()
                        baseline.name = name
                        baseline.learn(packets)
                        save_path = _baseline_path(name)
                        ensure_dir(BASELINE_DIR)
                        ok = baseline.save(save_path)
                        if not ok:
                            return f"❌ 基线保存失败：{name}", None, gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names())
                        # 关键修复：同步保存到SQLite数据库（_list_baselines从数据库读取）
                        try:
                            from src.storage.database import Database
                            db = Database()
                            db.save_baseline(
                                name=name,
                                profile=baseline.to_dict().get("profile", {}),
                                window_sec=baseline.window_sec,
                                total_packets=len(packets),
                            )
                        except Exception as db_err:
                            logger.warning(f"基线保存到数据库失败: {db_err}")
                        secs = _t.time() - t0
                        msg = (f"✅ 基线「{name}」学习完成：{len(packets)} 包 / 窗口 {baseline.window_sec}s / σ={baseline.sigma} / 耗时 {secs:.1f}s\n"
                               f"📌 已保存到数据库和JSON文件，列表已自动刷新，点击上方表格行查看画像图表")
                        return msg, baseline.to_dict(), gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names())
                    except Exception as e:
                        return f"❌ 学习失败：{e}", None, gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names())

                def on_baseline_row_click(evt: gr.SelectData):
                    rows = _baseline_table_value()
                    idx = evt.index[0]
                    if idx is None or idx < 0 or idx >= len(rows):
                        return {}, "⚠️ 未选中有效行", None, None
                    name = rows[idx][0]
                    for b in _list_baselines():
                        if b["name"] == name:
                            chart = _build_baseline_profile_svg(b.get("profile"), name)
                            return b["profile"], f"📌 已选中基线：`{name}`（Tab1 分析时可选用）", b, chart
                    return {}, f"⚠️ 基线不存在：{name}", None, None

                def delete_baseline_ui(sel):
                    name = (sel or {}).get("name") if isinstance(sel, dict) else None
                    if not name:
                        return "⚠️ 请先在表格中点击选择一条基线（行高亮后再点删除）", gr.update(value=_baseline_table_value(), interactive=False), gr.update(choices=_baseline_names()), {}, ""
                    # 同时删除JSON文件和SQLite数据库记录
                    path = _baseline_path(name)
                    deleted_file = False
                    if os.path.exists(path):
                        os.remove(path)
                        deleted_file = True
                    try:
                        from src.storage.database import Database
                        db = Database()
                        db.delete_baseline(name)
                    except Exception as db_err:
                        logger.warning(f"从数据库删除基线失败: {db_err}")
                    tip = ""
                    if name == "default":
                        tip = "\n⚠️ 已删除内置基线 default——Tab1 分析若仍选 default 将跳过基线对照，建议重新学习一份。"
                    file_msg = "JSON文件" if deleted_file else "（JSON文件不存在，仅删除数据库记录）"
                    # 【P0修复】强制刷新表格和下拉框
                    rows = _baseline_table_value()
                    choices = _baseline_names()
                    return (f"🗑 已删除基线「{name}」{file_msg}，Tab1 下拉框同步移除。{tip}\n"
                            f"💡 画像图表和详情已清空\n"
                            f"📊 当前剩余 {len(rows)} 条基线",
                            gr.update(value=rows, interactive=False),  # 强制刷新表格
                            gr.update(choices=choices),  # 强制刷新下拉框
                            {}, "")  # 清空baseline_profile_output和baseline_chart

                def refresh_baselines_ui():
                    # 强制重新从数据库读取（不使用缓存）
                    db_ok = True
                    try:
                        from src.storage.database import Database
                        db = Database()
                        # 触发一次查询，确保连接是新的
                        db.list_baselines()
                    except Exception as e:
                        # 静默失败会让界面声称"数据来源：SQLite数据库"，实际可能是旧数据
                        db_ok = False
                        logger.warning(f"刷新时连接 SQLite 失败，列表可能不是最新数据: {e}")
                    rows = _baseline_table_value()
                    src = "SQLite数据库" if db_ok else "本地缓存（数据库读取失败）"
                    return gr.update(value=rows), f"🔄 列表已刷新（{len(rows)} 条基线）—— 数据来源：{src}"

                learn_btn.click(learn_baseline_ui, inputs=[baseline_file, baseline_name_input],
                                outputs=[learn_feedback, learn_output, baseline_table, baseline_dropdown])
                refresh_baseline_btn.click(refresh_baselines_ui, outputs=[baseline_table, baseline_feedback])
                delete_baseline_btn.click(delete_baseline_ui, inputs=baseline_selected,
                                          outputs=[baseline_feedback, baseline_table, baseline_dropdown,
                                                   baseline_profile_output, baseline_chart])
                baseline_table.select(on_baseline_row_click,
                                      outputs=[baseline_profile_output, baseline_feedback,
                                               baseline_selected, baseline_chart])
                # 页面加载时自动显示默认基线图表
                demo.load(_load_default_baseline_chart,
                          outputs=[baseline_profile_output, baseline_feedback, baseline_selected, baseline_chart])

            with gr.Tab(_tab("⚙️ 设置")):
                # 从服务端配置加载语言偏好
                _default_lang = "zh"
                try:
                    _config_path = os.path.join(data_dir("config"), "ui_settings.json")
                    if os.path.exists(_config_path):
                        # 使用 utf-8-sig 兼容带 BOM 的文件（PowerShell Out-File 会添加 BOM）
                        with open(_config_path, encoding="utf-8-sig") as _f:
                            _ui_settings = json.load(_f)
                            _default_lang = _ui_settings.get("language", "zh")
                        # 同步设置 LLM 输出语言
                        from src.ai.llm_client import LLMClient
                        LLMClient.set_language(_default_lang)
                except Exception as _e:
                    logger.warning(f"加载语言偏好失败，使用默认中文: {_e}")

                # 语言选择器（i18n）
                with gr.Row():
                    language_selector = gr.Dropdown(
                        choices=[(_("简体中文"), "zh"), (_("English"), "en")],
                        value=_default_lang,
                        label=_("🌐 界面语言 / Interface Language"),
                        info=_("选择后立即生效，偏好将自动保存")
                    )
                gr.Markdown("---")
                gr.Markdown(_("""
                **大模型 API 配置** —— 用于 AI 威胁研判与安全问答，保存后立即生效
                支持服务商：智谱 / DeepSeek / 通义千问 / 硅基流动 / Ollama（任选其一）
                """))
                with gr.Row():
                    api_key_input = gr.Textbox(label=_("🔑 API Key"), type="password",
                                               placeholder="sk-...")
                    api_url_input = gr.Textbox(label=_("🔗 API 地址 (Base URL)"),
                                               placeholder="https://open.bigmodel.cn/api/paas/v4")
                    api_model_input = gr.Textbox(label=_("🧠 模型名称"),
                                                 placeholder="glm-4-flash")
                save_btn = gr.Button(_("💾 保存配置"), variant="primary")
                api_status = gr.Markdown(_("点击保存后立即生效，无需重启"))
                kb_paths_md = gr.Markdown("")

                def load_api_config_ui():
                    """读取当前配置用于预填。

                    【安全】**绝不回显真实 API Key**。此前该函数把 `.env` 里的明文
                    Key 直接返回并填入密码框，而它由 `demo.load(...)` 在**每次页面
                    加载**时调用——等于把密钥反复推送到浏览器（任何能加载页面的人
                    都能从网络响应里读到它）。

                    现改为：Key 输入框保持为空，仅通过 placeholder 提示"已配置"。
                    用户只有在想更换时才需重新输入。
                    """
                    vals = {"LLM_BASE_URL": "", "LLM_MODEL": ""}
                    try:
                        env = find_env_file()
                        if os.path.exists(env):
                            with open(env, encoding="utf-8") as f:
                                for line in f:
                                    st = line.strip()
                                    if st and not st.startswith("#") and "=" in st:
                                        k, v = st.split("=", 1)
                                        if k.strip() in vals and v.strip():
                                            vals[k.strip()] = v.strip()
                    except Exception as e:
                        logger.debug(f"读取 .env 失败（不影响预填基础 URL/模型）: {e}")

                    # 已配置的 Key 只以掩码形式提示，不回传明文
                    key_display = ""
                    try:
                        current = settings.llm_api_key or ""
                        if current and "xxxx" not in current:
                            key_display = (current[:4] + "…" + current[-4:]) \
                                if len(current) > 10 else "已配置"
                    except Exception:
                        pass
                    return key_display, vals["LLM_BASE_URL"], vals["LLM_MODEL"]

                def save_api_config_ui(key, url, model):
                    """保存 API 配置：Windows 仅写 DPAPI；其他平台写 .env 并明确告知未加密。

                    【安全】此前无论 DPAPI 是否可用，都会把**明文 Key 再写一份到
                    `.env`**，使加密存储沦为冗余副本（两者同目录、同 ACL）。
                    现改为：
                      · Windows：Key 只进 DPAPI；`.env` 中不再保留明文 Key；
                      · 其他平台（Docker/Linux 无 DPAPI）：写 `.env` 但明确提示未加密。
                    """
                    if not key:
                        return "⚠️ API Key 不能为空"
                    if "xxxx" in key:
                        return "⚠️ API Key 仍是占位符（sk-xxxx），请填写真实 Key"
                    try:
                        import sys as _sys

                        key_val = key.strip()
                        url_val = url.strip()
                        model_val = model.strip()
                        dpapi_ok = False
                        secure_msg = ""

                        # 1) Windows：DPAPI 加密存储（唯一持有明文 Key 的地方）
                        if _sys.platform == "win32":
                            try:
                                from src.security.secure_store import get_secure_store
                                ss = get_secure_store()
                                ss.set("LLM_API_KEY", key_val)
                                ss.set("LLM_BASE_URL", url_val)
                                ss.set("LLM_MODEL", model_val)
                                dpapi_ok = bool(ss.is_encrypted("LLM_API_KEY"))
                                secure_msg = ("🔒 Key 已加密存储（DPAPI），未写入 .env 明文\n"
                                              if dpapi_ok else
                                              "⚠️ DPAPI 加密失败，Key 未能安全保存\n")
                            except Exception as se:
                                secure_msg = f"⚠️ DPAPI 加密存储失败: {se}\n"

                        # 2) 非 Windows 或 DPAPI 不可用：写 .env（并明确告知未加密）
                        env = find_env_file()
                        write_env_key = (not dpapi_ok)
                        new_entries = {
                            "LLM_BASE_URL": url_val,
                            "LLM_MODEL": model_val,
                        }
                        if write_env_key:
                            new_entries["LLM_API_KEY"] = key_val

                        lines = []
                        if os.path.exists(env):
                            with open(env, encoding="utf-8") as f:
                                lines = f.readlines()

                        if write_env_key:
                            for i, line in enumerate(lines):
                                st = line.strip()
                                if st and not st.startswith("#") and "=" in st:
                                    k = st.split("=", 1)[0].strip()
                                    if k in new_entries:
                                        lines[i] = f"{k}={new_entries[k]}\n"
                        else:
                            # 已由 DPAPI 保存：把 .env 中的明文 Key 清除，避免明文残留
                            kept = []
                            for line in lines:
                                st = line.strip()
                                if st and not st.startswith("#") and "=" in st \
                                        and st.split("=", 1)[0].strip() == "LLM_API_KEY":
                                    kept.append("# LLM_API_KEY 已迁移到 DPAPI 加密存储"
                                                "（本行留空以避免明文泄露）\n")
                                    continue
                                kept.append(line)
                            lines = kept
                            for i, line in enumerate(lines):
                                st = line.strip()
                                if st and not st.startswith("#") and "=" in st:
                                    k = st.split("=", 1)[0].strip()
                                    if k in new_entries:
                                        lines[i] = f"{k}={new_entries[k]}\n"

                        present = set()
                        for line in lines:
                            st = line.strip()
                            if st and not st.startswith("#") and "=" in st:
                                present.add(st.split("=", 1)[0].strip())
                        for k, v in new_entries.items():
                            if k not in present:
                                lines.append(f"{k}={v}\n")
                        with open(env, "w", encoding="utf-8") as f:
                            f.writelines(lines)

                        env_msg = ("📄 .env：已写入 Base URL / 模型"
                                   + ("（Key 未入明文）" if not write_env_key
                                      else "；⚠️ 当前平台无 DPAPI，Key 以明文保存，请自行保护该文件"))
                        if not write_env_key:
                            env_msg += f"\n📂 配置文件: {env}"

                        # 3) 热生效
                        try:
                            from src.ai.llm_client import reset_llm_client
                            reset_llm_client()
                            settings.llm_api_key = key_val
                            settings.llm_base_url = url_val
                            settings.llm_model = model_val
                            return (f"✅ 已保存并生效\n{secure_msg}{env_msg}\n\n"
                                    f"服务商: {url_val}\n模型: {model_val}")
                        except Exception as e:
                            logger.error(f"⚠️ 配置已保存，但热生效失败（需重启应用）: {e}")
                            return (f"⚠️ 配置已保存，但热生效失败（需重启应用）\n"
                                    f"{secure_msg}{env_msg}\n\n错误: {e}")
                    except Exception as e:
                        return f"❌ 保存失败: {e}"

                def load_kb_paths_ui():
                    """显示 RAG 知识库存储路径（ChromaDB 向量库 + 知识源文档）"""
                    try:
                        from src.utils.paths import data_dir
                        chroma = data_dir("chroma_db")
                        kb_docs = data_dir("knowledge", "docs")
                        exists = os.path.isdir(chroma) and os.listdir(chroma)
                        # 根据当前语言选择文本
                        _lang = _i18n.current_lang if I18N_AVAILABLE and _i18n else "zh"
                        if _lang == "en":
                            state = "✅ Ready" if exists else "⚠️ Not initialized (go to 📚 Knowledge Base to init/rebuild)"
                            title = "### 📚 RAG Knowledge Base Paths"
                            vec_label = "**Vector DB (ChromaDB)**"
                            doc_label = "**Source Docs Directory**"
                            chunk_label = "**Document Chunks**"
                            status_label = "**Status**"
                            engine_note = "(engine not loaded)"
                        else:
                            state = "✅ 已就绪" if exists else "⚠️ 尚未初始化（可到「📚 知识库管理」初始化/重建）"
                            title = "### 📚 RAG 知识库路径"
                            vec_label = "**向量库目录（ChromaDB）**"
                            doc_label = "**知识源文档目录**"
                            chunk_label = "**文档块数**"
                            status_label = "**状态**"
                            engine_note = "（引擎未加载）"
                        try:
                            from src.ai.rag_engine import get_rag_engine
                            stats = get_rag_engine().get_stats()
                            chunks = stats.get("chunks") or stats.get("total_documents") or stats.get("documents") or "?"
                            lines = [title, "",
                                     f"- {vec_label}: `{chroma}`",
                                     f"- {doc_label}: `{kb_docs}`",
                                     f"- {chunk_label}: {chunks}",
                                     f"- {status_label}: {state}"]
                        except Exception:
                            lines = [title, "",
                                     f"- {vec_label}: `{chroma}`",
                                     f"- {doc_label}: `{kb_docs}`",
                                     f"- {status_label}: {state}{engine_note}"]
                        return "\n".join(lines)
                    except Exception as e:
                        return f"### 📚 RAG 知识库路径\n- ❌ 读取失败: {e}"

                def load_all_settings_ui():
                    k, u, m = load_api_config_ui()
                    return k, u, m, load_kb_paths_ui()

                demo.load(load_all_settings_ui,
                          outputs=[api_key_input, api_url_input, api_model_input, kb_paths_md])
                save_btn.click(save_api_config_ui,
                               inputs=[api_key_input, api_url_input, api_model_input],
                               outputs=api_status)

                # i18n：语言切换事件处理（LLM语言同步 + 服务端持久化）
                # 注意：不使用 language_selector.change 直接绑定，避免与 gradio-i18n 的事件冲突
                # gradio-i18n 通过 translate_blocks 内部注册 lang.change 事件处理UI文本切换
                # 这里使用 gr.on 额外监听语言变化，用于副作用（LLM同步 + 持久化），不返回输出
                def on_language_change(lang):
                    """语言切换副作用：更新 LLM 输出语言 + 保存到服务端配置"""
                    try:
                        from src.ai.llm_client import LLMClient
                        LLMClient.set_language(lang)
                    except Exception as e:
                        logger.warning(f"设置 LLM 语言失败: {e}")

                    try:
                        config_dir = data_dir("config")
                        os.makedirs(config_dir, exist_ok=True)
                        config_path = os.path.join(config_dir, "ui_settings.json")
                        settings_data = {}
                        if os.path.exists(config_path):
                            with open(config_path, encoding="utf-8") as f:
                                settings_data = json.load(f)
                        settings_data["language"] = lang
                        with open(config_path, "w", encoding="utf-8") as f:
                            json.dump(settings_data, f, ensure_ascii=False, indent=2)
                    except Exception as e:
                        logger.warning(f"保存语言偏好失败: {e}")

                    lang_name = "简体中文" if lang == "zh" else "English"
                    logger.info(f"语言切换为: {lang_name}")

        gr.Markdown("""
        ---
        💡 **使用提示**：
        1. 首次使用请先在「知识库管理」中初始化知识库
        2. 建议在「📈 基线管理」中用正常流量学习一份时序基线，分析时对照检测效果更佳
        3. 确保已在 `.env` 文件中配置 `LLM_API_KEY`（推荐DeepSeek/智谱）
        4. PCAP文件可用Wireshark抓包后导出
        """)

        # i18n 国际化：自动注册组件 + 语言切换事件
        if I18N_AVAILABLE and _i18n is not None:
            try:
                # 自动扫描所有组件，注册那些属性值在翻译字典中的组件
                _registered = 0
                _tab_count = 0
                _debug_info = []
                for _comp_id, _component in demo.blocks.items():
                    _comp_type = type(_component).__name__
                    # 跳过 Tab 组件（创建时已通过 _tab() 使用翻译文本，且无法通过事件更新 label）
                    if _comp_type == "Tab":
                        _tab_count += 1
                        continue
                    # 语言选择器：只注册 info（不注册 value 避免循环更新）
                    if _component is language_selector:
                        _info_val = getattr(_component, "info", None)
                        if _info_val and isinstance(_info_val, str) and _i18n.translations.get("en", {}).get(_info_val):
                            _i18n.register(_component, "info", _info_val)
                            _registered += 1
                        continue
                    # 检查常见文本字段（支持一个组件注册多个字段，如 label + info）
                    for _field in ["value", "label", "info", "placeholder"]:
                        _val = getattr(_component, _field, None)
                        if _val and isinstance(_val, str) and _i18n.translations.get("en", {}).get(_val):
                            _i18n.register(_component, _field, _val)
                            _registered += 1
                    # 调试：记录有 info 但未注册的 Dropdown
                    if _comp_type == "Dropdown":
                        _info_val = getattr(_component, "info", None)
                        if _info_val and isinstance(_info_val, str):
                            _has_trans = _info_val in _i18n.translations.get("en", {})
                            _debug_info.append(f"Dropdown info='{_info_val[:30]}...' trans={'Y' if _has_trans else 'N'}")
                    # 特殊处理 Dropdown 的 choices
                    _choices = getattr(_component, "choices", None)
                    if _choices and isinstance(_choices, list):
                        for _choice in _choices:
                            if isinstance(_choice, tuple) and len(_choice) == 2:
                                _display, _v = _choice
                                if isinstance(_display, str) and _i18n.translations.get("en", {}).get(_display):
                                    _i18n.register(_component, "choices", _display)
                                    _registered += 1
                                    break
                logger.info(f"i18n 自动注册完成: {_registered} 个组件 (Tab: {_tab_count})")
                for _d in _debug_info:
                    logger.debug(f"i18n 调试: {_d}")

                # 语言切换事件：批量更新所有注册组件 + LLM同步 + 持久化
                def _on_switch_language(lang):
                    # 更新当前语言（关键：确保刷新后初始加载使用新语言）
                    _i18n.current_lang = lang
                    # 更新 LLM 输出语言
                    try:
                        from src.ai.llm_client import LLMClient
                        LLMClient.set_language(lang)
                    except Exception as _e:
                        logger.warning(f"设置 LLM 语言失败: {_e}")
                    # 保存到服务端配置
                    _cfg_path = os.path.join(data_dir("config"), "ui_settings.json")
                    _i18n.save_preference(lang, _cfg_path)
                    # 返回所有注册组件的更新
                    return _i18n.get_updates(lang)

                language_selector.change(
                    _on_switch_language,
                    inputs=[language_selector],
                    outputs=_i18n.get_component_outputs(),
                )
                logger.info(f"i18n 语言切换事件已注册，输出 {len(_i18n.get_component_outputs())} 个组件")

                # 初始加载时触发一次语言切换（确保默认语言生效）
                def _on_initial_load():
                    return _i18n.get_updates(_i18n.current_lang)

                demo.load(
                    _on_initial_load,
                    inputs=[],
                    outputs=_i18n.get_component_outputs(),
                )
                logger.info(f"i18n 初始加载事件已注册，默认语言: {_default_lang}")
            except Exception as e:
                logger.warning(f"i18n 初始化失败（不影响主功能）: {e}")
                import traceback
                logger.warning(traceback.format_exc())

    return demo


# 集成Gradio到FastAPI
if GRADIO_AVAILABLE:
    try:
        gradio_app = create_gradio_interface()
        try:
            gradio_app.queue()
        except Exception as e:
            # 排队失败会导致并发行为退化（默认单并发），必须可见
            logger.warning(f"Gradio queue() 启用失败，并发处理可能退化为串行: {e}")
        _mount_kwargs = _UI_KWARGS if _GRADIO_MAJOR >= 6 else {}

        # 【安全】此前把 data/reports、data/uploads、data/history 放进
        # `allowed_paths`：Gradio 的 `/gradio_api/file=<绝对路径>` 会直接把这些
        # 目录下的文件**无鉴权**送出（报告含源/目的 IP、载荷、证据哈希与 AI 研判）。
        # 现由 Gradio 自身的缓存目录机制承担上传文件服务（上传时 Gradio 会把文件
        # 复制到 tempfile 下的 gradio 缓存），这三个业务目录不再对外暴露。
        #
        # 代价：报告下载需走会话内路径（已改为 report_path_state）而非任意路径读取，
        # 这正是我们想要的行为——文件服务必须受控，不能靠目录白名单。
        logger.info("Gradio allowed_paths 未暴露业务数据目录（reports/uploads/history 不对外服务）")

        # 全 app 鉴权：回环访问免 token（桌面版/本机浏览器），非回环强制 token。
        # 仅守 /api/* 是不够的——UI 回调（如打开文件、写配置）同样具备副作用。
        _mount_kwargs["auth_dependency"] = _require_token_for_external_access

        app = gr.mount_gradio_app(app, gradio_app, path="/", **_mount_kwargs)
        logger.info("Gradio Web UI 已挂载到 /（已启用全 app 鉴权：非回环访问需 X-API-Token）")
    except Exception as e:
        # 【重要】此前这里只记 warning 并提示"不影响API使用"，但实际上
        # create_gradio_interface() 失败会让应用变成 0 路由 0 UI 的空壳
        # （/ 与 /api/health 全部 404），却让日志读起来像"一切正常"。
        # 现改为 error 级别并明确说明实际后果。
        logger.error(
            f"❌ Gradio UI 挂载失败，应用将以「无界面」状态启动："
            f"/ 与所有界面功能不可用，仅 /api/* 路由可访问。原因: {e}"
        )
else:
    logger.info("gradio 未安装，仅启动API服务（可通过 /docs 查看API文档）")


def main():
    """启动服务。

    绑定地址取自 `HOST` 环境变量，**默认 127.0.0.1**：
      · 本机/桌面场景：默认回环，局域网无法访问（安全默认）；
      · 容器/服务器场景：Dockerfile 设置 HOST=0.0.0.0 才会对外监听——
        此时必须同时配置 API_AUTH_TOKEN，否则非回环请求会被鉴权层拒绝（fail closed）。

    此前该函数硬编码 host="127.0.0.1"，导致 Docker 的 HOST=0.0.0.0 从未生效，
    容器端口映射实际无法访问。
    """
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "127.0.0.1").strip() or "127.0.0.1"
    if host not in ("127.0.0.1", "localhost", "::1") and not settings.api_auth_token:
        logger.error(
            f"⚠️ 服务将对外监听（HOST={host}）但未配置 API_AUTH_TOKEN。"
            f"非回环请求会被拒绝；请设置 API_AUTH_TOKEN 后再对外提供服务。"
        )
    logger.info(f"启动服务: http://{host}:{port}")
    logger.info(f"API文档: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()





