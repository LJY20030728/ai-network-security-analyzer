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

# 确保项目根目录在path中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings, find_env_file
from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer
from src.analysis.baseline import TrafficBaseline
from src.ai.llm_client import get_llm_client
from src.ai.rag_engine import get_rag_engine
from src.ai.threat_analyzer import get_threat_analyzer
from src.knowledge.mitre_attck import get_all_knowledge
from src.report.html_report import save_html_report
from src.utils.helpers import setup_logging, ensure_dir, format_bytes, get_timestamp_str
from src.utils.paths import data_dir, seed_assets
from src.api.audit import AuditLogger
from src.api.history_store import get_history_store
from src.api.task_queue import get_task_queue

# 初始化日志
setup_logging(settings.log_level)

# 首次启动种子数据迁移（打包版：把内置预置基线复制到数据目录）
seed_assets()

# 创建FastAPI应用
app = FastAPI(
    title=settings.project_name,
    description="基于流行为检测与LLM辅助研判的网络异常分析系统",
    version="1.2.0"
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
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            lines = []
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
                except Exception:  # noqa: BLE001
                    pass
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
            except Exception:  # noqa: BLE001
                pass
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
        "version": "2.0.0",
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

        # 仅允许文本类型
        filename = file.filename or "doc.txt"
        ext = os.path.splitext(filename)[1].lower()
        if ext not in (".txt", ".md", ".markdown", ".json"):
            raise HTTPException(status_code=400, detail=f"不支持的文件类型 {ext}，仅支持 .txt/.md/.json")

        tmp_path = os.path.join(data_dir("knowledge"), f"import_{get_timestamp_str()}_{os.path.basename(filename)}")
        ensure_dir(os.path.dirname(tmp_path))
        with open(tmp_path, "wb") as f:
            f.write(content)

        def _add_task():
            rag = get_rag_engine()
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
    """基线文件名安全化 + 路径"""
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_.").strip()
    if not safe:
        safe = "baseline"
    return os.path.join(BASELINE_DIR, f"{safe}.json")


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
                    db.save_baseline(
                        name=b.name or os.path.splitext(fn)[0],
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



def _build_baseline_compare_svg(window_series, baseline_profile):
    """流量每窗口包数 vs 基线中位数 对比图（纯 SVG，零依赖）"""
    if not window_series:
        return None
    try:
        n = len(window_series)
        if n == 0:
            return None
        median = None
        win_sec = 10
        if isinstance(baseline_profile, dict):
            prof = baseline_profile.get("profile") or {}
            w = prof.get("window_packets") or {}
            if isinstance(w, dict) and w.get("median"):
                median = float(w["median"])
            win_sec = int(baseline_profile.get("window_sec", 10) or 10)
        values = [float(x.get("packets", 0)) for x in window_series]
        vmax = max(max(values), median or 0, 1) * 1.15
        W, H, P = 760, 220, 38
        iw, ih = W - 2 * P, H - 2 * P
        def _xy(i, v):
            x = P + (iw * i / max(n - 1, 1))
            y = P + ih - (ih * v / vmax)
            return x, y
        pts = " ".join(f"{_xy(i, v)[0]:.1f},{_xy(i, v)[1]:.1f}" for i, v in enumerate(values))
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" style="font-family:Segoe UI,Arial,sans-serif;background:linear-gradient(180deg,#f8faff,#eef4ff);border-radius:12px;border:1px solid #dbe6ff">']
        for g in range(5):
            gy = P + ih * g / 4
            svg.append(f'<line x1="{P}" y1="{gy:.1f}" x2="{W-P}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        if median:
            my = P + ih - (ih * median / vmax)
            svg.append(f'<line x1="{P}" y1="{my:.1f}" x2="{W-P}" y2="{my:.1f}" stroke="#ef4444" stroke-width="2" stroke-dasharray="6,4"/>')
            svg.append(f'<text x="{W-P-8}" y="{my-7:.1f}" text-anchor="end" font-size="11" fill="#ef4444">基线中位数 {median:.0f} 包/窗</text>')
        svg.append(f'<polyline points="{pts}" fill="none" stroke="#2563eb" stroke-width="2.4" stroke-linejoin="round"/>')
        for i, v in enumerate(values):
            x, y = _xy(i, v)
            svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#2563eb"/>')
        svg.append(f'<text x="{P}" y="{H-8}" font-size="11" fill="#64748b">窗口序号（每 {win_sec} 秒一个窗口，共 {n} 个）</text>')
        svg.append(f'<text x="{P}" y="{P-12}" font-size="11" fill="#64748b">每窗口包数</text>')
        svg.append(f'<text x="{W-P}" y="{P-12}" text-anchor="end" font-size="12" fill="#2563eb">当前流量</text>')
        svg.append('</svg>')
        return "".join(svg)
    except Exception:
        return None

def _build_baseline_profile_svg(profile, name):
    """基线画像（各维度 中位数±MAD）条形图（纯 SVG）"""
    if not isinstance(profile, dict) or not profile:
        return None
    try:
        dims = [("window_packets", "每窗包数"), ("window_bytes", "每窗字节"),
                ("window_syn", "每窗SYN"), ("window_dports", "每窗端口数")]
        rows = []
        vmax = 1
        for k, _lab in dims:
            v = profile.get(k) or {}
            if isinstance(v, dict) and v.get("median"):
                vmax = max(vmax, float(v["median"]) * 1.25)
        W, H, P = 560, 46 + len(dims) * 46, 40
        bar_w = W - 2 * P
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" style="font-family:Segoe UI,Arial,sans-serif;background:#f8faff;border-radius:12px;border:1px solid #dbe6ff">']
        svg.append(f'<text x="{P}" y="22" font-size="13" font-weight="600" fill="#1e293b">基线「{name or "?"}」画像（中位数 ± MAD）</text>')
        for i, (k, lab) in enumerate(dims):
            y = 44 + i * 46
            v = profile.get(k) or {}
            med = float(v.get("median", 0) or 0)
            mad = float(v.get("mad", 0) or 0)
            bw = bar_w * med / vmax
            svg.append(f'<text x="{P}" y="{y+13}" font-size="11" fill="#475569">{lab}</text>')
            svg.append(f'<rect x="{P}" y="{y+18}" width="{bw:.1f}" height="12" rx="4" fill="#60a5fa"/>')
            svg.append(f'<rect x="{P}" y="{y+18}" width="{bar_w*mad/vmax:.1f}" height="12" rx="4" fill="none" stroke="#ef4444" stroke-dasharray="4,3"/>')
            svg.append(f'<text x="{P+bw+8:.1f}" y="{y+29}" font-size="11" fill="#2563eb">中位 {med:.1f} · MAD {mad:.1f}</text>')
        svg.append('</svg>')
        return "".join(svg)
    except Exception:
        return None


def _load_baseline_into(analyzer: TrafficAnalyzer, baseline_name: str) -> bool:
    """加载基线到分析器（P1-4: 优先 SQLite，回退 JSON）"""
    if not baseline_name:
        return False
    from src.storage.database import Database
    db = Database()
    bl = db.get_baseline(baseline_name)
    if bl and bl.get("learned"):
        # 从 SQLite 数据重建 TrafficBaseline 对象
        b = TrafficBaseline(window_sec=bl.get("window_sec", 5))
        b.name = baseline_name
        b.learned = True
        prof = bl.get("profile", {})
        if isinstance(prof, dict) and "profile" in prof:
            b.profile = prof["profile"]
        elif isinstance(prof, dict):
            b.profile = prof
        analyzer.baseline = b
        logger.info(f"已加载基线(SQLite): {baseline_name}")
        return True
    # 回退到 JSON
    b = TrafficBaseline.load(_baseline_path(baseline_name))
    if b and b.learned:
        analyzer.baseline = b
        logger.info(f"已加载基线(JSON): {b.name or baseline_name}")
        return True
    logger.warning(f"基线加载失败或未学习: {baseline_name}")
    return False


@app.post("/api/baseline/learn")
async def baseline_learn(file: UploadFile = File(...), name: str = Form("default")):
    """
    上传正常流量 pcap 学习基线画像，保存为 JSON。
    检测阶段可引用该基线对照统计偏差。
    """
    try:
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


def _quick_sha256(filepath: str) -> str:
    """计算文件 SHA-256（证据溯源）"""
    import hashlib
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _check_upload_file(filename: str, size: int):
    """校验上传文件类型与大小"""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_PCAP_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"不支持的文件类型 {ext}，仅允许: {', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))}")
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if size > max_bytes:
        raise HTTPException(status_code=413, detail=f"文件超过大小限制（{settings.max_upload_mb}MB）")


def _analyze_pcap_task(filepath: str, enable_ai: bool, baseline_name: str = "") -> Dict[str, Any]:
    """在后台线程执行完整分析（解析+规则检测+基线对照+AI研判）"""
    import hashlib

    # 源文件 SHA-256（证据溯源）
    sha256 = ""
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        sha256 = h.hexdigest()
    except Exception as e:
        logger.warning(f"计算文件哈希失败: {e}")

    parser = PcapParser()
    # P0-1: 流式解析+流式分析（GB 级大文件不落全量内存，内存 O(活跃流+窗口数)）
    traffic_analyzer = TrafficAnalyzer()
    if baseline_name:
        _load_baseline_into(traffic_analyzer, baseline_name)
    analysis_report = None
    try:
        analysis_report = traffic_analyzer.analyze_stream(
            parser.iter_packets(filepath), sample_count=50)
    except Exception as e:
        logger.error(f"流式分析失败: {e}")
        raise HTTPException(status_code=400, detail=f"PCAP文件解析失败或为空")
    packet_count = analysis_report.get("summary", {}).get("total_packets", 0) if analysis_report else 0
    samples = (analysis_report or {}).pop("_samples", [])

    if packet_count == 0:
        raise HTTPException(status_code=400, detail="PCAP文件解析失败或为空")

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

    # AI威胁分析（可选）
    if enable_ai:
        llm = get_llm_client()
        if llm.is_available():
            logger.info("开始AI威胁分析...")
            threat_analyzer = get_threat_analyzer()
            _samples_dict = []
            if samples:
                from src.capture.packet_parser import PacketParser as _PP
                _pp = _PP()
                _pp.captured_packets = samples
                _samples_dict = _pp.to_dict_list()
            structured = threat_analyzer.analyze_threats_structured(
                analysis_report["anomaly_detection"],
                packet_samples=_samples_dict
            )
            ai_analysis = structured["raw_text"]
            result["ai_threat_analysis"] = ai_analysis
            result["ai_threat_structured"] = structured["structured"]
            result["ai_threat_structured_ok"] = structured["ok"]
            if ai_analysis.startswith("[大模型调用失败]") or ai_analysis.startswith("[LLM"):
                result["ai_analysis_failed"] = True

            # AI流量概览
            ai_traffic_summary = threat_analyzer.analyze_traffic_summary(
                analysis_report["summary"],
                analysis_report["protocol_distribution"],
                analysis_report["top_talkers"]
            )
            result["ai_traffic_summary"] = ai_traffic_summary
        else:
            result["ai_warning"] = "未配置大模型API Key，跳过AI分析"

    # 取证型 HTML 报告（含证据溯源）
    try:
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
        logger.warning(f"HTML 报告生成失败（不影响分析结果）: {e}")
        result["report_html"] = ""

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
        except Exception:
            pass
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


@app.post("/api/config/validate")
async def config_validate(api_key: str = Form(...), base_url: str = Form(""),
                           model: str = Form("")):
    """校验 API Key 有效性（发送一个简单的测试请求）"""
    if not api_key or "xxxx" in api_key:
        return {"valid": False, "message": "API Key 为空或仍是占位符"}
    try:
        import httpx
        url = base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model or "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 5,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                return {"valid": True, "message": "API Key 校验通过", "status_code": 200}
            else:
                return {"valid": False, "message": f"校验失败: HTTP {resp.status_code}",
                        "status_code": resp.status_code, "detail": resp.text[:200]}
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
        except Exception:
            pass
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


@app.get("/api/forensic/related/{{analysis_id}}")
async def forensic_related(analysis_id: str, max_related: int = 10):
    """跨样本关联分析"""
    try:
        from src.storage.forensic_kb import get_forensic_kb
        related = get_forensic_kb().find_related_samples(analysis_id, max_related)
        return {"analysis_id": analysis_id, "related_count": len(related), "related": related}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"关联分析失败: {e}")


@app.get("/api/forensic/iocs/{{analysis_id}}")
async def forensic_iocs(analysis_id: str):
    """从分析记录提取 IOC"""
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
        except Exception:
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



_GRADIO_MAJOR = int(getattr(gr, "__version__", "4").split(".")[0])


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


_UI_KWARGS = {"theme": gr.themes.Soft(primary_hue=gr.themes.colors.blue), "css": _load_custom_css()}


def create_gradio_interface():
    """创建Gradio Web界面（简单易用，无需前端开发）"""
    # P2-6: Gradio 6.x 也加载自定义 CSS
    _blocks_kwargs = {"css": _load_custom_css()} if _GRADIO_MAJOR >= 6 else _UI_KWARGS
    with gr.Blocks(title="AI网络安全分析系统", **_blocks_kwargs) as demo:
        gr.HTML(_render_app_header())

        with gr.Tabs():
            # Tab 1: PCAP分析
            with gr.Tab("📊 PCAP流量分析"):
                gr.Markdown("上传Wireshark抓包文件（.pcap/.pcapng），系统将自动进行流量分析和AI威胁研判")
                with gr.Row():
                    pcap_file = gr.File(label="上传PCAP文件", file_types=[".pcap", ".pcapng", ".cap"])
                    enable_ai = gr.Checkbox(label="启用AI分析", value=True)
                baseline_dropdown = gr.Dropdown(
                    label="时序基线（可选）", choices=_baseline_names(), interactive=True,
                    info="选择已学习的正常流量基线，分析时将对照时序偏差检测"
                )
                analyze_btn = gr.Button("🔍 开始分析", variant="primary")
                process_output = gr.Markdown(label="🧠 分析过程", value="🕐 等待上传 PCAP 开始分析")
                with gr.Row():
                    summary_output = gr.Textbox(label="📋 流量概览", lines=10)
                    threat_output = gr.Textbox(label="⚠️ AI威胁分析", lines=10)
                with gr.Row():
                    raw_output = gr.JSON(label="📊 完整分析报告（JSON）")
                    report_download = gr.DownloadButton(
                        label="📄 下载取证型HTML报告", value=None, visible=True)
                baseline_chart_output = gr.HTML(label="📈 流量 vs 基线对比图（选基线分析时显示）")
                report_feedback = gr.Markdown("💡 分析完成后：点一次「下载」载入最新报告 → 再点一次下载文件")
                open_report_dir_btn = gr.Button("📂 打开报告目录（保存位置）", size="sm")

                def refresh_baselines():
                    try:
                        bl = _list_baselines()
                        return gr.Dropdown(choices=[b["name"] for b in bl])
                    except Exception:
                        return gr.Dropdown(choices=[])

                baseline_dropdown.focus(refresh_baselines, outputs=baseline_dropdown)

                def on_report_download_click():
                    """点击下载：定位最新生成的报告并载入下载按钮，给出明确状态反馈"""
                    try:
                        d = data_dir("reports")
                        if not os.path.isdir(d):
                            return gr.update(value=None), "❌ 尚无报告：请先完成一次 PCAP 分析"
                        fs = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".html")]
                        if not fs:
                            return gr.update(value=None), "❌ 尚无报告：请先完成一次 PCAP 分析"
                        newest = max(fs, key=os.path.getmtime)
                        sz = os.path.getsize(newest) / 1024
                        return (gr.update(value=newest),
                                f"✅ 报告已载入下载按钮：{os.path.basename(newest)}（{sz:.1f} KB）\n"
                                f"👉 请**再点一次**「下载」按钮获取文件。\n"
                                f"📌 文件保存位置：`{newest}`")
                    except Exception as e:
                        return gr.update(value=None), f"❌ 载入报告失败：{e}"

                def analyze_pcap_gradio(file, ai_enabled, baseline_name):
                    """生成器版：分阶段输出分析过程 + AI 流式研判 + 写入历史记录"""
                    if not file:
                        yield ("❌ 请先上传PCAP文件", "请先上传PCAP文件", "", {}, None,
                               gr.update(value=_history_table_value()), gr.update(value=None))
                        return
                    try:
                        # 阶段 1：解析 + 特征提取 + 规则/基线/ML 检测
                        yield ("🔍 阶段 1/4：正在解析 PCAP 并提取网络流特征（规则→基线→ML 检测）...",
                               "⏳ 分析中...", "", {}, None, gr.update(value=_history_table_value()), gr.update(value=None))
                        parser = PcapParser()
                        traffic_analyzer = TrafficAnalyzer()
                        if baseline_name:
                            _load_baseline_into(traffic_analyzer, baseline_name)
                        report = traffic_analyzer.analyze_stream(
                            parser.iter_packets(file.name), sample_count=50)
                        if not report.get("summary", {}).get("total_packets"):
                            yield ("❌ PCAP文件解析失败", "PCAP文件解析失败", "", {}, None,
                                   gr.update(value=_history_table_value()), gr.update(value=None))
                            return

                        summary = f"""📊 流量分析概览
━━━━━━━━━━━━━━━━━━━━
📦 总数据包数: {report['summary']['total_packets']}
🔀 网络流数量: {report['summary']['total_flows']}
📈 总流量: {format_bytes(report['summary']['total_bytes'])}
⏰ 时间范围: {report['summary']['time_range']['start']} ~ {report['summary']['time_range']['end']}

📡 协议分布:
"""
                        for proto, count in report['protocol_distribution'].items():
                            summary += f"  • {proto}: {count} 包 ({count/report['summary']['total_packets']*100:.1f}%)\n"

                        # 主引擎（监督学习）判定
                        sup = report.get('supervised_detection')
                        if sup and sup.get('available'):
                            verdict = "🔴 攻击" if sup.get('is_attack') else "🟢 正常"
                            summary += f"\n🎯 主引擎判定（HistGradientBoosting，F1=0.9487）: {verdict}\n"
                            summary += f"  • 置信度: {sup.get('confidence', 0):.2f}\n"
                            summary += f"  • 攻击流: {sup.get('attack_flows', 0)}/{sup.get('total_flows', 0)} "
                            summary += f"({sup.get('attack_flow_ratio', 0)*100:.1f}%)\n"
                            if sup.get('category_distribution'):
                                cats = ', '.join(f'{k}({v})' for k, v in sup['category_distribution'].items())
                                summary += f"  • 攻击类别: {cats}\n"
                            agg = sup.get('aggregate_alert', {})
                            if agg.get('triggered'):
                                agg_types = ', '.join(a['type'] for a in agg.get('alerts', []))
                                summary += f"  • 聚合检测: {agg_types}\n"
                        elif sup and not sup.get('available'):
                            summary += f"\n🎯 主引擎判定: 不可用（{sup.get('reason', '未知')}）\n"

                        summary += f"\n🚨 异常检测: 共 {report['anomaly_detection']['total_alerts']} 条告警\n"
                        for sev, count in report['anomaly_detection']['severity_summary'].items():
                            if count > 0:
                                summary += f"  • {sev}: {count} 条\n"

                        # 阶段 2-3：AI 威胁研判（RAG 检索 + LLM 流式输出）
                        ai_threat = ""
                        if ai_enabled:
                            llm = get_llm_client()
                            if llm.is_available():
                                threat_analyzer = get_threat_analyzer()
                                yield ("📚 阶段 2/4：RAG 知识检索（MITRE ATT&CK + 处置手册）...",
                                       summary, "🔎 检索中...", report, None,
                                       gr.update(value=_history_table_value()), gr.update(value=None))
                                # 流式输出研判过程
                                ai_threat = ""
                                for chunk in threat_analyzer.analyze_threats_stream(
                                        report["anomaly_detection"],
                                        packet_samples=parser.to_dict_list()[:50]):
                                    ai_threat += chunk
                                    yield ("🧠 阶段 3/4：AI 威胁研判中（流式输出）...",
                                           summary, ai_threat, report, None,
                                           gr.update(value=_history_table_value()), gr.update(value=None))
                            else:
                                ai_threat = "⚠️ 未配置大模型API Key，无法进行AI分析\n请在⚙️设置中配置LLM_API_KEY"

                        # P0-3: LLM 幻觉控制三件套（输出校验+交叉验证+人工复核）
                        hallucination_result = None
                        try:
                            from src.ai.hallucination_control import run_hallucination_control
                            hallucination_result = run_hallucination_control(
                                ai_threat or "",
                                report.get("anomaly_detection", {}),
                                report.get("supervised_detection"),
                                report.get("baseline_profile"),
                            )
                            # 在威胁分析末尾附加幻觉控制结果
                            if hallucination_result:
                                hv = hallucination_result
                                ai_threat += f"\n\n━━━━━━━━━━━━━━━━━━━━\n"
                                ai_threat += f"🛡️ 幻觉控制校验\n"
                                ai_threat += f"  • 输出校验分: {hv['output_validation']['score']} ({hv['output_validation']['level']})\n"
                                ai_threat += f"  • 多引擎共识: {hv['cross_validation']['consensus']} "
                                ai_threat += f"(一致性 {hv['cross_validation']['agreement']:.0%})\n"
                                ai_threat += f"  • 幻觉风险: {hv['hallucination_risk']}\n"
                                if hv['review_marker']['needs_review']:
                                    ai_threat += f"  • ⚠️ 需人工复核: {hv['review_marker']['priority']}优先级\n"
                                    for reason in hv['review_marker']['reasons'][:3]:
                                        ai_threat += f"    - {reason}\n"
                                if hv['output_validation']['issues']:
                                    ai_threat += f"  • 校验问题: {len(hv['output_validation']['issues'])} 项\n"
                        except Exception as e:
                            logger.warning(f"幻觉控制失败（不影响主流程）: {e}")

                        # 阶段 4：生成 HTML 报告 + 写入历史
                        yield ("📄 阶段 4/4：生成取证型 HTML 报告...",
                               summary, ai_threat, report, None,
                               gr.update(value=_history_table_value()), gr.update(value=None))
                        html_path = None
                        try:
                            evidence = {
                                "source_file": os.path.basename(file.name),
                                "source_sha256": _quick_sha256(file.name),
                                "analyzed_at": get_timestamp_str(),
                                "rule_version": "2.0.0",
                            }
                            html_path = save_html_report(report, evidence, ai_analysis=ai_threat,
                                                         report_dir=data_dir("reports"))
                        except Exception as e:
                            logger.warning(f"HTML报告生成失败: {e}")

                        # 写入分析历史（供「📜 分析历史」Tab 回看）
                        try:
                            get_history_store().add_analysis({
                                "file": os.path.basename(file.name),
                                "packets": report["summary"]["total_packets"],
                                "flows": report["summary"]["total_flows"],
                                "bytes": report["summary"]["total_bytes"],
                                "alerts": report["anomaly_detection"]["total_alerts"],
                                "severity": report["anomaly_detection"]["severity_summary"],
                                "supervised_verdict": (report.get("supervised_detection") or {}).get("is_attack", False),
                                "supervised_confidence": (report.get("supervised_detection") or {}).get("confidence", 0),
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
                               summary, ai_threat, report, html_path,
                               gr.update(value=_history_table_value()),
                               _build_baseline_compare_svg(report.get("window_series"),
                                                           report.get("baseline_profile")))

                    except Exception as e:
                        logger.error(f"分析失败: {e}")
                        yield (f"❌ 分析失败: {str(e)}", "分析失败", "", {}, None,
                               gr.update(value=_history_table_value()), gr.update(value=None))

                # 注：analyze_btn 的事件注册在「📜 分析历史」Tab 定义之后（需引用 history_dropdown）

            # Tab 2: 分析历史（v1.5.1：表格列表 + 行点击查看详情）
            with gr.Tab("📜 分析历史"):
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
                        return f"📊 当前 **{n}** 条分析记录"
                    except Exception:
                        return "📊 当前 **0** 条分析记录"

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

                gr.Markdown("每次 PCAP 分析完成后自动记录。**点击表格任意一行**查看该次分析的详情、摘要与报告（最多保留 60 条）")
                history_count = gr.Markdown(value=_history_count_text())
                history_table = gr.Dataframe(
                    value=_history_table_value(),
                    label="历史分析记录（点击行查看详情）",
                    headers=["时间", "文件", "包数", "流数", "告警数", "严重度", "摘要"],
                    datatype=["str", "str", "number", "number", "number", "str", "str"],
                    interactive=False, row_count=(5, "dynamic"), column_count=7, wrap=True)
                with gr.Row():
                    refresh_history_btn = gr.Button("🔄 刷新列表")
                    load_history_btn = gr.Button("📂 加载到分析结果", variant="primary")
                    open_report_btn = gr.Button("📄 打开报告")
                    clear_history_btn = gr.Button("🗑 清空全部历史")
                history_detail = gr.JSON(label="记录详情（点击行后展示）")
                history_feedback = gr.Markdown(
                    "💡 **用法**：点击表格任意行 → 下方查看详情；\n"
                    "「加载到分析结果」= 把该次分析回填到上方 Tab1 结果区；\n"
                    "「打开报告」= 在浏览器打开该次 HTML 取证报告")
                selected_history = gr.State(None)

                def refresh_history_ui():
                    return (gr.update(value=_history_table_value()), _history_count_text(),
                            "🔄 列表已刷新")

                def on_history_row_click(evt: gr.SelectData):
                    """点击表格行 → 展示该记录详情 + 回填结果区 + 记录选中状态"""
                    idx = evt.index
                    row = idx[0] if isinstance(idx, (list, tuple)) else idx
                    try:
                        hs = get_history_store().list_analysis()
                    except Exception:
                        hs = []
                    if row is None or not hs or row >= len(hs):
                        return ({"info": "记录已不存在或已被清空"}, "", "", {}, None)
                    h = hs[row]
                    detail = {k: v for k, v in h.items() if k not in ('summary_text', 'ai_summary', 'raw')}
                    detail["_回填提示"] = "已加载到「PCAP流量分析」结果区"
                    return (detail, h.get("summary_text", ""), h.get("ai_summary", ""),
                            h.get("raw", {}), h)

                def load_history_ui(sel):
                    """将当前选中的历史记录回填到 Tab1 结果区（并在本 Tab 显示明确反馈）"""
                    h = sel
                    if not h:
                        return ("⚠️ 请先在表格中点击选择一条记录", {"info": "请先选择记录"},
                                "", "", {}, None)
                    detail = {k: v for k, v in h.items() if k not in ('summary_text', 'ai_summary', 'raw')}
                    detail["_回填提示"] = "已加载到「PCAP流量分析」结果区"
                    brief = (h.get("summary_text") or "").replace("\n", " ")[:60]
                    return (f"✅ **已回填到「🔍 PCAP流量分析」结果区**（请切换到第一个 Tab 查看）\n"
                            f"文件：`{h.get('file', '?')}` | 告警 {h.get('alerts', 0)} 条\n摘要：{brief}…",
                            detail, h.get("summary_text", ""), h.get("ai_summary", ""),
                            h.get("raw", {}), h)

                def open_selected_report_ui(sel):
                    h = sel
                    if not h:
                        return "⚠️ 请先在表格中点击选择一条记录"
                    rp = h.get("html_report")
                    if not rp:
                        return "⚠️ 该记录未生成 HTML 报告（本次分析未启用报告保存）"
                    if not os.path.exists(rp):
                        return f"❌ 报告文件已被移动或删除：`{rp}`"
                    try:
                        os.startfile(rp)
                        return (f"✅ **已在浏览器打开报告**：`{os.path.basename(rp)}`\n"
                                f"📌 如未弹出窗口，可手动打开：`{rp}`")
                    except Exception as e:
                        return f"❌ 打开报告失败：{e}"

                def clear_history_ui():
                    n = get_history_store().clear_analysis()
                    return (gr.update(value=[]), "📊 当前 **0** 条分析记录",
                            f"🗑 已清空全部历史记录（{n} 条）", {"cleared": n}, None)

                history_table.select(on_history_row_click,
                                     outputs=[history_detail, summary_output, threat_output,
                                              raw_output, selected_history])
                refresh_history_btn.click(refresh_history_ui,
                                          outputs=[history_table, history_count, history_feedback])
                load_history_btn.click(load_history_ui, inputs=[selected_history],
                                       outputs=[history_feedback, history_detail, summary_output,
                                                threat_output, raw_output, selected_history])
                open_report_btn.click(open_selected_report_ui, inputs=[selected_history],
                                      outputs=history_feedback)
                clear_history_btn.click(clear_history_ui,
                                        outputs=[history_table, history_count, history_feedback,
                                                 history_detail, selected_history])
                demo.load(refresh_history_ui, outputs=[history_table, history_count, history_feedback])

                def open_report_dir_ui():
                    try:
                        d = data_dir("reports")
                        os.makedirs(d, exist_ok=True)
                        os.startfile(d)
                        return "✅ 已打开报告目录: " + d
                    except Exception as e:
                        return f"❌ 打开失败: {e}"

                open_report_dir_btn.click(open_report_dir_ui, outputs=process_output)
                report_download.click(on_report_download_click,
                                      outputs=[report_download, report_feedback])

                # analyze_btn 事件注册（此处 history_dropdown 已定义）
                analyze_btn.click(
                    analyze_pcap_gradio,
                    inputs=[pcap_file, enable_ai, baseline_dropdown],
                    outputs=[process_output, summary_output, threat_output, raw_output,
                             report_download, history_table]
                )

            # Tab 3: 安全问答（v1.4.0：流式输出 + 对话历史持久化 + RAG 检索依据展示）
            with gr.Tab("💬 安全知识问答"):
                gr.Markdown("基于MITRE ATT&CK知识库的安全问答助手 —— 回答逐字流式显示，对话自动保存（刷新不丢失）")
                chatbot = gr.Chatbot(label="安全助手")
                msg_input = gr.Textbox(label="输入问题", placeholder="例如：什么是DNS隧道？如何检测端口扫描？")
                with gr.Row():
                    send_btn = gr.Button("发送", variant="primary")
                    clear_btn = gr.Button("清空对话")

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
                        for evt in threat_analyzer.chat_about_security_stream(message):
                            if evt["stage"] == "retrieval":
                                ev = evt.get("evidence") or []
                                if ev:
                                    ev_lines = "　".join(
                                        f"《{e['title']}》(相似度 {e['similarity']})" for e in ev[:3])
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
                    except Exception:
                        pass
                    return []

                send_btn.click(chat_response_stream, inputs=[msg_input, chatbot],
                               outputs=[chatbot])
                clear_btn.click(clear_chat_ui, outputs=chatbot)
                # 页面加载时恢复历史对话
                demo.load(lambda: get_history_store().load_chat(), outputs=chatbot)

            # Tab 3: 知识库管理
            with gr.Tab("📚 知识库管理"):
                gr.Markdown("管理安全知识库（MITRE ATT&CK、处置手册、协议知识）")
                with gr.Row():
                    init_btn = gr.Button("🔄 初始化/重建知识库", variant="primary")
                    stats_output = gr.JSON(label="知识库统计")
                with gr.Row():
                    kb_file = gr.File(label="导入知识文档（.txt/.md）", file_types=[".txt", ".md", ".json"])
                    import_btn = gr.Button("📥 导入到知识库")
                import_output = gr.JSON(label="导入结果")
                search_input = gr.Textbox(label="搜索知识库", placeholder="输入关键词搜索...")
                search_btn = gr.Button("🔍 搜索")
                search_output = gr.JSON(label="搜索结果")

                def init_kb():
                    try:
                        rag = get_rag_engine()
                        rag.clear()
                        items = get_all_knowledge()
                        count = rag.add_knowledge_base(items)
                        return rag.get_stats()
                    except Exception as e:
                        return {"error": str(e)}

                def search_kb(query):
                    if not query:
                        return {}
                    rag = get_rag_engine()
                    return rag.search(query, top_k=5)

                def import_kb(file):
                    if not file:
                        return {"error": "请先选择文档"}
                    try:
                        rag = get_rag_engine()
                        chunks = rag.add_file(file.name, source=f"user_import:{os.path.basename(file.name)}")
                        return {"status": "success", "chunks_added": chunks, "stats": rag.get_stats()}
                    except Exception as e:
                        return {"error": str(e)}

                init_btn.click(init_kb, outputs=stats_output)
                import_btn.click(import_kb, inputs=kb_file, outputs=import_output)
                search_btn.click(search_kb, inputs=search_input, outputs=search_output)

            # Tab 4: 基线管理
            with gr.Tab("📈 基线管理"):
                gr.Markdown("""
                **时序基线（EWMA 学习-检测两阶段）**
                上传一份**正常流量** pcap，系统学习该网络的"日常画像"（每时间窗的包数/字节/SYN/端口数中位数），
                之后分析可疑流量时可对照该基线，偏差超 σ 即告警。预置基线 `default`（学习自 normal.pcap）可直接使用。
                """)
                with gr.Row():
                    baseline_file = gr.File(label="上传正常流量PCAP", file_types=[".pcap", ".pcapng", ".cap"])
                    baseline_name_input = gr.Textbox(label="基线名称", value="default",
                                                     placeholder="如: office-network")
                learn_btn = gr.Button("🧠 一键学习基线", variant="primary")
                learn_feedback = gr.Markdown("💡 上传正常流量 pcap → 命名 → 点「一键学习」→ 结果与列表即时刷新，Tab1 下拉框同步更新")
                learn_output = gr.JSON(label="学习结果（基线画像）")
                def _baseline_table_value():
                    rows = []
                    for b in _list_baselines():
                        rows.append([b["name"], b["packets_used"], b["window_sec"],
                                     b.get("sigma", 3.0), b["created_at"], b["file"]])
                    return rows

                baseline_table = gr.Dataframe(
                    value=_baseline_table_value(),
                    headers=["名称", "学习包数", "窗口(s)", "σ", "创建时间", "文件"],
                    label="已保存基线（点击行查看画像）",
                    interactive=False)
                baseline_feedback = gr.Markdown("")
                with gr.Row():
                    refresh_baseline_btn = gr.Button("🔄 刷新列表")
                    delete_baseline_btn = gr.Button("🗑 删除选中基线", variant="stop")
                with gr.Row():
                    baseline_profile_output = gr.JSON(label="选中基线画像（点击表格行查看）")
                    baseline_chart = gr.HTML(label="📊 基线画像图表（点击行生成）")
                baseline_selected = gr.State(None)

                def learn_baseline_ui(file, name):
                    if not file:
                        return "❌ 请先上传正常流量PCAP", None, gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())
                    try:
                        import time as _t
                        t0 = _t.time()
                        parser = PcapParser()
                        packets = parser.parse_file(file.name)
                        if not packets:
                            return "❌ PCAP解析失败或为空，无法学习基线", None, gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())
                        name = (name or "default").strip()
                        baseline = TrafficBaseline()
                        baseline.name = name
                        baseline.learn(packets)
                        save_path = _baseline_path(name)
                        ensure_dir(BASELINE_DIR)
                        ok = baseline.save(save_path)
                        if not ok:
                            return f"❌ 基线保存失败：{name}（名称含非法字符？）", None, gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())
                        secs = _t.time() - t0
                        msg = (f"✅ 基线「{name}」学习完成：{len(packets)} 包 / 窗口 {baseline.window_sec}s / σ={baseline.sigma} / 耗时 {secs:.1f}s\n"
                               f"📌 已保存到 `{save_path}`，并已同步到 Tab1「基线选择」")
                        return msg, baseline.to_dict(), gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())
                    except Exception as e:
                        return f"❌ 学习失败：{e}", None, gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())

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
                        return "⚠️ 请先在表格中点击选择一条基线（行高亮后再点删除）", gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())
                    path = _baseline_path(name)
                    if not os.path.exists(path):
                        return f"❌ 基线文件不存在：{path}", gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names())
                    os.remove(path)
                    tip = ""
                    if name == "default":
                        tip = "\n⚠️ 已删除内置基线 default——Tab1 分析若仍选 default 将跳过基线对照，建议重新学习一份。"
                    return (f"🗑 已删除基线「{name}」，Tab1 下拉框同步移除。{tip}",
                            gr.update(value=_baseline_table_value()), gr.update(choices=_baseline_names()))

                def refresh_baselines_ui():
                    rows = _baseline_table_value()
                    return gr.update(value=rows), f"🔄 列表已刷新（{len(rows)} 条基线）"

                learn_btn.click(learn_baseline_ui, inputs=[baseline_file, baseline_name_input],
                                outputs=[learn_feedback, learn_output, baseline_table, baseline_dropdown])
                refresh_baseline_btn.click(refresh_baselines_ui, outputs=[baseline_table, baseline_feedback])
                delete_baseline_btn.click(delete_baseline_ui, inputs=baseline_selected,
                                          outputs=[baseline_feedback, baseline_table, baseline_dropdown])
                baseline_table.select(on_baseline_row_click,
                                      outputs=[baseline_profile_output, baseline_feedback,
                                               baseline_selected, baseline_chart])
                demo.load(lambda: gr.update(value=_baseline_table_value()), outputs=baseline_table)

            with gr.Tab("⚙️ 设置"):
                gr.Markdown("""
                **大模型 API 配置** —— 用于 AI 威胁研判与安全问答，保存后立即生效
                支持服务商：智谱 / DeepSeek / 通义千问 / 硅基流动 / Ollama（任选其一）
                """)
                with gr.Row():
                    api_key_input = gr.Textbox(label="🔑 API Key", type="password",
                                               placeholder="sk-...")
                    api_url_input = gr.Textbox(label="🔗 API 地址 (Base URL)",
                                               placeholder="https://open.bigmodel.cn/api/paas/v4")
                    api_model_input = gr.Textbox(label="🧠 模型名称",
                                                 placeholder="glm-4-flash")
                save_btn = gr.Button("💾 保存配置", variant="primary")
                api_status = gr.Markdown("点击保存后立即生效，无需重启")

                def load_api_config_ui():
                    """读取 .env 当前配置，用于预填"""
                    try:
                        env = find_env_file()
                        vals = {"LLM_API_KEY": "", "LLM_BASE_URL": "", "LLM_MODEL": ""}
                        if os.path.exists(env):
                            with open(env, encoding="utf-8") as f:
                                for line in f:
                                    st = line.strip()
                                    if st and not st.startswith("#") and "=" in st:
                                        k, v = st.split("=", 1)
                                        if k.strip() in vals:
                                            vals[k.strip()] = v.strip()
                        return vals["LLM_API_KEY"], vals["LLM_BASE_URL"], vals["LLM_MODEL"]
                    except Exception:
                        return "", "", ""

                def save_api_config_ui(key, url, model):
                    """保存 API 配置到 .env + DPAPI 加密存储（P1-3）并重置 LLM 客户端"""
                    if not key:
                        return "⚠️ API Key 不能为空"
                    if "xxxx" in key:
                        return "⚠️ API Key 仍是占位符（sk-xxxx），请填写真实 Key"
                    try:
                        # P1-3: 同时保存到 DPAPI 加密存储（Windows）
                        secure_msg = ""
                        try:
                            import sys
                            if sys.platform == "win32":
                                from src.security.secure_store import get_secure_store
                                ss = get_secure_store()
                                ss.set("LLM_API_KEY", key.strip())
                                ss.set("LLM_BASE_URL", url.strip())
                                ss.set("LLM_MODEL", model.strip())
                                secure_msg = "🔒 已加密存储（DPAPI）\n"
                        except Exception as se:
                            secure_msg = f"⚠️ 加密存储失败（不影响 .env 保存）: {se}\n"

                        # 保存到 .env（兼容备份）
                        env = find_env_file()
                        lines = []
                        if os.path.exists(env):
                            with open(env, encoding="utf-8") as f:
                                lines = f.readlines()
                        new_entries = {
                            "LLM_API_KEY": key.strip(),
                            "LLM_BASE_URL": url.strip(),
                            "LLM_MODEL": model.strip(),
                        }
                        updated = set()
                        for i, line in enumerate(lines):
                            st = line.strip()
                            if st and not st.startswith("#") and "=" in st:
                                k = st.split("=", 1)[0].strip()
                                if k in new_entries:
                                    lines[i] = f"{k}={new_entries[k]}\n"
                                    updated.add(k)
                        for k, v in new_entries.items():
                            if k not in updated:
                                lines.append(f"{k}={v}\n")
                        with open(env, "w", encoding="utf-8") as f:
                            f.writelines(lines)
                        # 重置 LLM 单例，下次分析立即用新配置
                        try:
                            from src.ai.llm_client import reset_llm_client
                            reset_llm_client()
                        except Exception:
                            pass
                        return f"✅ 已保存并生效\n{secure_msg}📄 .env: {env}\n\n服务商: {url.strip()}\n模型: {model.strip()}"
                    except Exception as e:
                        return f"❌ 保存失败: {e}"

                demo.load(load_api_config_ui,
                          outputs=[api_key_input, api_url_input, api_model_input])
                save_btn.click(save_api_config_ui,
                               inputs=[api_key_input, api_url_input, api_model_input],
                               outputs=api_status)

        gr.Markdown("""
        ---
        💡 **使用提示**：
        1. 首次使用请先在「知识库管理」中初始化知识库
        2. 建议在「📈 基线管理」中用正常流量学习一份时序基线，分析时对照检测效果更佳
        3. 确保已在 `.env` 文件中配置 `LLM_API_KEY`（推荐DeepSeek/智谱）
        4. PCAP文件可用Wireshark抓包后导出
        """)

    return demo


# 集成Gradio到FastAPI
if GRADIO_AVAILABLE:
    try:
        gradio_app = create_gradio_interface()
        try:
            gradio_app.queue()
        except Exception:
            pass
        _mount_kwargs = _UI_KWARGS if _GRADIO_MAJOR >= 6 else {}
        try:
            # Gradio 6.x 文件下载路由需白名单（修复 DownloadButton 下载失效）
            from src.utils.paths import data_dir
            _mount_kwargs["allowed_paths"] = [data_dir("reports"), data_dir("uploads"), data_dir("history")]
        except Exception:
            pass
        app = gr.mount_gradio_app(app, gradio_app, path="/", **_mount_kwargs)
        logger.info("Gradio Web UI 已挂载到 /")
    except Exception as e:
        logger.warning(f"Gradio UI 挂载失败（不影响API使用）: {e}")
else:
    logger.info("gradio 未安装，仅启动API服务（可通过 /docs 查看API文档）")


def main():
    """启动服务"""
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    logger.info(f"启动服务: http://127.0.0.1:{port}")
    logger.info(f"API文档: http://127.0.0.1:{port}/docs")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
