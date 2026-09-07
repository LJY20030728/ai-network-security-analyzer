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
import sys
import json
import secrets
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
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


@app.get("/api/health")
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
    """列出所有已保存基线（元信息）"""
    ensure_dir(BASELINE_DIR)
    items = []
    for fn in sorted(os.listdir(BASELINE_DIR)):
        if fn.endswith(".json"):
            path = os.path.join(BASELINE_DIR, fn)
            b = TrafficBaseline.load(path)
            if b and b.learned:
                profile_summary = {k: {"median": v["median"], "mad": v["mad"]}
                                   for k, v in b.profile.items()}
                items.append({
                    "name": b.name or os.path.splitext(fn)[0],
                    "file": fn,
                    "created_at": b.created_at,
                    "packets_used": b.packets_used,
                    "window_sec": b.window_sec,
                    "profile": profile_summary,
                })
    return items


def _load_baseline_into(analyzer: TrafficAnalyzer, baseline_name: str) -> bool:
    """加载基线到分析器（失败返回 False）"""
    if not baseline_name:
        return False
    b = TrafficBaseline.load(_baseline_path(baseline_name))
    if b and b.learned:
        analyzer.baseline = b
        logger.info(f"已加载基线: {b.name or baseline_name}")
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
    """删除基线"""
    try:
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

@app.post("/api/chat")
async def security_chat(request: ChatRequest):
    """安全知识问答（基于RAG）"""
    try:
        llm = get_llm_client()
        if not llm.is_available():
            raise HTTPException(status_code=400, detail="未配置大模型API Key")

        threat_analyzer = get_threat_analyzer()
        answer = threat_analyzer.chat_about_security(request.question, request.context)

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

def create_gradio_interface():
    """创建Gradio Web界面（简单易用，无需前端开发）"""
    with gr.Blocks(title="AI网络安全分析系统") as demo:
        gr.Markdown("""
        # 🛡️ AI网络安全智能分析系统
        基于流行为检测与LLM辅助研判的网络异常分析 | 上传PCAP文件，AI自动分析威胁
        """)

        with gr.Tabs():
            # Tab 1: PCAP分析
            with gr.Tab("📊 PCAP流量分析"):
                gr.Markdown("上传Wireshark抓包文件（.pcap/.pcapng），系统将自动进行流量分析和AI威胁研判")
                with gr.Row():
                    pcap_file = gr.File(label="上传PCAP文件", file_types=[".pcap", ".pcapng", ".cap"])
                    enable_ai = gr.Checkbox(label="启用AI分析", value=True)
                baseline_dropdown = gr.Dropdown(
                    label="时序基线（可选）", choices=[], interactive=True,
                    info="选择已学习的正常流量基线，分析时将对照时序偏差检测"
                )
                analyze_btn = gr.Button("🔍 开始分析", variant="primary")
                with gr.Row():
                    summary_output = gr.Textbox(label="📋 流量概览", lines=10)
                    threat_output = gr.Textbox(label="⚠️ AI威胁分析", lines=10)
                with gr.Row():
                    raw_output = gr.JSON(label="📊 完整分析报告（JSON）")
                    report_download = gr.File(label="📄 取证型HTML报告下载", visible=True)

                def refresh_baselines():
                    try:
                        bl = _list_baselines()
                        return gr.Dropdown(choices=[b["name"] for b in bl])
                    except Exception:
                        return gr.Dropdown(choices=[])

                baseline_dropdown.focus(refresh_baselines, outputs=baseline_dropdown)

                def analyze_pcap_gradio(file, ai_enabled, baseline_name):
                    if not file:
                        return "请先上传PCAP文件", "", {}, None
                    try:
                        parser = PcapParser()
                        traffic_analyzer = TrafficAnalyzer()
                        if baseline_name:
                            _load_baseline_into(traffic_analyzer, baseline_name)
                        report = traffic_analyzer.analyze_stream(
                            parser.iter_packets(file.name), sample_count=50)
                        if not report.get("summary", {}).get("total_packets"):
                            return "PCAP文件解析失败", "", {}, None

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

                        summary += f"\n🚨 异常检测: 共 {report['anomaly_detection']['total_alerts']} 条告警\n"
                        for sev, count in report['anomaly_detection']['severity_summary'].items():
                            if count > 0:
                                summary += f"  • {sev}: {count} 条\n"

                        ai_threat = ""
                        html_path = None
                        if ai_enabled:
                            llm = get_llm_client()
                            if llm.is_available():
                                threat_analyzer = get_threat_analyzer()
                                ai_threat = threat_analyzer.analyze_threats(
                                    report["anomaly_detection"],
                                    packet_samples=parser.to_dict_list()[:50]
                                )
                            else:
                                ai_threat = "⚠️ 未配置大模型API Key，无法进行AI分析\n请在.env文件中配置LLM_API_KEY"

                        try:
                            evidence = {
                                "source_file": os.path.basename(file.name),
                                "source_sha256": _quick_sha256(file.name),
                                "analyzed_at": get_timestamp_str(),
                                "rule_version": "2.0.0",
                            }
                            html_path = save_html_report(report, evidence, ai_analysis=ai_threat, report_dir=data_dir("reports"))
                        except Exception as e:
                            logger.warning(f"HTML报告生成失败: {e}")

                        return summary, ai_threat, report, html_path

                    except Exception as e:
                        return f"分析失败: {str(e)}", "", {}, None

                analyze_btn.click(
                    analyze_pcap_gradio,
                    inputs=[pcap_file, enable_ai, baseline_dropdown],
                    outputs=[summary_output, threat_output, raw_output, report_download]
                )

            # Tab 2: 安全问答
            with gr.Tab("💬 安全知识问答"):
                gr.Markdown("基于MITRE ATT&CK知识库的安全问答助手")
                chatbot = gr.Chatbot(label="安全助手")
                msg_input = gr.Textbox(label="输入问题", placeholder="例如：什么是DNS隧道？如何检测端口扫描？")
                with gr.Row():
                    send_btn = gr.Button("发送", variant="primary")
                    clear_btn = gr.Button("清空对话")

                def chat_response(message, history):
                    if not message:
                        return "", history
                    llm = get_llm_client()
                    if not llm.is_available():
                        history.append((message, "⚠️ 未配置大模型API Key，请在.env中配置LLM_API_KEY"))
                        return "", history
                    threat_analyzer = get_threat_analyzer()
                    answer = threat_analyzer.chat_about_security(message)
                    history.append((message, answer))
                    return "", history

                send_btn.click(chat_response, inputs=[msg_input, chatbot], outputs=[msg_input, chatbot])
                clear_btn.click(lambda: [], outputs=chatbot)

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
                上传一份正常流量 pcap，系统学习该网络的"日常画像"（每时间窗的包数/字节/SYN/端口数中位数），
                之后分析可疑流量时可对照该基线，统计偏差超 3σ 即告警。
                """)
                with gr.Row():
                    baseline_file = gr.File(label="上传正常流量PCAP", file_types=[".pcap", ".pcapng", ".cap"])
                    baseline_name_input = gr.Textbox(label="基线名称", value="default", placeholder="如: office-network")
                learn_btn = gr.Button("🧠 学习基线", variant="primary")
                learn_output = gr.JSON(label="学习结果（基线画像）")
                with gr.Row():
                    refresh_btn = gr.Button("🔄 刷新基线列表")
                    delete_name = gr.Textbox(label="要删除的基线名称")
                    delete_btn = gr.Button("🗑 删除基线")
                baseline_list_output = gr.JSON(label="已保存基线列表")
                baseline_profile_output = gr.JSON(label="选中基线画像")

                def learn_baseline_ui(file, name):
                    if not file:
                        return {"error": "请先上传正常流量PCAP"}
                    try:
                        parser = PcapParser()
                        packets = parser.parse_file(file.name)
                        if not packets:
                            return {"error": "PCAP解析失败或为空"}

                        baseline = TrafficBaseline()
                        baseline.name = name or "default"
                        baseline.learn(packets)

                        save_path = _baseline_path(baseline.name)
                        ensure_dir(BASELINE_DIR)
                        ok = baseline.save(save_path)
                        return {
                            "status": "success" if ok else "failed",
                            "name": baseline.name,
                            "packets_used": len(packets),
                            "profile": baseline.to_dict(),
                            "saved_to": save_path,
                        }
                    except Exception as e:
                        return {"error": str(e)}

                def list_baselines_ui():
                    return _list_baselines()

                def delete_baseline_ui(name):
                    if not name:
                        return {"error": "请输入基线名称"}
                    path = _baseline_path(name)
                    if os.path.exists(path):
                        os.remove(path)
                        return {"status": "success", "deleted": name}
                    return {"error": f"基线不存在: {name}"}

                learn_btn.click(learn_baseline_ui, inputs=[baseline_file, baseline_name_input],
                                outputs=learn_output)
                refresh_btn.click(list_baselines_ui, outputs=baseline_list_output)
                delete_btn.click(delete_baseline_ui, inputs=delete_name, outputs=baseline_list_output)

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
        app = gr.mount_gradio_app(app, gradio_app, path="/")
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
