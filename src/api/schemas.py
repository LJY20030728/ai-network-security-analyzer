# -*- coding: utf-8 -*-
"""
P1-5: FastAPI Pydantic 模型集中管理
所有 API 请求/响应模型定义在此，增强 API 规范性和可维护性。
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


# ===== 健康检查 =====

class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str = Field(..., description="服务状态: healthy/degraded/error")
    version: str = Field(..., description="系统版本")
    llm_model: Optional[str] = Field(None, description="LLM 模型名称")
    llm_available: bool = Field(..., description="LLM 是否可用")
    chroma_count: Optional[int] = Field(None, description="ChromaDB 文档数")
    uptime: Optional[float] = Field(None, description="运行时长(秒)")


# ===== 知识库 =====

class KnowledgeSearchRequest(BaseModel):
    """知识检索请求"""
    query: str = Field(..., min_length=1, max_length=500, description="检索查询")
    top_k: int = Field(5, ge=1, le=50, description="返回结果数")
    use_hybrid: bool = Field(True, description="是否启用混合检索")


class KnowledgeSearchResult(BaseModel):
    """单条检索结果"""
    id: str
    title: Optional[str] = None
    content: str
    metadata: Optional[Dict[str, Any]] = None
    distance: Optional[float] = None
    rerank_score: Optional[float] = None


class KnowledgeSearchResponse(BaseModel):
    """知识检索响应"""
    query: str
    total: int
    results: List[KnowledgeSearchResult]
    search_time_ms: Optional[float] = None


class KnowledgeAddRequest(BaseModel):
    """知识添加请求"""
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1)
    metadata: Optional[Dict[str, Any]] = None
    source: Optional[str] = None


class KnowledgeAddResponse(BaseModel):
    """知识添加响应"""
    success: bool
    added_count: int
    message: Optional[str] = None


class KnowledgeStatsResponse(BaseModel):
    """知识库统计响应"""
    total_documents: int
    collection_name: str
    persist_dir: Optional[str] = None


# ===== 基线管理 =====

class BaselineLearnRequest(BaseModel):
    """基线学习请求"""
    name: str = Field(..., min_length=1, max_length=100, description="基线名称")
    pcap_path: str = Field(..., description="用于学习的 PCAP 文件路径")
    window_sec: int = Field(5, ge=1, le=300, description="窗口大小(秒)")
    description: Optional[str] = None


class BaselineLearnResponse(BaseModel):
    """基线学习响应"""
    success: bool
    name: str
    windows_learned: int
    total_packets: int
    message: Optional[str] = None


class BaselineDeleteRequest(BaseModel):
    """基线删除请求"""
    name: str = Field(..., min_length=1, description="基线名称")


class BaselineDeleteResponse(BaseModel):
    """基线删除响应"""
    success: bool
    deleted: str
    message: Optional[str] = None


class BaselineProfile(BaseModel):
    """基线画像"""
    dimension: str
    median: float
    mad: float
    samples: int


class BaselineInfo(BaseModel):
    """基线信息"""
    name: str
    window_sec: int
    learned: bool
    total_packets: Optional[int] = None
    total_windows: Optional[int] = None
    created_at: Optional[str] = None
    description: Optional[str] = None
    profile: Optional[List[BaselineProfile]] = None


class BaselineListResponse(BaseModel):
    """基线列表响应"""
    baselines: List[BaselineInfo]
    total: int


# ===== PCAP 分析 =====

class AnalyzeRequest(BaseModel):
    """分析请求（包列表模式）"""
    packets: List[Dict[str, Any]]
    enable_ai_analysis: bool = True
    baseline_name: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """分析响应"""
    success: bool
    total_packets: int
    total_flows: int
    total_bytes: Optional[int] = None
    alerts: int
    severity_summary: Optional[Dict[str, int]] = None
    supervised_verdict: Optional[bool] = None
    supervised_confidence: Optional[float] = None
    ensemble_verdict: Optional[bool] = None
    ai_analysis: Optional[str] = None
    html_report_path: Optional[str] = None
    analysis_time_ms: Optional[float] = None
    error: Optional[str] = None


class AnalyzeAsyncResponse(BaseModel):
    """异步分析响应"""
    task_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    """任务状态响应"""
    task_id: str
    status: str
    progress: float = 0.0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ===== 安全问答 =====

class ChatRequest(BaseModel):
    """安全问答请求"""
    question: str = Field(..., min_length=1, max_length=1000)
    context: Optional[str] = None
    use_rag: bool = True
    stream: bool = False


class ChatResponse(BaseModel):
    """安全问答响应"""
    question: str
    answer: str
    sources: Optional[List[Dict[str, Any]]] = None
    rag_used: bool = False
    response_time_ms: Optional[float] = None


# ===== 事件报告 =====

class IncidentReportRequest(BaseModel):
    """事件报告请求"""
    title: str = Field(..., min_length=1, max_length=200)
    description: str
    severity: str = Field("medium", pattern="^(low|medium|high|critical)$")
    alerts: Optional[List[Dict[str, Any]]] = None
    iocs: Optional[List[Dict[str, Any]]] = None
    analyst_notes: Optional[str] = None


class IncidentReportResponse(BaseModel):
    """事件报告响应"""
    success: bool
    report_id: str
    title: str
    html_path: Optional[str] = None
    created_at: str


# ===== 审计日志 =====

class AuditLogEntry(BaseModel):
    """审计日志条目"""
    timestamp: str
    endpoint: str
    method: str
    status_code: int
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    latency_ms: Optional[float] = None


class AuditLogsResponse(BaseModel):
    """审计日志响应"""
    logs: List[AuditLogEntry]
    total: int
    page: int
    page_size: int


class AuditStatsResponse(BaseModel):
    """审计统计响应"""
    total_requests: int
    total_errors: int
    avg_latency_ms: Optional[float] = None
    top_endpoints: Optional[List[Dict[str, Any]]] = None
    error_rate: Optional[float] = None


# ===== 通用响应 =====

class ErrorResponse(BaseModel):
    """错误响应"""
    success: bool = False
    error: str
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class SuccessResponse(BaseModel):
    """通用成功响应"""
    success: bool = True
    message: Optional[str] = None
    data: Optional[Any] = None
