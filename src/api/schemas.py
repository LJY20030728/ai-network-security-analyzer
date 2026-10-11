# -*- coding: utf-8 -*-
"""
FastAPI Pydantic 模型

仅在**端点实际引用**时保留模型：本模块的类不会被任何工具自动发现，
未经 `response_model=` / `Body(...)` 引用的类既不影响 OpenAPI 文档，
也不参与请求校验，属于纯死代码。

当前只有两个端点声明了 `response_model`（`src/ui/gradio_app.py`）：
  · GET  /api/health -> HealthResponse
  · POST /api/chat   -> ChatResponse
其余类作为请求体 / 子模型被端点或上述响应模型直接引用。

历史上本文件曾定义 27 个模型（含"未来 API 预留"），其中 20 个零引用，
已于本次清理中移除。若新增 API 请**同时**在端点上引用模型，
否则该模型不会生效。
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ===== 健康检查 =====

class HealthResponse(BaseModel):
    """健康检查响应（GET /api/health）"""
    status: str = Field(..., description="服务状态: healthy/degraded/error")
    version: str = Field(..., description="系统版本")
    llm_model: Optional[str] = Field(None, description="LLM 模型名称")
    llm_available: bool = Field(..., description="LLM 是否可用")
    chroma_count: Optional[int] = Field(None, description="ChromaDB 文档数")
    uptime: Optional[float] = Field(None, description="运行时长(秒)")


# ===== 知识库 =====

class KnowledgeSearchResult(BaseModel):
    """单条检索结果（被 /api/knowledge/search 响应直接使用）"""
    id: str
    title: Optional[str] = None
    content: str
    metadata: Optional[Dict[str, Any]] = None
    distance: Optional[float] = None
    rerank_score: Optional[float] = None


# ===== 基线管理 =====

class BaselineProfile(BaseModel):
    """基线画像（被 BaselineInfo.profile 引用）"""
    dimension: str
    median: float
    mad: float
    samples: int


class BaselineInfo(BaseModel):
    """基线信息（/api/baseline/list 与 /api/baseline/get 的子模型）"""
    name: str
    window_sec: int
    learned: bool
    total_packets: Optional[int] = None
    total_windows: Optional[int] = None
    created_at: Optional[str] = None
    description: Optional[str] = None
    profile: Optional[List[BaselineProfile]] = None


# ===== PCAP 分析 =====

class AnalyzeRequest(BaseModel):
    """分析请求（包列表模式，POST /api/pcap/analyze）"""
    packets: List[Dict[str, Any]]
    enable_ai_analysis: bool = True
    baseline_name: Optional[str] = None


# ===== 安全问答 =====

class ChatRequest(BaseModel):
    """安全问答请求（POST /api/chat）"""
    question: str = Field(..., min_length=1, max_length=1000)
    context: Optional[str] = None
    use_rag: bool = True
    stream: bool = False


class ChatResponse(BaseModel):
    """安全问答响应（POST /api/chat）"""
    question: str
    answer: str
    sources: Optional[List[Dict[str, Any]]] = None
    rag_used: bool = False
    response_time_ms: Optional[float] = None
