"""
LLM 结构化输出 Schema（Pydantic 校验）
======================================
将 LLM 的威胁研判从自由文本升级为可校验、可消费的 JSON 结构：
- 研判结论（是否威胁 / 置信度 / 攻击类型 / MITRE 技术映射）
- 每条告警的独立研判（真伪判定 / 置信度 / 证据 / 处置建议）
- 知识库引用（溯源）

校验失败时上层自动降级为文本模式，不阻塞主流程。
"""
from typing import List, Optional
from pydantic import BaseModel, Field


class AlertJudgment(BaseModel):
    """单条告警的 LLM 独立研判"""
    alert_type: str = Field(description="告警类型（如端口扫描 / SYN洪水 / DNS隧道）")
    mitre_technique: Optional[str] = Field(default=None, description="对应 MITRE ATT&CK 技术编号，如 T1046")
    is_true_positive: bool = Field(description="是否为真实攻击（排除误报）")
    confidence: float = Field(ge=0.0, le=1.0, description="置信度 0~1")
    evidence: str = Field(description="依据的关键证据（引用检测数据）")
    recommended_actions: List[str] = Field(default_factory=list, description="针对该告警的处置动作")


class StructuredThreatReport(BaseModel):
    """整体威胁研判报告"""
    overview: str = Field(description="总体研判摘要（1-2句）")
    is_threat: bool = Field(description="整体判断：是否存在真实威胁")
    overall_confidence: float = Field(ge=0.0, le=1.0, description="整体置信度 0~1")
    attacks: List[AlertJudgment] = Field(default_factory=list, description="逐告警研判明细")
    recommended_actions: List[str] = Field(default_factory=list, description="整体处置建议")
    knowledge_references: List[str] = Field(default_factory=list, description="引用的知识库来源（溯源）")


def try_parse_structured_report(raw_text: str) -> Optional[StructuredThreatReport]:
    """
    从 LLM 输出中提取并校验结构化报告。
    容错：支持 ```json 代码块 / 纯 JSON / 前后多余文本。
    失败返回 None（调用方降级为文本展示）。
    """
    if not raw_text or not raw_text.strip():
        return None

    text = raw_text.strip()
    # 剥离 markdown 代码块围栏
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].strip().lower().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # 提取首尾 JSON 大括号
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = text[start:end + 1]

    try:
        import json
        data = json.loads(candidate)
    except Exception:
        return None

    try:
        return StructuredThreatReport(**data)
    except Exception:
        return None
