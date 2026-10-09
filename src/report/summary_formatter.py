# -*- coding: utf-8 -*-
"""
分析结果 → 人类可读摘要文本（纯函数，与 UI 框架解耦）

抽离自 src/ui/gradio_app.py 的 Gradio 回调闭包。原先这段展示逻辑嵌在
流式回调内部，导致：
  1. 无法单元测试（必须启动 Gradio 才能执行）
  2. 单文件持续膨胀

本模块只做「数据 → 文本」的纯转换，不依赖 gradio / fastapi，可直接单测。

【诚信约束】监督模型部分的展示必须同时呈现 confidence_source，
禁止把聚合启发式先验（aggregate_heuristic）呈现为模型置信度。
"""
from typing import Any, Dict, List

# 置信度来源 → 中文标签（用于向用户说明这个数字是怎么来的）
CONFIDENCE_SOURCE_LABELS: Dict[str, str] = {
    "model": "元学习器输出（Stacking）",
    "weighted_fallback": "固定权重回退（非模型输出）",
}


def format_traffic_overview(report: Dict[str, Any]) -> str:
    """流量概览 + 协议分布"""
    summary_sec = report.get("summary", {}) or {}
    total_packets = summary_sec.get("total_packets", 0) or 0
    time_range = summary_sec.get("time_range", {}) or {}

    text = (
        "📊 流量分析概览\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 总数据包数: {total_packets}\n"
        f"🔀 网络流数量: {summary_sec.get('total_flows', 0)}\n"
        f"📈 总流量: {_format_bytes(summary_sec.get('total_bytes', 0))}\n"
        f"⏰ 时间范围: {time_range.get('start', '')} ~ {time_range.get('end', '')}\n"
        "\n📡 协议分布:\n"
    )
    if total_packets:
        for proto, count in (report.get("protocol_distribution") or {}).items():
            text += f"  • {proto}: {count} 包 ({count / total_packets * 100:.1f}%)\n"
    return text


def format_stacking_verdict(fus: Dict[str, Any]) -> str:
    """
    三引擎 Stacking 融合判定段落（规则 + 时序基线 + 孤立森林）。

    :param fus: report["stacking_fusion"]，可能为 None（融合未启用或失败）
    """
    if not fus:
        return ""

    verdict = "🔴 攻击" if fus.get("is_attack") else "🟢 正常"
    text = f"\n🎯 三引擎融合判定（规则 + 时序基线 + 孤立森林 → Stacking）: {verdict}\n"

    # 置信度 + 来源标注（诚信字段：必须让用户知道这个数字是不是模型算出来的）
    source = fus.get("confidence_source", "unknown")
    source_label = CONFIDENCE_SOURCE_LABELS.get(source, source)
    text += f"  • 置信度: {fus.get('confidence', 0):.2f}（来源: {source_label}）\n"
    text += f"  • 攻击概率: {fus.get('attack_prob', 0):.4f}\n"
    text += f"  • 元学习器: {'已使用' if fus.get('meta_learner_used') else '未加载（固定权重回退）'}\n"

    contrib = fus.get("contributions") or {}
    parts = " | ".join(f"{k}:{v:.0%}" for k, v in contrib.items() if v)
    if parts:
        text += f"  • 引擎贡献: {parts}\n"

    return text


def format_anomaly_summary(anomaly: Dict[str, Any]) -> str:
    """规则/基线/孤立森林合并后的告警汇总"""
    if not anomaly:
        return ""
    text = f"\n🚨 异常检测: 共 {anomaly.get('total_alerts', 0)} 条告警\n"
    for sev, count in (anomaly.get("severity_summary") or {}).items():
        if count > 0:
            text += f"  • {sev}: {count} 条\n"
    return text


def format_analysis_summary(report: Dict[str, Any]) -> str:
    """
    组装完整摘要（流量概览 + 三引擎融合判定 + 告警汇总）。

    这是 gradio_app 回调原先内联拼接的等价实现，抽取后可直接单测。
    """
    return (
        format_traffic_overview(report)
        + format_stacking_verdict(report.get("stacking_fusion"))
        + format_anomaly_summary(report.get("anomaly_detection") or {})
    )


def format_hallucination_block(hv: Dict[str, Any]) -> str:
    """
    幻觉控制结果段落（输出校验 + 多引擎共识 + 复核提示）。

    :param hv: run_hallucination_control 的返回值
    """
    if not hv:
        return ""
    text = "\n━━━━━━━━━━━━━━━━━━━━\n🛡️ 幻觉控制校验\n"
    ov = hv.get("output_validation") or {}
    text += f"  • 输出校验分: {ov.get('score')} ({ov.get('level')})\n"
    cv = hv.get("cross_validation") or {}
    text += (f"  • 多引擎共识: {cv.get('consensus')} "
             f"(一致性 {cv.get('agreement', 0):.0%})\n")
    text += f"  • 幻觉风险: {hv.get('hallucination_risk')}\n"

    rm = hv.get("review_marker") or {}
    if rm.get("needs_review"):
        text += f"  • ⚠️ 需人工复核: {rm.get('priority')}优先级\n"
        for reason in (rm.get("reasons") or [])[:3]:
            text += f"    - {reason}\n"
    if ov.get("issues"):
        text += f"  • 校验问题: {len(ov['issues'])} 项\n"
    return text


def _format_bytes(size_bytes: Any) -> str:
    """本地轻量字节格式化（避免 utils.helpers 的循环依赖风险）"""
    try:
        n = float(size_bytes or 0)
    except (TypeError, ValueError):
        return str(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"
