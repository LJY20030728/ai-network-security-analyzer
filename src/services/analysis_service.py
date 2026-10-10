# -*- coding: utf-8 -*-
"""
分析流水线服务层（唯一实现）

背景：同一套「解析 → 检测 → AI 研判 → 幻觉控制 → 生成报告」此前有三份副本：
  · src/ui/gradio_app.py 的 _analyze_pcap_task（API 同步/异步、历史重新分析）
  · src/ui/gradio_app.py 的 analyze_pcap_gradio（UI 流式）
  · src/ui/gradio_app.py 的 confirm_regen_report_ui（历史重新生成报告）
三者在 kwargs、是否流式、**是否跑幻觉控制** 上互不一致，导致同一个 case_id
可能产出两份不同正文的报告（证据链自相矛盾）。

本模块提供**单一实现**。UI 层只负责展示（流式 yield）与持久化（写历史/复制 PCAP）。
"""
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from loguru import logger

from config.settings import settings
from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer
from src.utils.helpers import calculate_file_sha256, get_timestamp_str


@dataclass
class AnalysisOutcome:
    """分析产物（不含展示与持久化）"""

    report: Dict[str, Any]
    evidence: Dict[str, Any] = field(default_factory=dict)
    case_id: Optional[str] = None
    summary: str = ""
    report_json: str = ""
    packet_count: int = 0
    # AI 产物
    ai_text: str = ""
    ai_structured: Optional[Dict[str, Any]] = None
    ai_structured_ok: bool = False
    ai_traffic_summary: Optional[str] = None
    ai_failed: bool = False
    ai_warning: Optional[str] = None
    # 幻觉控制
    hallucination: Optional[Dict[str, Any]] = None
    # 报告
    html_path: Optional[str] = None
    # 供 UI 流式展示用的原始样本包
    samples: List[Any] = field(default_factory=list)


def quick_sha256(filepath: str) -> str:
    """文件 SHA-256（委托 utils.helpers，避免各处重复实现）"""
    return calculate_file_sha256(filepath)


def load_baseline_into(analyzer: TrafficAnalyzer, baseline_name: str) -> bool:
    """加载基线到分析器（P1-4: 优先 SQLite，回退 JSON）"""
    if not baseline_name:
        return False
    from src.analysis.baseline import TrafficBaseline
    from src.storage.database import Database

    try:
        db = Database()
        bl = db.get_baseline(baseline_name)
    except Exception as e:
        logger.warning(f"读取基线失败（回退 JSON）: {e}")
        bl = None

    if bl and bl.get("learned"):
        # 从 SQLite 数据重建 TrafficBaseline 对象
        b = TrafficBaseline(window_sec=bl.get("window_sec", 5))
        b.name = baseline_name
        b._learned = True
        prof = bl.get("profile", {})
        if isinstance(prof, dict) and "profile" in prof:
            b.profile = prof["profile"]
        elif isinstance(prof, dict):
            b.profile = prof
        analyzer.baseline = b
        logger.info(f"已加载基线(SQLite): {baseline_name}")
        return True

    # 回退到 JSON（文件名安全化策略与 UI 层一致：仅保留字母数字与 -_）
    from src.utils.paths import data_dir
    safe = "".join(ch for ch in (baseline_name or "") if ch.isalnum() or ch in "-_") or "baseline"
    b = TrafficBaseline.load(os.path.join(data_dir("baselines"), f"{safe[:64]}.json"))
    if b and b.learned:
        analyzer.baseline = b
        logger.info(f"已加载基线(JSON): {b.name or baseline_name}")
        return True
    logger.warning(f"基线加载失败或未学习: {baseline_name}")
    return False


def _samples_to_dicts(samples: List[Any]) -> List[Dict[str, Any]]:
    """原始样本包 → dict 列表（供 AI 研判使用）

    注意：不可用 parser.to_dict_list() 于 iter_packets 之后——流式解析从不填充
    parser.captured_packets，那样会得到空列表。
    """
    if not samples:
        return []
    from src.capture.packet_parser import PacketParser as _PP

    pp = _PP()
    pp.captured_packets = samples
    return pp.to_dict_list()


def run_analysis(
    filepath: str,
    enable_ai: bool = True,
    baseline_name: str = "",
    *,
    sample_count: int = 50,
    ai_mode: str = "structured",
    run_hallucination: bool = True,
    generate_report: bool = True,
    on_progress: Optional[Callable[[str], None]] = None,
    on_ai_chunk: Optional[Callable[[str], None]] = None,
    on_summary_ready: Optional[Callable[[str], None]] = None,
) -> AnalysisOutcome:
    """执行完整分析流水线（唯一实现）。

    :param ai_mode: "structured"（非流式，含流量概览，API 路径）或 "stream"（流式，UI 路径）
    :param run_hallucination: 是否运行幻觉控制。**两条路径统一为 True**——
        此前 API 路径不跑、UI 路径跑，导致同一 case 的产物不含同等校验。
    :param on_progress: 进度回调（阶段文案），供 UI 流式展示
    :param on_ai_chunk: AI 流式分片回调
    :param on_summary_ready: 摘要就绪回调（阶段 1 结束后触发，供 UI 进度事件展示摘要）
    """
    def _progress(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    _progress("阶段 1/4：解析 PCAP 并提取网络流特征")

    sha256 = quick_sha256(filepath)
    parser = PcapParser()
    traffic_analyzer = TrafficAnalyzer()
    if baseline_name:
        load_baseline_into(traffic_analyzer, baseline_name)

    try:
        report = traffic_analyzer.analyze_stream(
            parser.iter_packets(filepath), sample_count=sample_count)
    except Exception as e:
        logger.error(f"流式分析失败: {e}")
        raise ValueError("PCAP文件解析失败或为空") from e

    packet_count = (report or {}).get("summary", {}).get("total_packets", 0)
    if not packet_count:
        raise ValueError("PCAP文件解析失败或为空")

    samples = (report or {}).pop("_samples", []) or []
    _samples_dict = _samples_to_dicts(samples)

    from src.report.summary_formatter import format_analysis_summary

    outcome = AnalysisOutcome(
        report=report,
        packet_count=packet_count,
        samples=samples,
        summary=format_analysis_summary(report),
        # 与 API/UI 两处保持一致：case_id 由 PCAP 内容哈希决定
        case_id=f"PCAP-{sha256[:16]}" if sha256 else None,
        evidence={
            "source_file": os.path.basename(filepath),
            "source_sha256": sha256,
            "analyzed_at": get_timestamp_str(),
            "rule_version": settings.version,
        },
    )

    import json as _json

    outcome.report_json = _json.dumps(report, ensure_ascii=False, indent=2, default=str)

    # 摘要已就绪：通知 UI（进度事件需要展示摘要，而进度事件早于最终返回值）
    if on_summary_ready:
        try:
            on_summary_ready(outcome.summary)
        except Exception as e:  # 回调失败不能影响主流程
            logger.debug(f"on_summary_ready 回调异常: {e}")

    # ---------- AI 研判 ----------
    if enable_ai:
        from src.ai.llm_client import get_llm_client

        llm = get_llm_client()
        if llm.is_available():
            from src.ai.threat_analyzer import get_threat_analyzer

            threat_analyzer = get_threat_analyzer()
            if ai_mode == "stream":
                _progress("阶段 2/4：RAG 知识检索（MITRE ATT&CK + 处置手册）")
                _progress("阶段 3/4：AI 威胁研判中（流式输出）")
                buf = []
                for chunk in threat_analyzer.analyze_threats_stream(
                        report["anomaly_detection"], packet_samples=_samples_dict):
                    buf.append(chunk)
                    if on_ai_chunk:
                        on_ai_chunk("".join(buf))
                outcome.ai_text = "".join(buf)
            else:
                _progress("阶段 2/4：AI 威胁研判（结构化）")
                structured = threat_analyzer.analyze_threats_structured(
                    report["anomaly_detection"], packet_samples=_samples_dict)
                outcome.ai_text = structured.get("raw_text", "") or ""
                outcome.ai_structured = structured.get("structured")
                outcome.ai_structured_ok = bool(structured.get("ok"))
                outcome.ai_failed = outcome.ai_text.startswith(("[大模型调用失败]", "[LLM"))
                _progress("阶段 3/4：AI 流量概览")
                outcome.ai_traffic_summary = threat_analyzer.analyze_traffic_summary(
                    report["summary"], report["protocol_distribution"], report["top_talkers"])
        else:
            outcome.ai_warning = "未配置大模型API Key，跳过AI分析"
            outcome.ai_text = ("⚠️ 未配置大模型API Key，无法进行AI分析\n"
                               "请在⚙️设置中配置LLM_API_KEY")

    # ---------- 幻觉控制（统一在两路都跑） ----------
    if run_hallucination:
        try:
            from src.ai.hallucination_control import run_hallucination_control
            from src.report.summary_formatter import format_hallucination_block

            outcome.hallucination = run_hallucination_control(
                outcome.ai_text or "",
                report.get("anomaly_detection", {}),
                report.get("stacking_fusion"),
                report.get("baseline_profile"),
            )
            # 与 UI 路径原有行为一致：把校验块附加到研判文本末尾
            if outcome.hallucination:
                outcome.ai_text += "\n\n" + format_hallucination_block(outcome.hallucination)
        except Exception as e:
            logger.warning(f"幻觉控制失败（不影响主流程）: {e}")

    # ---------- HTML 报告（硬失败） ----------
    if generate_report:
        _progress("阶段 4/4：生成取证型 HTML 报告")
        from src.report.html_report import save_html_report
        from src.utils.paths import data_dir

        try:
            outcome.html_path = save_html_report(
                report,
                outcome.evidence,
                ai_analysis=outcome.ai_text,
                ai_traffic_summary=outcome.ai_traffic_summary,
                structured_report=outcome.ai_structured,
                report_dir=data_dir("reports"),
                case_id=outcome.case_id,
            )
        except Exception as e:
            # 硬失败：绝不留空的 html_path 让下载按钮退化为"取目录里最新报告"
            logger.error(f"HTML 报告生成失败: {e}")
            raise RuntimeError(f"报告生成失败: {e}") from e

    return outcome
