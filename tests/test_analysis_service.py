# -*- coding: utf-8 -*-
"""
分析流水线服务层 + 报告生成健壮性 的回归测试

锁定三类已确认缺陷：
  4a 报告生成遇非数值 confidence/overall_confidence 抛异常 → 被宽 except 吞掉
     → report_html="" 但界面显示"分析完成" → 下载按钮取到**别的案件**的报告。
  4a 同一 case_id 被两条调用路径写成同名但内容不同的两份报告（证据链自相矛盾）。
  4c 同一套流水线存在三份副本，其中 API 路径**完全不跑幻觉控制**。

本文件为新增测试，不修改任何既有测试。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.report.html_report import _coerce_num, _fmt_conf, build_html_report, save_html_report  # noqa: E402

ANALYSIS = {
    "summary": {"total_packets": 200, "total_flows": 6, "total_bytes": 4096,
                "time_range": {"start": "2026-01-01 00:00:00", "end": "2026-01-01 00:05:00"}},
    "anomaly_detection": {
        "alerts": [{"type": "SYN_FLOOD_SUSPECTED", "severity": "HIGH", "description": "d",
                    "detector": "rules", "z_score": 22.68, "value": 34, "baseline_median": 0.38}],
        "total_alerts": 1, "severity_summary": {"HIGH": 1}},
    "protocol_distribution": {"TCP": 190, "UDP": 10},
    "baseline_profile": {"window_sec": 10, "profile": {"window_packets": {"median": 10, "mad": 2}}},
}
EVIDENCE = {"source_file": "x.pcap", "source_sha256": "abc123",
            "analyzed_at": "2026-01-01 00:00:00", "rule_version": "3.3.0"}


def _structured(conf):
    return {"is_threat": True, "overall_confidence": conf, "overview": "o",
            "attacks": [{"alert_type": "A", "mitre_technique": "T1046",
                         "is_true_positive": True, "confidence": conf,
                         "evidence": "e", "recommended_actions": ["a"]}]}


# ----------------------------------------------------------------------
# 4a-1 数值兜底：非数值置信度不得让报告生成失败
# ----------------------------------------------------------------------

@pytest.mark.parametrize("value", ["0.9", None, "high", True, [], {}])
def test_numeric_string_and_odd_values_do_not_crash(value):
    """这些值此前会抛 ValueError/TypeError，导致报告静默为空。"""
    html = build_html_report(ANALYSIS, EVIDENCE, "ai", None, _structured(value), "CASE-X")
    assert isinstance(html, str) and html


def test_coerce_num_semantics():
    assert _coerce_num(0.5) == (0.5, None)
    assert _coerce_num("0.9") == (0.9, None)          # 数值字符串可转换
    assert _coerce_num(3) == (3.0, None)
    num, raw = _coerce_num("high")
    assert num == 0.0 and raw == "high"                # 失败 → 默认值 + 保留原值
    num, raw = _coerce_num(None)
    assert num == 0.0 and raw == "None"
    num, raw = _coerce_num(True)
    assert num == 0.0 and raw == "True"                # bool 作为置信度无意义


def test_unparsable_confidence_is_flagged_not_hidden():
    """不可解析时必须显式标注原值，而不是静默当成 0.0。"""
    html = build_html_report(ANALYSIS, EVIDENCE, None, None, _structured("high"), "CASE-X")
    assert "原始值不可解析" in html
    assert "high" in html


def test_valid_confidence_renders_two_decimals_without_flag():
    html = build_html_report(ANALYSIS, EVIDENCE, None, None, _structured(0.5), "CASE-X")
    assert "(conf 0.50)" in html
    assert "置信度 0.50" in html
    assert "原始值不可解析" not in html


def test_fmt_conf_escapes_marker():
    """原值标记也要转义，避免借置信度字段注入。"""
    out = _fmt_conf("<script>x</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


# ----------------------------------------------------------------------
# 4a-2 文件名含正文内容哈希：同一 case_id 不再互相覆盖
# ----------------------------------------------------------------------

def test_same_case_id_different_content_does_not_overwrite(tmp_path):
    p1 = save_html_report(ANALYSIS, EVIDENCE, "AI-A", None, None,
                          report_dir=str(tmp_path), case_id="PCAP-deadbeef")
    p2 = save_html_report(ANALYSIS, EVIDENCE, "AI-B", None, None,
                          report_dir=str(tmp_path), case_id="PCAP-deadbeef")
    assert p1 != p2, "不同正文写成同一文件 —— 证据链会被覆盖"
    assert os.path.isfile(p1) and os.path.isfile(p2)
    assert "PCAP-deadbeef" in os.path.basename(p1)
    for p in (p1, p2):
        os.remove(p)


def test_same_content_is_idempotent(tmp_path):
    """内容相同 → 文件名相同（可安全重跑，不产生垃圾文件）。"""
    kw = dict(report_dir=str(tmp_path), case_id="PCAP-cafebabe")
    p1 = save_html_report(ANALYSIS, EVIDENCE, "AI-A", None, None, **kw)
    p2 = save_html_report(ANALYSIS, EVIDENCE, "AI-A", None, None, **kw)
    assert p1 == p2
    assert len([f for f in os.listdir(tmp_path) if f.endswith(".html")]) == 1
    os.remove(p1)


def test_report_filename_has_content_hash_suffix(tmp_path):
    import re
    p = save_html_report(ANALYSIS, EVIDENCE, None, None, None,
                         report_dir=str(tmp_path), case_id="PCAP-1234")
    assert re.search(r"_[0-9a-f]{8}\.html$", os.path.basename(p)), os.path.basename(p)
    os.remove(p)


# ----------------------------------------------------------------------
# 4c 服务层：两条路径统一跑幻觉控制
# ----------------------------------------------------------------------

PCAP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "samples", "golden", "synflood.pcap")


@pytest.mark.skipif(not os.path.isfile(PCAP), reason="缺少 golden 样本 synflood.pcap")
def test_service_runs_hallucination_on_both_paths(tmp_path):
    """API 路径（structured）此前完全不跑幻觉控制，与 UI 路径产物不等价。"""
    from src.services.analysis_service import run_analysis

    for mode in ("structured", "stream"):
        out = run_analysis(PCAP, enable_ai=False, ai_mode=mode,
                           run_hallucination=True, generate_report=False)
        assert out.hallucination is not None, f"{mode} 路径未运行幻觉控制"
        assert out.report.get("summary", {}).get("total_packets", 0) > 0
        assert "_samples" not in out.report, "_samples 未被 pop，会污染报告 JSON"


@pytest.mark.skipif(not os.path.isfile(PCAP), reason="缺少 golden 样本 synflood.pcap")
def test_service_emits_summary_ready_and_progress_callbacks():
    from src.services.analysis_service import run_analysis

    progress, summaries = [], []
    run_analysis(PCAP, enable_ai=False, ai_mode="structured",
                 run_hallucination=False, generate_report=False,
                 on_progress=progress.append, on_summary_ready=summaries.append)
    assert progress, "未回调任何进度"
    assert summaries and summaries[0], "未回调摘要（UI 进度事件需要展示摘要）"


@pytest.mark.skipif(not os.path.isfile(PCAP), reason="缺少 golden 样本 synflood.pcap")
def test_service_report_failure_is_hard_error(monkeypatch):
    """报告生成失败必须上抛，不能返回一个 html_path=None 的"成功"结果。"""
    import src.services.analysis_service as svc
    import src.report.html_report as hr

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(hr, "save_html_report", boom)
    with pytest.raises(RuntimeError, match="报告生成失败"):
        svc.run_analysis(PCAP, enable_ai=False, run_hallucination=False, generate_report=True)


@pytest.mark.skipif(not os.path.isfile(PCAP), reason="缺少 golden 样本 synflood.pcap")
def test_service_empty_pcap_raises_value_error(tmp_path):
    from src.services.analysis_service import run_analysis

    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(ValueError):
        run_analysis(str(empty), enable_ai=False, run_hallucination=False, generate_report=False)
