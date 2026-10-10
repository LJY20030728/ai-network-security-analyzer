# -*- coding: utf-8 -*-
"""
幻觉控制 的回归测试

锁定三个已确认缺陷（均由实测复现）：

1. **LLM 调用失败被认证为合格输出**。`llm_client` 失败时返回哨兵字符串而非抛
   异常，而 `OutputValidator` 对任何 ≥20 字符的串都给 1.0 分——于是「API 报 401」
   在报告里被渲染成「校验分 1.0 (pass) / 幻觉风险 low」，与同页的报错自相矛盾。
   现改为 `level="unavailable"`，报告改为「AI 分析不可用」且不展示分数。

2. **否定词反向计分**：`"未发现"` 含子串 `"发现"`（攻击信号），一句
   「未发现攻击，流量正常」同时给两边计分，互相抵消后返回 unknown。
   现按**小句处理否定辖域**：含否定式的小句只计正常票，其内部攻击词不再计分。

3. **报错串被当作攻击技术**：`[大模型调用失败] Error code: 401 -
   Authentication Fails` 会把 "Authentication Fails" 提取为"攻击技术"；
   且 `KNOWN_ATTACK_TECHNIQUES` 混入 Analysis / Generic / DoS 等泛词，
   使"未识别技术"校验形同虚设。

本文件为新增测试，不修改任何既有测试。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ai.hallucination_control import (  # noqa: E402
    ConfidenceCrossValidator,
    OutputValidator,
    run_hallucination_control,
)
from src.report.summary_formatter import format_hallucination_block  # noqa: E402

RULES_ZERO = {"total_alerts": 0, "alerts": []}
RULES_SOME = {"total_alerts": 3, "alerts": [{"severity": "high"}]}
STACKING_NORMAL = {"is_attack": False, "confidence": 0.95}
STACKING_ATTACK = {"is_attack": True, "confidence": 0.9}


# ----------------------------------------------------------------------
# 缺陷 1：失败检测
# ----------------------------------------------------------------------

@pytest.mark.parametrize("failed_output", [
    "[大模型调用失败] Error code: 401 - {'error': {'message': 'Authentication Fails'}}",
    "[大模型调用失败] 400 messages 参数非法",
    "[错误] 未配置大模型API Key，请在.env文件中设置LLM_API_KEY",
    "[LLM timeout]",
    "[LLM error] connection reset",
])
def test_llm_failure_is_not_certified_as_pass(failed_output):
    """核心回归：失败输出绝不能被判为 pass / 低风险。"""
    result = run_hallucination_control(failed_output, RULES_ZERO, None, None)
    ov = result["output_validation"]

    assert ov["level"] == "unavailable", ov
    assert ov["valid"] is False
    assert ov["score"] == 0.0
    assert result["hallucination_risk"] == "unavailable"
    assert result["available"] is False
    assert result["review_marker"]["needs_review"] is True
    assert result["review_marker"]["priority"] == "high"
    assert result["overall_score"] == 0.0


def test_detect_llm_failure_only_matches_head():
    """只匹配开头哨兵，正文中偶然引用同样字串不算失败。"""
    assert OutputValidator.detect_llm_failure("[大模型调用失败] boom") is not None
    body = "分析结论：本次未出现 [大模型调用失败] 这类错误，链路正常。" * 2
    assert OutputValidator.detect_llm_failure(body) is None


def test_empty_output_is_unavailable():
    result = run_hallucination_control("", RULES_ZERO, None, None)
    assert result["output_validation"]["level"] == "unavailable"
    assert result["available"] is False


def test_report_block_hides_score_when_unavailable():
    """报告不得在 AI 不可用时展示校验分/风险等级。"""
    hv = run_hallucination_control("[大模型调用失败] 401", RULES_ZERO, None, None)
    block = format_hallucination_block(hv)

    assert "AI 分析不可用" in block
    assert "输出校验分: " not in block, "不可用时仍展示了校验分"
    assert "幻觉风险: unavailable" not in block


def test_report_block_still_shows_score_when_available():
    good = ("根据流量分析，检测到源 IP 10.0.0.5 发起 SYN Flood 攻击，"
            "共 500 个未完成握手，建议封禁该 IP 并排查横向移动。")
    hv = run_hallucination_control(good, RULES_SOME, STACKING_ATTACK, None)
    assert hv["available"] is True
    block = format_hallucination_block(hv)
    assert "输出校验分: " in block
    assert "AI 分析不可用" not in block


# ----------------------------------------------------------------------
# 缺陷 2：否定辖域
# ----------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("本次未发现攻击行为，流量表现正常，不排除误报。", "normal"),
    ("未检测到任何恶意流量。", "normal"),
    ("未发现异常，流量正常。", "normal"),
    ("无可疑活动，no anomaly detected。", "normal"),
    ("检测到 3 条告警，均为正常业务的误报。", "normal"),
    ("流量正常，无异常。", "normal"),
    ("存在 SYN Flood 攻击，恶意入侵行为明确。", "attack"),
    ("发现 2 个可疑 IP 正在发起入侵攻击。", "attack"),
    ("确认存在入侵行为，攻击者已建立 C2 通道。", "attack"),
])
def test_verdict_respects_negation_scope(text, expected):
    assert ConfidenceCrossValidator._parse_llm_verdict(text) == expected, text


def test_negation_does_not_leak_across_clauses():
    """前句否定不应把后句的真实攻击断言也否掉。"""
    text = "未发现异常。但经深入分析，确认存在 SYN Flood 攻击与恶意入侵。"
    assert ConfidenceCrossValidator._parse_llm_verdict(text) == "attack"


def test_empty_or_neutral_text_is_unknown():
    assert ConfidenceCrossValidator._parse_llm_verdict("") == "unknown"
    assert ConfidenceCrossValidator._parse_llm_verdict("???") == "unknown"


# ----------------------------------------------------------------------
# 缺陷 3：攻击技术提取
# ----------------------------------------------------------------------

def test_failure_sentinel_yields_no_techniques():
    """报错串里的 "Authentication Fails" 不是攻击技术。"""
    techs = OutputValidator._extract_mentioned_techniques(
        "[大模型调用失败] Error code: 401 - Authentication Fails")
    assert techs == []


def test_generic_words_removed_from_known_techniques():
    for generic in ["Analysis", "Generic", "DoS", "Exploit", "利用", "Recon", "侦察",
                    "Fuzzing", "模糊测试"]:
        assert generic not in OutputValidator.KNOWN_ATTACK_TECHNIQUES, generic


def test_real_techniques_still_recognized():
    for real in ["SYN Flood", "端口扫描", "DNS Tunneling", "SQL Injection", "Shellcode"]:
        assert real in OutputValidator.KNOWN_ATTACK_TECHNIQUES, real


def test_known_technique_contains_no_duplicate_substring_pairs():
    """避免 r"毫无疑问" 与 r"毫无疑问是" 这类重复扣分（同一句话扣两次）。"""
    patterns = OutputValidator.HALLUCINATION_PATTERNS
    for a in patterns:
        for b in patterns:
            if a is not b and a in b:
                pytest.fail(f"模式 {a!r} 是 {b!r} 的子串，会造成重复扣分")


# ----------------------------------------------------------------------
# 正常路径无回归
# ----------------------------------------------------------------------

def test_normal_output_still_scored():
    good = ("根据流量分析，检测到源 IP 10.0.0.5 发起 SYN Flood 攻击，"
            "共 500 个未完成握手，建议封禁该 IP。")
    result = run_hallucination_control(good, RULES_SOME, STACKING_ATTACK, None)
    assert result["available"] is True
    assert result["output_validation"]["level"] in ("pass", "warning", "fail")
    assert result["hallucination_risk"] in ("low", "medium", "high")
    # 结构完整性：下游依赖这些键
    for key in ("output_validation", "cross_validation", "review_marker",
                "overall_score", "hallucination_risk", "summary"):
        assert key in result, key


def test_evidence_consistency_check_is_reachable():
    """矛盾检测必须真的能触发（此前曾被误报为死代码路径）。"""
    text = "本次流量确认为 SYN Flood 攻击，存在明显的恶意入侵行为。"
    result = run_hallucination_control(text, RULES_ZERO, STACKING_NORMAL, None)
    issues = result["output_validation"]["issues"]
    assert any("矛盾" in i for i in issues), issues
