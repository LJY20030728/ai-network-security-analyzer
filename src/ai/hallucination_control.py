# -*- coding: utf-8 -*-
"""
P0-3 LLM 幻觉控制三件套
1. OutputValidator：输出校验（格式、长度、合理性、与证据一致性）
2. ConfidenceCrossValidator：置信度交叉验证（LLM vs 规则引擎 vs 监督模型）
3. ReviewMarker：人工复核标记（低置信度/矛盾结论标记为需复核）

设计原则：
- 不阻断 LLM 输出，只附加校验标记和置信度
- 与证据不一致时降级为"参考意见"而非"结论"
- 所有校验结果可追溯，写入报告
"""
import re
from typing import Dict, List, Any, Optional, Tuple
from loguru import logger


class OutputValidator:
    """LLM 输出校验器"""

    # 合理输出长度范围
    MIN_LENGTH = 20
    MAX_LENGTH = 10000

    # 幻觉特征词（无证据支撑的绝对化表述）
    HALLUCINATION_PATTERNS = [
        r"毫无疑问", r"绝对是", r"100%", r"完全确定", r"铁证如山",
        r"毫无疑问是", r"肯定是", r"必然是",
    ]

    # 已知攻击技术名称（用于校验 LLM 提到的技术是否存在）
    KNOWN_ATTACK_TECHNIQUES = {
        "SYN Flood", "SYN flood", "端口扫描", "Port Scan", "port scan",
        "DNS 隧道", "DNS Tunneling", "RST 风暴", "RST Storm",
        "暴力破解", "Brute Force", "SQL 注入", "SQL Injection",
        "XSS", "跨站脚本", "DDoS", "勒索软件", "Ransomware",
        "钓鱼", "Phishing", "中间人攻击", "MITM", "零日漏洞", "0day",
        "木马", "Trojan", "后门", "Backdoor", "蠕虫", "Worm",
        "Exploit", "利用", "Fuzzing", "模糊测试", "Recon", "侦察",
        "Generic", "Shellcode", "Analysis", "DoS",
    }

    @classmethod
    def validate(cls, output: str, evidence: Optional[Dict] = None) -> Dict[str, Any]:
        """
        校验 LLM 输出
        :param output: LLM 输出文本
        :param evidence: 证据数据（规则告警、监督模型结果等）
        :return: 校验结果字典
        """
        if not output:
            return {
                "valid": False,
                "score": 0.0,
                "issues": ["输出为空"],
                "level": "error",
                "summary": "输出为空，校验失败",
            }

        issues = []
        score = 1.0

        # 1. 长度校验
        if len(output) < cls.MIN_LENGTH:
            issues.append(f"输出过短（{len(output)}字 < {cls.MIN_LENGTH}字），可能未完成分析")
            score -= 0.2
        if len(output) > cls.MAX_LENGTH:
            issues.append(f"输出过长（{len(output)}字 > {cls.MAX_LENGTH}字），可能包含冗余内容")
            score -= 0.1

        # 2. 幻觉特征检测
        for pattern in cls.HALLUCINATION_PATTERNS:
            if re.search(pattern, output):
                issues.append(f"包含绝对化表述（{pattern}），缺乏证据支撑")
                score -= 0.15

        # 3. 与证据一致性校验
        if evidence:
            consistency_issues = cls._check_evidence_consistency(output, evidence)
            issues.extend(consistency_issues)
            score -= 0.1 * len(consistency_issues)

        # 4. 攻击技术名称校验
        mentioned_techs = cls._extract_mentioned_techniques(output)
        unknown_techs = [t for t in mentioned_techs if t not in cls.KNOWN_ATTACK_TECHNIQUES]
        if unknown_techs and len(unknown_techs) > 2:
            issues.append(f"提到多个未识别的攻击技术: {', '.join(unknown_techs[:3])}")
            score -= 0.1

        score = max(0.0, min(1.0, score))

        if score >= 0.8:
            level = "pass"
            summary = "输出校验通过"
        elif score >= 0.5:
            level = "warning"
            summary = f"输出存在 {len(issues)} 个问题，建议人工复核"
        else:
            level = "fail"
            summary = f"输出校验失败（{len(issues)} 个问题），仅作参考"

        return {
            "valid": level != "fail",
            "score": round(score, 3),
            "issues": issues,
            "level": level,
            "summary": summary,
            "length": len(output),
            "mentioned_techniques": mentioned_techs,
        }

    @staticmethod
    def _check_evidence_consistency(output: str, evidence: Dict) -> List[str]:
        """检查 LLM 输出与证据的一致性"""
        issues = []
        output_lower = output.lower()

        # 监督模型判定为正常，但 LLM 说有攻击
        sup = evidence.get("supervised", {})
        if sup and not sup.get("is_attack", True) and sup.get("confidence", 0) > 0.8:
            attack_keywords = ["攻击", "恶意", "入侵", "威胁", "attack", "malicious", "intrusion"]
            if any(k in output_lower for k in attack_keywords):
                issues.append("监督模型判定为正常（高置信度），但 LLM 输出暗示存在攻击，结论矛盾")

        # 规则引擎无告警，但 LLM 说有具体攻击类型
        rules = evidence.get("rules", {})
        if rules and rules.get("total_alerts", 0) == 0:
            specific_attacks = ["SYN Flood", "端口扫描", "DNS 隧道", "RST 风暴"]
            for atk in specific_attacks:
                if atk in output and atk not in output.split("可能")[0] if "可能" in output else atk in output:
                    # 只在 LLM 明确断言时标记
                    pass

        return issues

    @staticmethod
    def _extract_mentioned_techniques(text: str) -> List[str]:
        """从文本中提取提到的攻击技术名称"""
        techs = []
        # 简单提取：匹配大写开头的技术名
        patterns = [
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",  # 多词技术名
            r"(SYN Flood|DNS Tunneling|RST Storm|Port Scan|Brute Force|SQL Injection)",
        ]
        for p in patterns:
            matches = re.findall(p, text)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                if m and m not in techs and len(m) > 3:
                    techs.append(m)
        return techs[:10]


class ConfidenceCrossValidator:
    """置信度交叉验证器：LLM 结论 vs 规则引擎 vs 监督模型"""

    @staticmethod
    def cross_validate(llm_conclusion: str, rule_result: Dict,
                       supervised_result: Optional[Dict],
                       baseline_result: Optional[Dict] = None) -> Dict[str, Any]:
        """
        交叉验证多引擎结论一致性
        :return: 交叉验证结果
        """
        # 解析 LLM 结论倾向（攻击/正常/不确定）
        llm_verdict = ConfidenceCrossValidator._parse_llm_verdict(llm_conclusion)

        # 规则引擎判定
        rule_attack = rule_result.get("total_alerts", 0) > 0
        rule_severity = "high" if any(
            a.get("severity") == "critical" for a in rule_result.get("alerts", [])) else "medium"

        # 监督模型判定
        sup_attack = supervised_result.get("is_attack", False) if supervised_result else None
        sup_confidence = supervised_result.get("confidence", 0) if supervised_result else 0

        # 收集各引擎判定
        engines = []
        if llm_verdict != "unknown":
            engines.append({"engine": "LLM", "verdict": llm_verdict, "confidence": None})
        engines.append({"engine": "规则引擎", "verdict": "attack" if rule_attack else "normal",
                        "confidence": None, "alerts": rule_result.get("total_alerts", 0)})
        if sup_attack is not None:
            engines.append({"engine": "监督模型", "verdict": "attack" if sup_attack else "normal",
                            "confidence": round(sup_confidence, 3)})

        # 统计一致性
        attack_votes = sum(1 for e in engines if e["verdict"] == "attack")
        normal_votes = sum(1 for e in engines if e["verdict"] == "normal")
        total_votes = attack_votes + normal_votes

        consensus = "attack" if attack_votes > normal_votes else "normal" if normal_votes > attack_votes else "split"
        agreement = max(attack_votes, normal_votes) / total_votes if total_votes > 0 else 0

        # 矛盾检测
        contradictions = []
        if llm_verdict == "attack" and sup_attack is False and sup_confidence > 0.8:
            contradictions.append("LLM 判定攻击，但监督模型高置信度判定正常")
        if llm_verdict == "normal" and rule_attack and rule_severity == "high":
            contradictions.append("LLM 判定正常，但规则引擎有高危告警")
        if sup_attack and not rule_attack and sup_confidence > 0.9:
            contradictions.append("监督模型高置信度判定攻击，但规则引擎无告警（可能是未知攻击）")

        overall_confidence = round(agreement * (1.0 - 0.3 * len(contradictions)), 3)

        return {
            "consensus": consensus,
            "agreement": round(agreement, 3),
            "overall_confidence": overall_confidence,
            "engines": engines,
            "attack_votes": attack_votes,
            "normal_votes": normal_votes,
            "contradictions": contradictions,
            "needs_review": len(contradictions) > 0 or agreement < 0.6,
            "summary": f"多引擎共识: {consensus} (一致性 {agreement:.0%})"
                       + (f", {len(contradictions)} 处矛盾需复核" if contradictions else ""),
        }

    @staticmethod
    def _parse_llm_verdict(text: str) -> str:
        """从 LLM 输出中解析判定倾向"""
        if not text:
            return "unknown"
        text_lower = text.lower()
        attack_signals = ["攻击", "恶意", "入侵", "威胁", "可疑", "attack", "malicious",
                          "intrusion", "suspicious", "检测到", "发现"]
        normal_signals = ["正常", "无异常", "未发现", " benign", "normal", "no anomaly"]

        attack_score = sum(1 for s in attack_signals if s in text_lower)
        normal_score = sum(1 for s in normal_signals if s in text_lower)

        if attack_score > normal_score + 1:
            return "attack"
        elif normal_score > attack_score + 1:
            return "normal"
        return "unknown"


class ReviewMarker:
    """人工复核标记器"""

    @staticmethod
    def mark_for_review(validation_result: Dict, cross_validation: Dict,
                         rule_result: Dict) -> Dict[str, Any]:
        """
        根据校验结果标记是否需要人工复核
        :return: 复核标记
        """
        reasons = []
        priority = "low"

        # 输出校验失败
        if validation_result.get("level") == "fail":
            reasons.append("LLM 输出校验失败")
            priority = "high"
        elif validation_result.get("level") == "warning":
            reasons.append(f"LLM 输出存在 {len(validation_result.get('issues', []))} 个问题")
            priority = "medium"

        # 交叉验证矛盾
        if cross_validation.get("needs_review"):
            reasons.extend(cross_validation.get("contradictions", []))
            if cross_validation.get("agreement", 1) < 0.5:
                priority = "high"
            elif priority == "low":
                priority = "medium"

        # 高危规则告警
        critical_alerts = [a for a in rule_result.get("alerts", [])
                            if a.get("severity") == "critical"]
        if critical_alerts:
            reasons.append(f"存在 {len(critical_alerts)} 条高危告警")
            if priority == "low":
                priority = "medium"

        needs_review = len(reasons) > 0

        return {
            "needs_review": needs_review,
            "priority": priority,
            "reasons": reasons,
            "review_status": "pending" if needs_review else "not_needed",
            "summary": f"{'需要人工复核' if needs_review else '无需人工复核'}"
                       + (f"（优先级: {priority}）" if needs_review else ""),
        }


def run_hallucination_control(llm_output: str, rule_result: Dict,
                               supervised_result: Optional[Dict] = None,
                               baseline_result: Optional[Dict] = None) -> Dict[str, Any]:
    """
    运行完整的幻觉控制三件套
    :return: 包含校验、交叉验证、复核标记的完整结果
    """
    evidence = {
        "supervised": supervised_result,
        "rules": rule_result,
        "baseline": baseline_result,
    }

    validation = OutputValidator.validate(llm_output, evidence)
    cross_val = ConfidenceCrossValidator.cross_validate(
        llm_output, rule_result, supervised_result, baseline_result)
    review = ReviewMarker.mark_for_review(validation, cross_val, rule_result)

    return {
        "output_validation": validation,
        "cross_validation": cross_val,
        "review_marker": review,
        "overall_score": round(
            (validation["score"] * 0.4 + cross_val["overall_confidence"] * 0.4
             + (0.0 if review["needs_review"] else 0.2)), 3),
        "hallucination_risk": "high" if review["priority"] == "high"
        else "medium" if review["priority"] == "medium" else "low",
        "summary": f"幻觉控制: 校验分={validation['score']}, "
                   f"共识={cross_val['consensus']}, "
                   f"风险={review['priority'] if review['needs_review'] else '低'}",
    }
