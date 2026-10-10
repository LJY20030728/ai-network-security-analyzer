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
from typing import Dict, List, Any, Optional


class OutputValidator:
    """LLM 输出校验器"""

    # 合理输出长度范围
    MIN_LENGTH = 20
    MAX_LENGTH = 10000

    # 【关键】LLM 调用失败时 llm_client 返回的是**哨兵字符串**而非抛异常。
    # 此前校验器对它一视同仁地打分——任何 ≥20 字符的串都拿 1.0 分，
    # 结果是「API 报 401」在报告里被认证为「校验通过 / 幻觉风险低」。
    # 交付物因此自相矛盾：一张报错截图旁边写着质量合格。
    #
    # 与 src/ai/llm_client.py 的返回值严格对应（chat() 与 stream() 两条路径）。
    FAILURE_MARKERS = (
        "[大模型调用失败]",
        "[错误]",
        "[LLM",
    )

    # 幻觉特征词（无证据支撑的绝对化表述）
    HALLUCINATION_PATTERNS = [
        r"毫无疑问", r"绝对是", r"100%", r"完全确定", r"铁证如山",
        r"肯定是", r"必然是",
    ]

    # 已知攻击技术名称（用于校验 LLM 提到的技术是否存在）
    # 注：不含 Analysis / Generic / DoS / Exploit / 利用 / Recon 等泛词——
    # 它们不是具体攻击技术，混进来会让「未识别技术」校验形同虚设。
    KNOWN_ATTACK_TECHNIQUES = {
        "SYN Flood", "SYN flood", "端口扫描", "Port Scan", "port scan",
        "DNS 隧道", "DNS Tunneling", "RST 风暴", "RST Storm",
        "暴力破解", "Brute Force", "SQL 注入", "SQL Injection",
        "XSS", "跨站脚本", "DDoS", "勒索软件", "Ransomware",
        "钓鱼", "Phishing", "中间人攻击", "MITM", "零日漏洞", "0day",
        "木马", "Trojan", "后门", "Backdoor", "蠕虫", "Worm",
        "Shellcode",
    }

    @classmethod
    def detect_llm_failure(cls, output: str) -> Optional[str]:
        """检出 LLM 调用失败哨兵；未失败返回 None。

        只匹配**开头**的哨兵标记，避免把正文中偶然引用的同样字串误判为失败。
        """
        if not output:
            return "输出为空"
        head = output.lstrip()[:60]
        for marker in cls.FAILURE_MARKERS:
            if head.startswith(marker):
                # 去掉哨兵本身，保留剩余原因（便于报告展示）
                reason = output.lstrip()[len(marker):].strip()
                return reason or "大模型调用失败"
        return None

    @classmethod
    def unavailable(cls, reason: str, output: str = "") -> Dict[str, Any]:
        """LLM 不可用时的校验结果。

        `level="unavailable"` 与 `hallucination_risk="unavailable"` 是给下游
        （报告 / UI / 历史记录）的明确信号：**这次没有可评估的 AI 输出**，
        因此不得展示校验分与风险等级——那些数字在无输出时没有意义。
        """
        return {
            "valid": False,
            "score": 0.0,
            "issues": [f"AI 分析不可用：{reason}"],
            "level": "unavailable",
            "summary": f"AI 分析不可用（{reason}），未执行输出校验",
            "length": len(output or ""),
            "mentioned_techniques": [],
            "unavailable_reason": reason,
        }

    @classmethod
    def validate(cls, output: str, evidence: Optional[Dict] = None) -> Dict[str, Any]:
        """
        校验 LLM 输出
        :param output: LLM 输出文本
        :param evidence: 证据数据（规则告警、融合判定等）
        :return: 校验结果字典（level ∈ pass / warning / fail / error / unavailable）
        """
        if not output:
            return cls.unavailable("输出为空", output)

        # 0. 调用失败检测必须最先做：失败串既不是合格输出，也不是"低质量输出"，
        #    后续所有打分（长度/措辞/技术名）对它都没有意义。
        failure_reason = cls.detect_llm_failure(output)
        if failure_reason is not None:
            return cls.unavailable(failure_reason, output)

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

        # 三引擎融合判定为正常，但 LLM 说有攻击
        fus = evidence.get("stacking") or {}
        if fus and not fus.get("is_attack", True) and fus.get("confidence", 0) > 0.8:
            attack_keywords = ["攻击", "恶意", "入侵", "威胁", "attack", "malicious", "intrusion"]
            if any(k in output_lower for k in attack_keywords):
                issues.append("三引擎融合判定为正常（高置信度），但 LLM 输出暗示存在攻击，结论矛盾")

        # 规则引擎无告警，但 LLM 明确断言了具体攻击类型
        # （原实现在此处是空分支 `pass`，从未生效；现改为真实检测：
        #   仅当 LLM 以确定性措辞断言攻击类型、且规则引擎零告警时标记）
        rules = evidence.get("rules") or {}
        if rules and rules.get("total_alerts", 0) == 0:
            specific_attacks = ["SYN Flood", "SYN洪水", "端口扫描", "DNS 隧道", "DNS隧道", "RST 风暴", "RST风暴"]
            hedges = ["可能", "疑似", "或许", "不排除", "may", "might", "possibly"]
            for atk in specific_attacks:
                if atk not in output:
                    continue
                # 取该攻击类型首次出现位置之前 12 个字符作为措辞窗口
                idx = output.find(atk)
                window = output[max(0, idx - 12):idx]
                if not any(h in window for h in hedges):
                    issues.append(
                        f"规则引擎零告警，但 LLM 以确定性措辞断言「{atk}」，缺乏证据支撑"
                    )
                    break

        return issues

    @staticmethod
    def _extract_mentioned_techniques(text: str) -> List[str]:
        """从文本中提取提到的攻击技术名称。

        对 LLM 失败哨兵直接返回空列表：`[大模型调用失败] Error code: 401 -
        Authentication Fails` 此前会把 "Authentication Fails" 当成一种攻击技术
        提出来（它只是报错信息）。
        """
        if not text or OutputValidator.detect_llm_failure(text) is not None:
            return []
        techs = []
        # 匹配多词技术名（形如 "SQL Injection"）；不匹配报错文本形态
        patterns = [
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
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
    """置信度交叉验证器：LLM 结论 vs 规则引擎 vs 三引擎 Stacking 融合"""

    @staticmethod
    def cross_validate(llm_conclusion: str, rule_result: Dict,
                       stacking_result: Optional[Dict] = None,
                       baseline_result: Optional[Dict] = None) -> Dict[str, Any]:
        """
        交叉验证多引擎结论一致性

        :param stacking_result: 三引擎 Stacking 融合结果
                                （report["stacking_fusion"]，含 is_attack / confidence）
        :return: 交叉验证结果
        """
        # 解析 LLM 结论倾向（攻击/正常/不确定）
        llm_verdict = ConfidenceCrossValidator._parse_llm_verdict(llm_conclusion)

        # 规则引擎判定
        rule_attack = rule_result.get("total_alerts", 0) > 0
        rule_severity = "high" if any(
            a.get("severity") == "critical" for a in rule_result.get("alerts", [])) else "medium"

        # 三引擎融合判定（信号来自规则 + 基线 + 孤立森林）
        fus_attack = stacking_result.get("is_attack") if stacking_result else None
        fus_confidence = stacking_result.get("confidence", 0) if stacking_result else 0

        # 收集各引擎判定
        engines = []
        if llm_verdict != "unknown":
            engines.append({"engine": "LLM", "verdict": llm_verdict, "confidence": None})
        engines.append({"engine": "规则引擎", "verdict": "attack" if rule_attack else "normal",
                        "confidence": None, "alerts": rule_result.get("total_alerts", 0)})
        if fus_attack is not None:
            engines.append({"engine": "三引擎融合",
                            "verdict": "attack" if fus_attack else "normal",
                            "confidence": round(fus_confidence, 3)})

        # 统计一致性
        attack_votes = sum(1 for e in engines if e["verdict"] == "attack")
        normal_votes = sum(1 for e in engines if e["verdict"] == "normal")
        total_votes = attack_votes + normal_votes

        consensus = "attack" if attack_votes > normal_votes else "normal" if normal_votes > attack_votes else "split"
        agreement = max(attack_votes, normal_votes) / total_votes if total_votes > 0 else 0

        # 矛盾检测
        contradictions = []
        if llm_verdict == "attack" and fus_attack is False and fus_confidence > 0.8:
            contradictions.append("LLM 判定攻击，但三引擎融合高置信度判定正常")
        if llm_verdict == "normal" and rule_attack and rule_severity == "high":
            contradictions.append("LLM 判定正常，但规则引擎有高危告警")
        if fus_attack and not rule_attack and fus_confidence > 0.9:
            contradictions.append("三引擎融合高置信度判定攻击，但规则引擎无告警（可能是未知攻击）")

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
        """从 LLM 输出中解析判定倾向（attack / normal / unknown）。

        此前实现有两个真实缺陷：
        1. **否定词反向计分**：`"未发现"` 本身包含子串 `"发现"`，而后者在攻击
           信号表里——一句「未发现攻击，流量正常」会同时给攻击票和正常票，互相
           抵消后返回 unknown。
        2. **攻击偏置**：`"检测到"`、`"发现"` 是中性动词，几乎出现在任何分析
           文本里（包括「检测到 3 条告警，均为误报」），把它们算作攻击信号会让
           判定系统性偏向 attack。

        修复方式：先消解否定式，再匹配**倾向性**词汇，且中性动词不计分。
        """
        if not text:
            return "unknown"
        text_lower = text.lower()

        # 1. 否定式优先：出现这些短语即视为正常倾向的证据（并阻止其内部子串
        #    再被当作攻击信号）。中英文都要覆盖——此前只看攻击/正常两类词表，
        #    「无可疑活动」会因为「可疑」命中攻击词而报出倾向不明。
        negation_phrases = [
            # 中文
            "未发现", "未检测到", "未观察到", "未见", "未能发现",
            "没有发现", "没有检测到", "无异常", "无可疑", "无恶意",
            "不存在攻击", "不构成攻击", "并非攻击", "非攻击",
            # 英文
            "no anomaly", "no anomalies", "not detected", "no evidence",
            "no suspicious", "no malicious", "nothing malicious",
        ]
        normal_signals = ["正常", "无异常", "误报", "benign", "normal",
                          "no anomaly", "not detected", "false positive"]
        attack_signals = ["攻击", "恶意", "入侵", "威胁", "可疑", "attack",
                          "malicious", "intrusion", "suspicious", "exploit"]

        # 按小句处理**否定辖域**：全局关键词计数无法表达
        # 「未检测到任何恶意流量」这类句子——其中「恶意」是被否定的对象，
        # 不是断言，但全局计数会把它算作攻击信号，导致倾向不明。
        # 因此先切分小句；含否定式的小句只计正常票，其内部攻击词不再计分。
        # 分句符覆盖中英文标点（英文句点后可能跟空格）。
        clauses = [c for c in re.split(r"[。；;，,！!？?]|\.\s*|\n", text_lower) if c.strip()]

        attack_score = 0.0
        normal_score = 0.0
        for clause in clauses:
            if any(p in clause for p in negation_phrases):
                # 否定辖域：整句为正常倾向，其内部攻击词不再计分。
                # 权重 0.5 而非 1：否定的证据强度弱于明确断言——
                # 「未发现异常。但确认存在攻击。」里前者应被后者推翻。
                normal_score += 0.5
                continue
            if any(s in clause for s in attack_signals):
                attack_score += 1.0
            if any(s in clause for s in normal_signals):
                normal_score += 1.0

        if attack_score > normal_score:
            return "attack"
        elif normal_score > attack_score:
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
                               stacking_result: Optional[Dict] = None,
                               baseline_result: Optional[Dict] = None) -> Dict[str, Any]:
    """
    运行完整的幻觉控制三件套

    :param stacking_result: 三引擎 Stacking 融合结果（report["stacking_fusion"]）
    :return: 包含校验、交叉验证、复核标记的完整结果
    """
    evidence = {
        "stacking": stacking_result,
        "rules": rule_result,
        "baseline": baseline_result,
    }

    validation = OutputValidator.validate(llm_output, evidence)

    # 【关键】LLM 不可用时不得编造交叉验证分与风险等级。
    # 此前失败串会走完整套流程并得到「校验分=1.0 / 风险=low」，
    # 与同页的 API 报错自相矛盾。这里直接短路为 unavailable。
    if validation.get("level") == "unavailable":
        reason = validation.get("unavailable_reason", "未知原因")
        return {
            "output_validation": validation,
            "cross_validation": {
                "consensus": "unavailable",
                "agreement": 0.0,
                "overall_confidence": 0.0,
                "engines": [],
                "attack_votes": 0,
                "normal_votes": 0,
                "contradictions": [],
                "needs_review": True,
                "summary": "AI 输出不可用，未执行多引擎共识校验",
            },
            "review_marker": {
                "needs_review": True,
                "priority": "high",
                "reasons": [f"AI 分析不可用：{reason}"],
                "review_status": "pending",
                "summary": "AI 分析不可用，需人工研判",
            },
            "overall_score": 0.0,
            "hallucination_risk": "unavailable",
            "available": False,
            "unavailable_reason": reason,
            "summary": f"幻觉控制: AI 分析不可用（{reason}）",
        }

    cross_val = ConfidenceCrossValidator.cross_validate(
        llm_output, rule_result, stacking_result, baseline_result)
    review = ReviewMarker.mark_for_review(validation, cross_val, rule_result)

    overall = (validation["score"] * 0.4 + cross_val["overall_confidence"] * 0.4
               + (0.0 if review["needs_review"] else 0.2))

    return {
        "output_validation": validation,
        "cross_validation": cross_val,
        "review_marker": review,
        "overall_score": round(overall, 3),
        "hallucination_risk": "high" if review["priority"] == "high"
        else "medium" if review["priority"] == "medium" else "low",
        "available": True,
        "summary": f"幻觉控制: 校验分={validation['score']}, "
                   f"共识={cross_val['consensus']}, "
                   f"风险={review['priority'] if review['needs_review'] else '低'}",
    }
