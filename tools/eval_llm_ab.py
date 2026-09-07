# -*- coding: utf-8 -*-
"""L1 LLM 增量价值 A/B 评测：纯规则输出（A） vs 规则+LLM 结构化研判（B）
三维自动评分：
1. 信息完整性 completeness：B 的结构化字段覆盖（overview/confidence/attacks 覆盖告警数）
2. 证据引用准确率 evidence_accuracy：B 的 evidence 是否回引输入告警的真实数字/IP（防幻觉）
3. 处置建议可执行性 actionability：recommended_actions 非空率 + 动作词表命中
局限声明：自动启发式评分（词表/子串匹配），处置建议可执行性为代理指标，
不替代人工评审；评分口径写入结果文件。
真实 LLM 调用（.env API Key），结果写入 data/eval_perf/llm_ab.json
"""
import json
import os
import sys
import re
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from loguru import logger
logger.remove()

from src.ai.threat_analyzer import get_threat_analyzer
from tools.eval_llm_judgment import build_golden_set  # 复用同一黄金告警集（保证口径一致）

# 处置建议动作词表（可执行性代理指标）
ACTION_VERBS = [
    "封禁", "隔离", "阻断", "过滤", "限制", "升级", "查杀", "监控",
    "告警", "通知", "分析", "调查", "检查", "关闭", "修复", "加固",
    "block", "isolate", "quarantine", "disable", "monitor", "patch",
]

ACTION_PATTERNS = [r"\b(?:block|deny|drop|isolate|quarantine|disable|limit)\b", r"封禁", r"隔离", r"阻断"]


def extract_alert_facts(alerts):
    """从输入告警提取可核验事实（IP + 关键计数），用于证据引用比对"""
    facts = []
    for a in alerts:
        f = {"type": a.get("type", ""), "src_ip": a.get("src_ip", ""), "nums": []}
        for k, v in a.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and k not in ("window_index",):
                f["nums"].append(str(int(v)))
        for key in ("dst_ip",):
            if a.get(key):
                f.setdefault("extra", []).append(str(a[key]))
        facts.append(f)
    return facts


def score_completeness(structured, n_alerts):
    """信息完整性：overview/confidence 存在 + attacks 覆盖告警数"""
    if not structured:
        return 0.0
    parts = 0
    if structured.get("overview"):
        parts += 1
    if structured.get("overall_confidence") is not None:
        parts += 1
    n_attacks = len(structured.get("attacks") or [])
    coverage = n_attacks / max(1, n_alerts)
    return round((parts / 2 + coverage) / 2, 4)


def score_evidence_accuracy(structured, facts):
    """证据引用准确率：每条攻击研判的 evidence 是否回引输入告警的真实数字/IP"""
    if not structured:
        return 0.0
    attacks = structured.get("attacks") or []
    if not attacks:
        return 0.0
    hit = 0
    total = 0
    for atk in attacks:
        ev = str(atk.get("evidence", ""))
        if not ev:
            continue
        total += 1
        # 命中任一输入告警的 src_ip 或关键计数
        matched = False
        for f in facts:
            if f["src_ip"] and f["src_ip"] in ev:
                matched = True
                break
            for n in f["nums"]:
                if len(n) >= 2 and n in ev:
                    matched = True
                    break
            if matched:
                break
        hit += int(matched)
    return round(hit / max(1, total), 4)


def score_actionability(structured):
    """处置建议可执行性：整体+逐告警建议非空率 × 动作词命中率"""
    if not structured:
        return 0.0
    all_actions = list(structured.get("recommended_actions") or [])
    for a in (structured.get("attacks") or []):
        all_actions += list(a.get("recommended_actions") or [])
    if not all_actions:
        return 0.0
    non_empty = len(all_actions)
    with_verb = sum(1 for x in all_actions if any(p in x for p in ACTION_VERBS)
                    or any(re.search(pt, x, re.I) for pt in ACTION_PATTERNS))
    return round((1.0 * with_verb / non_empty), 4)


def main():
    cases = build_golden_set()
    analyzer = get_threat_analyzer()
    if not analyzer.llm.is_available():
        print("LLM 不可用，跳过评测")
        return

    rows = []
    for case in cases:
        alerts = (case["input"].get("alerts") or [])
        facts = extract_alert_facts(alerts)
        n_alerts = len(alerts)

        # A 侧：纯规则输出（无 LLM）——结构字段完备 + 证据数字自带 + 无处置建议
        a_completeness = 1.0 if n_alerts > 0 else 0.0   # 规则告警字段本身完备
        a_evidence = round(sum(1 for f in facts if f["src_ip"] or f["nums"]) / max(1, n_alerts), 4)
        a_action = 0.0                                    # 纯规则不产处置建议

        # B 侧：规则 + LLM 结构化研判
        t0 = time.perf_counter()
        r = analyzer.analyze_threats_structured(case["input"], packet_samples=None,
                                                use_evidence_match=True)
        dt = round(time.perf_counter() - t0, 2)
        structured = r.get("structured") if r.get("ok") else None
        b_completeness = score_completeness(structured, n_alerts)
        b_evidence = score_evidence_accuracy(structured, facts)
        b_action = score_actionability(structured)

        rows.append({
            "case": case["name"],
            "note": case["note"],
            "n_alerts": n_alerts,
            "A_rule_only": {"completeness": a_completeness, "evidence_accuracy": a_evidence,
                            "actionability": a_action},
            "B_rule_plus_llm": {"completeness": b_completeness, "evidence_accuracy": b_evidence,
                                "actionability": b_action, "structured_ok": r.get("ok"),
                                "seconds": dt, "evidence_match": bool(r.get("evidence_match"))},
            "increment": {
                "completeness_delta": round(b_completeness - a_completeness, 4),
                "evidence_delta": round(b_evidence - a_evidence, 4),
                "actionability_delta": round(b_action - a_action, 4),
            },
        })
        print(f"[{case['name']:22s}] A(证据={a_evidence:.2f}) → B(完整={b_completeness:.2f} "
              f"证据={b_evidence:.2f} 处置={b_action:.2f}) 结构化={r.get('ok')} 耗时={dt}s")

    n = len(rows)
    avg = lambda section, key: round(sum(r[section][key] for r in rows) / n, 4)
    summary = {
        "cases": n,
        "scoring_limitations": "自动启发式评分：证据引用为子串匹配（IP/计数），处置可执行性为动作词表命中率；不替代人工评审",
        "A_rule_only_avg": {k: avg("A_rule_only", k) for k in ("completeness", "evidence_accuracy", "actionability")},
        "B_rule_plus_llm_avg": {k: avg("B_rule_plus_llm", k) for k in ("completeness", "evidence_accuracy", "actionability")},
        "increment_avg": {k: avg("increment", k) for k in ("completeness_delta", "evidence_delta", "actionability_delta")},
        "conclusion": ("LLM 增量定位：不提高检测率（确定性引擎兜底），而提供 (1) 逐告警解释与证据回引，"
                       "(2) 可执行处置建议，(3) 结构化叙事。证据引用准确率与处置可行动性是 AI 的真实增量维度。"),
        "per_case": rows,
    }
    os.makedirs("data/eval_perf", exist_ok=True)
    with open("data/eval_perf/llm_ab.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n========== L1 LLM A/B 增量评测 ==========")
    print(f"纯规则 A   完整={summary['A_rule_only_avg']['completeness']:.3f} "
          f"证据={summary['A_rule_only_avg']['evidence_accuracy']:.3f} "
          f"处置={summary['A_rule_only_avg']['actionability']:.3f}")
    print(f"规则+LLM B 完整={summary['B_rule_plus_llm_avg']['completeness']:.3f} "
          f"证据={summary['B_rule_plus_llm_avg']['evidence_accuracy']:.3f} "
          f"处置={summary['B_rule_plus_llm_avg']['actionability']:.3f}")
    print(f"LLM 增量   完整={summary['increment_avg']['completeness_delta']:+.3f} "
          f"证据={summary['increment_avg']['evidence_delta']:+.3f} "
          f"处置={summary['increment_avg']['actionability_delta']:+.3f}")
    print("结果已写入 data/eval_perf/llm_ab.json")


if __name__ == "__main__":
    main()
