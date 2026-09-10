# -*- coding: utf-8 -*-
"""L3 LLM 多采样投票评测：单次研判 vs 3 温度投票（治非确定性）
- 同一黄金告警集（与 P1-1 同口径）
- 对每案例：单次调用（temperature=0.2，即现有 analyze_threats_structured）
  vs 3 温度采样投票（analyze_threats_structured_vote）
- 指标：判断准确率（is_threat vs 真值）、投票一致性 agreement、
  结构化成功率、置信度、延迟（投票=3 倍成本）
真实 LLM 调用（.env API Key，8 案例 × 4 次 ≈ 32 次调用）
结果写入 data/eval_perf/llm_voting.json
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from loguru import logger
logger.remove()

from src.ai.threat_analyzer import get_threat_analyzer
from tools.eval_llm_judgment import build_golden_set


def main():
    cases = build_golden_set()
    analyzer = get_threat_analyzer()
    if not analyzer.llm.is_available():
        print("LLM 不可用，跳过评测")
        return

    rows = []
    for case in cases:
        # 单次
        t0 = time.perf_counter()
        single = analyzer.analyze_threats_structured(case["input"], packet_samples=None,
                                                     use_evidence_match=True)
        dt_single = round(time.perf_counter() - t0, 2)
        sv = single["structured"] if single.get("ok") else None
        single_verdict = sv.get("is_threat") if sv else None
        single_conf = sv.get("overall_confidence") if sv else None

        # 投票（3 温度）
        t0 = time.perf_counter()
        vote = analyzer.analyze_threats_structured_vote(case["input"], packet_samples=None,
                                                        n_samples=3, use_evidence_match=True)
        dt_vote = round(time.perf_counter() - t0, 2)
        vv = vote["structured"] if vote.get("ok") else None
        vote_verdict = vv.get("is_threat") if vv else None
        vote_conf = vv.get("overall_confidence") if vv else None
        agreement = vote.get("agreement")
        votes_detail = vote.get("votes", [])

        rows.append({
            "case": case["name"],
            "note": case["note"],
            "expected_threat": case["expected_threat"],
            "single": {"is_threat": single_verdict, "confidence": single_conf,
                       "structured_ok": single.get("ok"), "seconds": dt_single},
            "voting3": {"is_threat": vote_verdict, "confidence": vote_conf,
                        "structured_ok": vote.get("ok"), "agreement": agreement,
                        "votes": votes_detail, "seconds": dt_vote},
        })
        m1 = "✓" if single_verdict == case["expected_threat"] else "✗"
        m3 = "✓" if vote_verdict == case["expected_threat"] else "✗"
        print(f"[{case['name']:22s}] 真值={case['expected_threat']!s:5s} "
              f"单次={m1}{single_verdict!s:5s}({single_conf}) | "
              f"投票={m3}{vote_verdict!s:5s}({vote_conf}) 一致性={agreement} "
              f"耗时: {dt_single}s/{dt_vote}s")

    n = len(rows)
    def acc(key):
        return round(sum(1 for r in rows if r[key]["is_threat"] == r["expected_threat"]) / n, 4)
    def avg(key, field):
        vals = [r[key].get(field) for r in rows if r[key].get(field) is not None]
        return round(sum(vals) / len(vals), 3) if vals else None
    def struct_rate(key):
        return round(sum(1 for r in rows if r[key]["structured_ok"]) / n, 4)

    summary = {
        "cases": n,
        "single": {"judgment_accuracy": acc("single"), "structured_success_rate": struct_rate("single"),
                   "avg_confidence": avg("single", "confidence"), "avg_latency_s": avg("single", "seconds")},
        "voting3": {"judgment_accuracy": acc("voting3"), "structured_success_rate": struct_rate("voting3"),
                    "avg_confidence": avg("voting3", "confidence"), "avg_latency_s": avg("voting3", "seconds"),
                    "avg_agreement": avg("voting3", "agreement")},
        "conclusion": ("多温度投票缓解 LLM 非确定性：is_threat 由多数票决定，一致性 agreement 作为"
                       "置信度加权因子；代价是延迟约 3 倍。若投票准确率 ≥ 单次且一致性高，"
                       "则证明投票是有效的工程化手段。"),
        "per_case": rows,
    }
    os.makedirs("data/eval_perf", exist_ok=True)
    with open("data/eval_perf/llm_voting.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n========== L3 LLM 多采样投票评测 ==========")
    print(f"单次:  准确率={summary['single']['judgment_accuracy']:.1%} "
          f"结构化={summary['single']['structured_success_rate']:.1%} "
          f"延迟={summary['single']['avg_latency_s']}s")
    print(f"投票3: 准确率={summary['voting3']['judgment_accuracy']:.1%} "
          f"结构化={summary['voting3']['structured_success_rate']:.1%} "
          f"一致性={summary['voting3']['avg_agreement']} "
          f"延迟={summary['voting3']['avg_latency_s']}s")
    print("结果已写入 data/eval_perf/llm_voting.json")


if __name__ == "__main__":
    main()
