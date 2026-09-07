# -*- coding: utf-8 -*-
"""P1-1 LLM 研判量化评测：黄金告警集 → 结构化研判 → 准确率/结构化率/降级率/延迟
真值标注：is_threat（是否真实威胁）+ 关键告警 verdict。
真实 LLM 调用（.env API Key），结果写入 data/eval_perf/llm_judgment.json
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from loguru import logger

logger.remove()

from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer
from src.ai.threat_analyzer import get_threat_analyzer

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "samples", "golden")


def analyze_pcap(fname, use_baseline=True):
    path = os.path.join(GOLDEN, fname)
    ta = TrafficAnalyzer()
    return ta.analyze_stream(PcapParser().iter_packets(path))


def weak_synflood_report():
    """假阳性候选：20 个 SYN 未完成握手（阈值 100 以下，正常误报场景）"""
    return {
        "total_alerts": 1,
        "alerts": [{
            "type": "SYN_FLOOD_SUSPECTED", "severity": "MEDIUM",
            "src_ip": "10.0.0.1", "syn_count": 20,
            "syn_ack_received": 0, "unanswered_syn": 20,
            "description": "源IP 10.0.0.1 发出 20 个SYN，仅收到 0 个SYN-ACK，未完成握手 20 个，疑似SYN洪水攻击",
        }],
        "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0},
    }


def noise_report():
    """噪音：单条 RST 告警（阈值边界）+ 低严重，应判低风险"""
    return {
        "total_alerts": 1,
        "alerts": [{
            "type": "RST_STORM", "severity": "LOW",
            "src_ip": "10.0.0.9", "rst_count": 55,
            "description": "源IP 10.0.0.9 发送了 55 个RST包，可能是扫描或异常连接",
        }],
        "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1},
    }


def build_golden_set():
    """黄金告警集：输入报告 + 真值（is_threat + 说明）"""
    cases = []
    for fname, truth, note in [
        ("synflood.pcap", True, "真实 SYN 洪水"),
        ("portscan.pcap", True, "真实端口扫描"),
        ("dnstunnel.pcap", True, "真实 DNS 隧道"),
        ("largeflow.pcap", True, "真实大流量渗出"),
        ("rststorm.pcap", True, "真实 RST 风暴"),
        ("burst.pcap", True, "真实基线偏差（时序异常）"),
    ]:
        rep = analyze_pcap(fname)
        cases.append({
            "name": fname.replace(".pcap", ""),
            "input": rep["anomaly_detection"],
            "expected_threat": truth,
            "note": note,
        })
    cases.append({"name": "weak_synflood_fp", "input": weak_synflood_report(),
                  "expected_threat": False, "note": "弱特征 SYN（阈值下界，正常抖动误报候选）"})
    cases.append({"name": "noise_rst", "input": noise_report(),
                  "expected_threat": False, "note": "边界 RST 噪音（低严重）"})
    return cases


def main():
    cases = build_golden_set()
    analyzer = get_threat_analyzer()
    if not analyzer.llm.is_available():
        print("LLM 不可用，跳过评测")
        return

    results = []
    for case in cases:
        t0 = time.perf_counter()
        r = analyzer.analyze_threats_structured(case["input"], packet_samples=None)
        dt = round(time.perf_counter() - t0, 2)
        verdict = None
        conf = None
        refs = 0
        if r.get("ok") and r.get("structured"):
            verdict = r["structured"].get("is_threat")
            conf = r["structured"].get("overall_confidence")
            refs = len(r["structured"].get("knowledge_references", []))
        row = {
            "case": case["name"],
            "note": case["note"],
            "expected_threat": case["expected_threat"],
            "llm_is_threat": verdict,
            "confidence": conf,
            "structured_ok": r.get("ok"),
            "degraded": r.get("ok") is False,
            "knowledge_refs": refs,
            "seconds": dt,
        }
        results.append(row)
        mark = "✓" if (verdict == case["expected_threat"]) else "✗"
        print(f"[{mark}] {case['name']:22s} 真值={case['expected_threat']} LLM={verdict} "
              f"conf={conf} 结构化={r.get('ok')} 引用={refs} 耗时={dt}s")

    # 汇总
    n = len(results)
    ok_struct = sum(1 for r in results if r["structured_ok"])
    degraded = sum(1 for r in results if r["degraded"])
    agree = sum(1 for r in results if r["llm_is_threat"] == r["expected_threat"])
    use_refs = sum(1 for r in results if r["knowledge_refs"] > 0)
    avg_s = sum(r["seconds"] for r in results) / n
    summary = {
        "cases": n,
        "structured_success_rate": round(ok_struct / n, 4),
        "degradation_rate": round(degraded / n, 4),
        "threat_judgment_accuracy": round(agree / n, 4),
        "rag_reference_usage": round(use_refs / n, 4),
        "avg_latency_s": round(avg_s, 2),
        "per_case": results,
    }
    os.makedirs("data/eval_perf", exist_ok=True)
    with open("data/eval_perf/llm_judgment.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n========== P1-1 LLM 研判量化 ==========")
    print(f"结构化成功率: {summary['structured_success_rate']:.1%} ({ok_struct}/{n})")
    print(f"降级率:       {summary['degradation_rate']:.1%} ({degraded}/{n})")
    print(f"威胁判断准确率: {summary['threat_judgment_accuracy']:.1%} ({agree}/{n})")
    print(f"RAG 引用率:   {summary['rag_reference_usage']:.1%} ({use_refs}/{n})")
    print(f"平均延迟:     {avg_s:.1f}s/次")
    print("结果已写入 data/eval_perf/llm_judgment.json")


if __name__ == "__main__":
    main()
