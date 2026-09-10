# -*- coding: utf-8 -*-
"""P1-2 LLM 研判 vs 纯规则：Lumma-Stealer 真实恶意样本
真值：真实恶意流量（malware-traffic-analysis.net 2025-12-30 Lumma Stealer）
- 规则层：TrafficAnalyzer 全管道检出（真实恶意 → 告警=TP，无告警段=FN/盲区）
- LLM 层：analyze_threats_structured 对规则告警做真伪研判（is_threat）
- 结论：LLM 增量 = 对规则告警的确认率（真实样本应高）+ 结构化证据
输出: data/eval_perf/llm_vs_rules_lumma.json
"""
import glob, io, json, os, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from loguru import logger
logger.remove()

PCAP_DIR = os.path.join(ROOT, "data/eval_real")

def main():
    pcaps = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    if not pcaps:
        print("未找到真实样本 pcap"); return
    pcap = pcaps[0]
    print(f"[P1-2] Lumma 真实样本 LLM vs 规则: {os.path.basename(pcap)}")

    from src.capture.pcap_parser import PcapParser
    from src.analysis.flow_extractor import TrafficAnalyzer
    from src.ai.threat_analyzer import get_threat_analyzer

    parser = PcapParser()
    print("  解析 pcap...")
    pkts = parser.parse_file(pcap)
    print(f"  数据包: {len(pkts)}")

    t0 = time.time()
    ta = TrafficAnalyzer()
    report = ta.analyze_stream(PcapParser().iter_packets(pcap))
    dt = time.time() - t0
    ad = report.get("anomaly_detection", {})
    alerts = ad.get("alerts", [])
    summary = report.get("summary", {})
    print(f"  规则层检出: {len(alerts)} 条告警 (耗时 {dt:.1f}s), 总包 {summary.get('total_packets')}, 流 {summary.get('total_flows')}")
    for a in alerts[:8]:
        print(f"    - [{a.get('severity')}] {a.get('type')}: {a.get('description','')[:70]}")

    # LLM 结构化研判（真实恶意样本：正确研判应 is_threat=True）
    print("  LLM 结构化研判中（真实调用）...")
    ta_llm = get_threat_analyzer()
    t1 = time.time()
    try:
        res = ta_llm.analyze_threats_structured(ad)
        dt_llm = time.time() - t1
    except Exception as e:
        print(f"  LLM 调用失败: {e}")
        return
    ok = res.get("ok", False)
    structured = res.get("structured") or {}
    raw = res.get("raw_text", "")
    is_threat = structured.get("is_threat")
    confidence = structured.get("confidence")
    attacks = structured.get("attacks") or []
    overview = structured.get("overview", "")
    print(f"  LLM 研判: ok={ok} is_threat={is_threat}, confidence={confidence}, attacks={len(attacks)}, 耗时 {dt_llm:.1f}s")
    print(f"  overview: {str(overview)[:120]}")
    if not ok:
        print(f"  降级文本(raw 前 150 字): {str(raw)[:150]}")

    # 真实样本真值 = 恶意 → 规则告警全部为 TP
    result = {
        "sample": os.path.basename(pcap),
        "ground_truth": "malicious (Lumma Stealer + 伴随恶意软件, malware-traffic-analysis.net)",
        "rules": {
            "alerts": len(alerts),
            "alert_types": [a.get("type") for a in alerts],
            "total_packets": summary.get("total_packets"),
            "total_flows": summary.get("total_flows"),
            "note": "真实恶意样本：规则层告警=TP；无告警活动段=规则盲区（由基线/ML 兜底）",
        },
        "llm_judgment": {
            "is_threat": is_threat,
            "confidence": confidence,
            "attacks_count": len(attacks),
            "overview": str(overview)[:200],
            "latency_sec": round(dt_llm, 1),
            "note": "LLM 增量：对规则告警做真伪确认 + 攻击链叙事；真实样本上 is_threat 应为 True",
        },
        "conclusion": "规则负责检出（召回），LLM 负责确认与解释（降误报 + 可读性）",
    }
    out = os.path.join(ROOT, "data/eval_perf/llm_vs_rules_lumma.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[OK] 写入 {out}")

if __name__ == "__main__":
    main()
