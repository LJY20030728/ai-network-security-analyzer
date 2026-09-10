# -*- coding: utf-8 -*-
"""
P0-6 RAG 检索质量评测（Recall@k 黄金问答集）
评测 RAG 引擎（ChromaDB + BGE ONNX + BM25 混合检索）的检索质量。
黄金问答集包含 15 个关于 MITRE ATT&CK 技术和安全处置的问题，
每个问题标注预期相关的技术 ID 或关键词。

输出：data/eval_perf/rag_recall_result.json
"""
import os
import sys
import json
import time
import io

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_JSON = os.path.join(ROOT, "data/eval_perf/rag_recall_result.json")

# 黄金问答集：15 个问题，每个标注预期相关的 ATT&CK 技术 ID 或关键词
GOLDEN_QA = [
    {
        "id": 1,
        "query": "什么是 SQL 注入攻击？如何检测和防御？",
        "expected_keywords": ["SQL", "注入", "Injection", "T1190", "Exploit Public-Facing Application"],
        "category": "攻击技术",
    },
    {
        "id": 2,
        "query": "SYN Flood 攻击的原理是什么？如何缓解？",
        "expected_keywords": ["SYN", "Flood", "DoS", "DDoS", "T1498", "Network Denial of Service"],
        "category": "拒绝服务",
    },
    {
        "id": 3,
        "query": "端口扫描属于 ATT&CK 哪个阶段？有哪些常见扫描技术？",
        "expected_keywords": ["端口扫描", "Port Scan", "Reconnaissance", "T1046", "Network Service Scanning"],
        "category": "侦察",
    },
    {
        "id": 4,
        "query": "DNS 隧道如何实现数据外泄？检测指标有哪些？",
        "expected_keywords": ["DNS", "隧道", "Tunneling", "T1071", "Application Layer Protocol", "Exfiltration"],
        "category": "命令控制",
    },
    {
        "id": 5,
        "query": "暴力破解攻击的检测方法和防御措施",
        "expected_keywords": ["暴力破解", "Brute Force", "T1110", "Credential Access"],
        "category": "凭据访问",
    },
    {
        "id": 6,
        "query": "横向移动有哪些常见技术？如何检测？",
        "expected_keywords": ["横向移动", "Lateral Movement", "T1021", "Remote Services"],
        "category": "横向移动",
    },
    {
        "id": 7,
        "query": "勒索软件的攻击链是什么？如何应急响应？",
        "expected_keywords": ["勒索", "Ransomware", "T1486", "Data Encrypted for Impact", "Impact"],
        "category": "影响",
    },
    {
        "id": 8,
        "query": "钓鱼攻击的社会工程学手段和检测方法",
        "expected_keywords": ["钓鱼", "Phishing", "T1566", "Spearphishing"],
        "category": "初始访问",
    },
    {
        "id": 9,
        "query": "恶意软件持久化技术有哪些？注册表启动项如何检测？",
        "expected_keywords": ["持久化", "Persistence", "T1547", "Boot or Logon Autostart", "注册表"],
        "category": "持久化",
    },
    {
        "id": 10,
        "query": "内存马的工作原理和检测方法",
        "expected_keywords": ["内存", "马", "Memory", "T1055", "Process Injection"],
        "category": "防御规避",
    },
    {
        "id": 11,
        "query": "零日漏洞利用的检测难点和防御策略",
        "expected_keywords": ["零日", "0day", "漏洞", "Exploit", "T1190", "Vulnerability"],
        "category": "初始访问",
    },
    {
        "id": 12,
        "query": "数据外泄的常见渠道和检测指标",
        "expected_keywords": ["数据外泄", "Exfiltration", "T1041", "T1048", "Data Exfiltration"],
        "category": "数据外泄",
    },
    {
        "id": 13,
        "query": "中间人攻击的原理和 HTTPS 如何防御",
        "expected_keywords": ["中间人", "MITM", "Man-in-the-Middle", "T1557", "Adversary-in-the-Middle"],
        "category": "凭据访问",
    },
    {
        "id": 14,
        "query": "日志审计在入侵检测中的作用和关键日志源",
        "expected_keywords": ["日志", "审计", "Log", "T1070", "Indicator Removal", "检测"],
        "category": "检测",
    },
    {
        "id": 15,
        "query": "应急响应的六个阶段是什么？每个阶段的关键动作",
        "expected_keywords": ["应急响应", "Incident Response", "处置", "响应", "阶段"],
        "category": "响应",
    },
]


def evaluate_recall(rag_engine, query: str, expected_keywords: list, top_k: int = 5) -> dict:
    """
    评测单个查询的 Recall@k
    :return: 评测结果
    """
    t0 = time.time()
    results = rag_engine.search(query, top_k=top_k, use_hybrid=True)
    search_time = time.time() - t0

    # 检查前 k 个结果中是否包含预期关键词
    hits = 0
    hit_details = []
    for i, r in enumerate(results):
        content = (r.get("content", "") or "") + " " + (r.get("title", "") or "")
        content_lower = content.lower()
        matched = [kw for kw in expected_keywords if kw.lower() in content_lower]
        if matched:
            hits += 1
            hit_details.append({
                "rank": i + 1,
                "matched_keywords": matched,
                "title": r.get("title", "")[:50],
                "score": r.get("distance", r.get("score", None)),
            })

    recall_at_k = hits / top_k if top_k > 0 else 0
    # 严格 Recall：至少命中 1 个相关结果即为 1.0
    strict_recall = 1.0 if hits > 0 else 0.0

    return {
        "query": query,
        "expected_keywords": expected_keywords,
        "top_k": top_k,
        "results_count": len(results),
        "hits": hits,
        "recall_at_k": round(recall_at_k, 3),
        "strict_recall": strict_recall,
        "search_time_sec": round(search_time, 3),
        "hit_details": hit_details,
        "missed": hits == 0,
    }


def main():
    print("=" * 60)
    print("P0-6 RAG 检索质量评测（Recall@5 黄金问答集）")
    print("=" * 60)

    from src.ai.rag_engine import get_rag_engine
    rag = get_rag_engine()

    print(f"\n黄金问答集: {len(GOLDEN_QA)} 个问题")
    print(f"RAG 引擎: ChromaDB + BGE ONNX + BM25 混合检索\n")

    results = []
    total_hits = 0
    total_strict_hits = 0
    total_time = 0

    for qa in GOLDEN_QA:
        print(f"[{qa['id']:2d}/{len(GOLDEN_QA)}] {qa['query'][:40]}...", end=" ", flush=True)
        try:
            r = evaluate_recall(rag, qa["query"], qa["expected_keywords"], top_k=5)
            r["id"] = qa["id"]
            r["category"] = qa["category"]
            results.append(r)
            total_hits += r["hits"]
            total_strict_hits += r["strict_recall"]
            total_time += r["search_time_sec"]
            status = "✓" if r["hits"] > 0 else "✗"
            print(f"{status} hits={r['hits']}/5 recall={r['recall_at_k']} ({r['search_time_sec']}s)")
        except Exception as e:
            print(f"错误: {e}")
            results.append({"id": qa["id"], "query": qa["query"], "error": str(e)})

    # 汇总
    valid_results = [r for r in results if "error" not in r]
    n = len(valid_results)
    avg_recall = sum(r["recall_at_k"] for r in valid_results) / n if n > 0 else 0
    strict_recall_rate = total_strict_hits / n if n > 0 else 0
    avg_search_time = total_time / n if n > 0 else 0
    missed_queries = [r for r in valid_results if r["missed"]]

    output = {
        "evaluation": "RAG 检索质量评测（Recall@5）",
        "golden_set_size": len(GOLDEN_QA),
        "evaluated": n,
        "metrics": {
            "avg_recall_at_5": round(avg_recall, 3),
            "strict_recall_rate": round(strict_recall_rate, 3),
            "total_hits": total_hits,
            "avg_search_time_sec": round(avg_search_time, 3),
            "missed_queries": len(missed_queries),
        },
        "missed_queries": [{"id": r["id"], "query": r["query"], "category": r["category"]}
                           for r in missed_queries],
        "results": results,
    }

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n{'=' * 60}")
    print(f"评测完成！")
    print(f"  黄金问答集: {len(GOLDEN_QA)} 题")
    print(f"  平均 Recall@5: {avg_recall:.3f}")
    print(f"  严格召回率（至少命中1个）: {strict_recall_rate:.1%}")
    print(f"  平均检索耗时: {avg_search_time:.3f}s")
    print(f"  未命中查询: {len(missed_queries)} 题")
    if missed_queries:
        print(f"  未命中列表:")
        for m in missed_queries:
            print(f"    - [{m['id']}] {m['query'][:50]}")
    print(f"  结果已保存: {OUT_JSON}")
    print("=" * 60)


if __name__ == "__main__":
    main()
