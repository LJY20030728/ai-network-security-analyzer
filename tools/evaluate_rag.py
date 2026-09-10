# -*- coding: utf-8 -*-
"""
RAG 检索质量评测（Recall@k / MRR）
==================================
基于知识库真实条目构建黄金问答集（14 问，覆盖 14 个条目），
对每个问题执行生产检索路径（RAGEngine.search, BGE 中文 Embedding + ChromaDB cosine），
检查期望条目是否出现在 top-k 结果中。

指标：
- Recall@1 / @3 / @5：期望条目进入 top-k 的问题占比
- MRR@5：期望条目首个命中位置的倒数均值（未命中记 0）
- 分类 Recall@5：按知识类别分组的命中率
输出：data/eval_rag/rag_result.json + regression_result.json 的 evaluation.rag 字段
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger
logger.remove()  # 评测期静默日志

from src.ai.rag_engine import RAGEngine
from src.utils.paths import data_dir

# ---------- 黄金问答集（query → 期望条目标题关键词） ----------
# 问题措辞模拟真实用户提问，不照抄知识条目标题
GOLDEN_QA = [
    # MITRE ATT&CK 技术
    ("短时间内同一IP向大量端口发SYN包，这属于什么攻击，怎么检测？", "T1046"),
    ("攻击者用DNS、HTTP等常见协议做C2通信伪装，有哪些流量特征能暴露？", "T1071"),
    ("内网主机向外部传输了超大流量，怀疑数据泄露，应该关注什么特征？", "T1048"),
    ("攻击者通过多级代理隐藏C2服务器地址，流量上有什么异常？", "T1090"),
    ("DNS查询名特别长还带随机字符串，这是什么攻击？", "T1572"),
    ("大量登录失败尝试来自同一IP，针对SSH的暴力破解怎么防护？", "T1110"),
    ("SYN包数量远超ACK包、带宽被打满，这是哪种攻击？", "T1498"),
    ("一台内网主机同时连很多主机的445端口，是横向移动吗？", "T1021"),
    ("攻击者收集系统信息做侦察，网络流量上能看到什么？", "T1082"),
    # 事件处置手册
    ("收到端口扫描告警，作为安全工程师第一步该做什么？", "端口扫描事件处置手册"),
    ("公司网站被DDoS了，网络层和应用层攻击分别怎么遏制？", "DDoS攻击事件处置手册"),
    ("怀疑内网有DNS隧道在传输数据，处置流程是什么？", "DNS隧道检测与处置手册"),
    ("RDP登录被爆破且疑似成功了，应急应该怎么处理？", "暴力破解攻击处置手册"),
    # 协议知识
    ("TCP三次握手具体是哪三步，SYN flood是怎么利用它的？", "TCP三次握手"),
    ("DNS放大攻击和DNS投毒的区别，检测上关注什么？", "DNS协议安全分析"),
    ("加密HTTPS流量看不到内容，安全分析还能看哪些特征？", "HTTP/HTTPS"),
]

# ---------- 评测逻辑 ----------

def _hit(meta: dict, keyword: str) -> bool:
    """期望条目是否命中：title 关键词子串匹配（部分命中即算）"""
    title = (meta or {}).get("title", "") or ""
    return keyword in title


def evaluate(top_k: int = 5) -> dict:
    engine = RAGEngine()
    per_query = []
    hits_at = {1: 0, 3: 0, 5: 0}
    mrr_sum = 0.0
    cat_stats = defaultdict(lambda: {"n": 0, "hit5": 0})

    for q, kw in GOLDEN_QA:
        results = engine.search(q, top_k=top_k)
        rank_hit = None
        for i, r in enumerate(results):
            if _hit(r.get("metadata"), kw):
                rank_hit = i + 1
                break
        # 分类（按关键词反推）
        cat = "mitre" if kw[0] == "T" else ("handbook" if "手册" in kw else "protocol")
        cat_stats[cat]["n"] += 1
        if rank_hit is not None and rank_hit <= 5:
            cat_stats[cat]["hit5"] += 1

        for k in (1, 3, 5):
            if rank_hit is not None and rank_hit <= k:
                hits_at[k] += 1
        mrr_sum += (1.0 / rank_hit) if rank_hit else 0.0

        per_query.append({
            "query": q,
            "expected_keyword": kw,
            "hit_rank": rank_hit,          # None = 未命中
            "hit": rank_hit is not None,
            "top1_title": (results[0]["metadata"].get("title") if results else ""),
        })

    n = len(GOLDEN_QA)
    result = {
        "method": "Recall@k / MRR@5，BGE 中文 Embedding + ChromaDB cosine",
        "golden_queries": n,
        "recall_at_1": round(hits_at[1] / n, 4),
        "recall_at_3": round(hits_at[3] / n, 4),
        "recall_at_5": round(hits_at[5] / n, 4),
        "mrr_at_5": round(mrr_sum / n, 4),
        "category_recall_at_5": {
            k: {"queries": v["n"], "hit": v["hit5"],
                "recall@5": round(v["hit5"] / v["n"], 4)}
            for k, v in cat_stats.items()
        },
        "per_query": per_query,
        "missed": [p for p in per_query if not p["hit"]],
    }
    return result


def main():
    result = evaluate()
    # 落盘：独立评测文件 + regression_result.json 的 evaluation.rag
    os.makedirs(data_dir("eval_rag"), exist_ok=True)
    out = os.path.join(data_dir("eval_rag"), "rag_result.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    reg_path = os.path.join(data_dir("samples"), "regression_result.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        reg = json.load(f)
    reg.setdefault("evaluation", {})["rag"] = {
        "recall_at_1": result["recall_at_1"],
        "recall_at_3": result["recall_at_3"],
        "recall_at_5": result["recall_at_5"],
        "mrr_at_5": result["mrr_at_5"],
        "golden_queries": result["golden_queries"],
    }
    with open(reg_path, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=2)

    # 控制台摘要
    print(f"黄金问答集: {result['golden_queries']} 问")
    print(f"Recall@1 = {result['recall_at_1']:.4f}")
    print(f"Recall@3 = {result['recall_at_3']:.4f}")
    print(f"Recall@5 = {result['recall_at_5']:.4f}")
    print(f"MRR@5    = {result['mrr_at_5']:.4f}")
    for cat, st in result["category_recall_at_5"].items():
        print(f"  类别[{cat}] Recall@5 = {st['recall@5']:.4f} ({st['hit']}/{st['queries']})")
    if result["missed"]:
        print("\n未命中问题:")
        for m in result["missed"]:
            print(f"  ✗ {m['query'][:40]}... 期望[{m['expected_keyword']}] top1={m['top1_title'][:30]}")
    else:
        print("\n全部命中（无漏检）")
    print(f"结果已写入 {out}")


if __name__ == "__main__":
    main()
