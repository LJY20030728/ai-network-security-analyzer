# -*- coding: utf-8 -*-
"""
RAG 检索质量评测（双口径 Recall@k / MRR）
=========================================
基于知识库真实条目构建 16 个黄金问答，对每个问题执行生产检索路径
（RAGEngine.search：查询改写 + BGE 向量 + BM25 + RRF 融合 + term-aware 重排）。

两种口径（同时报告，不掩盖差异）：
- Strict（权威条目）：gold = 唯一权威文档（标题含技术ID / 手册全名），
  衡量"特定权威条目"的排序能力。
- Relevant（相关文档集合）：gold = 客观上能回答该问题的文档集合（信息检索的标准做法，
  一个问题的相关文档本就不止一个），衡量"首位 / top-k 是否为相关内容"。
  关键词保守选取并在下方逐条注明依据，不为美化数字而无限放宽。

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

# ---------- 黄金问答集 ----------
# 每条 = (问题, strict权威关键词, [relevant相关关键词], 类别)
# 问题措辞模拟真实用户提问，不照抄知识条目标题。
GOLDEN_QA = [
    # —— MITRE ATT&CK 技术 ——
    # 1 端口扫描：攻击类型综述含"端口扫描检测特征"，可回答
    ("短时间内同一IP向大量端口发SYN包，这属于什么攻击，怎么检测？",
     "T1046", ["T1046", "端口扫描", "常见网络攻击类型"], "mitre"),
    # 2 应用层协议 C2：权威条目即 T1071
    ("攻击者用DNS、HTTP等常见协议做C2通信伪装，有哪些流量特征能暴露？",
     "T1071", ["T1071"], "mitre"),
    # 3 数据渗出：HTTP/HTTPS 流量分析含"大流量外发/渗出检测"，可回答
    ("内网主机向外部传输了超大流量，怀疑数据泄露，应该关注什么特征？",
     "T1048", ["T1048", "渗出", "泄露", "http/https流量安全"], "mitre"),
    # 4 代理：权威条目即 T1090
    ("攻击者通过多级代理隐藏C2服务器地址，流量上有什么异常？",
     "T1090", ["T1090"], "mitre"),
    # 5 DNS 隧道：DNS 协议安全 / DNS 隧道手册均客观相关
    ("DNS查询名特别长还带随机字符串，这是什么攻击？",
     "T1572", ["T1572", "dns"], "mitre"),
    # 6 暴力破解：暴力破解处置手册客观相关
    ("大量登录失败尝试来自同一IP，针对SSH的暴力破解怎么防护？",
     "T1110", ["T1110", "暴力破解"], "mitre"),
    # 7 SYN 洪水：DDoS / 拒绝服务资料客观相关
    ("SYN包数量远超ACK包、带宽被打满，这是哪种攻击？",
     "T1498", ["T1498", "ddos", "拒绝服务"], "mitre"),
    # 8 横向移动（445/SMB）：注意"端口对照表"不含 横向/远程服务，仍判不相关（保留真实瑕疵）
    ("一台内网主机同时连很多主机的445端口，是横向移动吗？",
     "T1021", ["T1021", "横向", "远程服务"], "mitre"),
    # 9 系统信息发现：top1 若为 T1046（网络扫描）不直接回答"系统信息发现"，保守判不相关（保留瑕疵）
    ("攻击者收集系统信息做侦察，网络流量上能看到什么？",
     "T1082", ["T1082"], "mitre"),
    # —— 事件处置手册 ——
    ("收到端口扫描告警，作为安全工程师第一步该做什么？",
     "端口扫描事件处置手册", ["端口扫描事件处置手册"], "handbook"),
    ("公司网站被DDoS了，网络层和应用层攻击分别怎么遏制？",
     "DDoS攻击事件处置手册", ["DDoS攻击事件处置手册"], "handbook"),
    ("怀疑内网有DNS隧道在传输数据，处置流程是什么？",
     "DNS隧道检测与处置手册", ["DNS隧道检测与处置手册"], "handbook"),
    ("RDP登录被爆破且疑似成功了，应急应该怎么处理？",
     "暴力破解攻击处置手册", ["暴力破解攻击处置手册"], "handbook"),
    # —— 协议知识 ——
    ("TCP三次握手具体是哪三步，SYN flood是怎么利用它的？",
     "TCP三次握手", ["TCP三次握手", "tcp"], "protocol"),
    ("DNS放大攻击和DNS投毒的区别，检测上关注什么？",
     "DNS协议安全分析", ["dns协议安全", "dns"], "protocol"),
    ("加密HTTPS流量看不到内容，安全分析还能看哪些特征？",
     "HTTP/HTTPS", ["http/https", "tls", "ssl", "加密"], "protocol"),
]


def _rank_of(results, keywords):
    """返回首个标题含任一关键词（子串、忽略大小写）的结果位置(1-based)与标题；未命中返回 None,"""
    for i, r in enumerate(results):
        title = ((r.get("metadata") or {}).get("title") or "")
        tlow = title.lower()
        if any(k.lower() in tlow for k in keywords):
            return i + 1, title
    return None, ""


def _empty_bucket():
    return {"hits": {1: 0, 3: 0, 5: 0}, "mrr": 0.0}


def evaluate(top_k: int = 5) -> dict:
    engine = RAGEngine()
    strict = _empty_bucket()
    relevant = _empty_bucket()
    cat_stats = defaultdict(lambda: {"n": 0, "hit5": 0})
    per_query = []

    for q, strict_kw, rel_kws, cat in GOLDEN_QA:
        results = engine.search(q, top_k=top_k)

        s_rank, _ = _rank_of(results, [strict_kw])
        r_rank, r_title = _rank_of(results, rel_kws)

        for bucket, rank in ((strict, s_rank), (relevant, r_rank)):
            for k in (1, 3, 5):
                if rank is not None and rank <= k:
                    bucket["hits"][k] += 1
            bucket["mrr"] += (1.0 / rank) if rank else 0.0

        cat_stats[cat]["n"] += 1
        if r_rank is not None and r_rank <= 5:
            cat_stats[cat]["hit5"] += 1

        top1_title = (results[0]["metadata"].get("title") if results else "")
        per_query.append({
            "query": q,
            "category": cat,
            "strict_keyword": strict_kw,
            "relevant_keywords": rel_kws,
            "strict_rank": s_rank,
            "relevant_rank": r_rank,
            "top1_title": top1_title,
            "top1_is_relevant": r_rank == 1,
        })

    n = len(GOLDEN_QA)

    def pack(bucket):
        return {
            "recall_at_1": round(bucket["hits"][1] / n, 4),
            "recall_at_3": round(bucket["hits"][3] / n, 4),
            "recall_at_5": round(bucket["hits"][5] / n, 4),
            "mrr_at_5": round(bucket["mrr"] / n, 4),
        }

    return {
        "method": "双口径 Recall@k / MRR，BGE 中文 Embedding + BM25 + RRF + term-aware 重排",
        "golden_queries": n,
        "strict": pack(strict),
        "relevant": pack(relevant),
        "category_recall_at_5": {
            k: {"queries": v["n"], "hit": v["hit5"],
                "recall@5": round(v["hit5"] / v["n"], 4)}
            for k, v in cat_stats.items()
        },
        "per_query": per_query,
        "note": "Strict=唯一权威条目；Relevant=客观相关文档集合（关键词依据见脚本注释）",
    }


def main():
    result = evaluate()
    os.makedirs(data_dir("eval_rag"), exist_ok=True)
    out = os.path.join(data_dir("eval_rag"), "rag_result.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # 同步到 regression_result.json
    reg_path = os.path.join(data_dir("samples"), "regression_result.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        reg = json.load(f)
    reg.setdefault("evaluation", {})["rag"] = {
        "golden_queries": result["golden_queries"],
        "strict": result["strict"],
        "relevant": result["relevant"],
    }
    with open(reg_path, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=2)

    # 控制台摘要
    print(f"黄金问答集: {result['golden_queries']} 问")
    s, r = result["strict"], result["relevant"]
    print(f"[Strict 权威条目]   Recall@1={s['recall_at_1']:.4f}  @3={s['recall_at_3']:.4f}  "
          f"@5={s['recall_at_5']:.4f}  MRR={s['mrr_at_5']:.4f}")
    print(f"[Relevant 相关集合] Recall@1={r['recall_at_1']:.4f}  @3={r['recall_at_3']:.4f}  "
          f"@5={r['recall_at_5']:.4f}  MRR={r['mrr_at_5']:.4f}")
    for cat, st in result["category_recall_at_5"].items():
        print(f"  类别[{cat}] Relevant Recall@5 = {st['recall@5']:.4f} ({st['hit']}/{st['queries']})")
    not_rel = [p for p in result["per_query"] if not p["top1_is_relevant"]]
    if not_rel:
        print("\n首位非相关（真实瑕疵）:")
        for p in not_rel:
            print(f"  ! {p['query'][:34]}... top1={p['top1_title'][:28]}")
    print(f"\n结果已写入 {out}")


if __name__ == "__main__":
    main()
