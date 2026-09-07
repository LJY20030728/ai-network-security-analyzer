# -*- coding: utf-8 -*-
"""RAG 混合检索消融实验：各改进贡献量化"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger
logger.remove()

from src.ai.rag_engine import RAGEngine
from src.ai.retrieval_hybrid import rewrite_query, rrf_fuse

GOLDEN_QA = [
    ("短时间内同一IP向大量端口发SYN包，这属于什么攻击，怎么检测？", "T1046"),
    ("攻击者用DNS、HTTP等常见协议做C2通信伪装，有哪些流量特征能暴露？", "T1071"),
    ("内网主机向外部传输了超大流量，怀疑数据泄露，应该关注什么特征？", "T1048"),
    ("攻击者通过多级代理隐藏C2服务器地址，流量上有什么异常？", "T1090"),
    ("DNS查询名特别长还带随机字符串，这是什么攻击？", "T1572"),
    ("大量登录失败尝试来自同一IP，针对SSH的暴力破解怎么防护？", "T1110"),
    ("SYN包数量远超ACK包、带宽被打满，这是哪种攻击？", "T1498"),
    ("一台内网主机同时连很多主机的445端口，是横向移动吗？", "T1021"),
    ("攻击者收集系统信息做侦察，网络流量上能看到什么？", "T1082"),
    ("收到端口扫描告警，作为安全工程师第一步该做什么？", "端口扫描事件处置手册"),
    ("公司网站被DDoS了，网络层和应用层攻击分别怎么遏制？", "DDoS攻击事件处置手册"),
    ("怀疑内网有DNS隧道在传输数据，处置流程是什么？", "DNS隧道检测与处置手册"),
    ("RDP登录被爆破且疑似成功了，应急应该怎么处理？", "暴力破解攻击处置手册"),
    ("TCP三次握手具体是哪三步，SYN flood是怎么利用它的？", "TCP三次握手"),
    ("DNS放大攻击和DNS投毒的区别，检测上关注什么？", "DNS协议安全分析"),
    ("加密HTTPS流量看不到内容，安全分析还能看哪些特征？", "HTTP/HTTPS"),
]


def hit(meta, kw):
    return kw in (meta or {}).get("title", "")


def main():
    engine = RAGEngine()
    engine._init_collection()
    engine._ensure_seeded()
    engine._ensure_bm25_index()

    def recall5(mode):
        hitn = 0
        for q, kw in GOLDEN_QA:
            found = False
            if mode == "vec":
                ids = engine._vector_search(q, 5)
                data = engine.collection.get(ids=ids, include=["metadatas"])
                hitn += int(any(hit(m, kw) for m in data["metadatas"]))
            elif mode == "vec+bm25":
                ids = rrf_fuse([engine._vector_search(q, 20),
                                engine._bm25.score(q, top_k=20)])[:5]
                data = engine.collection.get(ids=ids, include=["metadatas"])
                hitn += int(any(hit(m, kw) for m in data["metadatas"]))
            elif mode == "vec+rw":
                for sub in rewrite_query(q):
                    ids = engine._vector_search(sub, 5)
                    data = engine.collection.get(ids=ids, include=["metadatas"])
                    if any(hit(m, kw) for m in data["metadatas"]):
                        found = True
                        break
                hitn += int(found)
            else:  # full
                for sub in rewrite_query(q):
                    ids = rrf_fuse([engine._vector_search(sub, 20),
                                    engine._bm25.score(sub, top_k=20)])[:5]
                    data = engine.collection.get(ids=ids, include=["metadatas"])
                    if any(hit(m, kw) for m in data["metadatas"]):
                        found = True
                        break
                hitn += int(found)
        return hitn / len(GOLDEN_QA)

    print("消融实验（Recall@5，16 问黄金集）:")
    print(f"  纯向量（基线）    = {recall5('vec'):.4f}")
    print(f"  向量+BM25(RRF)    = {recall5('vec+bm25'):.4f}")
    print(f"  向量+查询改写     = {recall5('vec+rw'):.4f}")
    print(f"  全开（改写+双路） = {recall5('full'):.4f}")


if __name__ == "__main__":
    main()
