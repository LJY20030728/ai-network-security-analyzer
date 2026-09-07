# -*- coding: utf-8 -*-
"""混合检索单测：查询改写 / BM25 / RRF 融合"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest

from src.ai.retrieval_hybrid import (
    BM25Index,
    rewrite_query,
    rrf_fuse,
    tokenize,
)


class TestTokenizer:
    def test_english_words(self):
        toks = tokenize("DNS Tunneling Detection")
        assert "dns" in toks
        assert "tunneling" in toks
        # 停用词剔除
        assert "the" not in toks

    def test_chinese_bigram(self):
        toks = tokenize("放大攻击")
        assert "放大" in toks
        assert "大攻" in toks
        assert "攻击" in toks

    def test_mixed(self):
        toks = tokenize("DNS放大攻击")
        assert "dns" in toks
        assert "放大" in toks


class TestRewriteQuery:
    def test_compare_sentence_split(self):
        subs = rewrite_query("DNS放大攻击和DNS投毒的区别，检测上关注什么？")
        assert len(subs) == 2
        assert "DNS放大攻击" in subs[0]
        assert "DNS投毒" in subs[1]
        assert "检测上关注什么" in subs[0]  # 公共疑问尾保留

    def test_compare_without_tail(self):
        subs = rewrite_query("SYN flood和UDP flood的区别")
        assert len(subs) == 2
        assert subs[0].endswith("是什么") or "区别" not in subs[0]

    def test_plain_query_untouched(self):
        """普通问句（和 为概念整体）不得误拆"""
        q = "攻击者用DNS、HTTP等常见协议做C2通信伪装，有哪些流量特征能暴露？"
        assert rewrite_query(q) == [q]

    def test_simple_question_untouched(self):
        q = "什么是SYN flood攻击？"
        assert rewrite_query(q) == [q]


class TestBM25:
    @pytest.fixture
    def index(self):
        idx = BM25Index()
        idx.build(
            ids=["d1", "d2", "d3"],
            docs=[
                "DNS协议安全分析 放大攻击 投毒 缓存污染 递归服务器",
                "TCP三次握手 连接管理 半开连接 SYN flood",
                "HTTP HTTPS 流量安全 SQL注入 XSS Web Shell",
            ],
        )
        return idx

    def test_relevant_doc_ranked_first(self, index):
        """关键词命中的文档应排第一（无向量干扰下 BM25 直接命中）"""
        ranked = index.score("DNS放大攻击", top_k=3)
        assert ranked[0] == "d1"

    def test_irrelevant_not_ranked(self, index):
        ranked = index.score("TCP 半开连接 SYN", top_k=3)
        assert ranked[0] == "d2"
        assert "d1" not in ranked[:1]

    def test_metadata_filter(self, index):
        """元数据过滤：where 不匹配的文档不参与打分"""
        # 重建带 metadata 的索引
        idx = BM25Index()
        idx.build(
            ids=["a1", "a2"],
            docs=["DNS 放大攻击 检测", "DNS 投毒 检测"],
            metadatas=[{"category": "protocol"}, {"category": "mitre"}],
        )
        ranked = idx.score("DNS 检测", filter_dict={"category": "protocol"}, top_k=3)
        assert ranked == ["a1"]


class TestRRF:
    def test_fuse_merges_rankings(self):
        """两路排名融合：同时出现在两路的 doc 排名靠前"""
        fused = rrf_fuse([["a", "b", "c"], ["b", "c", "d"]])
        assert fused[0] == "b"  # 双路命中 → 最高融合分
        assert "a" in fused and "d" in fused

    def test_fuse_single_list_preserves_order(self):
        fused = rrf_fuse([["x", "y", "z"]])
        assert fused == ["x", "y", "z"]

    def test_fuse_deduplicates(self):
        fused = rrf_fuse([["a", "a", "b"], ["a"]])
        assert fused.count("a") == 1
