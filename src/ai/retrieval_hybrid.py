# -*- coding: utf-8 -*-
"""
混合检索模块（查询改写 + BM25 + RRF 融合）
=========================================
RAG 检索质量优化（对应评测 diagnosis 的三条改进方向中的 ①②）：

1. 查询改写 rewrite_query：
   仅对"显式比较问句"（X和Y的区别/对比/差异/不同）拆分为子查询分别检索——
   比较问句的多实体是明确并列，拆分后各自检索更聚焦；
   普通问句中的"和/与"多为概念整体的一部分，拆分会破坏语义，故不处理。

2. BM25Index：
   手写 BM25 关键词检索（无 jieba/无外部依赖）：
   - 分词：英文按词（小写+去停用），中文按 2-gram（bigram）
   - 倒排索引 + IDF（平滑） + 词频饱和（k1=1.5, b=0.75）
   解决向量检索对专有名词/组合实体（如 DNS放大攻击、DNS投毒）语义重心漂移的盲点。

3. RRF 融合：
   Reciprocal Rank Fusion（k=60）：向量检索 top-N 与 BM25 top-N 按排名倒数加权合并，
   无需调权重即可稳定融合异构排序，是信息检索领域的标准做法。
"""
import math
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

# ---------- 中文分词（bigram） ----------

_EN_WORD_RE = re.compile(r"[a-zA-Z0-9_]+")
_ZH_RE = re.compile(r"[\u4e00-\u9fff]")
_EN_STOP = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "with",
    "is", "are", "was", "were", "be", "been", "how", "what", "which", "why",
}


def tokenize(text: str) -> List[str]:
    """混合分词：英文词（小写去停用词）+ 中文 bigram"""
    tokens: List[str] = []
    # 英文/数字词
    for w in _EN_WORD_RE.findall(text.lower()):
        if w not in _EN_STOP and len(w) > 1:
            tokens.append(w)
    # 中文 bigram（连续中文串切 2-gram）
    zh_runs = re.findall(r"[\u4e00-\u9fff]+", text)
    for run in zh_runs:
        if len(run) == 1:
            tokens.append(run)
        for i in range(len(run) - 1):
            tokens.append(run[i:i + 2])
    return tokens


# ---------- BM25 ----------

class BM25Index:
    """轻量 BM25 倒排索引（文档级，支持元数据过滤）"""

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.doc_ids: List[str] = []
        self.doc_metas: List[Dict[str, Any]] = []
        self.doc_len: List[int] = []
        self.avgdl: float = 1.0
        self.postings: Dict[str, Dict[str, int]] = {}   # term -> {doc_id: tf}
        self.doc_freq: Dict[str, int] = {}              # term -> df
        self.n_docs: int = 0
        self._built = False

    def build(self, ids: List[str], docs: List[str],
              metadatas: Optional[List[Dict[str, Any]]] = None) -> None:
        """构建索引（doc_id 与 ChromaDB id 一一对应）"""
        self.doc_ids = list(ids)
        self.doc_metas = list(metadatas or [{}] * len(ids))
        self.n_docs = len(ids)
        self.doc_len = []
        term_doc: Dict[str, set] = defaultdict(set)
        for i, doc in enumerate(docs):
            toks = tokenize(doc or "")
            self.doc_len.append(len(toks))
            tf = Counter(toks)
            for term, cnt in tf.items():
                term_doc[term].add(i)
                self.postings.setdefault(term, {})[ids[i]] = cnt
        self.avgdl = (sum(self.doc_len) / self.n_docs) if self.n_docs else 1.0
        self.doc_freq = {t: len(docs_i) for t, docs_i in term_doc.items()}
        self._built = True
        logger.debug(f"BM25 索引构建完成 | 文档 {self.n_docs} | 词项 {len(self.postings)}")

    @property
    def built(self) -> bool:
        return self._built

    def _idf(self, term: str) -> float:
        df = self.doc_freq.get(term, 0)
        # 平滑 IDF：log(1 + (N - df + 0.5) / (df + 0.5))
        return math.log(1.0 + (self.n_docs - df + 0.5) / (df + 0.5))

    def score(self, query: str, filter_dict: Optional[Dict[str, Any]] = None,
              top_k: int = 20) -> List[str]:
        """BM25 打分排序，返回 doc_id 列表（按得分降序）"""
        if not self._built or not self.n_docs:
            return []
        q_terms = tokenize(query)
        if not q_terms:
            return []
        scores: Dict[str, float] = defaultdict(float)
        for term in set(q_terms):
            post = self.postings.get(term, {})
            if not post:
                continue
            idf = self._idf(term)
            for doc_id, tf in post.items():
                idx = self.doc_ids.index(doc_id) if doc_id in self.doc_ids else -1
                if idx < 0:
                    continue
                # 元数据过滤（与 ChromaDB where 语义一致：等值匹配）
                if filter_dict:
                    meta = self.doc_metas[idx] or {}
                    if not all(meta.get(k) == v for k, v in filter_dict.items()):
                        continue
                dl = self.doc_len[idx]
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                scores[doc_id] += idf * tf * (self.k1 + 1) / denom
        ranked = sorted(scores.items(), key=lambda x: -x[1])[:top_k]
        return [doc_id for doc_id, _ in ranked]


# ---------- 查询改写 ----------

_COMPARE_RE = re.compile(
    r"^(.+?)(?:和|与|及|、)(.+?)(?:的)?(?:区别|对比|差异|不同|有什么关系|有什么不同)"
)


def rewrite_query(query: str) -> List[str]:
    """
    显式比较问句拆分子查询；其余原样返回。
    "DNS放大攻击和DNS投毒的区别，检测上关注什么？"
      -> ["DNS放大攻击，检测上关注什么？", "DNS投毒，检测上关注什么？"]
    """
    m = _COMPARE_RE.match(query.strip())
    if not m:
        return [query]
    head_a = m.group(1).strip()
    head_b = m.group(2).strip()
    tail = query[m.end():].strip()
    # 子查询 = 实体 + 公共疑问尾（若无疑问尾则附加"是什么"保持完整问句）
    tail_q = tail if tail else "是什么"
    subs = []
    for h in (head_a, head_b):
        if h:
            subs.append(f"{h}{tail_q}")
    return subs if len(subs) >= 2 else [query]


# ---------- RRF 融合 ----------

def rrf_fuse(ranked_lists: List[List[str]], k: int = 60) -> List[str]:
    """Reciprocal Rank Fusion：多路排序按 1/(k+rank) 加权合并"""
    scores: Dict[str, float] = defaultdict(float)
    for lst in ranked_lists:
        for rank, doc_id in enumerate(lst, 1):
            scores[doc_id] += 1.0 / (k + rank)
    return [doc_id for doc_id, _ in sorted(scores.items(), key=lambda x: -x[1])]
