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
from typing import Any, Dict, List, Optional

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

# 比较问句的「标记」与「实体连接词」拆成两步匹配（见 rewrite_query 的说明）。
# 标记优先匹配更长的形态，避免 "有什么区别" 只被吃掉 "区别"。
_COMPARE_MARK_RE = re.compile(
    r"的?(?:有什么区别|有什么不同|有什么关系|有何区别|有什么区别吗|的区别|的差异|的不同|的对比)"
)
_ENTITY_SPLIT_RE = re.compile(r"(?:和|与|及|、|vs\.?|VS\.?)")

# 术语映射表：缩写/简称 → 完整术语
# 用于把用户查询中的缩写扩展为完整术语，提升召回率
TERM_SYNONYMS = {
    # 路由协议
    "BGP": "边界网关协议 BGP",
    "OSPF": "开放最短路径优先 OSPF",
    "RIP": "路由信息协议 RIP",
    # MITRE ATT&CK T编号
    "T1046": "T1046 网络服务扫描",
    "T1110": "T1110 暴力破解",
    "T1498": "T1498 网络拒绝服务",
    "T1572": "T1572 协议隧道",
    "T1071": "T1071 应用层协议",
    "T1048": "T1048 数据渗出",
    "T1090": "T1090 代理",
    "T1021": "T1021 远程服务",
    "T1005": "T1005 本地数据窃取",
    "T1082": "T1082 系统信息发现",
    # Web攻击
    "XSS": "跨站脚本 XSS",
    "CSRF": "跨站请求伪造 CSRF",
    "SQLi": "SQL注入 SQLi",
    # 网络协议
    "SSH": "SSH 安全外壳",
    "RDP": "RDP 远程桌面",
    "FTP": "FTP 文件传输",
    "HTTP": "HTTP 超文本传输",
    "HTTPS": "HTTPS 超文本传输安全",
    "DNS": "DNS 域名系统",
    "DHCP": "DHCP 动态主机配置",
    "NTP": "NTP 网络时间协议",
    "SNMP": "SNMP 简单网络管理",
    # 安全工具
    "Wireshark": "Wireshark 网络封包分析",
    "Nmap": "Nmap 网络扫描",
    "Tcpdump": "Tcpdump 命令行抓包",
    "Snort": "Snort 入侵检测",
    # 加密协议
    "SSL": "SSL 安全套接层",
    "TLS": "TLS 传输层安全",
    "IPsec": "IPsec 互联网协议安全",
    "VPN": "VPN 虚拟专用网络",
}


def _term_pattern(abbr: str):
    """为术语构造「独立出现」的匹配正则。

    ASCII 术语用单词边界（避免 `HTTP` 命中 `HTTPS` 内部）；含非 ASCII 的术语
    （如 `IPsec` 全为 ASCII，`SQLi` 也是）同样适用 `\\b`。中文术语退化为
    直接匹配（`\\b` 对中文字符不成立）。
    """
    if abbr.isascii():
        return re.compile(rf"(?<![A-Za-z0-9]){re.escape(abbr)}(?![A-Za-z0-9])")
    return re.compile(re.escape(abbr))


# 预编译并按**长度降序**排列：长术语优先匹配，避免短术语吃掉长术语的前缀
_SYNONYM_PATTERNS = [
    (abbr, _term_pattern(abbr), full)
    for abbr, full in sorted(TERM_SYNONYMS.items(), key=lambda kv: -len(kv[0]))
]


def expand_terms(query: str) -> str:
    """扩展查询中的缩写/简称为完整术语。

    【修复】原实现按 dict 顺序做**朴素子串替换**，而表里同时存在
    `HTTP`→`HTTP 超文本传输` 与 `HTTPS`→`HTTPS 超文本传输安全`：`HTTP` 先被替换，
    于是 `HTTPS` 被改写成 `HTTP 超文本传输S`（残留一个孤立的 `S`），
    这个损坏的字符串随后同时进入向量检索与 BM25 两条臂。
    原注释声称"只在缩写独立出现时替换"，但 `if abbr in expanded` + `str.replace`
    并不做任何边界判断。

    现改为：按术语长度降序、用预编译的边界正则做**单次遍历**替换，
    保证长术语优先且不会命中更长标识符的内部。
    """
    if not query:
        return query
    out = query
    for _abbr, pattern, full in _SYNONYM_PATTERNS:
        out = pattern.sub(full, out)
    return out


def rewrite_query(query: str) -> List[str]:
    """
    仅做查询结构变换：显式比较问句拆分为多个子查询；其余原样返回（不做术语扩展）。
    术语扩展 expand_terms 是独立的检索增强步骤，由检索层在召回前单独应用，
    二者职责分离、可独立测试与组合。

    "DNS放大攻击和DNS投毒的区别，检测上关注什么？"
      -> ["DNS放大攻击，检测上关注什么？", "DNS投毒，检测上关注什么？"]
    "XSS和CSRF有什么区别" -> ["XSS是什么", "CSRF是什么"]

    【修复】原 `_COMPARE_RE` 的 alternation 里 `区别` 排在 `有什么关系`/`有什么不同`
    之前，正则引擎优先匹配最短的 `区别`，于是 `tail` 变成 `有什么`，
    拼接后得到 `CSRF有什么是什么` 这种破损子查询。
    现改为：先剥离比较问句后缀，再按「有效疑问尾（丢弃纯疑问短语）」重建。
    """
    text = (query or "").strip()

    # 【修复】原实现用单个 `_COMPARE_RE` 一次性切分，但第 2 组 `(.+?)` 会在
    # 找到匹配的前提下**贪婪地吃掉疑问短语**——"XSS和CSRF有什么区别" 切出的是
    # ("XSS", "CSRF有什么")，于是子查询变成 `CSRF有什么是什么`（XSS 那条恰好碰巧正确，
    # 掩盖了缺陷）。根因是"实体边界"与"比较标记"纠缠在同一个正则里。
    #
    # 现改为两步，边界清晰：
    #   1) 先剥离比较标记（有什么区别/有什么不同/的区别…）及其后的疑问尾；
    #   2) 再在剩余部分里按连接词断开两个实体。
    m_mark = _COMPARE_MARK_RE.search(text)
    if not m_mark:
        return [query]
    head_part = text[:m_mark.start()].strip()
    tail = text[m_mark.end():].strip()

    parts = _ENTITY_SPLIT_RE.split(head_part, maxsplit=1)
    if len(parts) < 2:
        return [query]
    head_a, head_b = parts[0].strip(), parts[1].strip()
    if not head_a or not head_b:
        return [query]

    # 剩余部分若只是纯疑问/标点，则统一重建为简洁问句
    stripped = tail.strip("？?，,。. 　")
    fillers = {"是什么", "什么意思", "什么", "有何区别", "有哪些区别", ""}
    if stripped in fillers:
        tail_q = "是什么"
    elif re.match(r"^[，,？?。.]", tail):
        # 已自带标点前缀，原样使用（避免出现 "，，" 这类重复标点）
        tail_q = tail
    else:
        tail_q = "，" + tail

    subs = [f"{h}{tail_q}" for h in (head_a, head_b)]
    return subs if len(subs) >= 2 else [query]


# ---------- RRF 融合 ----------

def rrf_fuse(ranked_lists: List[List[str]], k: int = 60) -> List[str]:
    """Reciprocal Rank Fusion：多路排序按 1/(k+rank) 加权合并"""
    scores: Dict[str, float] = defaultdict(float)
    for lst in ranked_lists:
        for rank, doc_id in enumerate(lst, 1):
            scores[doc_id] += 1.0 / (k + rank)
    return [doc_id for doc_id, _ in sorted(scores.items(), key=lambda x: -x[1])]
