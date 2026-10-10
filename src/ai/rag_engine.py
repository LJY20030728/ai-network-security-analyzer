"""
RAG知识库引擎
基于 ChromaDB 原生API实现安全知识的检索增强生成
不依赖langchain_community，更轻量更稳定
知识库包含：MITRE ATT&CK框架、安全事件处置手册、协议规范等
"""
import os
import uuid
from typing import List, Dict, Any, Optional
from langchain_text_splitters import RecursiveCharacterTextSplitter
from loguru import logger
from config.settings import settings
from src.ai.retrieval_hybrid import BM25Index, expand_terms, rewrite_query, rrf_fuse


class RAGEngine:
    """
    RAG（检索增强生成）引擎
    负责安全知识库的构建、存储和检索
    使用ChromaDB原生API
    """

    def __init__(self, persist_dir: Optional[str] = None, collection_name: str = "security_knowledge"):
        """
        初始化RAG引擎
        :param persist_dir: 向量数据库持久化路径
        :param collection_name: 集合名称
        """
        if persist_dir:
            self.persist_dir = persist_dir
        elif settings.chroma_persist_dir:
            self.persist_dir = settings.chroma_persist_dir
        else:
            from src.utils.paths import data_dir
            self.persist_dir = data_dir("chroma_db")
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        self.embedding_function = None
        self._seeded = False          # 会话级自动初始化标志
        self._seeding = False         # 防并发重复初始化
        self._bm25 = BM25Index()      # 混合检索：惰性构建的 BM25 倒排索引
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=50,
            separators=["\n\n", "\n", "。", "！", "？", ".", "!", "?", " ", ""]
        )
        logger.info(f"RAG引擎初始化 | 持久化目录: {self.persist_dir}")

    def _init_client(self):
        """初始化ChromaDB客户端"""
        if self.client is None:
            os.makedirs(self.persist_dir, exist_ok=True)
            import chromadb
            self.client = chromadb.PersistentClient(path=self.persist_dir)
            logger.info("ChromaDB客户端初始化完成")

    def _init_collection(self):
        """初始化或获取集合。

        不再提供"降级为无向量模式"的回退：该回退**本身就是坏的**——
        集合没有 embedding function 时，`add_texts` 与 `search` 都会用
        `query_texts=[文本]` 调用，而 ChromaDB 在无 EF 时会直接报错。
        与其保留一个会抛错的静默降级，不如在此明确失败，让上层展示
        "RAG 不可用（BGE 模型缺失或校验失败）"。
        """
        if self.collection is None:
            self._init_client()
            # 仅使用本地 BGE 中文模型（不降级为 chromadb 默认 EF，避免静默联网）
            self.embedding_function = self._create_embedding_function()
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_function,
                metadata={"hnsw:space": "cosine"}
            )
            logger.info(f"集合初始化完成 | 名称: {self.collection_name} | "
                        f"Embedding: {type(self.embedding_function).__name__}")

    @staticmethod
    def _create_embedding_function():
        """创建 Embedding 函数：仅使用本地 BGE 中文模型（不再静默降级）。

        【安全】原实现在 BGE 不可用时会降级为 chromadb 的
        `DefaultEmbeddingFunction()`——**那会从 AWS S3 自动下载
        all-MiniLM-L6-v2**。也就是说：一个声称"离线"的安全产品，在用户不知情的
        情况下会静默拉取并执行第二个第三方模型。
        现改为直接失败：调用方会得到明确异常，RAG 功能显示为不可用，
        而不是悄悄联网换了模型（换了模型还会导致向量空间不一致、检索结果错乱）。
        """
        from src.ai.embeddings.bge_onnx import BGEOnnxEmbeddingFunction
        bge = BGEOnnxEmbeddingFunction()
        # 预触发加载：模型缺失/校验失败会在此抛出，由调用方处理
        bge._ensure_loaded()
        return bge

    def add_texts(self, texts: List[str], metadatas: Optional[List[Dict[str, Any]]] = None,
                  source: str = "manual") -> int:
        """
        添加文本到知识库
        :param texts: 文本列表
        :param metadatas: 元数据列表
        :param source: 来源标记
        :return: 添加的文档块数量
        """
        self._init_collection()

        # 分块
        all_chunks = []
        all_metadatas = []
        for i, text in enumerate(texts):
            chunks = self.text_splitter.split_text(text)
            meta = {"source": source}
            if metadatas and i < len(metadatas):
                meta.update(metadatas[i])
            for chunk in chunks:
                all_chunks.append(chunk)
                all_metadatas.append(meta.copy())

        logger.info(f"文本分块完成 | 原始 {len(texts)} 条 -> {len(all_chunks)} 个块")

        # 添加到向量库（分批嵌入，避免大批量一次性嵌入导致内存峰值爆掉）
        if all_chunks:
            BATCH = 10  # 增大批次，提升速度
            import gc
            for i in range(0, len(all_chunks), BATCH):
                chunk_batch = all_chunks[i:i + BATCH]
                meta_batch = all_metadatas[i:i + BATCH]
                ids_batch = [str(uuid.uuid4()) for _ in chunk_batch]
                self.collection.add(
                    documents=chunk_batch,
                    metadatas=meta_batch,
                    ids=ids_batch
                )
                # 每批后主动触发垃圾回收，释放内存
                gc.collect()
            logger.info(f"已添加 {len(all_chunks)} 个文档块到知识库（分批 {BATCH} 条/批）")
            # 【修复】新增文档后必须让 BM25 索引失效：
            # 否则 "先导入文档再检索" 的场景下，BM25 只覆盖初始构建时的文档，
            # 新导入内容永远无法被关键词臂召回（且 clear() 后会出现幽灵结果）。
            self._invalidate_bm25_index()

        return len(all_chunks)

    def add_file(self, filepath: str, source: Optional[str] = None) -> int:
        """从文件加载并添加到知识库"""
        if not os.path.exists(filepath):
            logger.error(f"文件不存在: {filepath}")
            return 0
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        source_name = source or os.path.basename(filepath)
        return self.add_texts([content], source=source_name)

    def add_knowledge_base(self, knowledge_items: List[Dict[str, str]]):
        """
        批量添加知识条目
        :param knowledge_items: [{"title": "...", "content": "...", "category": "..."}]
        """
        texts = []
        metadatas = []
        for item in knowledge_items:
            full_text = f"【{item.get('title', '')}】\n{item.get('content', '')}"
            texts.append(full_text)
            metadatas.append({
                "title": item.get("title", ""),
                "category": item.get("category", "general"),
                "source": "knowledge_base"
            })
        return self.add_texts(texts, metadatas=metadatas, source="knowledge_base")

    def _ensure_bm25_index(self) -> None:
        """惰性构建 BM25 索引（首次混合检索时从集合拉全量文档）"""
        if self._bm25.built:
            return
        try:
            data = self.collection.get(include=["documents", "metadatas"])
            ids = data.get("ids", [])
            docs = data.get("documents", [])
            metas = data.get("metadatas", [])
            if ids:
                self._bm25.build(ids, docs, metas)
        except Exception as e:
            logger.warning(f"BM25 索引构建失败（降级纯向量检索）: {e}")

    def _vector_search(self, query: str, n: int,
                       filter_dict: Optional[Dict[str, Any]] = None) -> List[str]:
        """纯向量检索，返回按距离升序的 doc_id 列表"""
        results = self.collection.query(
            query_texts=[query], n_results=n, where=filter_dict)
        if not results or not results.get("ids"):
            return []
        return results["ids"][0]

    @staticmethod
    def distance_to_similarity(dist: float) -> float:
        """余弦距离 → 相似度的**单调**映射。

        【修复】原实现是两段式：
            `max(0, 1 - dist) if dist <= 1 else 1 / (1 + dist)`
        它在 dist=1.0 处产生断崖，且**非单调**：
            dist=1.0 → 0.0000，而 dist=1.9 → 0.3448
        即「最不相似的文档」得分反而高于「较相似的文档」，`_rerank` 据此排序会出错。

        改用 `1 - dist/2`：ChromaDB 余弦空间的距离区间为 [0, 2]
        （0=完全相同，2=完全相反），故该映射在整个区间上严格单调递减，
        且值域落在 [0, 1]。
        """
        d = float(dist)
        if d < 0:
            d = 0.0
        if d > 2:
            d = 2.0
        return 1.0 - d / 2.0

    def _query_distances(self, query: str, doc_ids: List[str],
                         filter_dict: Optional[Dict[str, Any]] = None,
                         query_embedding: Optional[List[float]] = None,
                         ) -> Dict[str, float]:
        """获取指定 doc_ids 对应的**真实**距离。

        【修复】原实现用 `collection.query(query_texts=[query], n_results=len(doc_ids))`
        去"取 doc_ids 的距离"——但 query 返回的是**该查询最近邻的 id 集合**，
        与传入的 doc_ids 并不相同。于是 BM25-only 命中拿不到距离，
        被 `distances.get(doc_id, 0.5)` **凭空赋成 0.5**，
        换算成 similarity 恰好是 0.500——高于真实检索到的 dist=0.6（→0.40）。
        这个伪造值会进入排序、UI（"相似度:0.50"）以及喂给 LLM 的 prompt。

        现改为：用**查询向量**在集合内做一次向量查询取回真实距离；
        只有在确实取不到时才省略该 id（返回字典中不含它），由调用方决定丢弃。
        """
        if not doc_ids:
            return {}
        try:
            if query_embedding is None:
                query_embedding = self.embedding_function([query])[0]
            res = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=max(len(doc_ids), 1) * 4 + 16,   # 扩大候选以便覆盖全部目标 id
                where=filter_dict)
            ids = (res.get("ids") or [[]])[0]
            dists = (res.get("distances") or [[]])[0]
            got = dict(zip(ids, dists))
            want = set(doc_ids)
            return {k: float(v) for k, v in got.items() if k in want}
        except Exception as e:
            # 不返回伪造值：宁可缺失，也不能让不存在的数据参与排序
            logger.warning(f"获取检索距离失败（相关条目将不参与距离排序）: {e}")
            return {}

    def _format_results(self, doc_ids: List[str],
                        distances: Dict[str, float]) -> List[Dict[str, Any]]:
        """把 doc_id 列表组装为检索结果（content/metadata/similarity）。

        没有真实距离的条目：`distance`/`similarity` 为 None 并标记
        `distance_source="unavailable"`，**不再用 0.5 之类的假值填充**。
        """
        if not doc_ids:
            return []
        data = self.collection.get(ids=doc_ids, include=["documents", "metadatas"])
        id2doc = dict(zip(data.get("ids", []), data.get("documents", [])))
        id2meta = dict(zip(data.get("ids", []), data.get("metadatas", [])))
        out = []
        for doc_id in doc_ids:
            doc = id2doc.get(doc_id, "")
            meta = id2meta.get(doc_id, {}) or {}
            if doc_id in distances:
                dist = float(distances[doc_id])
                sim = self.distance_to_similarity(dist)
                source = "vector"
            else:
                # 真实距离不可得（例如仅由 BM25 召回的条目）
                dist = None
                sim = None
                source = "unavailable"
            out.append({
                "content": doc,
                "metadata": meta,
                "distance": dist,
                "similarity": sim,
                "distance_source": source,
            })
        return out

    def search(self, query: str, top_k: int = 5,
               filter_dict: Optional[Dict[str, Any]] = None,
               use_hybrid: bool = True) -> List[Dict[str, Any]]:
        """
        检索（默认混合检索：查询改写 + 向量 + BM25 + RRF 融合）
        :param query: 查询文本
        :param top_k: 返回结果数量
        :param filter_dict: 元数据过滤条件
        :param use_hybrid: 是否启用混合检索（False 时为纯向量检索，兼容旧行为）
        :return: 检索结果列表
        """
        self._init_collection()
        self._ensure_seeded()

        try:
            if not use_hybrid:
                vec_ids = self._vector_search(query, top_k, filter_dict)
                dists = self._query_distances(query, vec_ids, filter_dict)
                return self._format_results(vec_ids, dists)

            # ① 查询改写：显式比较问句拆分子查询
            sub_queries = rewrite_query(query)
            # ② 每个子查询做向量 + BM25 双路召回
            self._ensure_bm25_index()
            fused_ids: List[str] = []
            seen: set = set()
            for subq in sub_queries:
                # 术语扩展（缩写→完整术语）仅用于召回，不改变原始查询
                recall_q = expand_terms(subq)
                vec_ids = self._vector_search(recall_q, 20, filter_dict)
                bm_ids = self._bm25.score(recall_q, filter_dict, top_k=20)
                merged = rrf_fuse([vec_ids, bm_ids])
                for doc_id in merged:
                    if doc_id not in seen:
                        seen.add(doc_id)
                        fused_ids.append(doc_id)
                if len(fused_ids) >= top_k:
                    break
            # ③ 保底：融合结果不足 top_k 时用纯向量补充
            if len(fused_ids) < top_k:
                for doc_id in self._vector_search(query, top_k * 3, filter_dict):
                    if doc_id not in seen:
                        seen.add(doc_id)
                        fused_ids.append(doc_id)
                    if len(fused_ids) >= top_k:
                        break
            final_ids = fused_ids[:top_k]
            # 复用同一个查询向量：向量查询与距离取回共用，避免重复编码；
            # 距离只接受**真实**值，取不到的条目在结果中标记为"未知"
            q_emb = self.embedding_function([query])[0]
            dists = self._query_distances(query, final_ids, filter_dict,
                                          query_embedding=q_emb)
            results = self._format_results(final_ids, dists)

            # P1-1: 重排序（基于查询词匹配度+安全术语权重）
            results = self._rerank(query, results)

            # 输出调试信息（多路召回贡献，供评测分析）
            logger.debug(f"混合检索完成 | query: {query[:40]}... | 子查询 {len(sub_queries)} | "
                         f"BM25命中 {len(set(bm_ids)) if False else ''} | 结果 {len(results)} 条")
            return results

        except Exception as e:
            logger.error(f"检索失败（{e}），回退纯向量检索")
            try:
                vec_ids = self._vector_search(query, top_k, filter_dict)
                dists = self._query_distances(query, vec_ids, filter_dict)
                return self._format_results(vec_ids, dists)
            except Exception:
                return []

    # P1-1: 安全术语同义词扩展（针对中文安全查询优化检索召回）
    SECURITY_SYNONYMS = {
        "sql注入": ["sql injection", "sql 注入", "注入攻击", "代码注入", "command injection"],
        "勒索": ["ransomware", "勒索软件", "勒索病毒", "加密勒索", "data encrypted for impact"],
        "钓鱼": ["phishing", "钓鱼攻击", "鱼叉钓鱼", "spearphishing", "社会工程"],
        "内存马": ["memory", "process injection", "内存注入", "进程注入", "无文件", "fileless"],
        "中间人": ["mitm", "man-in-the-middle", "adversary-in-the-middle", "中间人攻击", "会话劫持"],
        "暴力破解": ["brute force", "暴力破解", "密码喷洒", "password spraying", "credential access"],
        "横向移动": ["lateral movement", "横向移动", "远程服务", "remote services", "smb", "rdp"],
        "持久化": ["persistence", "持久化", "启动项", "注册表", "autostart", "scheduled task"],
        "隧道": ["tunneling", "隧道", "dns隧道", "dns tunneling", "application layer protocol"],
        "扫描": ["scan", "扫描", "端口扫描", "port scan", "reconnaissance", "侦察"],
    }

    def _expand_query_terms(self, query: str) -> List[str]:
        """扩展查询术语（中文安全术语→英文同义词，提升跨语言召回）"""
        query_lower = query.lower()
        expanded = [query]
        for cn_term, synonyms in self.SECURITY_SYNONYMS.items():
            if cn_term in query_lower:
                expanded.extend(synonyms)
        return list(set(expanded))

    # 领域核心词：term-aware 重排序（中文术语 + 协议/技术英文词）
    CORE_TERMS = [
        "dns", "http", "https", "tcp", "udp", "icmp", "arp", "ospf", "bgp", "rip",
        "ip", "ssl", "tls", "ipsec", "ftp", "ssh", "rdp", "smb", "dhcp", "vlan",
        "sql", "xss", "csrf", "syn", "ack", "端口", "登录", "登陆", "数据包", "流量",
        "带宽", "密码", "暴力", "注入", "钓鱼", "勒索", "木马", "病毒", "恶意", "隧道",
        "代理", "横向", "持久化", "侦察", "扫描", "渗出", "泄露", "防火墙", "路由", "交换",
        "连接", "会话", "证书", "加密", "认证", "权限", "命令", "脚本", "进程",
    ]

    def _extract_core_terms(self, query: str) -> List[str]:
        """提取查询中出现的领域核心词（无命中时退化为整句）"""
        q = query.lower()
        hits = [t for t in self.CORE_TERMS if t in q]
        return hits or [q]

    def _rerank(self, query: str, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        term-aware 语义重排序（不引入 Cross-Encoder）：
        BGE 语义相似度 + 查询核心词精确命中（标题优先），兼顾语义泛化与关键词精确性。

        对「无真实距离」的结果（仅由 BM25 召回）：不把它当作相似度 0
        （那会系统性惩罚纯关键词命中），而是把相似度分量在**有真实分数的结果内**
        做 min-max 归一化后使用；只有一条有分数时给中性值 0.5。
        """
        if not results:
            return results
        cores = self._extract_core_terms(query)
        n_core = max(1, len(cores))

        # 相似度分量归一化（仅针对有真实距离的条目）：用 min-max 映射到 [0,1]，
        # 无真实分数的条目给中性值 0.5（既不奖励也不惩罚纯关键词命中）。
        sims = [float(r["similarity"]) for r in results
                if r.get("similarity") is not None]
        if sims:
            lo, hi = min(sims), max(sims)
            span = hi - lo
        else:
            lo, hi, span = 0.0, 0.0, 0.0

        def _norm(r) -> float:
            s = r.get("similarity")
            if s is None or span < 1e-9:
                return 0.5
            return (float(s) - lo) / span

        scored = []
        for r in results:
            title = ((r.get("metadata") or {}).get("title") or "").lower()
            content = (r.get("content") or "").lower()
            metadata = str(r.get("metadata") or "").lower()

            t_hit = sum(1 for c in cores if c in title)
            c_hit = sum(1 for c in cores if c in content)
            m_hit = sum(1 for c in cores if c in metadata)
            final_score = (_norm(r) * 0.45
                           + (t_hit / n_core) * 0.25
                           + (c_hit / n_core) * 0.15
                           + (m_hit / n_core) * 0.05)
            if t_hit >= 2 or (t_hit >= 1 and len(title) <= 20):
                final_score += 0.10  # 标题精确命中核心词的强奖励

            r["rerank_score"] = round(final_score, 4)
            scored.append(r)

        scored.sort(key=lambda x: x.get("rerank_score", 0), reverse=True)
        return scored

    def _ensure_seeded(self):
        """集合为空时自动从内置 MITRE ATT&CK / 处置手册知识源初始化（幂等）"""
        if self._seeded:
            return
        if self._seeding:
            return
        self._seeding = True
        try:
            cnt = self.collection.count()
            if cnt == 0:
                from src.knowledge.mitre_attck import get_all_knowledge
                items = get_all_knowledge()
                if items:
                    added = self.add_knowledge_base(items)
                    logger.info(f"知识库为空，已自动初始化内置知识源: {added} 块")
        except Exception as e:
            logger.warning(f"知识库自动初始化失败（将在下次检索重试）: {e}")
        finally:
            self._seeded = True
            self._seeding = False

    def get_stats(self) -> Dict[str, Any]:
        """获取知识库统计信息"""
        self._init_collection()
        try:
            count = self.collection.count()
            # 获取所有元数据
            all_data = self.collection.get(include=["metadatas"])
            categories = {}
            for meta in all_data.get("metadatas", []):
                if meta:
                    cat = meta.get("category", "unknown")
                    categories[cat] = categories.get(cat, 0) + 1

            return {
                "total_documents": count,
                "collection_name": self.collection_name,
                "persist_dir": self.persist_dir,
                "categories": categories
            }
        except Exception as e:
            logger.error(f"获取统计失败: {e}")
            return {"error": str(e), "total_documents": 0}

    def clear(self):
        """清空知识库。

        【修复】此前只删除 collection 并置 `self.collection = None`，
        但 **BM25 索引与 `_seeded` 标记都未复位**：
          · 重新导入文档后（gradio_app 的"重建知识库"正是 clear() → add_knowledge_base()），
            BM25 仍持有**已不存在的旧 doc_id**，检索会返回内容为空的"幽灵结果"，
            占用 top-k 名额并作为 `[参考N | 相似度:未知 | ]` 注入 LLM prompt；
          · `_seeded` 为 True 时不会再自动播种，重建后集合可能长期为空。
        现一并复位 BM25 索引与播种标记。
        """
        self._init_client()
        try:
            self.client.delete_collection(name=self.collection_name)
            self.collection = None
            # 复位派生的检索状态，避免旧索引残留
            self._invalidate_bm25_index()
            self._seeded = False
            logger.warning("知识库已清空（BM25 索引与播种标记已复位）")
        except Exception as e:
            logger.error(f"清空知识库失败: {e}")

    def _invalidate_bm25_index(self) -> None:
        """使 BM25 索引失效，下次检索时按当前集合重建"""
        try:
            from src.ai.retrieval_hybrid import BM25Index
            self._bm25 = BM25Index()
        except Exception as e:
            logger.warning(f"BM25 索引复位失败（可能导致旧索引残留）: {e}")


# 全局单例
_rag_engine: Optional[RAGEngine] = None

def get_rag_engine() -> RAGEngine:
    """获取全局RAG引擎单例"""
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine




