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
from src.ai.retrieval_hybrid import BM25Index, rewrite_query, rrf_fuse


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
            chunk_size=500,
            chunk_overlap=100,
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
        """初始化或获取集合"""
        if self.collection is None:
            self._init_client()
            # Embedding 选型：优先 BGE 中文模型（针对中文安全知识库），失败降级默认英文模型
            self.embedding_function = self._create_embedding_function()
            try:
                self.collection = self.client.get_or_create_collection(
                    name=self.collection_name,
                    embedding_function=self.embedding_function,
                    metadata={"hnsw:space": "cosine"}
                )
                logger.info(f"集合初始化完成 | 名称: {self.collection_name} | "
                            f"Embedding: {type(self.embedding_function).__name__}")
            except Exception as e:
                logger.warning(f"Embedding初始化失败，使用无向量模式: {e}")
                self.collection = self.client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"hnsw:space": "cosine"}
                )

    @staticmethod
    def _create_embedding_function():
        """创建 Embedding 函数：BGE 中文（优先）→ 默认英文（降级）"""
        try:
            from src.ai.embeddings.bge_onnx import BGEOnnxEmbeddingFunction
            bge = BGEOnnxEmbeddingFunction()
            # 预触发加载，验证模型可用；失败则降级
            bge._ensure_loaded()
            return bge
        except Exception as e:
            logger.warning(f"BGE 中文 Embedding 不可用（{e}），降级为默认英文 Embedding")
            from chromadb.utils import embedding_functions
            return embedding_functions.DefaultEmbeddingFunction()

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

        # 添加到向量库
        if all_chunks:
            ids = [str(uuid.uuid4()) for _ in all_chunks]
            self.collection.add(
                documents=all_chunks,
                metadatas=all_metadatas,
                ids=ids
            )
            logger.info(f"已添加 {len(all_chunks)} 个文档块到知识库")

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

    def _format_results(self, doc_ids: List[str],
                        distances: Dict[str, float]) -> List[Dict[str, Any]]:
        """把 doc_id 列表组装为检索结果（content/metadata/similarity）"""
        if not doc_ids:
            return []
        data = self.collection.get(ids=doc_ids, include=["documents", "metadatas"])
        id2doc = dict(zip(data.get("ids", []), data.get("documents", [])))
        id2meta = dict(zip(data.get("ids", []), data.get("metadatas", [])))
        out = []
        for doc_id in doc_ids:
            doc = id2doc.get(doc_id, "")
            meta = id2meta.get(doc_id, {}) or {}
            dist = distances.get(doc_id, 0.5)
            similarity = max(0, 1 - dist) if dist <= 1 else 1 / (1 + dist)
            out.append({
                "content": doc,
                "metadata": meta,
                "distance": float(dist),
                "similarity": float(similarity),
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
                vec_ids = self._vector_search(subq, 20, filter_dict)
                bm_ids = self._bm25.score(subq, filter_dict, top_k=20)
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
            dists = self._query_distances(query, final_ids, filter_dict)
            results = self._format_results(final_ids, dists)

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

    def _query_distances(self, query: str, doc_ids: List[str],
                         filter_dict: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
        """获取 doc_ids 对应距离（ChromaDB query 需传查询文本）"""
        if not doc_ids:
            return {}
        try:
            results = self.collection.query(
                query_texts=[query], n_results=len(doc_ids), where=filter_dict)
            ids = results.get("ids", [[]])[0] if results else []
            dists = results.get("distances", [[]])[0] if results else []
            return dict(zip(ids, dists))
        except Exception:
            return {doc_id: 0.5 for doc_id in doc_ids}

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
        """清空知识库"""
        self._init_client()
        try:
            self.client.delete_collection(name=self.collection_name)
            self.collection = None
            logger.warning("知识库已清空")
        except Exception as e:
            logger.error(f"清空知识库失败: {e}")


# 全局单例
_rag_engine: Optional[RAGEngine] = None

def get_rag_engine() -> RAGEngine:
    """获取全局RAG引擎单例"""
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine
