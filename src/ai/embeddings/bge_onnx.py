"""
BGE 中文 Embedding（ONNX Runtime 轻量实现）
============================================
针对中文安全知识库的检索质量优化：
- 模型：BAAI/bge-small-zh-v1.5（ONNX 格式，~90MB，无需 torch）
- 推理：onnxruntime CPU 执行（已随项目打包）
- 池化：取 [CLS] 向量（BGE 论文推荐），L2 归一化
- 设计：
  1. 模型懒加载（首次调用才加载，避免拖慢启动）
  2. 模型文件缺失时**自动下载**（首次启动需联网一次；安装包已内置则直接使用）
  3. 下载失败抛异常，由调用方降级到默认英文 Embedding

模型文件位置探测：
1. 程序同级 models/（PyInstaller 打包后 --add-data 放置）
2. 项目根 models/（开发模式）

下载源：hf-mirror 的 Xenova/bge-small-zh-v1.5（注意：BAAI 官方仓库仅含 PyTorch
权重，无 ONNX；此坑已在开发期定位，下载源固定为含 onnx/ 的转换仓库）
"""
import os
import sys
from typing import List, Optional

from loguru import logger

# ChromaDB EmbeddingFunction 协议
try:
    from chromadb.api.types import Documents, EmbeddingFunction, Embeddings
except ImportError:
    # 协议类型缺失时退化为动态协议（仍可调用）
    class Documents:
        pass
    class Embeddings:
        pass
    EmbeddingFunction = object


MODEL_DIR_NAME = "bge-small-zh-v1.5"
MODEL_FILES = ("tokenizer.json", "model.onnx")
# 文件最小合法大小（防 404 等返回的垃圾小文件，开发期踩过 15 字节 404 body 的坑）
MODEL_MIN_BYTES = {"tokenizer.json": 1000, "model.onnx": 1024 * 1024}
# 自动下载源（hf-mirror 镜像，Xenova 为 ONNX 转换仓库）
MODEL_DOWNLOAD_BASE = "https://hf-mirror.com/Xenova/bge-small-zh-v1.5/resolve/main"
MODEL_DOWNLOAD_URLS = {
    "tokenizer.json": f"{MODEL_DOWNLOAD_BASE}/tokenizer.json",
    "model.onnx": f"{MODEL_DOWNLOAD_BASE}/onnx/model.onnx",
}

# 【安全】期望的 sha256。
#
# 背景：本项目是**安全分析工具**，而原实现会从第三方镜像（hf-mirror.com）自动
# 下载 ~91MB 的 onnx 模型、**不做任何完整性校验**就交给 onnxruntime 执行——
# 只校验了"文件大小下限"。一个安全产品静默拉取并执行未验证的第三方二进制，
# 是最不该出现的行为。
#
# 下列哈希由随仓库分发的模型文件实测得出，作为下载/就绪判定的白名单。
# 若上游模型更新导致校验失败，请显式更新本表（而不是删掉校验）——
# 更新前应先人工核对文件来源。
#
# 可通过环境变量 `AI_NSA_MODEL_SHA256_<文件名大写>` 覆盖（便于离线分发自有副本）：
#   例：AI_NSA_MODEL_SHA256_MODEL_ONNX=<hex>
MODEL_SHA256 = {
    "tokenizer.json": "48cea5d44424912a6fd1ea647bf4fe50b55ab8b1e5879c3275f80e339e8fae26",
    "model.onnx": "69a0b846f4f116b5e6aabf9546ea6754d02264f3211a13a1bd69b31b8040749a",
}

# 设为 "0"/"false" 可完全禁用自动下载（离线/受限环境）。
# 禁用后模型缺失会直接报错，而不是联网拉取。
MODEL_AUTO_DOWNLOAD_ENV = "AI_NSA_MODEL_AUTO_DOWNLOAD"


def expected_sha256(fname: str) -> str:
    """取某文件的期望哈希（允许环境变量覆盖，便于私有镜像分发）"""
    override = os.environ.get(f"AI_NSA_MODEL_SHA256_{fname.replace('.', '_').upper()}")
    return (override or MODEL_SHA256.get(fname, "")).strip().lower()


def auto_download_enabled() -> bool:
    """自动下载是否启用（默认启用；显式设为 0/false/no 则禁用）"""
    return os.environ.get(MODEL_AUTO_DOWNLOAD_ENV, "1").strip().lower() not in (
        "0", "false", "no", "off")


def sha256_of(path: str, chunk: int = 1024 * 1024) -> str:
    """流式计算文件 sha256（91MB 模型也不吃内存）"""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def file_is_valid(path: str, fname: str, verify_hash: bool = True) -> bool:
    """文件是否可用：存在 + 达到最小大小 + （可选）sha256 匹配。

    :param verify_hash: 只对缺少期望哈希的文件跳过校验；有期望值就必须匹配。
    """
    if not os.path.isfile(path):
        return False
    if os.path.getsize(path) < MODEL_MIN_BYTES.get(fname, 1000):
        return False
    if not verify_hash:
        return True
    want = expected_sha256(fname)
    if not want:
        return True
    return sha256_of(path) == want


def _candidate_dirs() -> List[str]:
    """
    模型目录候选（按优先级）。

    注：原先每段都包了 try/except + pass，但 os.path.join / os.path.dirname /
    getattr 均不会抛异常，属于"空保护"——它掩盖不了任何真实故障，
    却让读者误以为这些路径构造可能失败。此处改为直接构造，
    并在最终结果为空时给出明确告警（否则 RAG 会静默降级为关键词匹配）。
    """
    candidates = []

    # 0. PyInstaller 打包内部目录（onedir 模式下 add-data 位于 _internal，sys._MEIPASS 指向它）
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "models", MODEL_DIR_NAME))

    # 1. 程序入口同级（exe 旁手动部署 models/ 的场景）
    candidates.append(
        os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "models", MODEL_DIR_NAME)
    )

    # 2. 项目根（本文件 src/ai/embeddings/ → 上溯 4 级）
    candidates.append(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))),
            "models", MODEL_DIR_NAME,
        )
    )

    if not candidates:
        logger.warning(
            "未能构造出任何嵌入模型候选目录，RAG 语义检索将不可用（会退化为关键词匹配）"
        )
    return candidates


def _dir_complete(model_dir: str) -> bool:
    """目录内模型文件是否完整：存在 + 大小合法 + sha256 匹配期望值。

    哈希校验是必需的：本函数决定是否直接加载模型交给 onnxruntime 执行，
    仅凭"文件够大"无法排除被替换/损坏的模型。
    """
    for fn in MODEL_FILES:
        fp = os.path.join(model_dir, fn)
        if not file_is_valid(fp, fn):
            return False
    return True


def find_model_dir() -> Optional[str]:
    """按优先级探测已完整的模型目录"""
    for cand in _candidate_dirs():
        if _dir_complete(cand):
            return cand
    return None


class BGEOnnxEmbeddingFunction(EmbeddingFunction):
    """基于 ONNX Runtime 的 BGE 中文 Embedding（缺失自动下载）"""

    def __init__(self, model_dir: Optional[str] = None, max_length: int = 512):
        self.model_dir = model_dir
        self.max_length = max_length
        self._tokenizer = None
        self._session = None

    def _ensure_loaded(self):
        """懒加载 tokenizer + onnx session（必要时先自动下载模型）"""
        if self._session is not None:
            return

        model_dir = self.model_dir or find_model_dir()
        if not model_dir or not _dir_complete(model_dir):
            model_dir = self._prepare_model_dir()

        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        tok.enable_truncation(max_length=self.max_length)
        tok.enable_padding(pad_id=0, pad_token="[PAD]", length=self.max_length)

        import onnxruntime as ort
        import numpy as np

        self._np = np
        # 限制推理线程数，避免 onnxruntime 多线程导致内存峰值爆掉（bad allocation）
        sess_opts = ort.SessionOptions()
        sess_opts.intra_op_num_threads = 2
        sess_opts.inter_op_num_threads = 1
        sess_opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        session = ort.InferenceSession(
            os.path.join(model_dir, "model.onnx"),
            sess_options=sess_opts,
            providers=["CPUExecutionProvider"],
        )
        self._input_names = [i.name for i in session.get_inputs()]
        self._tokenizer = tok
        self._session = session
        self.model_dir = model_dir
        logger.info(f"BGE 中文 Embedding 就绪 | 模型目录: {model_dir}")

    def _prepare_model_dir(self) -> str:
        """确保模型文件就绪：优先使用已有目录，缺失则在允许时下载；失败抛异常"""
        # 1. 已有完整模型目录（含 sha256 校验）
        existing = self.model_dir or find_model_dir()
        if existing and _dir_complete(existing):
            return existing

        # 2. 自动下载（受 AI_NSA_MODEL_AUTO_DOWNLOAD 开关控制）
        if not auto_download_enabled():
            raise FileNotFoundError(
                f"BGE 模型文件缺失或校验失败，且自动下载已被禁用"
                f"（{MODEL_AUTO_DOWNLOAD_ENV}=0）。请手动将 "
                f"models/{MODEL_DIR_NAME}/（tokenizer.json + model.onnx）放到程序目录。"
            )

        for cand in _candidate_dirs():
            try:
                self._auto_download(cand)
                return cand
            except FileNotFoundError as e:
                logger.error(str(e))
                continue

        raise FileNotFoundError(
            f"BGE 模型文件缺失且自动下载/校验失败，请将 models/{MODEL_DIR_NAME}/ "
            "（tokenizer.json + model.onnx）手动放到程序目录。"
        )

    def _auto_download(self, model_dir: str) -> None:
        """下载缺失的模型文件（联网，带进度日志、半文件防护与 sha256 校验）"""
        import urllib.request

        os.makedirs(model_dir, exist_ok=True)
        for fname, url in MODEL_DOWNLOAD_URLS.items():
            target = os.path.join(model_dir, fname)
            if file_is_valid(target, fname):
                continue  # 已就绪且哈希匹配
            if os.path.exists(target):
                # 存在但哈希不符：说明文件损坏或被替换，必须重下
                logger.warning(
                    f"BGE {fname} 已存在但 sha256 校验未通过，将重新下载"
                    f"（期望 {expected_sha256(fname)[:16]}…）")
            tmp = target + ".part"
            logger.warning(f"BGE 模型文件缺失: {fname}，自动下载中（首次启动需联网）: {url}")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as f:
                    total = int(resp.headers.get("Content-Length") or 0)
                    done = 0
                    last_log = 0
                    while True:
                        chunk = resp.read(1024 * 256)
                        if not chunk:
                            break
                        f.write(chunk)
                        done += len(chunk)
                        # 每 ~10MB 打一次进度
                        if done - last_log >= 10 * 1024 * 1024:
                            last_log = done
                            logger.info(f"  BGE {fname} 下载中 {done / 1048576:.0f}/{total / 1048576:.0f} MB")
                # 【安全】落盘前必须校验 sha256：下载内容来自第三方镜像，
                # 未经校验就交给 onnxruntime 执行等同于信任任意远端代码。
                want = expected_sha256(fname)
                actual = sha256_of(tmp)
                if want and actual != want:
                    os.remove(tmp)
                    raise FileNotFoundError(
                        f"BGE {fname} sha256 校验失败，已删除下载文件。"
                        f"期望 {want[:16]}…，实际 {actual[:16]}…。"
                        f"可能是镜像内容变更或传输损坏；请勿直接使用，"
                        f"如需更新请人工核对来源后修改 MODEL_SHA256。"
                    )
                os.replace(tmp, target)
                logger.info(f"BGE {fname} 下载完成并通过 sha256 校验: "
                            f"{os.path.getsize(target) / 1048576:.1f} MB")
            except Exception as e:
                if os.path.exists(tmp):
                    os.remove(tmp)
                if isinstance(e, FileNotFoundError):
                    raise
                raise FileNotFoundError(f"BGE 模型自动下载失败（{fname}）: {e}")

    def __call__(self, input: Documents) -> Embeddings:
        """输入文本列表，输出归一化向量列表（ChromaDB 协议）"""
        import numpy as np

        self._ensure_loaded()
        np = self._np
        tok = self._tokenizer
        session = self._session

        texts = list(input)
        if not texts:
            return []

        # 分批推理（每批 32 条），控制单次 session.run 内存峰值（修复 bad allocation）
        BATCH = 32  # 增大批次，提升速度
        all_vecs: List[List[float]] = []
        for start in range(0, len(texts), BATCH):
            batch = texts[start:start + BATCH]
            encodings = [tok.encode(t) for t in batch]
            input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
            attention_mask = np.array([e.attention_mask for e in encodings], dtype=np.int64)

            feed = {}
            if "input_ids" in self._input_names:
                feed["input_ids"] = input_ids
            elif len(self._input_names) >= 1:
                feed[self._input_names[0]] = input_ids
            if "attention_mask" in self._input_names:
                feed["attention_mask"] = attention_mask
            elif len(self._input_names) >= 2:
                feed[self._input_names[1]] = attention_mask
            if "token_type_ids" in self._input_names:
                feed["token_type_ids"] = np.zeros_like(input_ids)

            outputs = session.run(None, feed)
            # last_hidden_state: (B, L, H)，取 [CLS]（index 0）
            last_hidden = outputs[0]
            cls_emb = last_hidden[:, 0, :]
            norms = np.linalg.norm(cls_emb, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            normalized = (cls_emb / norms).astype(np.float32)
            all_vecs.extend(normalized.tolist())
        return all_vecs


