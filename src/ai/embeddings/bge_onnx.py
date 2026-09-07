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


def _candidate_dirs() -> List[str]:
    """模型目录候选（按优先级）"""
    candidates = []
    # 0. PyInstaller 打包内部目录（onedir 模式下 add-data 位于 _internal，sys._MEIPASS 指向它）
    try:
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(str(os.path.join(meipass, "models", MODEL_DIR_NAME)))
    except Exception:
        pass
    # 1. 程序入口同级（exe 旁手动部署 models/ 的场景）
    try:
        candidates.append(str(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "models", MODEL_DIR_NAME)))
    except Exception:
        pass
    # 2. 项目根（本文件 src/ai/embeddings/ → 上溯 4 级）
    try:
        candidates.append(str(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "models", MODEL_DIR_NAME)))
    except Exception:
        pass
    return candidates


def _dir_complete(model_dir: str) -> bool:
    """目录内模型文件是否完整且大小合法"""
    for fn in MODEL_FILES:
        fp = os.path.join(model_dir, fn)
        if not os.path.exists(fp):
            return False
        if os.path.getsize(fp) < MODEL_MIN_BYTES.get(fn, 1000):
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
        session = ort.InferenceSession(
            os.path.join(model_dir, "model.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self._input_names = [i.name for i in session.get_inputs()]
        self._tokenizer = tok
        self._session = session
        self.model_dir = model_dir
        logger.info(f"BGE 中文 Embedding 就绪 | 模型目录: {model_dir}")

    def _prepare_model_dir(self) -> str:
        """确保模型文件就绪：优先使用已有目录，缺失则自动下载；失败抛异常（上层降级）"""
        # 1. 已有完整模型目录
        existing = self.model_dir or find_model_dir()
        if existing and _dir_complete(existing):
            return existing

        # 2. 自动下载到第一个候选目录
        for cand in _candidate_dirs():
            try:
                self._auto_download(cand)
                return cand
            except FileNotFoundError as e:
                logger.error(str(e))
                continue

        raise FileNotFoundError(
            "BGE 模型文件缺失且自动下载失败，请检查网络后将 models/bge-small-zh-v1.5/ "
            "（tokenizer.json + model.onnx）放置到程序目录，或等待自动降级为默认 Embedding"
        )

    def _auto_download(self, model_dir: str) -> None:
        """下载缺失的模型文件（联网，带进度日志与半文件防护）"""
        import urllib.request

        os.makedirs(model_dir, exist_ok=True)
        for fname, url in MODEL_DOWNLOAD_URLS.items():
            target = os.path.join(model_dir, fname)
            if os.path.exists(target) and os.path.getsize(target) >= MODEL_MIN_BYTES.get(fname, 1000):
                continue  # 已就绪
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
                os.replace(tmp, target)
                logger.info(f"BGE {fname} 下载完成: {os.path.getsize(target) / 1048576:.1f} MB")
            except Exception as e:
                if os.path.exists(tmp):
                    os.remove(tmp)
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

        encodings = [tok.encode(t) for t in texts]
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
        return normalized.tolist()
