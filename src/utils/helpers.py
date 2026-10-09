"""
通用工具函数
"""
import os
import json
import time
from typing import Any, List, Optional
from datetime import datetime
from loguru import logger


def force_utf8_stdout() -> None:
    """
    让 stdout/stderr 能安全输出中文与 emoji。

    背景：Windows 控制台默认 GBK，`print("✅ ...")` 会抛
    UnicodeEncodeError: 'gbk' codec can't encode character '\\u2705'，
    导致评测脚本在打印结果时崩溃（功能已跑完却拿不到结论）。

    做两层保护：
      1. reconfigure(encoding='utf-8') —— 让底层流按 UTF-8 编码；
      2. 追加 errors='replace' —— 即使 reconfigure 不可用（如被 colorama
         等包装过、或 stdout 被重定向到不支持的对象），也无法因为
         编码不了某个字符而中断程序，最多显示为替代字符。

    失败时静默：此时日志系统通常尚未初始化，无法通过 logger 记录，
    且失败不影响功能（仅可能显示为乱码）。
    """
    import sys
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            elif hasattr(stream, "errors"):
                stream.errors = "replace"
        except Exception:
            # 合理沉默：见 docstring（日志系统未就绪 + 失败仅影响显示）
            try:
                if hasattr(stream, "errors"):
                    stream.errors = "replace"
            except Exception:
                pass


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """
    配置日志系统
    """
    import sys
    # Windows下设置UTF-8输出，避免中文/特殊字符编码错误
    force_utf8_stdout()

    logger.remove()
    logger.add(
        lambda msg: sys.stdout.write(msg),
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    if log_file:
        logger.add(log_file, level=log_level, rotation="10 MB", retention="7 days")
    logger.info("日志系统初始化完成")


def ensure_dir(dir_path: str):
    """确保目录存在"""
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
        logger.debug(f"创建目录: {dir_path}")


def save_json(data: Any, filepath: str):
    """保存为JSON文件"""
    ensure_dir(os.path.dirname(filepath))
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    logger.info(f"已保存JSON: {filepath}")


def load_json(filepath: str) -> Any:
    """加载JSON文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def format_bytes(size_bytes: int) -> str:
    """格式化字节数为人类可读格式"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def format_duration(seconds: float) -> str:
    """格式化时长"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}min"
    else:
        return f"{seconds / 3600:.2f}h"


def get_timestamp_str() -> str:
    """获取当前时间戳字符串（用于文件名）"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def resolve_n_jobs(default: int = 1) -> int:
    """
    解析并行度，优先读环境变量 `AI_NSA_N_JOBS`。

    为什么检测路径默认串行（1）而不是 -1：
      · `n_jobs=-1` 会让 joblib/sklearn 拉起多进程（loky），需要创建命名管道；
        在权限收紧的终端、CI 沙箱、部分企业环境会直接失败为
        `PermissionError: [WinError 5]`，导致功能与评测脚本都无法复现。
      · 检测路径的数据规模（4 维、百级窗口）并行收益趋近于零。
    需要并行时显式设置环境变量，例如 `set AI_NSA_N_JOBS=4`。

    :param default: 未设置环境变量时的取值。离线评测脚本可传更大值
                    （如 -1 用满所有核心），因为它们是离线批处理、
                    且数据规模大，并行有实际收益。
    """
    import os
    raw = os.environ.get("AI_NSA_N_JOBS")
    if raw:
        try:
            n = int(raw)
            return n if n != 0 else default
        except ValueError:
            pass
    return default


def calculate_file_sha256(filepath: str) -> str:
    """
    计算文件 SHA-256（证据溯源用）。

    分块读取（1MB），大文件不占内存。失败时返回空字符串并记录告警，
    不抛异常 —— 哈希失败不应阻断分析流程。
    """
    import hashlib
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning(f"计算文件哈希失败: {e}")
        return ""


def validate_upload_file(filename: str, size: int,
                         allowed_extensions: Optional[List[str]] = None,
                         max_mb: Optional[int] = None) -> Optional[str]:
    """
    校验上传的 PCAP 文件类型与大小。

    与 UI 框架解耦：返回错误信息字符串（None 表示通过），
    由调用方决定如何呈现（API 层转 HTTPException，UI 层转提示）。
    """
    if allowed_extensions is None:
        allowed_extensions = [".pcap", ".pcapng", ".cap", ".pcap.gz"]
    if max_mb is None:
        max_mb = 200

    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in allowed_extensions:
        return f"不支持的文件类型 {ext}，仅允许: {', '.join(sorted(allowed_extensions))}"

    max_bytes = int(max_mb) * 1024 * 1024
    if size > max_bytes:
        return f"文件超过大小限制（{max_mb}MB）"
    return None


def timing_decorator(func):
    """函数执行计时装饰器"""
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        logger.debug(f"{func.__name__} 执行耗时: {elapsed:.3f}s")
        return result
    return wrapper


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """将列表分块"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def is_valid_ip(ip: str) -> bool:
    """简单的IP地址验证"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """判断是否为内网IP"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False
