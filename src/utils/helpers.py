"""
通用工具函数
"""
import os
import json
import time
from typing import Any, Dict, List, Optional
from datetime import datetime
from loguru import logger


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """
    配置日志系统
    """
    import sys
    # Windows下设置UTF-8输出，避免中文/特殊字符编码错误
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

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
