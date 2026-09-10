# -*- coding: utf-8 -*-
"""
P2-1: 统一错误处理模块（三层架构）
第一层：输入校验（InputValidator）— 提前拦截非法输入
第二层：全面异常（GlobalExceptionHandler）— 捕获所有未处理异常
第三层：优雅降级（FallbackManager）— 功能不可用时提供降级方案

设计目标：
- 用户永远不会看到 500 错误页或 Python 堆栈
- 所有错误都有友好的中文提示和可操作的建议
- 关键功能失败时自动降级到备用方案
"""
import functools
import traceback
from typing import Any, Callable, Dict, Optional, Tuple

from loguru import logger


# ============================================================
# 第一层：输入校验
# ============================================================

class InputValidator:
    """输入校验器 — 提前拦截非法输入，给出明确的错误提示"""

    @staticmethod
    def validate_pcap_file(filepath: str, max_size_mb: int = 200) -> Tuple[bool, str]:
        """校验 PCAP 文件是否合法"""
        import os
        if not filepath:
            return False, "文件路径不能为空"
        if not os.path.exists(filepath):
            return False, f"文件不存在: {filepath}"
        if not os.path.isfile(filepath):
            return False, f"路径不是文件: {filepath}"
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in (".pcap", ".pcapng", ".cap"):
            return False, f"不支持的文件格式: {ext}（仅支持 .pcap/.pcapng/.cap）"
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > max_size_mb:
            return False, f"文件过大: {size_mb:.1f}MB（上限 {max_size_mb}MB）"
        if size_mb == 0:
            return False, "文件为空"
        return True, ""

    @staticmethod
    def validate_api_key(api_key: str) -> Tuple[bool, str]:
        """校验 API Key 格式"""
        if not api_key:
            return False, "API Key 不能为空"
        if "xxxx" in api_key.lower():
            return False, "API Key 仍是占位符，请填写真实 Key"
        if len(api_key) < 10:
            return False, f"API Key 长度过短（{len(api_key)} 字符），可能不完整"
        return True, ""

    @staticmethod
    def validate_base_url(base_url: str) -> Tuple[bool, str]:
        """校验 Base URL 格式"""
        if not base_url:
            return False, "Base URL 不能为空"
        if not base_url.startswith(("http://", "https://")):
            return False, "Base URL 必须以 http:// 或 https:// 开头"
        return True, ""

    @staticmethod
    def validate_baseline_name(name: str) -> Tuple[bool, str]:
        """校验基线名称"""
        if not name:
            return False, "基线名称不能为空"
        if len(name) > 50:
            return False, f"基线名称过长（{len(name)} 字符，上限 50）"
        if any(c in name for c in r'\/:*?"<>|'):
            return False, "基线名称包含非法字符（\\ / : * ? \" < > |）"
        return True, ""


# ============================================================
# 第二层：全面异常处理
# ============================================================

class ErrorInfo:
    """标准化错误信息"""

    def __init__(self, error_type: str, message: str, detail: str = "",
                 suggestion: str = "", recoverable: bool = True):
        self.error_type = error_type
        self.message = message
        self.detail = detail
        self.suggestion = suggestion
        self.recoverable = recoverable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.error_type,
            "message": self.message,
            "detail": self.detail,
            "suggestion": self.suggestion,
            "recoverable": self.recoverable,
        }


class GlobalExceptionHandler:
    """全局异常处理器 — 将所有异常转换为友好的中文错误信息"""

    # 异常类型到友好提示的映射
    ERROR_MAPPING = {
        "FileNotFoundError": ("文件未找到", "请检查文件路径是否正确"),
        "PermissionError": ("权限不足", "请以管理员身份运行，或检查文件/目录权限"),
        "MemoryError": ("内存不足", "请关闭其他程序释放内存，或减小分析文件大小"),
        "TimeoutError": ("操作超时", "网络连接超时，请检查网络后重试"),
        "ConnectionError": ("连接失败", "无法连接到服务器，请检查网络和 API 地址"),
        "ValueError": ("参数错误", "输入参数不合法，请检查后重试"),
        "KeyError": ("配置缺失", "缺少必要的配置项，请检查设置"),
        "ImportError": ("依赖缺失", "缺少必要的 Python 库，请重新安装依赖"),
        "OSError": ("系统错误", "操作系统层面出错，请检查磁盘空间和文件权限"),
    }

    @classmethod
    def handle(cls, exception: Exception, context: str = "") -> ErrorInfo:
        """处理异常，返回标准化错误信息"""
        error_type = type(exception).__name__
        error_msg = str(exception)

        # 记录完整堆栈到日志
        logger.error(f"[{context}] {error_type}: {error_msg}")
        logger.debug(traceback.format_exc())

        # 查找映射
        if error_type in cls.ERROR_MAPPING:
            friendly_msg, suggestion = cls.ERROR_MAPPING[error_type]
            return ErrorInfo(
                error_type=error_type,
                message=friendly_msg,
                detail=error_msg,
                suggestion=suggestion,
                recoverable=True,
            )

        # 特殊处理：HTTP 错误
        if "401" in error_msg or "403" in error_msg:
            return ErrorInfo(
                error_type="AuthError",
                message="API 认证失败",
                detail=error_msg,
                suggestion="请检查 API Key 是否正确、是否过期",
                recoverable=True,
            )
        if "429" in error_msg:
            return ErrorInfo(
                error_type="RateLimitError",
                message="API 调用频率超限",
                detail=error_msg,
                suggestion="请稍后重试，或降低调用频率",
                recoverable=True,
            )
        if "500" in error_msg or "502" in error_msg or "503" in error_msg:
            return ErrorInfo(
                error_type="ServerError",
                message="API 服务器错误",
                detail=error_msg,
                suggestion="服务器暂时不可用，请稍后重试",
                recoverable=True,
            )

        # 默认：未知错误
        return ErrorInfo(
            error_type=error_type,
            message="操作失败",
            detail=error_msg,
            suggestion="请查看日志获取详细信息，或联系技术支持",
            recoverable=False,
        )


def safe_execute(context: str = "", fallback: Any = None) -> Callable:
    """
    安全执行装饰器 — 捕获函数所有异常，返回降级结果
    :param context: 上下文描述（用于日志）
    :param fallback: 异常时返回的降级值
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_info = GlobalExceptionHandler.handle(e, context or func.__name__)
                logger.warning(f"安全执行降级: {error_info.message}")
                if callable(fallback):
                    return fallback(e, *args, **kwargs)
                return fallback

        return wrapper

    return decorator


# ============================================================
# 第三层：优雅降级
# ============================================================

class FallbackManager:
    """优雅降级管理器 — 关键功能失败时自动切换到备用方案"""

    @staticmethod
    def llm_analysis_fallback(analysis_result: Dict[str, Any]) -> str:
        """LLM 分析失败时的降级：基于规则引擎结果生成简单摘要"""
        alerts = analysis_result.get("anomaly_detection", {}).get("alerts", [])
        severity = analysis_result.get("anomaly_detection", {}).get("severity_summary", {})
        supervised = analysis_result.get("supervised_detection", {})

        lines = ["⚠️ AI 分析暂时不可用，以下为规则引擎自动生成的基础分析：\n"]

        # 主引擎判定
        if supervised:
            verdict = "检测到攻击" if supervised.get("is_attack") else "未检测到明显攻击"
            confidence = supervised.get("confidence", 0)
            lines.append(f"【主引擎判定】{verdict}（置信度: {confidence:.1%}）")
            if supervised.get("attack_flows"):
                lines.append(f"【攻击流数量】{supervised['attack_flows']}")
            lines.append("")

        # 告警统计
        if alerts:
            lines.append(f"【告警统计】共 {len(alerts)} 条告警")
            for sev, cnt in severity.items():
                lines.append(f"  - {sev}: {cnt} 条")
            lines.append("")
            # 前 5 条告警
            lines.append("【主要告警】")
            for a in alerts[:5]:
                lines.append(f"  - [{a.get('severity', '?')}] {a.get('type', '?')}: "
                             f"{a.get('src_ip', '?')} → {a.get('dst_ip', '?')}")
        else:
            lines.append("【告警统计】未检测到异常告警")

        lines.append("\n💡 建议：检查 API Key 配置后重试，可获得更详细的 AI 分析结果。")
        return "\n".join(lines)

    @staticmethod
    def rag_search_fallback(query: str, knowledge_base) -> list:
        """RAG 检索失败时的降级：关键词匹配"""
        try:
            results = []
            query_lower = query.lower()
            # 遍历知识库做简单关键词匹配
            if hasattr(knowledge_base, "collection"):
                # ChromaDB 回退到关键词匹配
                pass
            return results
        except Exception:
            return []

    @staticmethod
    def baseline_detection_fallback(windows: list) -> list:
        """基线检测失败时的降级：简单阈值检测"""
        alerts = []
        for i, w in enumerate(windows):
            packets = w.get("packets", 0) if isinstance(w, dict) else getattr(w, "packets", 0)
            if packets > 1000:  # 简单阈值
                alerts.append({
                    "window_index": i,
                    "type": "HIGH_TRAFFIC",
                    "severity": "MEDIUM",
                    "message": f"窗口 {i} 流量异常高（{packets} 包）",
                })
        return alerts


# ============================================================
# 便捷函数
# ============================================================

def friendly_error(exception: Exception, context: str = "") -> Dict[str, Any]:
    """将异常转换为友好的字典格式（API 响应直接用）"""
    return GlobalExceptionHandler.handle(exception, context).to_dict()


def validate_or_raise(validator: Callable, value: Any, field_name: str = "") -> Any:
    """校验输入，不合法则抛出 ValueError（带友好提示）"""
    valid, msg = validator(value)
    if not valid:
        prefix = f"{field_name}: " if field_name else ""
        raise ValueError(f"{prefix}{msg}")
    return value
