# -*- coding: utf-8 -*-
"""
UI 层工具函数集合

从 gradio_app.py 拆出的独立工具函数，降低主文件复杂度。
仅包含不依赖全局状态的纯函数：API Key 校验、掩码、回环地址检测。

注意：_baseline_path 和 _check_upload_file 依赖 gradio_app.py 的全局状态
（settings、BASELINE_DIR、validate_upload_file），保留在主文件中，未拆分。
"""
import os


def _looks_like_real_api_key(value: str) -> bool:
    """判断字符串是否"看起来是真实 API Key"。

    【为什么要这个函数】曾发生真实数据丢失：UI 的掩码 `'0bf7…4U3u'`（含 U+2026）
    被当作 Key 写进 DPAPI，而 `.env` 的明文同时被清除 —— 真实 Key 就此不可恢复；
    且掩码的非 ASCII 字符让后续每次 LLM 调用都在 HTTP 头 ASCII 编码处失败。

    掩码/占位符/被截断的值必须被**主动拒绝**，而不是只检查 `'xxxx'`。
    判定标准（全部满足才算真实）：
      · 非空且长度 ≥ 20（真实 Key 通常 30+ 字符，掩码只有 9）
      · 纯 ASCII（掩码含 U+2026，非 ASCII 会在 HTTP 头编码时抛异常）
      · 不含空白字符
      · 不含省略号/U+2026 等掩码标记
    """
    if not value:
        return False
    v = value.strip()
    if len(v) < 20:
        return False
    if not v.isascii():
        return False
    if any(c.isspace() for c in v):
        return False
    if "\u2026" in v or "..." in v or "***" in v:
        return False
    if "xxxx" in v.lower():
        return False
    return True


def mask_key(value: str) -> str:
    """把 Key 变成仅用于**展示**的掩码（返回空串表示无有效 Key）。

    只应出现在 info / placeholder / 日志里，**绝不能作为组件的 value**。
    """
    if not _looks_like_real_api_key(value):
        return ""
    v = value.strip()
    return f"{v[:4]}…{v[-4:]}"


def _is_loopback_host(host: str) -> bool:
    """主机名/IP 是否为回环地址"""
    import ipaddress

    h = (host or "").strip().lower()
    if not h:
        return False
    if h in ("localhost", "::1", "[::1]"):
        return True
    try:
        return ipaddress.ip_address(h.strip("[]")).is_loopback
    except ValueError:
        return False
