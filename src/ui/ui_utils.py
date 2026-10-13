# -*- coding: utf-8 -*-
"""
UI 层工具函数集合

从 gradio_app.py 拆出的独立工具函数，降低主文件复杂度。
包含：API Key 校验、路径安全、文件上传校验、基线路径管理等。
"""
import os
import re
from typing import List, Dict, Any, Optional

from loguru import logger

from src.utils.paths import data_dir
from src.storage.baseline_name import safe_baseline_name


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


def _baseline_path(name: str) -> str:
    """根据基线名称生成安全的 JSON 文件路径（防路径穿越 + 长度限制）。"""
    safe = safe_baseline_name(name)
    return os.path.join(data_dir("baselines"), f"{safe}.json")


def _check_upload_file(filename: str, size: int):
    """校验上传文件：扩展名白名单 + 大小限制，不通过则抛 HTTPException。"""
    from fastapi import HTTPException

    ALLOWED_EXT = {".pcap", ".pcapng", ".cap"}
    MAX_SIZE = 200 * 1024 * 1024  # 200MB

    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件类型: {ext}（仅支持 {', '.join(sorted(ALLOWED_EXT))}）"
        )
    if size > MAX_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"文件过大: {size / 1024 / 1024:.1f}MB（上限 {MAX_SIZE // 1024 // 1024}MB）"
        )
