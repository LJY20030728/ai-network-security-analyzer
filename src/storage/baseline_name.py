# -*- coding: utf-8 -*-
"""
基线名称校验（安全边界）

背景：基线名会成为 SQLite 主键、以及 UI 图表里的展示文本。此前名称只做了
`.strip()`，可直接携带 HTML/SVG 片段（如 ``</svg><img src=x onerror=...>``）
穿透到 `gr.HTML` 组件——而 `gr.HTML` 没有 `sanitize_html`，且该图表由
`demo.load(...)` 驱动，等于**每次页面加载都执行存储型 XSS**。

防御采用双层：
  1. 写入层（本模块）：非法名称直接拒绝，脏数据无法入库；
  2. 渲染层（src/ui/charts.py）：所有插值 `html.escape`，兜住历史脏数据。

允许字符：中英文、数字、空格、``_`` ``-`` ``.``
（中文依赖 Python 的 ``str.isalnum()``，它覆盖 Unicode 字母与数字）
长度：strip 后 1–64 字符
"""
from typing import Optional

# 除字母数字外额外允许的字符（显式列出，便于审计）
_ALLOWED_EXTRA_CHARS = frozenset(" _-.")

# Windows 保留设备名：用作文件名时会被系统特殊对待（写出失败或产生异常设备文件）
_WINDOWS_RESERVED = frozenset(
    [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
    + ["CON", "PRN", "AUX", "NUL"]
)

MAX_BASELINE_NAME_LEN = 64

# 供 UI/API 复用的提示文案（保持中文，与项目现有错误文案风格一致）
NAME_RULE_HINT = "名称仅允许中英文、数字、空格、下划线、连字符和点，长度 1–64 字符"


def normalize_baseline_name(name: Optional[str]) -> str:
    """只做首尾 strip，不做任何静默替换（内部空白原样保留）。

    :raises ValueError: 名称非字符串或为空
    """
    if name is None:
        raise ValueError("基线名称不能为空")
    if not isinstance(name, str):
        raise ValueError(f"基线名称必须是字符串，实际为 {type(name).__name__}")
    stripped = name.strip()
    if not stripped:
        raise ValueError("基线名称不能为空")
    return stripped


def validate_baseline_name(name: Optional[str]) -> str:
    """校验基线名称，返回规范化后的名称。

    非法原因一律抛 ValueError（调用方负责转成用户文案或 HTTP 400）。

    :raises ValueError: 名称为空、超长、含不允许字符、或以点/空格结尾
    """
    normalized = normalize_baseline_name(name)

    if len(normalized) > MAX_BASELINE_NAME_LEN:
        raise ValueError(
            f"基线名称过长（{len(normalized)} 字符 > {MAX_BASELINE_NAME_LEN}）：{NAME_RULE_HINT}"
        )

    illegal = sorted({ch for ch in normalized if not (ch.isalnum() or ch in _ALLOWED_EXTRA_CHARS)})
    if illegal:
        shown = "".join(illegal[:8])
        raise ValueError(f"基线名称含不允许的字符 {shown!r}：{NAME_RULE_HINT}")

    # Windows 下以点或空格结尾的文件名会被系统截断，导致名字与文件名不一致
    if normalized[-1] in ". ":
        raise ValueError(f"基线名称不能以点或空格结尾：{NAME_RULE_HINT}")

    # 保留设备名（大小写不敏感；带扩展名形式如 CON.json 同样危险）
    if normalized.split(".")[0].upper() in _WINDOWS_RESERVED:
        raise ValueError(f"基线名称不能使用系统保留名（如 CON/PRN/NUL/COM1）：{NAME_RULE_HINT}")

    return normalized


def safe_baseline_name(name: Optional[str], fallback: str = "") -> str:
    """宽松版：能校验通过就返回规范名，否则回退到 fallback。

    专供「从既有 JSON 文件导入」这类无法拒绝的历史路径使用——那些数据不由
    用户当场输入，直接抛错会让整个列表页挂掉，因此降级为回退值。
    """
    try:
        return validate_baseline_name(name)
    except ValueError:
        return fallback
