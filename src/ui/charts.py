# -*- coding: utf-8 -*-
"""
轻量纯 SVG 图表构建（零第三方依赖）

安全约定（重要）：
本模块产出的是**直接交给 `gr.HTML` 渲染的 HTML/SVG 字符串**，而 `gr.HTML`
与 `gr.Markdown` 不同，**没有 `sanitize_html` 属性**（Markdown 组件默认
`sanitize_html=True`，本模块对应的组件没有这层保护）。

因此：**任何进入本模块的字符串型数据都必须经 `_esc()` 转义后才能插值。**
数值可以格式化后直接插入（`{v:.1f}` / `{v:d}` 不会产生标签）。

历史上 `_build_baseline_profile_svg` 直接把基线名拼进 SVG，而基线名可被用户
通过 UI 表单或 `/api/baseline/learn` 写入并持久化到 SQLite，导致存储型 XSS
（`demo.load(...)` 驱动该图表 → 每次页面加载都执行）。现已双层防御：
  - 写入层：`src/storage/baseline_name.py` 拒绝非法名称；
  - 渲染层：本模块 `_esc()` 兜住历史脏数据。
"""
import html


def _esc(value) -> str:
    """转义任意值为可安全嵌入 HTML/SVG 文本节点的字符串。

    `quote=True` 使 `"` 与 `'` 也被转义，因此本函数对「属性值内插值」同样安全。
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _build_baseline_compare_svg(window_series, baseline_profile):
    """流量每窗口包数 vs 基线中位数 对比图（纯 SVG，零依赖）"""
    if not window_series:
        return None
    try:
        n = len(window_series)
        if n == 0:
            return None
        median = None
        win_sec = 10
        if isinstance(baseline_profile, dict):
            prof = baseline_profile.get("profile") or {}
            w = prof.get("window_packets") or {}
            if isinstance(w, dict) and w.get("median"):
                median = float(w["median"])
            win_sec = int(baseline_profile.get("window_sec", 10) or 10)
        values = [float(x.get("packets", 0)) for x in window_series]
        vmax = max(max(values), median or 0, 1) * 1.15
        W, H, P = 760, 220, 38
        iw, ih = W - 2 * P, H - 2 * P
        def _xy(i, v):
            x = P + (iw * i / max(n - 1, 1))
            y = P + ih - (ih * v / vmax)
            return x, y
        pts = " ".join(f"{_xy(i, v)[0]:.1f},{_xy(i, v)[1]:.1f}" for i, v in enumerate(values))
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" style="font-family:Segoe UI,Arial,sans-serif;background:linear-gradient(180deg,#f8faff,#eef4ff);border-radius:12px;border:1px solid #dbe6ff">']
        for g in range(5):
            gy = P + ih * g / 4
            svg.append(f'<line x1="{P}" y1="{gy:.1f}" x2="{W-P}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        if median:
            my = P + ih - (ih * median / vmax)
            svg.append(f'<line x1="{P}" y1="{my:.1f}" x2="{W-P}" y2="{my:.1f}" stroke="#ef4444" stroke-width="2" stroke-dasharray="6,4"/>')
            svg.append(f'<text x="{W-P-8}" y="{my-7:.1f}" text-anchor="end" font-size="11" fill="#ef4444">基线中位数 {median:.0f} 包/窗</text>')
        svg.append(f'<polyline points="{pts}" fill="none" stroke="#2563eb" stroke-width="2.4" stroke-linejoin="round"/>')
        for i, v in enumerate(values):
            x, y = _xy(i, v)
            svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#2563eb"/>')
        svg.append(f'<text x="{P}" y="{H-8}" font-size="11" fill="#64748b">窗口序号（每 {_esc(win_sec)} 秒一个窗口，共 {_esc(n)} 个）</text>')
        svg.append(f'<text x="{P}" y="{P-12}" font-size="11" fill="#64748b">每窗口包数</text>')
        svg.append(f'<text x="{W-P}" y="{P-12}" text-anchor="end" font-size="12" fill="#2563eb">当前流量</text>')
        svg.append('</svg>')
        return "".join(svg)
    except Exception:
        return None

def _build_baseline_profile_svg(profile, name):
    """基线画像（各维度 中位数±MAD）条形图（纯 SVG）

    注意：`name` 来自用户输入并持久化，必须转义——见模块 docstring。
    """
    if not isinstance(profile, dict) or not profile:
        return None
    try:
        dims = [("window_packets", "每窗包数"), ("window_bytes", "每窗字节"),
                ("window_syn", "每窗SYN"), ("window_dports", "每窗端口数")]
        rows = []
        vmax = 1
        for k, _lab in dims:
            v = profile.get(k) or {}
            if isinstance(v, dict) and v.get("median"):
                vmax = max(vmax, float(v["median"]) * 1.25)
        W, H, P = 560, 46 + len(dims) * 46, 40
        bar_w = W - 2 * P
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" style="font-family:Segoe UI,Arial,sans-serif;background:#f8faff;border-radius:12px;border:1px solid #dbe6ff">']
        svg.append(f'<text x="{P}" y="22" font-size="13" font-weight="600" fill="#1e293b">基线「{_esc(name or "?")}」画像（中位数 ± MAD）</text>')
        for i, (k, lab) in enumerate(dims):
            y = 44 + i * 46
            v = profile.get(k) or {}
            med = float(v.get("median", 0) or 0)
            mad = float(v.get("mad", 0) or 0)
            bw = bar_w * med / vmax
            svg.append(f'<text x="{P}" y="{y+13}" font-size="11" fill="#475569">{_esc(lab)}</text>')
            svg.append(f'<rect x="{P}" y="{y+18}" width="{bw:.1f}" height="12" rx="4" fill="#60a5fa"/>')
            svg.append(f'<rect x="{P}" y="{y+18}" width="{bar_w*mad/vmax:.1f}" height="12" rx="4" fill="none" stroke="#ef4444" stroke-dasharray="4,3"/>')
            svg.append(f'<text x="{P+bw+8:.1f}" y="{y+29}" font-size="11" fill="#2563eb">中位 {med:.1f} · MAD {mad:.1f}</text>')
        svg.append('</svg>')
        return "".join(svg)
    except Exception:
        return None
