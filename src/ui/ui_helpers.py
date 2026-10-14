"""
UI 辅助函数与样式

从 gradio_app.py 拆分出的 UI 辅助函数：
- 上传文件校验
- LLM Base URL SSRF 防护校验
- 应用顶部 Hero 渲染
- 自定义 CSS 加载
- Gradio UI kwargs 初始化
"""
import os
import sys
from typing import Dict, Any

from fastapi import HTTPException
from loguru import logger

from config.settings import settings
from src.utils.helpers import validate_upload_file

# 蓝色二次元风格基础 CSS
_GRADIO_CSS = """
body {
    background:
        radial-gradient(circle at 18% 8%, rgba(96,165,250,0.14), transparent 42%),
        radial-gradient(circle at 82% 92%, rgba(147,197,253,0.18), transparent 45%),
        radial-gradient(circle at 55% 45%, rgba(219,234,254,0.35), transparent 60%),
        linear-gradient(160deg, #eaf2ff 0%, #f7faff 50%, #eaf6ff 100%) !important;
    background-attachment: fixed !important;
}
body::before {
    content: "";
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
        radial-gradient(rgba(59,130,246,0.10) 1px, transparent 1.6px),
        radial-gradient(rgba(147,197,253,0.16) 1px, transparent 1.6px);
    background-size: 34px 34px, 51px 51px;
    background-position: 0 0, 17px 17px;
}
.gradio-container { max-width: 1280px !important; }
#app-hero {
    display: flex; align-items: center; gap: 16px;
    padding: 18px 24px; margin: 6px 0 14px;
    background: linear-gradient(120deg, #1d4ed8 0%, #2563eb 45%, #3b82f6 75%, #60a5fa 100%);
    border-radius: 18px; color: #fff;
    box-shadow: 0 8px 24px rgba(37,99,235,0.28), inset 0 1px 0 rgba(255,255,255,0.25);
}
#app-hero .hero-logo {
    width: 64px; height: 64px; border-radius: 50%; flex: none;
    border: 3px solid rgba(255,255,255,0.92);
    box-shadow: 0 0 0 5px rgba(255,255,255,0.18), 0 6px 16px rgba(0,0,0,0.25);
    object-fit: cover;
}
#app-hero .hero-title { font-size: 21px; font-weight: 800; letter-spacing: 1px; text-shadow: 0 2px 8px rgba(0,0,0,0.18); }
#app-hero .hero-sub { font-size: 12px; opacity: 0.95; margin-top: 3px; letter-spacing: 0.3px; }
#app-hero .hero-star { font-size: 13px; opacity: 0.9; margin-top: 2px; }
.tabs { border-radius: 14px; }
.gr-button-primary {
    background: linear-gradient(135deg, #2563eb, #60a5fa) !important;
    border: none !important;
    box-shadow: 0 4px 12px rgba(37,99,235,0.25) !important;
}
.gr-button-primary:hover { filter: brightness(1.06); }
"""


def check_upload_file(filename: str, size: int):
    """校验上传文件类型与大小——委托 src.utils.helpers，由 UI 层决定如何提示"""
    err = validate_upload_file(filename, size, max_mb=settings.max_upload_mb)
    if err:
        status = 413 if "大小限制" in err else 400
        raise HTTPException(status_code=status, detail=err)


def assert_safe_llm_base_url(base_url: str) -> str:
    """校验 LLM Base URL，拒绝 SSRF 目标，返回规范化后的 URL。

    【安全】原实现直接把用户传入的 `base_url` 拼上 `/chat/completions` 发请求，
    并把 `Authorization: Bearer <用户的真实 API Key>` 一同送出，仅检查了"非空"。
    这意味着任意能调用该接口的人都可以：
      · 让服务器向内网/云元数据地址发起请求（SSRF）；
      · 把用户的真实 LLM Key 外带到自己的服务器（凭据泄露）。

    本函数只允许 https、禁止回环/私网/链路本地/保留地址、禁止非标准端口，
    并拒绝明显的内网主机名。
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    raw = (base_url or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="base_url 不能为空")

    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="仅允许 https:// 的 Base URL（拒绝 http/其他协议，避免明文传输 API Key）",
        )
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise HTTPException(status_code=400, detail="Base URL 缺少主机名")

    # 主机名黑名单（内网常用名与云元数据别名）
    if host in {"localhost", "metadata", "metadata.google.internal"} or \
            host.endswith((".local", ".internal", ".localhost")):
        raise HTTPException(status_code=400, detail=f"Base URL 主机名不被允许: {host}")

    # 端口：仅允许标准 HTTPS 端口
    if parsed.port not in (None, 443):
        raise HTTPException(status_code=400,
                            detail=f"仅允许 443 端口（当前 {parsed.port}）")

    # 解析主机名并检查所有解析结果，阻断内网 / 回环 / 链路本地 / 保留地址
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Base URL 主机名无法解析: {e}") from e

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(
                status_code=400,
                detail=f"Base URL 解析到内网/保留地址（{ip}），已拒绝以避免 SSRF",
            )

    return raw.rstrip("/")


def render_app_header() -> str:
    """顶部 Hero：应用图标 + 标题（蓝色二次元风格，图标与快捷方式同源）"""
    import base64
    logo_b64 = None
    cands = []
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cands.append(os.path.join(root, 'assets', 'app_logo.png'))
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        cands.append(os.path.join(meipass, 'assets', 'app_logo.png'))
        cands.append(os.path.join(os.path.dirname(meipass), 'assets', 'app_logo.png'))
    cands.append(os.path.join(os.getcwd(), 'assets', 'app_logo.png'))
    for p in cands:
        try:
            if os.path.exists(p):
                with open(p, 'rb') as f:
                    logo_b64 = 'data:image/png;base64,' + base64.b64encode(f.read()).decode('utf-8')
                    break
        except Exception as e:
            # 仅影响界面 logo（纯装饰），失败时回退到内置图标；留痕便于排查资源问题
            logger.debug(f"加载界面 logo 失败，已回退内置图标: {p} ({type(e).__name__}: {e})")
            continue
    if logo_b64:
        logo_html = '<img class="hero-logo" src="' + logo_b64 + '" alt="logo"/>'
    else:
        logo_html = '<div class="hero-logo" style="display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,0.3);font-size:30px;">🛡️</div>'
    return (
        '<div id="app-hero">' + logo_html
        + '<div><div class="hero-title">AI 网络安全智能分析系统</div>'
        + '<div class="hero-sub">流行为检测 × LLM 研判 × 证据溯源 ｜ 上传 PCAP，AI 自动分析威胁</div>'
        + '<div class="hero-star">✦ 蓝白星光主题 · 桌面应用版 ✦</div></div></div>'
    )


def load_custom_css() -> str:
    """加载自定义 CSS（内联基础样式 + 外部蓝色二次元风格文件）"""
    css = _GRADIO_CSS
    try:
        css_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "ui", "custom_style.css")
        if os.path.exists(css_path):
            with open(css_path, "r", encoding="utf-8") as f:
                css += "\n\n/* ===== 外部自定义样式 ===== */\n" + f.read()
    except Exception as e:
        logger.warning(f"加载自定义 CSS 失败: {e}")
    return css


# 【重要】以下两项必须惰性求值，不能放在模块级：
# 无 gradio 环境下 `gr` 为 None，模块级 `gr.themes.Soft(...)` 会抛
# AttributeError，导致本模块（以及 re-export 它的 src/api/main.py）
# 整体导入失败——"gradio 未安装时仅启动 API 服务"这条降级路径随之失效。
_GRADIO_MAJOR: int = 0
_UI_KWARGS: Dict[str, Any] = {}


def init_gradio_ui_kwargs(gr_module) -> None:
    """在确认 gradio 可用后初始化 UI kwargs（幂等）。

    Args:
        gr_module: gradio 模块实例（从调用方传入，避免本模块硬依赖 gradio）
    """
    global _GRADIO_MAJOR, _UI_KWARGS
    if _UI_KWARGS:
        return
    _GRADIO_MAJOR = int(getattr(gr_module, "__version__", "4").split(".")[0])
    _UI_KWARGS = {"theme": gr_module.themes.Soft(primary_hue=gr_module.themes.colors.blue),
                  "css": load_custom_css()}


def get_ui_kwargs() -> Dict[str, Any]:
    """获取已初始化的 UI kwargs（未初始化时返回空 dict）"""
    return _UI_KWARGS


def get_gradio_major() -> int:
    """获取 Gradio 主版本号（未初始化时返回 0）"""
    return _GRADIO_MAJOR
