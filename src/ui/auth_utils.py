"""
认证与安全工具函数

从 gradio_app.py 拆分出的认证相关函数：
- API 令牌生成与持久化
- 审计日志延迟初始化
- 本地请求检测（回环判断）
- 外部访问令牌校验（Gradio auth_dependency）
- 安全路径打开（默认禁用）
"""
import os
import hmac
import secrets
import subprocess
import sys
from typing import Optional

from fastapi import Request
from loguru import logger

from config.settings import settings
from src.api.audit import AuditLogger
from src.ui.ui_utils import _is_loopback_host
from src.utils.paths import data_dir


def generate_and_persist_token(find_env_file_fn=None) -> str:
    """生成随机访问令牌并写入 .env（保留原有配置项）

    Args:
        find_env_file_fn: 可选的 .env 路径探测函数（用于测试 mock）。
            为 None 时使用 config.settings.find_env_file。
    """
    if find_env_file_fn is None:
        from config.settings import find_env_file as find_env_file_fn
    token = secrets.token_hex(16)
    # 与 settings 使用同一探测逻辑（exe同级 → cwd → 项目根）
    env_path = find_env_file_fn()
    lines = []
    env_existed = os.path.exists(env_path)
    read_ok = True
    if env_existed:
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            # 【数据安全】原实现此处 lines = [] 并继续向下写回文件，
            # 效果是：.env 无法读取时（编码/权限/被占用），
            # 整个 .env 会被覆盖成只剩 API_AUTH_TOKEN 一行，
            # 用户的 LLM_API_KEY / BASE_URL / MODEL 全部丢失。
            # 且因为 token 已生成、鉴权看起来正常，故障被自我掩盖。
            read_ok = False
            lines = []
            logger.error(
                f"⚠️ 读取 .env 失败（{type(e).__name__}: {e}）。"
                f"为避免覆盖并丢失现有配置，本次跳过令牌落盘。"
            )
    replaced = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key == "API_AUTH_TOKEN":
                lines[i] = f"API_AUTH_TOKEN={token}\n"
                replaced = True
                break
    if not replaced:
        lines.append(f"API_AUTH_TOKEN={token}\n")

    # 仅当"文件本来不存在"或"成功读取了原内容"时才写回，避免破坏用户配置
    if env_existed and not read_ok:
        logger.error(
            "已跳过写入 .env：原文件存在但读取失败。"
            "本次生成的 API_AUTH_TOKEN 仅在本次运行内存中有效，"
            "请修复 .env 权限/编码后重启应用以持久化。"
        )
        return token
    try:
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        logger.warning(f"无法写入 API 令牌到 .env: {e}")
    return token


_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """延迟初始化审计日志（首次 /api 请求时创建，DB 落在用户数据目录）"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger.get(os.path.join(data_dir("audit"), "audit.db"))
    return _audit_logger


def request_is_local(request: Request) -> bool:
    """请求是否来自本机（回环）。

    同时检查客户端地址与 Host 头：Docker 端口映射下，局域网请求的客户端 IP 会是
    网桥地址（非回环），但如果只看客户端 IP，某些反代/宿主场景会误判为本地；
    反向检查 Host 头能兜住这种情况——真正的本机访问 Host 一定是 127.0.0.1/localhost。

    设计依据：项目默认绑定 127.0.0.1（desktop_app.py 与本机 API 启动方式），
    此时局域网本就无法访问，回环访问无需 token 以保证桌面版与浏览器直访体验；
    而 Docker / 显式绑 0.0.0.0 的场景必须携带 token。
    """
    client_host = request.client.host if request.client else ""
    host_header = request.headers.get("host", "")
    # 用 urlsplit 解析 Host 头，正确处理 "127.0.0.1:8080" 与 "[::1]:8080"
    # （不能用 host_header.count(":") == 1，IPv6 字面量含多个冒号）
    from urllib.parse import urlsplit

    try:
        host_only = urlsplit(f"//{host_header}").hostname or ""
    except ValueError:
        host_only = ""
    return _is_loopback_host(client_host) and _is_loopback_host(host_only)


def require_token_for_external_access(request: Request) -> Optional[str]:
    """Gradio `auth_dependency`：非回环访问必须携带正确 token。

    【Gradio 6 约定】该依赖必须 **返回用户 ID 字符串** 表示认证通过、
    返回 `None` 表示未通过（Gradio 自己会抛 401 "Not authenticated"）。
    此处**不能**自己抛 HTTPException——那会被 Gradio 视为依赖异常。

    【安全背景】此前的 token 中间件只覆盖 `/api/*`，而 Gradio UI 挂载在 `/`，
    于是 UI 的全部事件回调（打开文件、写配置、触发分析）在对外暴露时均可被
    无鉴权调用。本依赖挂在 Gradio 挂载点上，覆盖 UI 整体。

    - 回环访问：返回 "local"（桌面版 pywebview 与本机浏览器无需 token）。
    - 非回环：校验 X-API-Token 头（或 ?token= 查询参数），通过则返回用户标识。
    """
    if request_is_local(request):
        return "local"

    token = settings.api_auth_token
    if not token:
        # 未配置 token 却对外暴露：fail closed（拒绝而非放行）
        logger.error("服务对外暴露但未配置 API_AUTH_TOKEN，已拒绝非回环 UI 访问")
        return None

    provided = request.headers.get("x-api-token") or request.query_params.get("token") or ""
    # 常量时间比较，避免逐字节时间侧信道
    if not hmac.compare_digest(str(provided), str(token)):
        try:
            get_audit_logger().log(
                method=request.method, path=request.url.path, status_code=401,
                duration_ms=0.0,
                client_ip=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent", "")[:200],
                note="unauthorized UI access attempt")
        except Exception as e:
            logger.error(f"⚠️ 审计日志写入失败（UI 鉴权拒绝未能留痕）: {e}")
        return None
    return "api-token"


def open_path_with_shell(path: str) -> tuple:
    """用系统默认程序打开文件/目录——**默认禁用**，需显式开启。

    【安全】`os.startfile()` 会以当前用户身份用 shell 打开任意路径。此前它在
    4 个 UI 回调中被无条件调用，而这些回调在应用对外暴露时可能被无鉴权触发；
    再叠加"递归搜索文件系统找文件再打开"的逻辑，等于把本机 shell 的执行入口
    交给了调用方。安全工具不应自带这种能力。

    开启条件（两者满足其一）：
      1. 环境变量 AI_NSA_ALLOW_OPEN_PATH=true
      2. settings.allow_open_file = True（.env 中配置）

    路径限制：仅允许打开 data_dir 下的文件（reports/uploads/history等）。
    """
    if not path:
        return False, "路径为空"
    # 路径限制：仅允许 data_dir 下的文件（先于启用检查，确保越权路径始终被拒）
    from src.utils.paths import data_dir as _data_dir
    data_root = os.path.abspath(_data_dir(""))
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(data_root):
        return False, f"仅允许打开数据目录下的文件（{data_root}），拒绝: {abs_path}"
    # 检查开启条件
    env_enabled = os.environ.get("AI_NSA_ALLOW_OPEN_PATH", "").lower() in ("1", "true", "yes")
    settings_enabled = getattr(settings, "allow_open_file", False)
    if not (env_enabled or settings_enabled):
        return False, (
            f"已禁用自动打开文件（安全策略）。设置环境变量 AI_NSA_ALLOW_OPEN_PATH=true "
            f"或在 .env 中配置 ALLOW_OPEN_FILE=true 后可开启。目标路径: {abs_path}"
        )
    if not os.path.exists(abs_path):
        return False, f"文件不存在: {abs_path}"
    try:
        if sys.platform == "win32":
            os.startfile(abs_path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", abs_path])
        else:
            subprocess.Popen(["xdg-open", abs_path])
        return True, f"已打开: {abs_path}"
    except Exception as e:
        return False, f"打开失败: {e}"
