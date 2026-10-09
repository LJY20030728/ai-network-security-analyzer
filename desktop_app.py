"""
桌面应用启动器
双击运行后自动启动后端服务并弹出独立桌面窗口，无需手动打开浏览器
基于 pywebview + FastAPI/uvicorn

API Key 配置策略（重要）：
- 程序不内置、不写死任何 API Key
- 启动阶段不再使用阻塞式 tkinter 弹窗（windowed 打包下该弹窗不显示、会卡死启动）
- 核心检测（规则 / 时序基线 / 孤立森林 / Stacking 融合）完全不需要 API Key，开箱即用
- AI 威胁研判、安全问答需要大模型 Key：在主窗口「⚙️ 设置」中配置，
  未配置时界面会给出明确引导；Key 经 Windows DPAPI 加密存储

优雅降级策略（3.3.0 修复）：
- 桌面窗口依赖 pywebview → pythonnet → .NET Framework。若该链路不可用
  （如系统缺 .NET Framework），旧版会直接 sys.exit(1)，
  把**已经启动成功、可以正常使用**的 Web 服务一并杀掉，用户只看到一个闪退。
- 现改为：桌面窗口失败 → 提示原因 → 自动用默认浏览器打开 → 进程继续运行，
  用户始终有一个可用的界面（Ctrl+C 或关闭窗口退出）。
"""
import os
import sys
import time
import threading
import urllib.request
import logging

# 确保项目根目录在 path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# 配置
DEFAULT_PORT = 8080
WINDOW_TITLE = "AI网络安全智能分析系统"
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 900
SERVER_START_TIMEOUT = 120  # 秒（首次运行可能需加载模型/初始化）


def get_port():
    """获取端口号，优先环境变量，否则默认"""
    return int(os.getenv("PORT", str(DEFAULT_PORT)))


def wait_for_server(port, timeout=SERVER_START_TIMEOUT):
    """等待服务就绪，轮询健康检查接口"""
    url = f"http://127.0.0.1:{port}/api/health"
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def get_log_dir():
    """日志目录：程序同级 logs（打包部署场景）"""
    return os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "logs")


def setup_file_logging():
    """
    把启动日志写入程序同级 logs 目录，便于排查问题（windowed 模式无控制台）。

    注意：此处若失败必须显式记录——否则"没有日志"本身会变成无法排查的谜题
    （旧版静默 pass 正是这个问题）。
    """
    try:
        log_dir = get_log_dir()
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(log_dir, "app.log"),
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            encoding="utf-8",
        )
        logging.info("=" * 50)
        logging.info("应用启动")
        logging.info("=" * 50)
    except Exception as e:
        # 不能静默：额外写一份到临时目录，并把原因打到 stderr（若有控制台）
        try:
            import tempfile
            p = os.path.join(tempfile.gettempdir(), "ai_nsa_startup_error.log")
            with open(p, "a", encoding="utf-8") as f:
                f.write(f"[日志初始化失败] {type(e).__name__}: {e}\n")
            sys.stderr.write(f"[警告] 文件日志初始化失败，已记录到 {p}: {e}\n")
        except Exception:
            pass


def notify_user(title, message):
    """
    在 windowed（无控制台）模式下向用户显示提示。

    优先用 Windows 原生 MessageBox（ctypes，无第三方依赖）；失败退化为 stderr。
    """
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, message, title, 0x40)  # MB_ICONINFORMATION
        return True
    except Exception:
        try:
            sys.stderr.write(f"{title}: {message}\n")
        except Exception:
            pass
        return False


def open_in_browser(url):
    """在默认浏览器中打开 URL"""
    try:
        import webbrowser
        webbrowser.open(url)
        return True
    except Exception as e:
        logging.warning("浏览器打开失败: %s", e)
        return False


def keep_alive() -> None:
    """保持进程存活（供浏览器降级模式使用），Ctrl+C 可退出"""
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n服务已停止")
        os._exit(0)


def start_server(port):
    """在后台线程启动 uvicorn 服务（异常写入日志文件）"""
    import traceback
    try:
        import uvicorn
        from src.api.main import app

        # 首次启动：把内置种子数据（预置基线 / 预构建向量库 / 知识源文档）
        # 从只读 _internal 迁移到可写数据目录
        try:
            from src.utils.paths import seed_assets
            seed_assets()
        except Exception as e:
            logging.warning("种子数据迁移异常: %s", e)

        # windowed 模式下 sys.stdout/stderr 为 None，uvicorn 默认日志格式化会崩溃，
        # 因此把 uvicorn 日志配置为写入文件（logs/uvicorn.log）
        log_dir = get_log_dir()
        os.makedirs(log_dir, exist_ok=True)
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": os.path.join(log_dir, "uvicorn.log"),
                    "formatter": "default",
                    "encoding": "utf-8",
                }
            },
            "loggers": {
                "uvicorn": {"handlers": ["file"], "level": "INFO"},
                "uvicorn.error": {"handlers": ["file"], "level": "INFO"},
                "uvicorn.access": {"handlers": ["file"], "level": "WARNING"},
            },
        }
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_config=log_config,
            access_log=False,
        )
        server = uvicorn.Server(config)
        server.run()
    except Exception:
        try:
            log_dir = get_log_dir()
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "startup_error.log"), "w", encoding="utf-8") as f:
                f.write(traceback.format_exc())
            logging.error("服务启动失败: %s", traceback.format_exc())
        except Exception:
            pass
        raise


def on_closed():
    """窗口关闭时的回调，退出整个应用"""
    print("窗口已关闭，正在退出...")
    os._exit(0)  # 强制退出，终止后台服务线程


def main():
    """主函数：启动服务 -> 等待就绪 -> 打开桌面窗口"""
    port = get_port()
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print(f"  {WINDOW_TITLE}")
    print("=" * 60)

    # 0. 初始化文件日志（windowed 模式无控制台，靠日志文件排查）
    setup_file_logging()

    # 1. 后台线程启动服务（核心检测无需 Key；种子数据在此线程内迁移）
    print(f"正在启动后端服务 (端口 {port})...")
    server_thread = threading.Thread(
        target=start_server,
        args=(port,),
        daemon=True
    )
    server_thread.start()

    # 2. 等待服务就绪
    print("等待服务启动...")
    if not wait_for_server(port):
        # 服务本身起不来，这才是真正的致命错误
        msg = (f"后端服务启动超时（{SERVER_START_TIMEOUT} 秒）。\n\n"
               f"可能原因：端口 {port} 被占用，或依赖缺失。\n"
               f"日志目录：{get_log_dir()}")
        print(f"错误：{msg}")
        logging.error(msg)
        notify_user(WINDOW_TITLE, msg)
        sys.exit(1)

    print(f"✓ 服务已启动: {url}")
    logging.info("服务已就绪: %s", url)

    # 3. 创建并显示桌面窗口；失败则优雅降级到浏览器（服务继续运行）
    print("正在打开桌面窗口...")
    reason = None
    try:
        import webview

        window = webview.create_window(
            title=WINDOW_TITLE,
            url=url,
            width=WINDOW_WIDTH,
            height=WINDOW_HEIGHT,
            resizable=True,
            frameless=False,
            easy_drag=True,
            background_color="#1a1a2e",
        )

        # 窗口关闭时退出应用
        window.events.closed += on_closed

        # 启动 pywebview 事件循环（阻塞，直到窗口关闭）
        webview.start(debug=False)
        return  # 窗口正常关闭，on_closed 已退出进程
    except ImportError:
        reason = "pywebview 未安装"
    except Exception as e:
        reason = f"{type(e).__name__}: {e}"

    # ---------- 降级路径：服务保持运行，改用浏览器 ----------
    logging.warning("桌面窗口不可用（%s），降级为浏览器模式", reason)
    print(f"警告：桌面窗口不可用（{reason}）")

    # pywebview 依赖 pythonnet + .NET Framework，缺失时给出可操作建议
    hint = ""
    low = str(reason).lower()
    if "python.runtime" in low or "clr" in low or ".net" in low:
        hint = ("\n\n该问题通常是系统缺少 .NET Framework 4.7.2+ 运行库所致。\n"
                "安装后重启本程序即可恢复独立窗口；\n"
                "或继续使用下方的浏览器界面（功能完全一致）。")

    opened = open_in_browser(url)
    print(f"已在浏览器中打开: {url}" if opened else f"请手动访问: {url}")
    print("按 Ctrl+C 停止服务")

    # 仅在交互式环境弹提示框，避免自动化场景被阻塞
    try:
        interactive = bool(sys.stdin) and sys.stdin.isatty()
    except Exception:
        interactive = False
    if interactive:
        notify_user(
            WINDOW_TITLE,
            f"独立窗口无法启动，已自动改用浏览器打开。\n\n"
            f"原因：{reason}{hint}\n\n"
            f"服务地址：{url}\n"
            f"（服务已就绪，请保持本进程运行）",
        )

    keep_alive()


if __name__ == "__main__":
    main()
