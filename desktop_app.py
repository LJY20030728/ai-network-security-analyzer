"""
桌面应用启动器
双击运行后自动启动后端服务并弹出独立桌面窗口，无需手动打开浏览器
基于 pywebview + FastAPI/uvicorn

API Key 配置策略：
- 程序不内置任何 API Key
- 首次运行若检测到 .env 缺失或未配置 Key，自动弹出配置引导窗口
- 用户填写后写入程序同级目录的 .env，之后每次启动自动读取
"""
import os
import sys
import time
import threading
import urllib.request
import logging

# 确保项目根目录在path中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# 配置
DEFAULT_PORT = 8080
WINDOW_TITLE = "AI网络安全智能分析系统"
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 900
SERVER_START_TIMEOUT = 120  # 秒（首次运行可能需加载模型/初始化）

# 可用的默认模型方案（用于配置引导窗口的提示）
API_PRESETS = [
    ("智谱AI GLM-4-Flash（免费）", "https://open.bigmodel.cn/api/paas/v4", "glm-4-flash"),
    ("DeepSeek", "https://api.deepseek.com", "deepseek-chat"),
    ("通义千问（阿里云百炼）", "https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen-turbo"),
    ("硅基流动（免费额度）", "https://api.siliconflow.cn/v1", "Qwen/Qwen2.5-7B-Instruct"),
    ("Ollama本地模型（无需Key）", "http://localhost:11434/v1", "qwen2.5:7b"),
]


def get_env_path():
    """确定 .env 文件路径：优先程序同级目录（打包部署场景）"""
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    p1 = os.path.join(exe_dir, ".env")
    p2 = os.path.join(PROJECT_ROOT, ".env")
    return p1 if os.path.exists(p1) else p2


def load_env_values(env_path):
    """读取 .env 中的现有配置（用于预填）"""
    values = {"LLM_API_KEY": "", "LLM_BASE_URL": "", "LLM_MODEL": ""}
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        if k in values:
                            values[k] = v.strip()
        except Exception:
            pass
    return values


def api_key_configured(api_key):
    """判断 API Key 是否有效（非空且非占位符）"""
    if not api_key:
        return False
    if api_key.startswith("sk-xxxx") or "xxxx" in api_key:
        return False
    return True


def save_env(env_path, api_key, base_url, model):
    """将配置写入 .env（保留原有其他配置项）"""
    lines = []
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            lines = []

    new_entries = {
        "LLM_API_KEY": api_key.strip(),
        "LLM_BASE_URL": base_url.strip(),
        "LLM_MODEL": model.strip(),
    }

    # 逐行更新已有键
    updated_keys = set()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in new_entries:
                lines[i] = f"{key}={new_entries[key]}\n"
                updated_keys.add(key)

    # 追加缺失的键
    for key, val in new_entries.items():
        if key not in updated_keys:
            lines.append(f"{key}={val}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def prompt_api_config(env_path):
    """
    弹出 API 配置引导窗口（tkinter，Python 标准库，打包无需额外依赖）
    返回 True 表示用户已保存配置，False 表示跳过
    """
    values = load_env_values(env_path)
    defaults = {
        "LLM_API_KEY": values["LLM_API_KEY"],
        "LLM_BASE_URL": values["LLM_BASE_URL"] or API_PRESETS[0][1],
        "LLM_MODEL": values["LLM_MODEL"] or API_PRESETS[0][2],
    }

    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except Exception as e:
        print(f"[WARN] 无法打开配置窗口({e})，请手动创建 .env 文件")
        return False

    result = {"saved": False}

    root = tk.Tk()
    root.title("AI网络安全分析系统 - 首次配置")
    root.geometry("560x460")
    root.resizable(False, False)

    # 标题
    tk.Label(root, text="🔑 大模型 API 配置", font=("Microsoft YaHei UI", 14, "bold")).pack(pady=(16, 4))
    tk.Label(root, text="系统内置的安全分析功能无需配置即可使用；\n"
                        "只有 AI 威胁研判、安全问答需要大模型 API（以下任选一种）。",
             font=("Microsoft YaHei UI", 9), fg="#666666", justify="left").pack(pady=(0, 10))

    frame = tk.Frame(root)
    frame.pack(padx=24, fill="x")

    # 方案选择（下拉）
    tk.Label(frame, text="① 选择模型服务商", font=("Microsoft YaHei UI", 10)).pack(anchor="w", pady=(4, 2))
    preset_var = tk.StringVar(value=API_PRESETS[0][0])
    preset_combo = ttk.Combobox(frame, textvariable=preset_var, state="readonly",
                                values=[p[0] for p in API_PRESETS], width=50)
    preset_combo.pack(anchor="w")

    # API Key
    tk.Label(frame, text="② API Key（智谱在 open.bigmodel.cn 控制台获取；Ollama 填任意值）",
             font=("Microsoft YaHei UI", 10)).pack(anchor="w", pady=(10, 2))
    key_var = tk.StringVar(value=defaults["LLM_API_KEY"])
    key_entry = tk.Entry(frame, textvariable=key_var, width=56, show="●")
    key_entry.pack(anchor="w")

    # Base URL
    tk.Label(frame, text="③ API 地址（Base URL）", font=("Microsoft YaHei UI", 10)).pack(anchor="w", pady=(10, 2))
    url_var = tk.StringVar(value=defaults["LLM_BASE_URL"])
    url_entry = tk.Entry(frame, textvariable=url_var, width=56)
    url_entry.pack(anchor="w")

    # Model
    tk.Label(frame, text="④ 模型名称", font=("Microsoft YaHei UI", 10)).pack(anchor="w", pady=(10, 2))
    model_var = tk.StringVar(value=defaults["LLM_MODEL"])
    model_entry = tk.Entry(frame, textvariable=model_var, width=56)
    model_entry.pack(anchor="w")

    def on_preset_change(*_):
        """切换服务商时自动填充对应的 URL 和 Model"""
        for name, url, model in API_PRESETS:
            if preset_var.get() == name:
                url_var.set(url)
                model_var.set(model)
                break

    preset_combo.bind("<<ComboboxSelected>>", on_preset_change)

    def on_save():
        key = key_var.get().strip()
        url = url_var.get().strip()
        model = model_var.get().strip()
        if not api_key_configured(key):
            messagebox.showwarning("提示", "API Key 不能为空或仍为占位符。\n如使用 Ollama 本地模型可填任意非空值（如 local）。")
            return
        if not url or not model:
            messagebox.showwarning("提示", "API 地址和模型名称不能为空。")
            return
        try:
            save_env(env_path, key, url, model)
            result["saved"] = True
            messagebox.showinfo("保存成功", f"配置已保存到：\n{env_path}\n\n点击确定后系统将自动启动。")
            root.destroy()
        except Exception as e:
            messagebox.showerror("保存失败", f"写入 .env 失败：{e}")

    def on_skip():
        result["saved"] = False
        root.destroy()

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=(18, 6))
    tk.Button(btn_frame, text="保存并启动", command=on_save, width=16,
              bg="#2F6FED", fg="white", font=("Microsoft YaHei UI", 10)).pack(side="left", padx=8)
    tk.Button(btn_frame, text="跳过（暂不配置）", command=on_skip, width=16,
              font=("Microsoft YaHei UI", 10)).pack(side="left", padx=8)

    tk.Label(root, text="跳过配置后，抓包/PCAP分析/规则检测仍可用，仅 AI 功能不可用。\n"
                        "之后随时可编辑安装目录下的 .env 文件补充配置。",
             font=("Microsoft YaHei UI", 8), fg="#999999").pack(pady=(6, 10))

    root.mainloop()
    return result["saved"]


def ensure_api_config():
    """确保 API 配置存在：缺失或无效时弹出配置引导"""
    env_path = get_env_path()

    # 有现成有效配置则直接跳过
    values = load_env_values(env_path)
    if api_key_configured(values["LLM_API_KEY"]):
        print(f"✓ 检测到已配置的大模型 API Key（{os.path.basename(env_path)}）")
        return

    print("=" * 60)
    print("未检测到有效的大模型 API 配置")
    print("=" * 60)
    print("将打开配置窗口（也可稍后手动编辑 .env 文件）...")
    saved = prompt_api_config(env_path)
    if saved:
        print("✓ API 配置已保存")
    else:
        print("⚠ 已跳过配置：AI 分析功能不可用，其他功能正常")


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
    """把启动日志写入程序同级 logs 目录，便于排查问题（windowed 模式无控制台）"""
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
    except Exception:
        pass


def start_server(port):
    """在后台线程启动uvicorn服务（异常写入日志文件）"""
    import traceback
    try:
        import uvicorn
        from src.api.main import app

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
    """主函数：配置检查 -> 启动服务 -> 等待就绪 -> 打开桌面窗口"""
    port = get_port()
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print(f"  {WINDOW_TITLE}")
    print("=" * 60)

    # 0. 初始化文件日志（windowed 模式无控制台，靠日志文件排查）
    setup_file_logging()

    # 0.5 首次运行配置引导（API Key 不内置，由用户填写）
    ensure_api_config()

    # 1. 后台线程启动服务
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
        print(f"错误：服务启动超时（{SERVER_START_TIMEOUT}秒）")
        print("请检查端口是否被占用，或查看日志")
        input("按回车键退出...")
        sys.exit(1)

    print(f"✓ 服务已启动: {url}")
    print("正在打开桌面窗口...")

    # 3. 创建并显示桌面窗口
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

        # 启动pywebview事件循环（阻塞，直到窗口关闭）
        webview.start(debug=False)

    except ImportError:
        print("警告：pywebview未安装，将使用默认浏览器打开")
        import webbrowser
        webbrowser.open(url)
        print(f"已在浏览器中打开: {url}")
        print("按 Ctrl+C 停止服务")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n服务已停止")
    except Exception as e:
        print(f"桌面窗口启动失败: {e}")
        print(f"你可以手动在浏览器中访问: {url}")
        input("按回车键退出...")
        sys.exit(1)


if __name__ == "__main__":
    main()
