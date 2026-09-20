"""
FastAPI 主服务入口（规范入口）
==============================

实际的 FastAPI 应用 —— 中间件（本地令牌鉴权 + 请求审计）、全部 /api 路由、
以及 Gradio Web UI 的挂载 —— 统一在 ``src/ui/gradio_app.py`` 中装配
（该模块由早期单文件应用演进而来，应用装配与 UI 构建目前共存于一处）。

本模块仅作为规范入口 **re-export** 同一个 ``app``，保证
``from src.api.main import app`` 与直接导入得到的是**唯一**应用实例，
避免出现两套并行、行为不一致（一个有鉴权/审计、另一个没有）的 FastAPI 应用。
"""

from src.ui.gradio_app import app, main  # noqa: F401

if __name__ == "__main__":
    main()
