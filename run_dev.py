# -*- coding: utf-8 -*-
"""服务启动入口（支持Docker部署和本地开发）"""
import os
import uvicorn
from src.api.main import app

if __name__ == "__main__":
    # Docker部署时需要绑定 0.0.0.0，本地开发可用 127.0.0.1
    # 通过环境变量 HOST 配置，默认 0.0.0.0（兼容Docker和本地访问）
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    log_level = os.getenv("LOG_LEVEL", "warning")
    uvicorn.run(app, host=host, port=port, log_level=log_level)
