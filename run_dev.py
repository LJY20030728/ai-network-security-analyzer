# -*- coding: utf-8 -*-
"""开发环境服务启动入口（后台）"""
import uvicorn
from src.api.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="warning")
