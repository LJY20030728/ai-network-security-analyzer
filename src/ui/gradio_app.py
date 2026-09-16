"""
Gradio Web UI 模块

负责：
- Gradio界面定义
- 事件绑定
- UI交互逻辑
"""

import os
import sys
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 确保项目根目录在path中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings
from src.utils.paths import data_dir
from src.utils.helpers import ensure_dir

# 可选导入gradio
try:
    import gradio as gr
    GRADIO_AVAILABLE = True
except ImportError:
    GRADIO_AVAILABLE = False
    gr = None


def create_gradio_ui(app):
    """
    创建Gradio Web UI并挂载到FastAPI应用
    
    Args:
        app: FastAPI应用实例
        
    Returns:
        Gradio demo实例
    """
    if not GRADIO_AVAILABLE:
        logger.warning("Gradio未安装，跳过UI挂载")
        return None
    
    try:
        # 从原来的main.py中导入UI创建函数
        # 为了避免大规模重构，我们暂时从原备份文件导入
        # 后续再逐步把所有UI代码迁移到这里
        
        logger.info("Gradio UI模块已加载")
        
        # TODO: 逐步把main.py中的Gradio UI代码迁移到这里
        # 1. CSS样式
        # 2. 界面布局
        # 3. 事件绑定
        
        return None
        
    except Exception as e:
        logger.error(f"创建Gradio UI失败: {e}")
        return None
