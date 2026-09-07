#!/usr/bin/env python3
"""
AI网络安全智能分析系统 - 启动脚本
用法: python run.py
"""
import os
import sys

# 确保项目根目录在Python路径中
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from loguru import logger

def check_environment():
    """检查运行环境"""
    logger.info("=" * 60)
    logger.info("环境检查")
    logger.info("=" * 60)

    # Python版本
    logger.info(f"Python版本: {sys.version}")

    # 检查.env文件
    env_path = os.path.join(project_root, ".env")
    if os.path.exists(env_path):
        logger.info("✓ .env 配置文件存在")
    else:
        logger.warning("⚠ .env 文件不存在，正在从 .env.example 复制...")
        env_example = os.path.join(project_root, ".env.example")
        if os.path.exists(env_example):
            import shutil
            shutil.copy(env_example, env_path)
            logger.info("✓ 已创建 .env 文件，请编辑并填写 LLM_API_KEY")
        else:
            logger.error("✗ .env.example 也不存在，请手动创建 .env 文件")

    # 检查关键依赖
    required_packages = {
        "fastapi": "FastAPI Web框架",
        "uvicorn": "ASGI服务器",
        "scapy": "网络抓包库",
        "langchain": "大模型应用框架",
        "chromadb": "向量数据库",
        "gradio": "Web UI界面",
        "pandas": "数据处理",
    }

    missing = []
    for pkg, desc in required_packages.items():
        try:
            __import__(pkg)
            logger.info(f"✓ {pkg} ({desc})")
        except ImportError:
            logger.warning(f"✗ {pkg} ({desc}) - 未安装")
            missing.append(pkg)

    if missing:
        logger.warning(f"\n缺少 {len(missing)} 个依赖包，请运行: pip install -r requirements.txt")
    else:
        logger.info("\n✓ 所有核心依赖已安装")

    logger.info("=" * 60)
    return len(missing) == 0


def main():
    """主函数"""
    # 切换到项目目录
    os.chdir(project_root)

    # 环境检查
    env_ok = check_environment()

    if not env_ok:
        logger.warning("环境不完整，但仍尝试启动（部分功能可能不可用）")

    # 导入并启动服务
    try:
        from src.api.main import main as api_main
        logger.info("\n" + "=" * 60)
        logger.info("🚀 启动 AI网络安全智能分析系统")
        logger.info("=" * 60)
        logger.info("Web UI:   http://localhost:8000")
        logger.info("API文档:  http://localhost:8000/docs")
        logger.info("按 Ctrl+C 停止服务")
        logger.info("=" * 60 + "\n")

        api_main()
    except ImportError as e:
        logger.error(f"导入失败: {e}")
        logger.error("请确保已安装所有依赖: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\n服务已停止")
    except Exception as e:
        logger.error(f"服务启动失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
