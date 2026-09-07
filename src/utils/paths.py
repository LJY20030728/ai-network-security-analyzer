"""
统一路径管理（数据目录 vs 资源目录分离）
========================================
解决打包后相对路径失效问题：
- app_root() : 应用根目录（开发=项目根，打包=exe 所在目录，用户可写）
- data_dir() : 用户数据目录 {app_root}/data（基线/向量库/报告/上传，可持久化）
- asset_dir(): 打包内置资源目录（PyInstaller _internal，只读种子数据；开发时=项目根）
- seed_assets(): 首次启动把内置种子数据（预置基线等）复制到数据目录
"""
import os
import shutil
import sys
from typing import Optional

from loguru import logger


def app_root() -> str:
    """应用根目录：打包后为 exe 所在目录（用户可写），开发为项目根"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    # src/utils/paths.py → 上溯 3 级 = 项目根
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def data_dir(*sub: str) -> str:
    """用户数据目录（持久化，可写）：{app_root}/data[/sub...]"""
    base = os.path.join(app_root(), "data")
    if sub:
        base = os.path.join(base, *sub)
    os.makedirs(base, exist_ok=True)
    return base


def asset_dir(*sub: str) -> str:
    """打包内置资源（只读种子）：PyInstaller _internal；开发模式=项目根"""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        base = os.path.join(meipass, *sub)
    else:
        base = os.path.join(app_root(), *sub)
    return base


# 需要首启迁移到数据目录的种子资源（源相对 asset_dir，目标相对 data_dir）
SEED_COPIES = [
    ("data/baselines", "baselines"),   # 预置时序基线 default.json
    ("data/knowledge", "knowledge"),   # 知识库源文档（如存在）
]


def seed_assets() -> None:
    """
    首次启动种子迁移：把打包内置的预置数据复制到用户数据目录。
    仅当目标目录不存在时执行（不覆盖用户已有数据），开发模式无 _MEIPASS 时跳过。
    """
    if not getattr(sys, "_MEIPASS", None):
        return  # 开发模式：项目根即数据目录，无需迁移
    for src_rel, dst_rel in SEED_COPIES:
        src = os.path.join(app_root(), src_rel)  # 兼容旧路径
        if not os.path.isdir(src):
            src = os.path.join(asset_dir(), src_rel)
        if not os.path.isdir(src):
            continue
        dst = data_dir(dst_rel)
        if os.path.isdir(dst) and os.listdir(dst):
            logger.info(f"种子数据已存在，跳过迁移: {dst_rel}")
            continue
        try:
            os.makedirs(dst, exist_ok=True)
            for fn in os.listdir(src):
                s = os.path.join(src, fn)
                if os.path.isfile(s):
                    shutil.copy2(s, os.path.join(dst, fn))
            logger.info(f"种子数据迁移完成: {src_rel} -> {dst}")
        except Exception as e:
            logger.warning(f"种子数据迁移失败（{src_rel}）: {e}")
