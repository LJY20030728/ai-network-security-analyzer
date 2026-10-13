"""
基线管理工具函数

从 gradio_app.py 拆分出的基线管理相关函数：
- 基线文件路径安全化
- 基线列表读取（SQLite 为主，JSON 为兼容备份）
- 基线名称列表（UI 下拉框选项）
"""
import os
from typing import List, Dict, Any

from loguru import logger

from src.analysis.baseline import TrafficBaseline
from src.storage.baseline_name import safe_baseline_name
from src.storage.database import Database
from src.utils.helpers import ensure_dir
from src.utils.paths import data_dir

BASELINE_DIR = data_dir("baselines")


def baseline_path(name: str) -> str:
    """基线文件名安全化 + 路径

    复用 `validate_baseline_name` 的字符策略（消除此前「内联过滤规则」与
    「名称校验规则」两套并存的漂移），但文件名额外不允许空格与点。
    """
    safe = "".join(ch for ch in (name or "") if ch.isalnum() or ch in "-_")
    if not safe:
        safe = "baseline"
    return os.path.join(BASELINE_DIR, f"{safe[:64]}.json")


def list_baselines() -> List[Dict[str, Any]]:
    """列出所有已保存基线（SQLite 为主，JSON 为兼容备份）"""
    db = Database()
    items = db.list_baselines()
    if not items:
        # SQLite 为空时从 JSON 导入（向后兼容）
        ensure_dir(BASELINE_DIR)
        for fn in sorted(os.listdir(BASELINE_DIR)):
            if fn.endswith(".json"):
                path = os.path.join(BASELINE_DIR, fn)
                b = TrafficBaseline.load(path)
                if b and b.learned:
                    # JSON 文件的 name 属不可信输入（文件可被手工编辑），
                    # 非法名回退到文件名 stem；仍非法则跳过该条并记日志，
                    # 不能让整个列表页因一条脏数据挂掉。
                    raw_name = b.name or os.path.splitext(fn)[0]
                    safe_name = safe_baseline_name(raw_name, fallback="")
                    if not safe_name:
                        safe_name = safe_baseline_name(os.path.splitext(fn)[0], fallback="")
                    if not safe_name:
                        logger.warning(f"跳过名称非法的基线文件: {fn}（name={raw_name!r}）")
                        continue
                    if safe_name != raw_name:
                        logger.warning(f"基线名称非法，已回退为安全名: {raw_name!r} → {safe_name!r}")
                    db.save_baseline(
                        name=safe_name,
                        profile=b.to_dict().get("profile", {}),
                        window_sec=b.window_sec,
                        total_packets=getattr(b, "packets_used", 0),
                        description=getattr(b, "description", None),
                    )
        items = db.list_baselines()
    # 转换为 UI 需要的格式
    result = []
    for item in items:
        bl = db.get_baseline(item["name"])
        profile_summary = {}
        if bl and bl.get("profile"):
            prof = bl["profile"].get("profile", bl["profile"])
            if isinstance(prof, dict):
                profile_summary = {k: {"median": v.get("median"), "mad": v.get("mad")}
                                   for k, v in prof.items() if isinstance(v, dict)}
        result.append({
            "name": item["name"],
            "file": f"{item['name']}.json",
            "created_at": item.get("created_at", ""),
            "packets_used": item.get("total_packets", 0),
            "window_sec": item.get("window_sec", 5),
            "profile": profile_summary,
        })
    return result


def baseline_names() -> List[str]:
    """所有已保存基线名称（UI 下拉框选项）"""
    return [b["name"] for b in list_baselines()]
