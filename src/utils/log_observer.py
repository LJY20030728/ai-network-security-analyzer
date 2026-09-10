# -*- coding: utf-8 -*-
"""
P2-2: 日志可观测性模块
- 规范化日志格式（结构化 JSON + 人类可读）
- UI 日志查看器（读取最近 N 条日志，支持级别过滤）
- 一键诊断报告（系统信息+配置状态+最近错误+性能指标）
"""
import json
import os
import platform
import sys
import traceback
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from loguru import logger

from src.utils.paths import data_dir
from src.utils.helpers import ensure_dir


class LogObserver:
    """日志观察者 — 提供日志查询和诊断功能"""

    def __init__(self):
        self._log_dir = data_dir("logs")
        ensure_dir(self._log_dir)
        self._log_file = os.path.join(self._log_dir, "analyzer.log")

    def get_recent_logs(self, limit: int = 100, level: Optional[str] = None,
                         keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        读取最近的日志
        :param limit: 返回条数
        :param level: 过滤级别（DEBUG/INFO/WARNING/ERROR/CRITICAL）
        :param keyword: 关键词过滤
        """
        logs = []
        try:
            if not os.path.exists(self._log_file):
                return logs

            # 从文件末尾读取，倒序返回
            with open(self._log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # 倒序遍历，取最近的
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue

                # 解析 loguru 格式：时间 | 级别 | 模块 - 消息
                parsed = self._parse_log_line(line)
                if not parsed:
                    continue

                # 级别过滤
                if level and parsed.get("level", "").upper() != level.upper():
                    continue

                # 关键词过滤
                if keyword and keyword.lower() not in parsed.get("message", "").lower():
                    continue

                logs.append(parsed)
                if len(logs) >= limit:
                    break

        except Exception as e:
            logger.error(f"读取日志失败: {e}")

        return logs

    @staticmethod
    def _parse_log_line(line: str) -> Optional[Dict[str, Any]]:
        """解析 loguru 格式的日志行"""
        try:
            # 格式：2024-01-01 12:00:00 | INFO     | module:function:line - message
            parts = line.split(" | ", 2)
            if len(parts) < 3:
                return None

            timestamp = parts[0].strip()
            level = parts[1].strip()
            rest = parts[2]

            # 分离模块和消息
            if " - " in rest:
                module_part, message = rest.split(" - ", 1)
            else:
                module_part = ""
                message = rest

            return {
                "timestamp": timestamp,
                "level": level,
                "module": module_part.strip(),
                "message": message.strip(),
            }
        except Exception:
            return None

    def get_log_stats(self) -> Dict[str, Any]:
        """获取日志统计信息"""
        try:
            logs = self.get_recent_logs(limit=1000)
            level_counts = {}
            for log in logs:
                level = log.get("level", "UNKNOWN")
                level_counts[level] = level_counts.get(level, 0) + 1

            return {
                "total_recent": len(logs),
                "level_distribution": level_counts,
                "error_count": level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0),
                "warning_count": level_counts.get("WARNING", 0),
                "log_file": self._log_file,
                "log_file_size_mb": round(os.path.getsize(self._log_file) / (1024 * 1024), 2)
                if os.path.exists(self._log_file) else 0,
            }
        except Exception as e:
            return {"error": str(e)}

    def generate_diagnostic_report(self) -> Dict[str, Any]:
        """
        生成一键诊断报告
        包含：系统信息、Python 环境、配置状态、数据库状态、最近错误、性能指标
        """
        report = {
            "report_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system": {},
            "python": {},
            "configuration": {},
            "database": {},
            "recent_errors": [],
            "performance": {},
            "recommendations": [],
        }

        # 1. 系统信息
        try:
            report["system"] = {
                "os": platform.system(),
                "os_version": platform.version(),
                "os_release": platform.release(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "hostname": platform.node(),
            }
        except Exception as e:
            report["system"]["error"] = str(e)

        # 2. Python 环境
        try:
            report["python"] = {
                "version": sys.version,
                "executable": sys.executable,
                "platform": sys.platform,
                "prefix": sys.prefix,
            }
            # 检查关键依赖
            key_packages = ["fastapi", "gradio", "scapy", "loguru", "chromadb",
                           "onnxruntime", "joblib", "sklearn", "pydantic"]
            installed = {}
            for pkg in key_packages:
                try:
                    mod = __import__(pkg)
                    installed[pkg] = getattr(mod, "__version__", "installed")
                except ImportError:
                    installed[pkg] = "NOT INSTALLED"
                    report["recommendations"].append(f"缺少关键依赖: {pkg}")
            report["python"]["packages"] = installed
        except Exception as e:
            report["python"]["error"] = str(e)

        # 3. 配置状态
        try:
            from config.settings import settings
            report["configuration"] = {
                "project_name": settings.project_name,
                "debug": settings.debug,
                "log_level": settings.log_level,
                "llm_base_url": settings.llm_base_url,
                "llm_model": settings.llm_model,
                "api_key_configured": bool(settings.llm_api_key and "xxxx" not in settings.llm_api_key),
                "api_key_masked": (settings.llm_api_key[:6] + "..." + settings.llm_api_key[-4:])
                if settings.llm_api_key else "",
                "max_upload_mb": settings.max_upload_mb,
                "ml_engine_enabled": settings.ml_engine_enabled,
            }
            if not report["configuration"]["api_key_configured"]:
                report["recommendations"].append("API Key 未配置，AI 功能不可用")
        except Exception as e:
            report["configuration"]["error"] = str(e)

        # 4. 数据库状态
        try:
            from src.storage.database import Database
            db = Database()
            report["database"] = db.get_stats()
        except Exception as e:
            report["database"]["error"] = str(e)

        # 5. 最近错误
        try:
            errors = self.get_recent_logs(limit=20, level="ERROR")
            report["recent_errors"] = errors
            if errors:
                report["recommendations"].append(f"发现 {len(errors)} 条最近错误，请检查日志")
        except Exception as e:
            report["recent_errors"] = [{"error": str(e)}]

        # 6. 性能指标（如果有基准测试结果）
        try:
            import sys
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            perf_file = os.path.join(project_root, "data", "eval_perf", "benchmark_result.json")
            if os.path.exists(perf_file):
                with open(perf_file, "r", encoding="utf-8") as f:
                    perf = json.load(f)
                report["performance"] = {
                    "avg_total_time_sec": perf.get("avg_total_time_sec", 0),
                    "avg_peak_memory_mb": perf.get("avg_peak_memory_mb", 0),
                    "total_samples": perf.get("total_samples", 0),
                }
        except Exception:
            pass

        # 7. 模型文件检查
        try:
            import sys
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_dir = os.path.join(project_root, "models")
            models = {}
            if os.path.exists(model_dir):
                for f in os.listdir(model_dir):
                    if f.endswith(".joblib"):
                        fpath = os.path.join(model_dir, f)
                        models[f] = f"{os.path.getsize(fpath) / 1024:.1f} KB"
            report["models"] = models
            if not models:
                report["recommendations"].append("未找到训练好的模型文件，监督检测功能不可用")
        except Exception:
            pass

        # 总体健康状态
        report["health_status"] = "healthy" if not report["recommendations"] else "warning"
        if report["recent_errors"]:
            report["health_status"] = "error"

        return report

    def clear_logs(self) -> bool:
        """清空日志文件"""
        try:
            if os.path.exists(self._log_file):
                with open(self._log_file, "w", encoding="utf-8") as f:
                    f.write("")
                logger.info("日志已清空")
                return True
            return False
        except Exception as e:
            logger.error(f"清空日志失败: {e}")
            return False


# 全局单例
_log_observer: Optional[LogObserver] = None


def get_log_observer() -> LogObserver:
    """获取日志观察者单例"""
    global _log_observer
    if _log_observer is None:
        _log_observer = LogObserver()
    return _log_observer
