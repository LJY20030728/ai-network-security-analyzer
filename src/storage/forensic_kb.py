# -*- coding: utf-8 -*-
"""
P1-2: 取证知识库（历史记录升级）
基于 SQLite 的历史记录，提供：
1. 跨样本关联分析：相同 IP/端口/攻击类型的样本关联
2. 趋势分析：攻击数量、类型分布、严重度变化趋势
3. 重复检测缓存：基于文件 SHA256 的分析结果缓存，避免重复分析
"""
import hashlib
import json
import os
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from src.storage.database import Database


class ForensicKnowledgeBase:
    """取证知识库（历史记录升级）"""

    def __init__(self):
        self._db = Database()

    # ---------- 重复检测缓存 ----------

    @staticmethod
    def _file_sha256(filepath: str) -> str:
        """计算文件 SHA256"""
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def get_cached_analysis(self, filepath: str) -> Optional[Dict[str, Any]]:
        """获取缓存的分析结果（基于文件 SHA256）"""
        if not filepath or not os.path.exists(filepath):
            return None
        file_hash = self._file_sha256(filepath)
        if not file_hash:
            return None
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT id, raw_json FROM analysis_history WHERE raw_json LIKE ? LIMIT 1",
            (f'%{file_hash}%',)
        ).fetchone()
        if row:
            try:
                raw = json.loads(row["raw_json"])
                if raw.get("file_hash") == file_hash:
                    logger.info(f"命中分析缓存: {os.path.basename(filepath)} (id={row['id']})")
                    return raw
            except Exception:
                pass
        return None

    def cache_analysis(self, filepath: str, analysis_result: Dict[str, Any]) -> bool:
        """缓存分析结果（写入 file_hash 到 raw_json）"""
        if not filepath:
            return False
        file_hash = self._file_sha256(filepath)
        if file_hash:
            analysis_result["file_hash"] = file_hash
        return True

    # ---------- 跨样本关联分析 ----------

    def find_related_samples(self, analysis_id: str,
                              max_related: int = 10) -> List[Dict[str, Any]]:
        """
        跨样本关联分析：找出与指定样本相关的其他分析记录
        关联维度：相同攻击类型、相似告警数量、相近时间
        """
        target = self._db.get_analysis(analysis_id)
        if not target:
            return []

        all_records = self._db.list_analysis(limit=100)
        related = []

        target_alerts = target.get("alerts", 0)
        target_severity = target.get("severity", {})
        target_supervised = target.get("supervised_verdict", False)

        for rec in all_records:
            if rec["id"] == analysis_id:
                continue
            score = 0.0
            reasons = []

            # 相同监督模型判定
            if rec.get("supervised_verdict") == target_supervised:
                score += 0.3
                reasons.append("相同主引擎判定")

            # 相似告警数量（±20%）
            if target_alerts > 0:
                ratio = abs(rec.get("alerts", 0) - target_alerts) / target_alerts
                if ratio < 0.2:
                    score += 0.3
                    reasons.append("相似告警数量")

            # 相同严重度分布
            rec_severity = rec.get("severity", {})
            if rec_severity and target_severity:
                common_sev = set(rec_severity.keys()) & set(target_severity.keys())
                if common_sev:
                    score += 0.2 * len(common_sev)
                    reasons.append(f"相同严重度: {','.join(common_sev)}")

            # 相近时间（7天内）
            try:
                from datetime import datetime
                target_ts = datetime.fromisoformat(target.get("ts", ""))
                rec_ts = datetime.fromisoformat(rec.get("ts", ""))
                if abs((target_ts - rec_ts).days) <= 7:
                    score += 0.2
                    reasons.append("时间相近(7天内)")
            except Exception:
                pass

            if score > 0.3:
                related.append({
                    "id": rec["id"],
                    "file": rec.get("file", ""),
                    "ts": rec.get("ts", ""),
                    "alerts": rec.get("alerts", 0),
                    "similarity_score": round(score, 3),
                    "reasons": reasons,
                })

        related.sort(key=lambda x: x["similarity_score"], reverse=True)
        return related[:max_related]

    # ---------- 趋势分析 ----------

    def get_trend_analysis(self, days: int = 30) -> Dict[str, Any]:
        """
        趋势分析：分析历史记录的攻击趋势
        返回：按日统计、攻击类型分布、严重度趋势、主引擎判定趋势
        """
        records = self._db.list_analysis(limit=500)
        if not records:
            return {"total": 0, "message": "无历史数据"}

        # 按日统计
        daily_stats = defaultdict(lambda: {"total": 0, "attack": 0, "normal": 0, "alerts": 0})
        severity_trend = defaultdict(lambda: defaultdict(int))
        supervised_trend = defaultdict(lambda: {"attack": 0, "normal": 0})

        for rec in records:
            try:
                from datetime import datetime
                ts = rec.get("ts", "")
                if "T" in ts:
                    day = ts.split("T")[0]
                elif " " in ts:
                    day = ts.split(" ")[0]
                else:
                    day = ts[:10]
            except Exception:
                day = "unknown"

            daily_stats[day]["total"] += 1
            daily_stats[day]["alerts"] += rec.get("alerts", 0)

            if rec.get("supervised_verdict"):
                daily_stats[day]["attack"] += 1
                supervised_trend[day]["attack"] += 1
            else:
                daily_stats[day]["normal"] += 1
                supervised_trend[day]["normal"] += 1

            for sev, cnt in (rec.get("severity") or {}).items():
                severity_trend[day][sev] += cnt

        # 攻击类型分布（从告警类型推断）
        attack_types = Counter()
        for rec in records:
            raw = rec.get("raw", {})
            if isinstance(raw, dict):
                alerts = raw.get("anomaly_detection", {}).get("alerts", [])
                for a in alerts:
                    atype = a.get("type", "unknown")
                    attack_types[atype] += 1

        # 汇总统计
        total = len(records)
        attack_count = sum(1 for r in records if r.get("supervised_verdict"))
        total_alerts = sum(r.get("alerts", 0) for r in records)

        return {
            "total_records": total,
            "attack_records": attack_count,
            "normal_records": total - attack_count,
            "attack_rate": round(attack_count / total, 3) if total > 0 else 0,
            "total_alerts": total_alerts,
            "avg_alerts_per_record": round(total_alerts / total, 2) if total > 0 else 0,
            "daily_stats": dict(sorted(daily_stats.items())[-days:]),
            "severity_trend": {k: dict(v) for k, v in sorted(severity_trend.items())[-days:]},
            "supervised_trend": {k: dict(v) for k, v in sorted(supervised_trend.items())[-days:]},
            "top_attack_types": attack_types.most_common(10),
            "needs_review_count": sum(1 for r in records if r.get("needs_review")),
            "high_risk_count": sum(1 for r in records if r.get("hallucination_risk") == "high"),
        }

    # ---------- IOC 知识库 ----------

    def extract_iocs(self, analysis_id: str) -> List[Dict[str, Any]]:
        """从分析记录中提取 IOC（IP、端口、域名）"""
        rec = self._db.get_analysis(analysis_id)
        if not rec:
            return []
        iocs = []
        raw = rec.get("raw", {})
        if isinstance(raw, dict):
            alerts = raw.get("anomaly_detection", {}).get("alerts", [])
            for a in alerts:
                if a.get("src_ip"):
                    iocs.append({"type": "IP", "value": a["src_ip"], "source": a.get("type", "")})
                if a.get("dst_port"):
                    iocs.append({"type": "Port", "value": str(a["dst_port"]), "source": a.get("type", "")})
        return iocs

    def get_stats(self) -> Dict[str, Any]:
        """获取取证知识库统计"""
        db_stats = self._db.get_stats()
        trend = self.get_trend_analysis(days=7)
        return {
            **db_stats,
            "attack_rate": trend.get("attack_rate", 0),
            "top_attack_types": trend.get("top_attack_types", []),
            "needs_review": trend.get("needs_review_count", 0),
            "high_risk": trend.get("high_risk_count", 0),
        }


# 全局单例
_kb: Optional[ForensicKnowledgeBase] = None


def get_forensic_kb() -> ForensicKnowledgeBase:
    """获取取证知识库单例"""
    global _kb
    if _kb is None:
        _kb = ForensicKnowledgeBase()
    return _kb
