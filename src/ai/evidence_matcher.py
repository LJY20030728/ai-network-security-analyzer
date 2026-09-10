"""
RAG 证据比对匹配器（L4）
==========================
把 RAG 从"塞背景知识"升级为"证据比对"：告警特征 ↔ 知识库攻击模式指纹 的
可量化匹配，让检索结果真正参与研判决策，而不是装饰。

流程：
1. 告警类型 → 检索关键词 + 期望特征关键词表
2. RAG 检索相关攻击模式条目（top_k）
3. 指纹比对：
   - 关键词命中率（期望特征词出现在知识文本中的比例）
   - 端口共现率（知识文本中的端口号与告警实际端口/数值字段的共现）
   - 检索相似度
   → 综合 match_score（0~1），输出最佳匹配 + 证据引用

设计口径（诚实性）：
- 匹配度是启发式（关键词/端口共现），用于给 LLM 研判提供"知识-告警对应关系"，
  不是精确判定；note 字段显式声明启发式性质。
- 告警文本不可信（可能含注入），仅提取数值/端口/类型字段做比对，不执行任何内容。
"""
import re
from typing import List, Dict, Any, Optional
from loguru import logger

from src.ai.rag_engine import get_rag_engine

# 告警类型 → (检索查询, 期望特征关键词)
ALERT_TYPE_PROFILE = {
    "SYN_FLOOD_SUSPECTED": (
        "SYN洪水 拒绝服务 洪泛攻击 检测", 
        ["SYN", "洪水", "洪泛", "DDoS", "拒绝服务", "半开"]),
    "PORT_SCAN_SUSPECTED": (
        "端口扫描 网络服务扫描 侦察 T1046",
        ["扫描", "SYN", "端口", "侦察", "探测"]),
    "DNS_TUNNEL_SUSPECTED": (
        "DNS隧道 命令与控制 异常DNS查询",
        ["DNS", "隧道", "查询", "命令控制", "编码"]),
    "LARGE_DATA_TRANSFER": (
        "数据渗出 数据外传 大流量传输 DLP",
        ["渗出", "数据", "传输", "外传", "DLP", "出站"]),
    "RST_STORM": (
        "RST 连接重置 扫描 异常流量",
        ["RST", "重置", "扫描", "连接"]),
    "BASELINE_DEVIATION": (
        "流量异常 统计基线 时序偏差 检测",
        ["基线", "异常", "偏差", "统计", "时序"]),
    "ML_ANOMALY": (
        "无监督异常检测 流量异常 机器学习",
        ["异常", "检测", "机器学习", "无监督"]),
}

_PORT_RE = re.compile(r"\b(\d{1,5})\b")


class EvidenceMatcher:
    """告警-知识证据比对器"""

    def __init__(self, rag=None):
        self.rag = rag or get_rag_engine()

    # ---------- 对外接口 ----------

    def match_alert(self, alert: Dict[str, Any], top_k: int = 3) -> Dict[str, Any]:
        """对单条告警做知识证据比对，返回匹配结果"""
        atype = str(alert.get("type", ""))
        profile = ALERT_TYPE_PROFILE.get(atype)
        if profile is None:
            query, expect_kw = f"网络攻击 检测 {atype}", []
        else:
            query, expect_kw = profile

        try:
            results = self.rag.search(query, top_k=top_k, use_hybrid=True)
        except Exception as e:
            logger.warning(f"证据比对检索失败: {e}")
            results = []

        alert_fields = self._alert_numeric_fields(alert)
        alert_text = self._alert_plain_text(alert)

        best = None
        for r in results:
            content = r.get("content", "")
            meta = r.get("metadata", {}) or {}
            title = meta.get("title", "")
            similarity = r.get("similarity", 0.0)

            kw_hit = [k for k in expect_kw if k in content]
            kw_rate = len(kw_hit) / len(expect_kw) if expect_kw else 0.0

            # 端口/数值共现：知识中的数字 token 是否出现在告警数值字段
            know_nums = {int(m) for m in _PORT_RE.findall(content)} | {int(m) for m in _PORT_RE.findall(title)}
            alert_nums = set(alert_fields)
            shared = know_nums & alert_nums
            port_rate = len(shared) / len(know_nums) if know_nums else 0.0

            # 文本共现：知识内容里出现告警文本里的关键 token（如域名/IP/协议）
            text_shared = sum(1 for tok in self._alert_tokens(alert_text) if tok and tok in content)
            text_rate = min(1.0, text_shared / 3.0)

            score = 0.45 * kw_rate + 0.30 * port_rate + 0.25 * min(1.0, similarity) + 0.10 * text_rate
            score = round(min(1.0, score), 4)

            if best is None or score > best["match_score"]:
                best = {
                    "match_score": score,
                    "knowledge_title": title,
                    "knowledge_ref": meta.get("source", "knowledge_base"),
                    "matched_keywords": kw_hit,
                    "matched_ports": sorted(int(x) for x in shared)[:10],
                    "content_excerpt": content[:220],
                }

        if best is None:
            return {
                "alert_type": atype,
                "match_score": 0.0,
                "note": "知识库无相关条目，证据比对未命中（不改变检测结论）",
            }

        best.update({
            "alert_type": atype,
            "note": "启发式证据比对（关键词/端口共现 + 检索相似度），供研判参考，不替代检测引擎",
        })
        return best

    def match_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量比对（保持告警顺序）"""
        return [self.match_alert(a) for a in alerts]

    # ---------- 内部工具 ----------

    @staticmethod
    def _alert_numeric_fields(alert: Dict[str, Any]) -> List[int]:
        """提取告警中的数值字段（计数/端口等），供端口共现比对"""
        out = []
        skip = {"window_index"}
        for k, v in alert.items():
            if k in skip:
                continue
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                iv = int(v)
                if 1 <= iv <= 65535:
                    out.append(iv)
            elif isinstance(v, list) and k in ("sample_ports",):
                out.extend(int(x) for x in v if isinstance(x, int) and 1 <= x <= 65535)
        return out

    @staticmethod
    def _alert_plain_text(alert: Dict[str, Any]) -> str:
        """拼接告警可读文本（type/ip/description）"""
        parts = [str(alert.get("type", ""))]
        for k in ("src_ip", "dst_ip", "protocol", "description"):
            v = alert.get(k)
            if v:
                parts.append(str(v))
        return " ".join(parts)

    @staticmethod
    def _alert_tokens(text: str) -> List[str]:
        """从告警文本提取可比对 token（IP、域名、协议关键词）"""
        tokens = []
        tokens += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)          # IP
        tokens += re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b", text)  # 域名
        tokens += re.findall(r"\b(TCP|UDP|DNS|HTTP|HTTPS|ICMP|RST|SYN|ACK)\b", text, re.I)  # 协议/标志
        return list({t for t in tokens if t})


# 全局单例
_evidence_matcher: Optional[EvidenceMatcher] = None


def get_evidence_matcher() -> EvidenceMatcher:
    """获取全局证据比对器单例"""
    global _evidence_matcher
    if _evidence_matcher is None:
        _evidence_matcher = EvidenceMatcher()
    return _evidence_matcher
