"""
基线管理服务

负责：
- 基线学习（从正常流量PCAP学习基线画像）
- 基线存储与加载（SQLite + JSON双写）
- 基线列表查询
- 基线删除
- 基线可视化SVG生成
"""

import os
import logging
from typing import Dict, Any, List, Optional

from config.settings import settings
from src.core.exceptions import (
    BaselineError,
    BaselineNotFoundError,
    BaselineTrainingError,
    BaselineInvalidDataError,
)

logger = logging.getLogger(__name__)


class BaselineService:
    """基线管理服务"""
    
    def __init__(self):
        self._baseline_dir = None
    
    @property
    def baseline_dir(self) -> str:
        """基线存储目录"""
        if self._baseline_dir is None:
            from src.utils.paths import data_dir
            self._baseline_dir = data_dir("baselines")
        return self._baseline_dir
    
    def _baseline_path(self, name: str) -> str:
        """基线文件名安全化 + 路径"""
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_.").strip()
        if not safe:
            safe = "baseline"
        return os.path.join(self.baseline_dir, f"{safe}.json")
    
    def list_baselines(self) -> List[Dict[str, Any]]:
        """列出所有已保存基线"""
        from src.storage.database import Database
        from src.analysis.baseline import TrafficBaseline
        from src.utils.paths import ensure_dir
        
        db = Database()
        items = db.list_baselines()
        
        # SQLite为空时从JSON导入（向后兼容）
        if not items:
            ensure_dir(self.baseline_dir)
            for fn in sorted(os.listdir(self.baseline_dir)):
                if fn.endswith(".json"):
                    path = os.path.join(self.baseline_dir, fn)
                    b = TrafficBaseline.load(path)
                    if b and b.learned:
                        db.save_baseline(
                            name=b.name or os.path.splitext(fn)[0],
                            profile=b.to_dict().get("profile", {}),
                            window_sec=b.window_sec,
                            total_packets=getattr(b, "packets_used", 0),
                            description=getattr(b, "description", None),
                        )
            items = db.list_baselines()
        
        # 转换为UI需要的格式
        result = []
        for item in items:
            bl = db.get_baseline(item["name"])
            profile_summary = {}
            if bl and bl.get("profile"):
                prof = bl["profile"].get("profile", bl["profile"])
                if isinstance(prof, dict):
                    profile_summary = {
                        k: {"median": v.get("median"), "mad": v.get("mad")}
                        for k, v in prof.items() if isinstance(v, dict)
                    }
            result.append({
                "name": item["name"],
                "file": f"{item['name']}.json",
                "created_at": item.get("created_at", ""),
                "packets_used": item.get("total_packets", 0),
                "window_sec": item.get("window_sec", 5),
                "profile": profile_summary,
            })
        return result
    
    def get_baseline_names(self) -> List[str]:
        """获取所有基线名称（用于下拉框）"""
        return [b["name"] for b in self.list_baselines()]
    
    def learn_baseline(self, filepath: str, name: str) -> Dict[str, Any]:
        """
        从PCAP文件学习基线
        
        Args:
            filepath: 正常流量PCAP文件路径
            name: 基线名称
            
        Returns:
            学习结果
        """
        from src.capture.pcap_parser import PcapParser
        from src.analysis.baseline import TrafficBaseline
        from src.storage.database import Database
        from src.utils.paths import ensure_dir
        
        # 解析PCAP
        parser = PcapParser()
        packets = parser.parse_file(filepath)
        
        if not packets:
            raise BaselineInvalidDataError(
                message="PCAP解析失败或为空，无法学习基线"
            )
        
        # 学习基线
        baseline = TrafficBaseline()
        baseline.name = name
        baseline.learn(packets)
        packet_count = len(packets)
        
        # 保存到JSON
        save_path = self._baseline_path(name)
        ensure_dir(self.baseline_dir)
        if not baseline.save(save_path):
            raise BaselineTrainingError(message="基线保存失败")
        
        # 同时保存到SQLite
        try:
            db = Database()
            db.save_baseline(
                name=name,
                profile=baseline.to_dict().get("profile", {}),
                window_sec=baseline.window_sec,
                total_packets=packet_count,
                description=f"从 {os.path.basename(filepath)} 学习",
            )
        except Exception as e:
            logger.warning(f"基线保存到SQLite失败（不影响JSON保存）: {e}")
        
        return {
            "status": "success",
            "name": name,
            "packet_count": packet_count,
            "saved_to": save_path,
            "profile": baseline.to_dict(),
        }
    
    def get_baseline(self, name: str) -> Dict[str, Any]:
        """获取基线详情"""
        from src.analysis.baseline import TrafficBaseline
        
        b = TrafficBaseline.load(self._baseline_path(name))
        if not b or not b.learned:
            raise BaselineNotFoundError(message=f"基线不存在或未学习: {name}")
        return b.to_dict()
    
    def delete_baseline(self, name: str) -> Dict[str, Any]:
        """删除基线"""
        from src.storage.database import Database
        
        # 删除SQLite
        try:
            Database().delete_baseline(name)
        except Exception as e:
            logger.warning(f"从SQLite删除基线失败: {e}")
        
        # 删除JSON
        path = self._baseline_path(name)
        if os.path.exists(path):
            os.remove(path)
            return {"status": "success", "deleted": name}
        
        raise BaselineNotFoundError(message=f"基线不存在: {name}")
    
    def load_baseline_into(self, analyzer, baseline_name: str) -> bool:
        """
        加载基线到分析器
        
        Args:
            analyzer: TrafficAnalyzer实例
            baseline_name: 基线名称
            
        Returns:
            是否加载成功
        """
        from src.analysis.baseline import TrafficBaseline
        from src.storage.database import Database
        
        if not baseline_name:
            return False
        
        # 优先从SQLite加载
        db = Database()
        bl = db.get_baseline(baseline_name)
        if bl and bl.get("learned"):
            b = TrafficBaseline(window_sec=bl.get("window_sec", 5))
            b.name = baseline_name
            b._learned = True
            prof = bl.get("profile", {})
            if isinstance(prof, dict) and "profile" in prof:
                b.profile = prof["profile"]
            elif isinstance(prof, dict):
                b.profile = prof
            analyzer.baseline = b
            logger.info(f"已加载基线(SQLite): {baseline_name}")
            return True
        
        # 回退到JSON
        b = TrafficBaseline.load(self._baseline_path(baseline_name))
        if b and b.learned:
            analyzer.baseline = b
            logger.info(f"已加载基线(JSON): {b.name or baseline_name}")
            return True
        
        logger.warning(f"基线加载失败或未学习: {baseline_name}")
        return False
    
    def build_compare_svg(self, window_series, baseline_profile):
        """
        流量每窗口包数 vs 基线中位数 对比图
        
        Args:
            window_series: 时间窗口序列
            baseline_profile: 基线画像
            
        Returns:
            SVG字符串
        """
        if not window_series:
            return None
        
        try:
            n = len(window_series)
            if n == 0:
                return None
            
            median = None
            win_sec = 10
            if isinstance(baseline_profile, dict):
                prof = baseline_profile.get("profile") or {}
                w = prof.get("window_packets") or {}
                if isinstance(w, dict) and w.get("median"):
                    median = float(w["median"])
                win_sec = int(baseline_profile.get("window_sec", 10) or 10)
            
            values = [float(x.get("packets", 0)) for x in window_series]
            vmax = max(max(values), median or 0, 1) * 1.15
            W, H, P = 760, 220, 38
            iw, ih = W - 2 * P, H - 2 * P
            
            def _xy(i, v):
                x = P + (iw * i / max(n - 1, 1))
                y = P + ih - (ih * v / vmax)
                return x, y
            
            pts = " ".join(f"{_xy(i, v)[0]:.1f},{_xy(i, v)[1]:.1f}" for i, v in enumerate(values))
            svg = [
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
                f'viewBox="0 0 {W} {H}" '
                f'style="font-family:Segoe UI,Arial,sans-serif;'
                f'background:linear-gradient(180deg,#f8faff,#eef4ff);'
                f'border-radius:12px;border:1px solid #dbe6ff">'
            ]
            
            for g in range(5):
                gy = P + ih * g / 4
                svg.append(f'<line x1="{P}" y1="{gy:.1f}" x2="{W-P}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
            
            if median:
                my = P + ih - (ih * median / vmax)
                svg.append(
                    f'<line x1="{P}" y1="{my:.1f}" x2="{W-P}" y2="{my:.1f}" '
                    f'stroke="#ef4444" stroke-width="2" stroke-dasharray="6,4"/>'
                )
                svg.append(
                    f'<text x="{W-P-8}" y="{my-7:.1f}" text-anchor="end" font-size="11" fill="#ef4444">'
                    f'基线中位数 {median:.0f} 包/窗</text>'
                )
            
            svg.append(
                f'<polyline points="{pts}" fill="none" stroke="#2563eb" '
                f'stroke-width="2.4" stroke-linejoin="round"/>'
            )
            
            for i, v in enumerate(values):
                x, y = _xy(i, v)
                svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#2563eb"/>')
            
            svg.append(
                f'<text x="{P}" y="{H-8}" font-size="11" fill="#64748b">'
                f'窗口序号（每 {win_sec} 秒一个窗口，共 {n} 个）</text>'
            )
            svg.append(f'<text x="{P}" y="{P-12}" font-size="11" fill="#64748b">每窗口包数</text>')
            svg.append(f'<text x="{W-P}" y="{P-12}" text-anchor="end" font-size="12" fill="#2563eb">当前流量</text>')
            svg.append('</svg>')
            
            return "".join(svg)
        except Exception:
            return None
    
    def build_profile_svg(self, profile, name):
        """
        基线画像SVG（各维度 中位数±MAD 条形图）
        
        Args:
            profile: 基线画像
            name: 基线名称
            
        Returns:
            SVG字符串
        """
        if not isinstance(profile, dict) or not profile:
            return None
        
        try:
            dims = [
                ("window_packets", "每窗包数"),
                ("window_bytes", "每窗字节"),
                ("window_syn", "每窗SYN"),
                ("window_dports", "每窗端口数"),
            ]
            
            rows = []
            vmax = 1
            for k, _lab in dims:
                v = profile.get(k) or {}
                if isinstance(v, dict) and v.get("median"):
                    vmax = max(vmax, float(v["median"]) * 1.25)
            
            W, H, P = 560, 46 + len(dims) * 46, 40
            bar_w = W - 2 * P
            
            svg = [
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
                f'viewBox="0 0 {W} {H}" '
                f'style="font-family:Segoe UI,Arial,sans-serif;'
                f'background:#f8faff;border-radius:12px;border:1px solid #dbe6ff">'
            ]
            svg.append(
                f'<text x="{P}" y="22" font-size="13" font-weight="600" fill="#1e293b">'
                f'基线「{name or "?"}」画像（中位数 ± MAD）</text>'
            )
            
            for i, (k, lab) in enumerate(dims):
                y = 44 + i * 46
                v = profile.get(k) or {}
                med = float(v.get("median", 0) or 0)
                mad = float(v.get("mad", 0) or 0)
                bw = bar_w * med / vmax
                
                svg.append(f'<text x="{P}" y="{y+13}" font-size="11" fill="#475569">{lab}</text>')
                svg.append(
                    f'<rect x="{P}" y="{y+18}" width="{bw:.1f}" height="12" rx="4" fill="#60a5fa"/>'
                )
                svg.append(
                    f'<rect x="{P}" y="{y+18}" width="{bar_w*mad/vmax:.1f}" height="12" rx="4" '
                    f'fill="none" stroke="#ef4444" stroke-dasharray="4,3"/>'
                )
                svg.append(
                    f'<text x="{P+bw+8:.1f}" y="{y+29}" font-size="11" fill="#2563eb">'
                    f'中位 {med:.1f} · MAD {mad:.1f}</text>'
                )
            
            svg.append('</svg>')
            return "".join(svg)
        except Exception:
            return None


# 全局服务单例
_baseline_service: Optional[BaselineService] = None


def get_baseline_service() -> BaselineService:
    """获取基线服务单例"""
    global _baseline_service
    if _baseline_service is None:
        _baseline_service = BaselineService()
    return _baseline_service
