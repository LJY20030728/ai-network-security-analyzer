"""
EWMA 时序基线引擎（学习-检测两阶段）
=====================================
设计动机（简历叙事要点）：
- 网络流量具有昼夜周期性、重尾分布、非平稳特性
- 检测系统受资源约束（内网/嵌入式部署），深度模型不可解释、无法逐告警溯源
- 故选择统计基线：EWMA 中位数 + MAD（绝对中位差）鲁棒尺度，而非均值+标准差
  （均值/标准差假设正态分布，流量是重尾分布，单个离群点即可拉爆阈值）

实现要点：
1. 时间窗聚合：按固定窗口（默认10s）聚合 包数/字节数/SYN数/端口数 等维度
2. 学习阶段 learn()：对窗口序列计算各维度 EWMA 中位数 与 MAD
   - 先跑一轮粗检测剔除异常窗口，防止攻击流量污染基线（基线污染防御）
3. 检测阶段 detect()：z-score = 0.6745*(x - median) / MAD（MAD 正态换算系数）
   z > sigma 阈值 → 标记偏差，输出偏差数值（证据链中的量化依据）
"""
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime
from loguru import logger

from config.settings import settings
from src.capture.packet_parser import PacketInfo


# MAD → 正态标准差换算系数（0.6745），使 z-score 与 3σ 语义可比
MAD_SIGMA_FACTOR = 0.6745


def _median(values: List[float]) -> float:
    """中位数（鲁棒中心估计）"""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def _mad(values: List[float], center: float) -> float:
    """绝对中位差（鲁棒尺度估计），未乘换算系数"""
    if not values:
        return 0.0
    return _median([abs(v - center) for v in values])


class TrafficBaseline:
    """
    流量时序基线：学习正常流量画像，检测统计偏差。

    维度：window_packets(窗口包数) / window_bytes(窗口字节数)
          / window_syn(窗口SYN数) / window_dports(窗口目的端口数)
    """

    DIMENSIONS = ["window_packets", "window_bytes", "window_syn", "window_dports"]

    # 各维度相对灵敏度（最小可检测波动 = 中位数 * ratio）。
    # 解决 MAD 趋零导致的过敏感：流量高度均匀时，绝对 MAD 很小，
    # 任何微小波动都会 z 爆表；用相对下限保证"可解释的最小偏差"。
    DIM_SENSITIVITY = {
        "window_packets": 0.30,
        "window_bytes": 0.50,
        "window_syn": 0.50,
        "window_dports": 0.50,
    }

    def __init__(self,
                 alpha: Optional[float] = None,
                 sigma: Optional[float] = None,
                 window_sec: Optional[int] = None):
        self.alpha = alpha if alpha is not None else settings.baseline_alpha
        self.sigma = sigma if sigma is not None else settings.baseline_sigma
        self.window_sec = window_sec if window_sec is not None else settings.baseline_window_sec

        # 元信息（持久化）
        self.name: str = ""
        self.created_at: str = ""
        self.packets_used: int = 0

        # 基线画像：{维度: {"median": float, "mad": float, "samples": int}}
        self.profile: Dict[str, Dict[str, float]] = {}
        self._learned = False
        # 学习阶段的窗口统计缓存（供训练/校验）
        self._train_windows: List[Dict[str, float]] = []
        # P1: EWMA 在线滚动更新（检测阶段）
        self.online_update = settings.baseline_online_update
        self.updated_windows = 0          # 已滚动更新的窗口计数（供报告）
        self._recent_windows: List[Dict[str, float]] = []   # 漂移检测：最近窗口缓存
        self.last_drift = None            # 最近一次漂移检测结果

    # ---------- 内部：时间窗聚合 ----------

    def _aggregate_windows(self, packets: List[PacketInfo]) -> List[Dict[str, float]]:
        """按固定时间窗聚合各维度统计"""
        if not packets:
            return []

        # 找出时间范围（用第一个包时间作为起点）
        try:
            from datetime import datetime
            times = [datetime.strptime(p.timestamp, "%Y-%m-%d %H:%M:%S.%f") for p in packets]
            t0 = times[0]
            # 转为相对秒
            rel = [(t - t0).total_seconds() for t in times]
        except Exception:
            # 时间解析失败则退化为单窗口
            rel = [float(i) for i in range(len(packets))]

        windows: Dict[int, Dict[str, float]] = defaultdict(lambda: {
            "window_packets": 0.0, "window_bytes": 0.0,
            "window_syn": 0.0, "window_dports": 0.0,
        })
        dports_seen: Dict[int, set] = defaultdict(set)

        for p, sec in zip(packets, rel):
            w = int(sec // self.window_sec)
            windows[w]["window_packets"] += 1
            windows[w]["window_bytes"] += float(p.length)
            if p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags:
                windows[w]["window_syn"] += 1
            if p.dst_port > 0:
                dports_seen[w].add(p.dst_port)

        for w, ports in dports_seen.items():
            windows[w]["window_dports"] = float(len(ports))

        return [windows[w] for w in sorted(windows.keys())]

    # ---------- 学习阶段 ----------

    def learn(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """从正常流量学习基线画像（全量路径：聚合窗口后委托 learn_windows）"""
        windows = self._aggregate_windows(packets)
        self.packets_used = len(packets)
        return self.learn_windows(windows)

    def learn_windows(self, windows: List[Dict[str, float]]) -> Dict[str, Any]:
        """
        从窗口统计序列学习基线画像（流式/全量共用核心）。
        基线污染防御：先按 中位数+3*MAD 粗剔除极端窗口，再重建基线。
        """
        if len(windows) < max(3, settings.baseline_min_windows // 5):
            logger.warning(f"学习阶段窗口数不足（{len(windows)}），基线可能不稳定")

        # 第一遍：对每个维度粗剔除极端窗口
        cleaned = windows
        for dim in self.DIMENSIONS:
            vals = [w[dim] for w in windows]
            med = _median(vals)
            mad = _mad(vals, med)
            if mad > 0:
                upper = med + 3.0 * mad / MAD_SIGMA_FACTOR
                cleaned = [w for w in cleaned if w[dim] <= upper]

        # 第二遍：用清洗后的窗口计算鲁棒基线
        self.profile = {}
        for dim in self.DIMENSIONS:
            vals = [w[dim] for w in cleaned]
            med = _median(vals)
            mad = _mad(vals, med)
            # 有效 MAD = max(绝对MAD, 相对灵敏度下限)，防止过敏感
            sensitivity = max(1.0, med * self.DIM_SENSITIVITY.get(dim, 0.3))
            eff_mad = max(mad, sensitivity)
            self.profile[dim] = {"median": med, "mad": eff_mad,
                                 "raw_mad": mad, "samples": len(vals)}

        self._train_windows = cleaned
        self._learned = True
        if not self.created_at:
            self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"基线学习完成 | 窗口数: {len(windows)} → 清洗后 {len(cleaned)} | "
                    f"维度: {list(self.profile.keys())}")
        return self.profile

    @property
    def learned(self) -> bool:
        return self._learned

    # ---------- 检测阶段 ----------

    def detect(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """对照基线检测统计偏差（全量路径：聚合窗口后委托 detect_windows）"""
        if not self._learned:
            return {"total_deviations": 0, "deviations": [], "error": "基线未学习，请先调用 learn()"}
        windows = self._aggregate_windows(packets)
        return self.detect_windows(windows)

    def detect_windows(self, windows: List[Dict[str, float]]) -> Dict[str, Any]:
        """
        对照基线检测窗口统计序列（流式/全量共用核心）。
        返回：{total_deviations, deviations, drift, updated_windows}
        """
        if not self._learned:
            return {"total_deviations": 0, "deviations": [], "error": "基线未学习，请先调用 learn()"}

        deviations = []
        update_enabled = self.online_update

        for idx, w in enumerate(windows):
            # 漂移检测缓存：保留最近 N 个窗口的包数序列
            self._recent_windows.append(w)
            if len(self._recent_windows) > settings.baseline_drift_window:
                self._recent_windows.pop(0)

            is_deviation_window = False
            for dim in self.DIMENSIONS:
                med = self.profile[dim]["median"]
                mad = self.profile[dim]["mad"]
                value = w[dim]
                # 鲁棒 z-score（有效 MAD 换算到正态尺度）
                z = (value - med) * MAD_SIGMA_FACTOR / mad if mad > 0 else 0.0
                if z > self.sigma:
                    severity = "HIGH" if z > self.sigma * 2 else "MEDIUM"
                    deviations.append({
                        "window_index": idx,
                        "dimension": dim,
                        "value": round(value, 2),
                        "baseline_median": round(med, 2),
                        "baseline_mad": round(mad, 2),
                        "z_score": round(z, 2),
                        "severity": severity,
                    })
                    is_deviation_window = True

            # P1: EWMA 在线滚动更新（仅无偏差窗口参与，防攻击污染基线）
            if update_enabled and not is_deviation_window and mad is not None:
                for dim in self.DIMENSIONS:
                    med = self.profile[dim]["median"]
                    mad = self.profile[dim]["mad"]
                    value = w[dim]
                    new_med = self.alpha * value + (1 - self.alpha) * med
                    # 指数加权移动 MAD（对 |value-median| 平滑）
                    new_mad = self.alpha * abs(value - med) + (1 - self.alpha) * mad
                    # 保持相对灵敏度下限（防止 MAD 趋零过敏感）
                    sensitivity = max(1.0, new_med * self.DIM_SENSITIVITY.get(dim, 0.3))
                    self.profile[dim]["median"] = round(new_med, 4)
                    self.profile[dim]["mad"] = round(max(new_mad, sensitivity), 4)
                self.updated_windows += 1

        # P1: KS 漂移失效检测（最近窗口分布 vs 学习分布）
        drift = self._detect_drift()
        self.last_drift = drift

        # P1-6: 多维度联合判定（一个窗口多维度同时偏差时，生成联合告警，严重度提升）
        multi_dim_alerts = []
        windows_by_idx = {}
        for d in deviations:
            wi = d["window_index"]
            if wi not in windows_by_idx:
                windows_by_idx[wi] = []
            windows_by_idx[wi].append(d)
        for wi, devs in windows_by_idx.items():
            if len(devs) >= 2:
                dims = [d["dimension"] for d in devs]
                max_z = max(d["z_score"] for d in devs)
                severity = "CRITICAL" if len(devs) >= 3 or max_z > 6 else "HIGH"
                multi_dim_alerts.append({
                    "window_index": wi,
                    "dimensions": dims,
                    "dimension_count": len(dims),
                    "max_z_score": round(max_z, 2),
                    "severity": severity,
                    "description": f"多维度联合偏差：窗口{wi}同时{len(dims)}个维度异常"
                                   f"（{', '.join(dims)}），最大z-score={max_z:.2f}",
                })

        logger.info(f"基线检测完成 | 偏差窗口数: {len(deviations)} | "
                    f"多维度联合告警: {len(multi_dim_alerts)} | "
                    f"滚动更新窗口: {self.updated_windows} | 漂移: {drift['detected']}")
        return {
            "total_deviations": len(deviations),
            "deviations": deviations,
            "multi_dim_alerts": multi_dim_alerts,
            "drift": drift,
            "updated_windows": self.updated_windows,
        }

    # ---------- P1: KS 漂移失效检测 ----------

    @staticmethod
    def _ks2_dstat(sample1: List[float], sample2: List[float]) -> float:
        """两样本 Kolmogorov-Smirnov D 统计量（纯 Python，无 scipy 依赖）"""
        if not sample1 or not sample2:
            return 0.0
        merged = sorted((v, 0) for v in sample1) + sorted((v, 1) for v in sample2)
        merged.sort(key=lambda x: x[0])
        n1, n2 = len(sample1), len(sample2)
        cdf1 = cdf2 = 0.0
        d = 0.0
        i = j = 0
        # 按值推进经验 CDF，取最大差
        while i < len(merged):
            v = merged[i][0]
            c1 = c2 = 0
            while i < len(merged) and merged[i][0] == v:
                if merged[i][1] == 0:
                    c1 += 1
                else:
                    c2 += 1
                i += 1
            cdf1 += c1 / n1
            cdf2 += c2 / n2
            d = max(d, abs(cdf1 - cdf2))
        return d

    def _detect_drift(self) -> Dict[str, Any]:
        """
        漂移失效检测：最近 N 个窗口的分布 vs 学习阶段分布，做两样本 KS 检验。
        任一维度 D 统计量超临界值 → 判定基线可能失效（业务流量画像已变化）。
        """
        if len(self._recent_windows) < 5 or not self._train_windows:
            return {"detected": False, "dimension": None, "d_stat": 0.0,
                    "note": "窗口样本不足，暂不评估漂移"}
        n1 = len(self._train_windows)
        n2 = len(self._recent_windows)
        crit = 1.36 * ((n1 + n2) / (n1 * n2)) ** 0.5  # α=0.05 近似临界值
        worst = {"d": 0.0, "dim": None}
        for dim in self.DIMENSIONS:
            base = [w[dim] for w in self._train_windows]
            recent = [w[dim] for w in self._recent_windows]
            d = self._ks2_dstat(base, recent)
            if d > worst["d"]:
                worst = {"d": d, "dim": dim}
        detected = worst["d"] > crit
        return {
            "detected": detected,
            "dimension": worst["dim"],
            "d_stat": round(worst["d"], 4),
            "critical_value": round(crit, 4),
            "note": ("流量分布显著偏离学习基线（KS 检验），基线可能失效，"
                     "建议重新学习" if detected else "流量分布与基线一致"),
        }

    def to_dict(self) -> Dict[str, Any]:
        """导出基线画像（可持久化/展示）"""
        return {
            "name": self.name,
            "created_at": self.created_at,
            "packets_used": self.packets_used,
            "alpha": self.alpha,
            "sigma": self.sigma,
            "window_sec": self.window_sec,
            "learned": self._learned,
            "dimensions": self.DIMENSIONS,
            "profile": self.profile,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrafficBaseline":
        """从字典恢复基线画像"""
        b = cls(alpha=data.get("alpha"), sigma=data.get("sigma"),
                window_sec=data.get("window_sec"))
        b.name = data.get("name", "")
        b.created_at = data.get("created_at", "")
        b.packets_used = data.get("packets_used", 0)
        b.profile = data.get("profile", {})
        b._learned = bool(b.profile)
        return b

    def save(self, filepath: str) -> bool:
        """持久化到 JSON 文件"""
        import json
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"基线保存失败: {e}")
            return False

    @classmethod
    def load(cls, filepath: str) -> Optional["TrafficBaseline"]:
        """从 JSON 文件加载基线"""
        import json
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            b = cls.from_dict(data)
            if not b._learned:
                logger.warning(f"基线文件无画像数据: {filepath}")
            return b
        except Exception as e:
            logger.error(f"基线加载失败 {filepath}: {e}")
            return None

    # ---------- P2-3: STL 高级时序分解检测 ----------

    def detect_seasonal(self, windows: List[Dict[str, float]],
                         metric: str = "window_packets",
                         period: Optional[int] = None) -> Dict[str, Any]:
        """
        STL 高级时序分解检测（零依赖轻量级实现）
        分解为趋势+季节性+残差，检测残差异常（捕捉周期性偏离）
        :param windows: 窗口数据列表
        :param metric: 检测指标（window_packets/window_bytes/window_syn/window_dports）
        :param period: 季节性周期（窗口数，默认自动估计）
        :return: 分解结果 + 异常告警
        """
        try:
            from src.analysis.stl_decomposer import detect_seasonal_anomalies
            if period is None:
                # 自动估计周期：数据量的 1/4，至少 6，最多 48
                period = max(6, min(48, len(windows) // 4))
            result = detect_seasonal_anomalies(windows, metric=metric, period=period)
            logger.info(f"STL 分解完成: {len(windows)} 窗口, "
                       f"{len(result.get('anomalies', []))} 个异常, "
                       f"方法={result.get('method', '?')}")
            return result
        except Exception as e:
            logger.warning(f"STL 分解失败，回退常规检测: {e}")
            return {"alerts": [], "anomalies": [], "error": str(e), "method": "failed"}


class WindowAccumulator:
    """流式窗口聚合器：逐包喂入，按时间窗增量聚合（内存 O(窗口数)，不持有原始包）"""

    def __init__(self, window_sec: int = 10):
        self.window_sec = window_sec
        self._base_time = None
        self._windows = defaultdict(lambda: {
            "window_packets": 0.0, "window_bytes": 0.0,
            "window_syn": 0.0, "window_dports": 0.0,
        })
        self._dports = defaultdict(set)
        self._fallback_idx = 0

    def add(self, p: PacketInfo) -> None:
        """喂入一个包，归入对应窗口（时间解析失败则按到达顺序编号）"""
        if self._base_time is None:
            try:
                self._base_time = datetime.strptime(p.timestamp, "%Y-%m-%d %H:%M:%S.%f")
            except Exception:
                self._base_time = False  # 时间不可用标记
        if self._base_time:
            try:
                t = datetime.strptime(p.timestamp, "%Y-%m-%d %H:%M:%S.%f")
                rel = (t - self._base_time).total_seconds()
            except Exception:
                self._fallback_idx += 1
                rel = float(self._fallback_idx)
        else:
            self._fallback_idx += 1
            rel = float(self._fallback_idx)

        w = int(rel // self.window_sec)
        self._windows[w]["window_packets"] += 1
        self._windows[w]["window_bytes"] += float(p.length)
        if p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags:
            self._windows[w]["window_syn"] += 1
        if p.dst_port > 0:
            self._dports[w].add(p.dst_port)

    def get_windows(self) -> List[Dict[str, float]]:
        """返回有序窗口统计列表（同 _aggregate_windows 输出格式）"""
        for w, ports in self._dports.items():
            self._windows[w]["window_dports"] = float(len(ports))
        return [self._windows[w] for w in sorted(self._windows.keys())]

