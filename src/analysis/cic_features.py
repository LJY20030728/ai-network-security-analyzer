# -*- coding: utf-8 -*-
"""
CIC 风格网络流特征提取器
从 PacketInfo 列表中提取双向流的 76 维 CICFlowMeter 风格特征，
用于监督学习模型（HistGradientBoosting）的推理。

特征顺序与 data/eval_cicids/csv/CIC_Data.csv header 严格对齐。
"""
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime
import math
import numpy as np
from loguru import logger
from ..capture.packet_parser import PacketInfo


# 76 维特征名（与 CIC_Data.csv header 严格一致）
CIC_FEATURE_NAMES = [
    "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Fwd Segment Size Avg", "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes",
    "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def _parse_ts(ts: str) -> float:
    """解析时间戳为秒（float）"""
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f").timestamp()
    except (ValueError, TypeError):
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp()
        except (ValueError, TypeError):
            return 0.0


def _stats(values: List[float]) -> Tuple[float, float, float, float]:
    """返回 (mean, std, max, min)，空列表返回 (0,0,0,0)"""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    return float(arr.mean()), float(arr.std()), float(arr.max()), float(arr.min())


@dataclass
class BidirFlow:
    """双向流（按五元组聚合，第一个包方向为 fwd）"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    fwd_pkts: List[PacketInfo] = field(default_factory=list)
    bwd_pkts: List[PacketInfo] = field(default_factory=list)

    def all_pkts(self) -> List[PacketInfo]:
        """按时间排序的所有包"""
        return sorted(self.fwd_pkts + self.bwd_pkts, key=lambda p: _parse_ts(p.timestamp))


class CICFlowExtractor:
    """
    CIC 风格流特征提取器
    将 PacketInfo 列表聚合为双向流，提取 76 维特征。
    """

    def __init__(self):
        self.flows: Dict[str, BidirFlow] = {}

    def extract(self, packets: List[PacketInfo]) -> List[Dict[str, Any]]:
        """
        提取所有流的 76 维特征
        :return: 列表，每个元素含 flow_key, src_ip, src_port, dst_ip, dst_port, protocol, features(76维list)
        """
        self.flows = {}
        # 第一遍：聚合双向流
        for pkt in packets:
            if not pkt.src_ip or not pkt.dst_ip:
                continue
            if pkt.protocol not in ("TCP", "UDP"):
                continue
            ep1 = f"{pkt.src_ip}:{pkt.src_port}"
            ep2 = f"{pkt.dst_ip}:{pkt.dst_port}"
            key = f"{pkt.protocol}|" + " <-> ".join(sorted([ep1, ep2]))
            if key not in self.flows:
                endpoints = key.split("|")[1].split(" <-> ")
                s = endpoints[0].split(":")
                d = endpoints[1].split(":")
                self.flows[key] = BidirFlow(
                    src_ip=s[0], src_port=int(s[1]),
                    dst_ip=d[0], dst_port=int(d[1]),
                    protocol=pkt.protocol,
                )
            flow = self.flows[key]
            # 判断方向：以流的第一个包的源为 fwd
            if not flow.fwd_pkts and not flow.bwd_pkts:
                flow.fwd_pkts.append(pkt)
            else:
                # 检查是否与 fwd 方向一致
                first = flow.fwd_pkts[0] if flow.fwd_pkts else flow.bwd_pkts[0]
                if pkt.src_ip == first.src_ip and pkt.src_port == first.src_port:
                    flow.fwd_pkts.append(pkt)
                else:
                    flow.bwd_pkts.append(pkt)

        logger.info(f"CIC 流聚合完成 | {len(packets)} 包 → {len(self.flows)} 流")

        # 第二遍：提取特征
        results = []
        for key, flow in self.flows.items():
            features = self._extract_flow(flow)
            results.append({
                "flow_key": key,
                "src_ip": flow.src_ip,
                "src_port": flow.src_port,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "fwd_packets": len(flow.fwd_pkts),
                "bwd_packets": len(flow.bwd_pkts),
                "features": features,
            })
        return results

    def _extract_flow(self, flow: BidirFlow) -> List[float]:
        """提取单个双向流的 76 维特征"""
        fwd = flow.fwd_pkts
        bwd = flow.bwd_pkts
        all_pkts = flow.all_pkts()
        n_all = len(all_pkts)

        # 时间戳（秒）
        fwd_ts = [_parse_ts(p.timestamp) for p in fwd]
        bwd_ts = [_parse_ts(p.timestamp) for p in bwd]
        all_ts = [_parse_ts(p.timestamp) for p in all_pkts]

        # 包长
        fwd_lens = [float(p.length) for p in fwd]
        bwd_lens = [float(p.length) for p in bwd]
        all_lens = [float(p.length) for p in all_pkts]

        # 1. Flow Duration（CIC 单位：微秒）
        if n_all >= 2:
            duration = (max(all_ts) - min(all_ts)) * 1e6
        else:
            duration = 0.0

        # 2-3. Total Fwd/Bwd Packet
        total_fwd = len(fwd)
        total_bwd = len(bwd)

        # 4-5. Total Length of Fwd/Bwd Packet
        total_fwd_len = sum(fwd_lens)
        total_bwd_len = sum(bwd_lens)

        # 6-9. Fwd Packet Length Max/Min/Mean/Std
        fwd_mean, fwd_std, fwd_max, fwd_min = _stats(fwd_lens)
        # 10-13. Bwd Packet Length
        bwd_mean, bwd_std, bwd_max, bwd_min = _stats(bwd_lens)

        # 14-15. Flow Bytes/s, Flow Packets/s
        flow_bytes_s = (total_fwd_len + total_bwd_len) / duration if duration > 0 else 0.0
        flow_pkts_s = n_all / duration if duration > 0 else 0.0

        # 16-19. Flow IAT Mean/Std/Max/Min（CIC 单位：微秒）
        flow_iats = [(all_ts[i + 1] - all_ts[i]) * 1e6 for i in range(n_all - 1)]
        fi_mean, fi_std, fi_max, fi_min = _stats(flow_iats)

        # 20-24. Fwd IAT Total/Mean/Std/Max/Min（微秒）
        fwd_iats = [(fwd_ts[i + 1] - fwd_ts[i]) * 1e6 for i in range(len(fwd_ts) - 1)]
        fwd_iat_total = sum(fwd_iats)
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(fwd_iats)
        # 25-29. Bwd IAT（微秒）
        bwd_iats = [(bwd_ts[i + 1] - bwd_ts[i]) * 1e6 for i in range(len(bwd_ts) - 1)]
        bwd_iat_total = sum(bwd_iats)
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(bwd_iats)

        # 30-33. PSH/URG Flags（有该标志的包数）
        fwd_psh = sum(1 for p in fwd if "PSH" in (p.flags or ""))
        bwd_psh = sum(1 for p in bwd if "PSH" in (p.flags or ""))
        fwd_urg = sum(1 for p in fwd if "URG" in (p.flags or ""))
        bwd_urg = sum(1 for p in bwd if "URG" in (p.flags or ""))

        # 34-35. Header Length（TCP 头 20 字节/包）
        fwd_hdr_len = total_fwd * 20 if flow.protocol == "TCP" else 8
        bwd_hdr_len = total_bwd * 20 if flow.protocol == "TCP" else 8

        # 36-37. Fwd/Bwd Packets/s
        fwd_pkts_s = total_fwd / duration if duration > 0 else 0.0
        bwd_pkts_s = total_bwd / duration if duration > 0 else 0.0

        # 38-42. Packet Length Min/Max/Mean/Std/Variance
        p_mean, p_std, p_max, p_min = _stats(all_lens)
        p_var = p_std ** 2

        # 43-50. Flag Count
        flag_counts = defaultdict(int)
        for p in all_pkts:
            if p.flags:
                for f in p.flags.split(","):
                    flag_counts[f.strip()] += 1
        fin_cnt = flag_counts.get("FIN", 0)
        syn_cnt = flag_counts.get("SYN", 0)
        rst_cnt = flag_counts.get("RST", 0)
        psh_cnt = flag_counts.get("PSH", 0)
        ack_cnt = flag_counts.get("ACK", 0)
        urg_cnt = flag_counts.get("URG", 0)
        cwr_cnt = flag_counts.get("CWR", 0)
        ece_cnt = flag_counts.get("ECE", 0)

        # 51. Down/Up Ratio
        down_up_ratio = total_bwd / total_fwd if total_fwd > 0 else 0.0

        # 52. Average Packet Size
        avg_pkt_size = (total_fwd_len + total_bwd_len) / n_all if n_all > 0 else 0.0

        # 53-54. Fwd/Bwd Segment Size Avg
        fwd_seg_avg = fwd_mean
        bwd_seg_avg = bwd_mean

        # 55-60. Bulk 统计（简化：连续包间时间<1s且>=4包为一个bulk）
        fwd_bulk_bytes, fwd_bulk_pkts, fwd_bulk_rate = self._bulk_stats(fwd, fwd_ts)
        bwd_bulk_bytes, bwd_bulk_pkts, bwd_bulk_rate = self._bulk_stats(bwd, bwd_ts)

        # 61-64. Subflow（简化：等于总包数/总字节）
        subflow_fwd_pkts = total_fwd
        subflow_fwd_bytes = total_fwd_len
        subflow_bwd_pkts = total_bwd
        subflow_bwd_bytes = total_bwd_len

        # 65-66. Init Win Bytes（第一个包的 window size）
        fwd_init_win = fwd[0].tcp_window if fwd else 0
        bwd_init_win = bwd[0].tcp_window if bwd else 0

        # 67. Fwd Act Data Pkts（有 payload 的前向包数）
        fwd_act_data = sum(1 for p in fwd if p.payload_size > 0)

        # 68. Fwd Seg Size Min
        fwd_seg_min = fwd_min

        # 69-76. Active/Idle（Active: 有包的连续段；Idle: 包间>5s的间隔）
        active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min = \
            self._active_idle_stats(all_ts)

        # 组装 76 维（顺序严格对齐 CIC_FEATURE_NAMES）
        features = [
            duration, total_fwd, total_bwd, total_fwd_len, total_bwd_len,
            fwd_max, fwd_min, fwd_mean, fwd_std,
            bwd_max, bwd_min, bwd_mean, bwd_std,
            flow_bytes_s, flow_pkts_s,
            fi_mean, fi_std, fi_max, fi_min,
            fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
            float(fwd_psh), float(bwd_psh), float(fwd_urg), float(bwd_urg),
            float(fwd_hdr_len), float(bwd_hdr_len),
            fwd_pkts_s, bwd_pkts_s,
            p_min, p_max, p_mean, p_std, p_var,
            float(fin_cnt), float(syn_cnt), float(rst_cnt), float(psh_cnt),
            float(ack_cnt), float(urg_cnt), float(cwr_cnt), float(ece_cnt),
            down_up_ratio, avg_pkt_size,
            fwd_seg_avg, bwd_seg_avg,
            fwd_bulk_bytes, fwd_bulk_pkts, fwd_bulk_rate,
            bwd_bulk_bytes, bwd_bulk_pkts, bwd_bulk_rate,
            float(subflow_fwd_pkts), float(subflow_fwd_bytes),
            float(subflow_bwd_pkts), float(subflow_bwd_bytes),
            float(fwd_init_win), float(bwd_init_win),
            float(fwd_act_data), float(fwd_seg_min),
            active_mean, active_std, active_max, active_min,
            idle_mean, idle_std, idle_max, idle_min,
        ]
        assert len(features) == 76, f"特征维度错误: {len(features)}"
        # 替换 NaN/Inf 为 0
        features = [0.0 if (math.isnan(f) or math.isinf(f)) else f for f in features]
        return features

    @staticmethod
    def _bulk_stats(pkts: List[PacketInfo], ts: List[float]) -> Tuple[float, float, float]:
        """
        Bulk 统计：连续包间时间<1s且>=4个包为一个bulk
        返回 (avg_bytes_per_bulk, avg_packets_per_bulk, avg_bulk_rate)
        """
        if len(pkts) < 4:
            return 0.0, 0.0, 0.0
        bulks = []
        current = [pkts[0]]
        for i in range(1, len(pkts)):
            if ts[i] - ts[i - 1] < 1.0:
                current.append(pkts[i])
            else:
                if len(current) >= 4:
                    bulks.append(current)
                current = [pkts[i]]
        if len(current) >= 4:
            bulks.append(current)
        if not bulks:
            return 0.0, 0.0, 0.0
        avg_bytes = sum(sum(p.length for p in b) for b in bulks) / len(bulks)
        avg_pkts = sum(len(b) for b in bulks) / len(bulks)
        avg_rate = avg_bytes / avg_pkts if avg_pkts > 0 else 0.0
        return avg_bytes, avg_pkts, avg_rate

    @staticmethod
    def _active_idle_stats(ts: List[float]) -> Tuple[float, float, float, float, float, float, float, float]:
        """
        Active/Idle 统计
        Active: 有包的连续时间段（包间<=5s算同一active段）
        Idle: 包间>5s的间隔
        返回 (active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min)
        """
        if len(ts) < 2:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        active_durations = []
        idle_durations = []
        seg_start = ts[0]
        for i in range(1, len(ts)):
            gap = ts[i] - ts[i - 1]
            if gap > 5.0:
                # 结束一个 active 段
                active_durations.append(ts[i - 1] - seg_start)
                idle_durations.append(gap)
                seg_start = ts[i]
        active_durations.append(ts[-1] - seg_start)

        a_mean, a_std, a_max, a_min = _stats([d * 1e6 for d in active_durations if d > 0])
        i_mean, i_std, i_max, i_min = _stats([d * 1e6 for d in idle_durations])
        return a_mean, a_std, a_max, a_min, i_mean, i_std, i_max, i_min
