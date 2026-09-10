"""
网络流提取与统计分析模块
从数据包列表中提取网络流、计算统计特征、生成分析报告
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from loguru import logger
from typing import Optional
from config.settings import settings
from src.analysis.baseline import TrafficBaseline, WindowAccumulator
from ..capture.packet_parser import PacketInfo


@dataclass
class NetworkFlow:
    """网络流数据结构（按五元组聚合）"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int = 0
    total_bytes: int = 0
    start_time: str = ""
    end_time: str = ""
    flag_counts: Dict[str, int] = field(default_factory=dict)
    payload_bytes: int = 0
    duration_seconds: float = 0.0


class FlowExtractor:
    """
    网络流提取器
    将离散的数据包聚合为网络流，并计算统计特征
    """

    def __init__(self, flow_timeout: int = 60):
        """
        :param flow_timeout: 流超时时间（秒），超过此时间无数据包则认为流结束
        """
        self.flow_timeout = flow_timeout
        self.flows: Dict[str, NetworkFlow] = {}
        logger.info(f"流提取器初始化 | 流超时: {flow_timeout}s")

    def extract_flows(self, packets: List[PacketInfo]) -> List[NetworkFlow]:
        """
        从数据包列表提取网络流
        :param packets: 数据包列表
        :return: 网络流列表
        """
        self.flows = {}
        active_flows: Dict[str, List[PacketInfo]] = defaultdict(list)

        for pkt in packets:
            if not pkt.src_ip or not pkt.dst_ip:
                continue
            if pkt.protocol not in ("TCP", "UDP"):
                continue

            # 规范化流标识（双向流合并）
            ep1 = f"{pkt.src_ip}:{pkt.src_port}"
            ep2 = f"{pkt.dst_ip}:{pkt.dst_port}"
            flow_key = f"{pkt.protocol}|" + " <-> ".join(sorted([ep1, ep2]))

            active_flows[flow_key].append(pkt)

        # 转换为NetworkFlow对象
        for flow_key, pkts in active_flows.items():
            protocol = flow_key.split("|")[0]
            endpoints = flow_key.split("|")[1].split(" <-> ")
            src_ep = endpoints[0].split(":")
            dst_ep = endpoints[1].split(":")

            flow = NetworkFlow(
                src_ip=src_ep[0],
                src_port=int(src_ep[1]),
                dst_ip=dst_ep[0],
                dst_port=int(dst_ep[1]),
                protocol=protocol,
                packet_count=len(pkts),
                total_bytes=sum(p.length for p in pkts),
                start_time=pkts[0].timestamp,
                end_time=pkts[-1].timestamp,
                payload_bytes=sum(p.payload_size for p in pkts),
            )

            # 统计标志位
            for p in pkts:
                if p.flags:
                    for flag in p.flags.split(","):
                        flow.flag_counts[flag] = flow.flag_counts.get(flag, 0) + 1

            self.flows[flow_key] = flow

        logger.info(f"流提取完成 | {len(packets)} 个包 → {len(self.flows)} 条流")
        return list(self.flows.values())

    def get_top_flows_by_bytes(self, top_n: int = 10) -> List[NetworkFlow]:
        """按流量字节数排序的TOP流"""
        return sorted(self.flows.values(), key=lambda f: f.total_bytes, reverse=True)[:top_n]

    def get_top_flows_by_packets(self, top_n: int = 10) -> List[NetworkFlow]:
        """按包数量排序的TOP流"""
        return sorted(self.flows.values(), key=lambda f: f.packet_count, reverse=True)[:top_n]

    def get_flows_by_protocol(self, protocol: str) -> List[NetworkFlow]:
        """按协议过滤流"""
        return [f for f in self.flows.values() if f.protocol.upper() == protocol.upper()]

    def get_flows_by_ip(self, ip: str) -> List[NetworkFlow]:
        """按IP过滤流（源或目的）"""
        return [f for f in self.flows.values() if f.src_ip == ip or f.dst_ip == ip]

    def get_flows_by_port(self, port: int) -> List[NetworkFlow]:
        """按端口过滤流"""
        return [f for f in self.flows.values() if f.src_port == port or f.dst_port == port]

    def to_records(self) -> List[Dict[str, Any]]:
        """转换为记录列表（替代pandas DataFrame，纯Python实现）"""
        data = []
        for flow in self.flows.values():
            data.append({
                "src_ip": flow.src_ip,
                "src_port": flow.src_port,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "packet_count": flow.packet_count,
                "total_bytes": flow.total_bytes,
                "payload_bytes": flow.payload_bytes,
                "start_time": flow.start_time,
                "end_time": flow.end_time,
                "syn_count": flow.flag_counts.get("SYN", 0),
                "ack_count": flow.flag_counts.get("ACK", 0),
                "fin_count": flow.flag_counts.get("FIN", 0),
                "rst_count": flow.flag_counts.get("RST", 0),
            })
        return data

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """转换为字典列表"""
        return [
            {
                "src_ip": f.src_ip,
                "src_port": f.src_port,
                "dst_ip": f.dst_ip,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "packet_count": f.packet_count,
                "total_bytes": f.total_bytes,
                "payload_bytes": f.payload_bytes,
                "start_time": f.start_time,
                "end_time": f.end_time,
                "flag_counts": f.flag_counts,
            }
            for f in self.flows.values()
        ]

    def generate_flow_stats(self) -> Dict[str, Any]:
        """生成流统计报告（纯Python实现，无需pandas）"""
        if not self.flows:
            return {"error": "no flows extracted"}

        flows_list = list(self.flows.values())
        records = self.to_records()

        # 协议分布
        protocol_counter = Counter(r["protocol"] for r in records)
        protocol_distribution = dict(protocol_counter.most_common())

        # 基础统计
        packet_counts = [f.packet_count for f in flows_list]
        byte_counts = [f.total_bytes for f in flows_list]
        src_ips = set(f.src_ip for f in flows_list)
        dst_ips = set(f.dst_ip for f in flows_list)
        src_ports = set(f.src_port for f in flows_list)
        dst_ports = set(f.dst_port for f in flows_list)

        # TOP5目的端口
        dst_port_counter = Counter(f.dst_port for f in flows_list)
        top_5_ports = dict(dst_port_counter.most_common(5))

        return {
            "total_flows": len(flows_list),
            "total_packets": sum(packet_counts),
            "total_bytes": sum(byte_counts),
            "total_payload_bytes": sum(f.payload_bytes for f in flows_list),
            "protocol_distribution": protocol_distribution,
            "avg_packets_per_flow": round(sum(packet_counts) / len(packet_counts), 2),
            "avg_bytes_per_flow": round(sum(byte_counts) / len(byte_counts), 2),
            "max_flow_bytes": max(byte_counts),
            "max_flow_packets": max(packet_counts),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "unique_src_ports": len(src_ports),
            "unique_dst_ports": len(dst_ports),
            "top_5_ports": top_5_ports,
        }


class TrafficAnalyzer:
    """
    综合流量分析器
    整合流提取、规则异常检测、EWMA时序基线检测、统计分析
    """

    # 规则元信息（证据链标注用）
    RULE_NAMES = {
        "SYN_FLOOD_SUSPECTED": "syn-flood-rate",
        "PORT_SCAN_SUSPECTED": "port-scan-distinct-ports",
        "DNS_TUNNEL_SUSPECTED": "dns-tunnel-query-length",
        "LARGE_DATA_TRANSFER": "large-flow-bytes",
        "RST_STORM": "rst-storm-rate",
        "BASELINE_DEVIATION": "ewma-statistical-baseline",
    }

    def __init__(self, use_baseline: bool = True, use_ml: Optional[bool] = None):
        self.flow_extractor = FlowExtractor()
        # L2：孤立森林无监督第三轨（默认随 settings.ml_engine_enabled）
        self.use_ml = settings.ml_engine_enabled if use_ml is None else use_ml
        self.isolation_detector = None
        # 规则阈值全部来自 settings（可 .env 覆盖），不再硬编码
        self._t = {
            "syn_flood_min_count": settings.syn_flood_min_count,
            "syn_flood_high_count": settings.syn_flood_high_count,
            "port_scan_min_ports": settings.port_scan_min_ports,
            "port_scan_high_ports": settings.port_scan_high_ports,
            "dns_tunnel_max_query_len": settings.dns_tunnel_max_query_len,
            "dns_tunnel_min_count": settings.dns_tunnel_min_count,
            "dns_tunnel_high_count": settings.dns_tunnel_high_count,
            "large_flow_min_mb": settings.large_flow_min_mb,
            "rst_storm_min_count": settings.rst_storm_min_count,
        }
        # EWMA 时序基线（学习-检测两阶段）
        self.baseline: Optional[TrafficBaseline] = None
        self.use_baseline = use_baseline
        self.baseline_drift: Optional[Dict[str, Any]] = None
        logger.info("综合流量分析器初始化完成（规则阈值参数化）")

    def learn_baseline(self, packets: List[PacketInfo]) -> bool:
        """学习正常流量基线画像（供检测阶段对照）；启用 ML 时同步训练孤立森林（同窗口输入）"""
        if not self.use_baseline:
            return False
        self.baseline = TrafficBaseline()
        self.baseline.learn(packets)
        if self.use_ml:
            from src.analysis.isolation_detector import IsolationDetector
            self.isolation_detector = IsolationDetector()
            try:
                windows = self.baseline._aggregate_windows(packets)
                if len(windows) >= 10:
                    self.isolation_detector.learn_windows(windows)
                else:
                    logger.warning(f"ML 学习窗口不足（{len(windows)}），跳过 ML 模型训练")
            except Exception as e:
                logger.warning(f"ML 模型训练失败（不影响基线）: {e}")
                self.isolation_detector = None
        return self.baseline.learned

    def analyze_packets(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """
        完整分析数据包列表
        :return: 包含流统计、协议分布、异常检测的完整报告
        """
        logger.info(f"开始综合流量分析 | 共 {len(packets)} 个包")

        # 1. 流提取
        flows = self.flow_extractor.extract_flows(packets)
        flow_stats = self.flow_extractor.generate_flow_stats()

        # 2. 协议分布
        protocol_dist = defaultdict(int)
        for p in packets:
            protocol_dist[p.protocol] += 1
        protocol_dist = dict(sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True))

        # 3. TOP通信对
        top_talkers = self.flow_extractor.get_top_flows_by_bytes(10)
        top_talkers_list = [
            {
                "flow": f"{f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port}",
                "protocol": f.protocol,
                "packets": f.packet_count,
                "bytes": f.total_bytes,
            }
            for f in top_talkers
        ]

        # 4. 规则引擎异常检测 + 时序基线偏差检测
        anomalies = self._detect_anomalies(packets, flows)
        ml_profile = None
        supervised_result = None
        if self.baseline and self.baseline.learned:
            baseline_result = self.baseline.detect(packets)
            anomalies = self._merge_baseline_deviations(anomalies, baseline_result)
            # P1: 基线漂移失效提示（流量画像变化时检测结果可信度降低）
            self.baseline_drift = baseline_result.get("drift")
            # L2: 孤立森林第三轨（同窗口输入，多维耦合异常）
            if self.isolation_detector and self.isolation_detector.learned:
                try:
                    windows = self.baseline._aggregate_windows(packets)
                    ml_result = self.isolation_detector.detect_windows(windows)
                    anomalies = self._merge_ml_anomalies(anomalies, ml_result)
                    ml_profile = self.isolation_detector.to_dict()
                except Exception as e:
                    logger.warning(f"ML 检测失败（不影响主流程）: {e}")

        # L3: 监督学习主引擎（HistGradientBoosting，CIC-UNSW 44万流训练，F1=0.9487）
        try:
            from src.analysis.supervised_detector import SupervisedDetector
            if not hasattr(self, '_supervised_detector') or self._supervised_detector is None:
                self._supervised_detector = SupervisedDetector()
                self._supervised_detector.load()
            if self._supervised_detector.loaded:
                supervised_result = self._supervised_detector.detect(packets)
        except Exception as e:
            logger.warning(f"监督模型检测失败（不影响主流程）: {e}")

        # P0-2 B: 自适应阈值（基于输入流量分位数动态调整）
        adaptive_thresholds = None
        try:
            from src.analysis.supervised_detector import SupervisedDetector as _SD
            adaptive_thresholds = _SD.adaptive_thresholds(packets)
        except Exception as e:
            logger.warning(f"自适应阈值计算失败: {e}")

        # P0-2 C: 多模型集成投票（监督+规则+基线+孤立森林）
        ensemble_result = None
        try:
            from src.analysis.supervised_detector import SupervisedDetector as _SD2
            baseline_det = None
            if self.baseline and self.baseline.learned:
                baseline_det = {"detected": anomalies.get("total_alerts", 0) > 0}
            iso_det = None
            if ml_profile and ml_profile.get("learned"):
                iso_det = {"anomaly_windows": ml_profile.get("anomaly_windows", 0)}
            ensemble_result = _SD2.ensemble_vote(
                supervised_result or {},
                anomalies.get("alerts", []),
                baseline_det,
                iso_det,
            )
        except Exception as e:
            logger.warning(f"多模型集成失败: {e}")

        report = {
            "summary": {
                "total_packets": len(packets),
                "total_flows": len(flows),
                "time_range": {
                    "start": packets[0].timestamp if packets else "",
                    "end": packets[-1].timestamp if packets else "",
                },
                "total_bytes": sum(p.length for p in packets),
            },
            "flow_stats": flow_stats,
            "protocol_distribution": protocol_dist,
            "top_talkers": top_talkers_list,
            "anomaly_detection": anomalies,
            "baseline_profile": self.baseline.to_dict() if self.baseline else None,
            "baseline_drift": self.baseline_drift,
            "ml_profile": ml_profile,
            "supervised_detection": supervised_result,
            "ensemble_detection": ensemble_result,
            "adaptive_thresholds": adaptive_thresholds,
        }

        logger.info(f"综合流量分析完成 | 发现 {len(anomalies.get('alerts', []))} 条异常告警")
        return report

    def analyze_stream(self, packet_iter, use_baseline: bool = True,
                       sample_count: int = 0) -> Dict[str, Any]:
        """
        流式综合分析（内存 O(活跃流数 + 窗口数)，支持 GB 级 PCAP，不持有原始包列表）。
        - 规则累加器与 _detect_anomalies 同阈值、同告警字段（证据链完整）
        - 基线经 WindowAccumulator 增量窗口聚合后走 detect_windows（含滚动更新/漂移）
        - 报告结构与 analyze_packets 一致，可作为大文件入口
        """
        from src.analysis.baseline import WindowAccumulator as _WA
        t = self._t
        # ---------- 流式规则累加器（只存计数与首末时间戳，不缓存原始包） ----------
        syn_sent = defaultdict(int)
        synack_recv = defaultdict(int)
        syn_ts = defaultdict(list)          # [first, last]
        ports_by_src = defaultdict(set)
        port_ts = defaultdict(list)
        dns_long = defaultdict(int)
        dns_ts = defaultdict(list)
        rst = defaultdict(int)
        rst_ts = defaultdict(list)
        flows: Dict[tuple, Dict[str, Any]] = {}
        protocol_dist = defaultdict(int)
        total_bytes = 0
        n = 0
        first_ts = last_ts = ""
        samples: List[Any] = []

        win_acc = None
        if use_baseline and self.baseline and self.baseline.learned:
            win_acc = _WA(window_sec=self.baseline.window_sec)

        def _push(ts_map, key, ts):
            if not ts_map.get(key):
                ts_map[key] = [ts, ts]
            else:
                ts_map[key][1] = ts

        for p in packet_iter:
            n += 1
            total_bytes += int(p.length)
            protocol_dist[p.protocol] += 1
            if not first_ts:
                first_ts = p.timestamp
            last_ts = p.timestamp
            if sample_count and len(samples) < sample_count:
                samples.append(p)

            # SYN Flood（状态化）
            if p.protocol == "TCP" and "SYN" in p.flags:
                if "ACK" in p.flags:
                    synack_recv[p.dst_ip] += 1
                else:
                    syn_sent[p.src_ip] += 1
                    _push(syn_ts, p.src_ip, p.timestamp)
            # 端口扫描（方向化）
            if (p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags
                    and p.src_ip and p.dst_port > 0):
                ports_by_src[p.src_ip].add(p.dst_port)
                _push(port_ts, p.src_ip, p.timestamp)
            # DNS 隧道
            if p.protocol == "DNS" and p.dns_query:
                q = p.dns_query.rstrip('.')
                if len(q) > t["dns_tunnel_max_query_len"]:
                    dns_long[p.src_ip] += 1
                    _push(dns_ts, p.src_ip, p.timestamp)
            # RST 风暴
            if p.protocol == "TCP" and "RST" in p.flags:
                rst[p.src_ip] += 1
                _push(rst_ts, p.src_ip, p.timestamp)
            # 流聚合（大流量检测，双向流规范化，与 FlowExtractor 同口径）
            if p.protocol in ("TCP", "UDP") and p.src_ip and p.dst_ip:
                ep1 = f"{p.src_ip}:{p.src_port}"
                ep2 = f"{p.dst_ip}:{p.dst_port}"
                lo, hi = sorted([ep1, ep2])
                key = (p.protocol, lo, hi)
                f = flows.get(key)
                if f is None:
                    lip, lport = lo.rsplit(':', 1)
                    hip, hport = hi.rsplit(':', 1)
                    f = {"src_ip": lip, "src_port": int(lport),
                         "dst_ip": hip, "dst_port": int(hport),
                         "protocol": p.protocol, "bytes": 0,
                         "first": p.timestamp, "last": p.timestamp}
                    flows[key] = f
                f["bytes"] += int(p.length)
                f["last"] = p.timestamp
            # 基线窗口增量聚合
            if win_acc is not None:
                win_acc.add(p)

        def _tw(ts_list):
            if not ts_list:
                return ""
            return f"{ts_list[0]} ~ {ts_list[1]}"

        # ---------- 规则告警组装（字段与 _detect_anomalies 完全一致） ----------
        alerts = []
        for src, count in syn_sent.items():
            net = count - synack_recv.get(src, 0)
            if net >= t["syn_flood_min_count"]:
                alerts.append({
                    "type": "SYN_FLOOD_SUSPECTED",
                    "severity": "HIGH" if net > t["syn_flood_high_count"] else "MEDIUM",
                    "src_ip": src, "syn_count": count,
                    "syn_ack_received": synack_recv.get(src, 0),
                    "unanswered_syn": net,
                    "detector": self.RULE_NAMES["SYN_FLOOD_SUSPECTED"],
                    "rule_threshold": {"syn_flood_min_count": t["syn_flood_min_count"]},
                    "time_window": _tw(syn_ts.get(src, [])),
                    "description": f"源IP {src} 发出 {count} 个SYN，仅收到 {synack_recv.get(src, 0)} 个SYN-ACK，"
                                   f"未完成握手 {net} 个，疑似SYN洪水攻击",
                })
        for src, ports in ports_by_src.items():
            if len(ports) >= t["port_scan_min_ports"]:
                alerts.append({
                    "type": "PORT_SCAN_SUSPECTED",
                    "severity": "HIGH" if len(ports) > t["port_scan_high_ports"] else "MEDIUM",
                    "src_ip": src, "unique_ports_scanned": len(ports),
                    "sample_ports": sorted(list(ports))[:20],
                    "detector": self.RULE_NAMES["PORT_SCAN_SUSPECTED"],
                    "rule_threshold": {"port_scan_min_ports": t["port_scan_min_ports"]},
                    "time_window": _tw(port_ts.get(src, [])),
                    "description": f"源IP {src} 访问了 {len(ports)} 个不同端口，疑似端口扫描",
                })
        for src, count in dns_long.items():
            if count >= t["dns_tunnel_min_count"]:
                alerts.append({
                    "type": "DNS_TUNNEL_SUSPECTED",
                    "severity": "HIGH" if count > t["dns_tunnel_high_count"] else "MEDIUM",
                    "src_ip": src, "suspicious_query_count": count,
                    "detector": self.RULE_NAMES["DNS_TUNNEL_SUSPECTED"],
                    "rule_threshold": {"dns_tunnel_max_query_len": t["dns_tunnel_max_query_len"]},
                    "time_window": _tw(dns_ts.get(src, [])),
                    "description": f"源IP {src} 发送了 {count} 个超长DNS查询（>{t['dns_tunnel_max_query_len']}字符），疑似DNS隧道",
                })
        for f in flows.values():
            if f["bytes"] > t["large_flow_min_mb"] * 1024 * 1024:
                alerts.append({
                    "type": "LARGE_DATA_TRANSFER",
                    "severity": "MEDIUM",
                    "src_ip": f["src_ip"], "dst_ip": f["dst_ip"],
                    "bytes_transferred": f["bytes"],
                    "detector": self.RULE_NAMES["LARGE_DATA_TRANSFER"],
                    "rule_threshold": {"large_flow_min_mb": t["large_flow_min_mb"]},
                    "time_window": f"{f['first']} ~ {f['last']}",
                    "description": f"流 {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} "
                                   f"传输了 {f['bytes']/1024/1024:.1f}MB 数据，需关注是否为数据渗出",
                })
        for src, count in rst.items():
            if count >= t["rst_storm_min_count"]:
                alerts.append({
                    "type": "RST_STORM",
                    "severity": "LOW",
                    "src_ip": src, "rst_count": count,
                    "detector": self.RULE_NAMES["RST_STORM"],
                    "rule_threshold": {"rst_storm_min_count": t["rst_storm_min_count"]},
                    "time_window": _tw(rst_ts.get(src, [])),
                    "description": f"源IP {src} 发送了 {count} 个RST包，可能是扫描或异常连接",
                })

        anomalies = {
            "total_alerts": len(alerts),
            "alerts": self._sort_alerts(alerts),
            "severity_summary": {
                "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in alerts if a["severity"] == "LOW"),
            },
        }

        # ---------- 基线偏差（增量窗口） ----------
        baseline_profile = None
        baseline_drift = None
        ml_profile = None
        window_series = None
        if win_acc is not None:
            windows = win_acc.get_windows()
            # 窗口序列（供 UI 绘制 流量 vs 基线 对比图；仅包数与字节数两个轻量维度）
            window_series = [{"packets": int(w["window_packets"]),
                              "bytes": int(w["window_bytes"])} for w in windows]
            bres = self.baseline.detect_windows(windows)
            anomalies = self._merge_baseline_deviations(anomalies, bres)
            self.baseline_drift = bres.get("drift")
            baseline_drift = self.baseline_drift
            baseline_profile = self.baseline.to_dict()
            # L2: 孤立森林第三轨（同一窗口序列）
            if self.isolation_detector and self.isolation_detector.learned:
                try:
                    mlres = self.isolation_detector.detect_windows(windows)
                    anomalies = self._merge_ml_anomalies(anomalies, mlres)
                    ml_profile = self.isolation_detector.to_dict()
                except Exception as e:
                    logger.warning(f"ML 流式检测失败（不影响主流程）: {e}")

        # 流统计摘要（轻量：只出 top 数量与字节，不再全量 flow_stats）
        top_flows = sorted(flows.values(), key=lambda x: x["bytes"], reverse=True)[:10]
        report = {
            "summary": {
                "total_packets": n,
                "total_flows": len(flows),
                "time_range": {"start": first_ts, "end": last_ts},
                "total_bytes": total_bytes,
            },
            "flow_stats": {
                "total_flows": len(flows),
                "top_flows": [
                    {"flow": f"{x['src_ip']}:{x['src_port']} -> {x['dst_ip']}:{x['dst_port']}",
                     "protocol": x["protocol"], "packets": 0, "bytes": x["bytes"]}
                    for x in top_flows
                ],
            },
            "protocol_distribution": dict(sorted(protocol_dist.items(),
                                                 key=lambda x: x[1], reverse=True)),
            "top_talkers": [
                {"flow": f"{x['src_ip']}:{x['src_port']} -> {x['dst_ip']}:{x['dst_port']}",
                 "protocol": x["protocol"], "packets": 0, "bytes": x["bytes"]}
                for x in top_flows
            ],
            "anomaly_detection": anomalies,
            "window_series": window_series,
            "baseline_profile": baseline_profile,
            "baseline_drift": baseline_drift,
            "ml_profile": ml_profile,
            "streaming": True,
        }
        if samples:
            report["_samples"] = samples
        logger.info(f"流式分析完成 | {n} 包 | 发现 {len(alerts)} 条异常告警")
        return report

    def _merge_baseline_deviations(self, anomalies: Dict[str, Any], baseline_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        将时序基线偏差合并进告警列表（每维度最多保留 top 3 窗口，防止告警爆炸）
        """
        deviations = baseline_result.get("deviations", [])
        if not deviations:
            return anomalies

        alerts = anomalies["alerts"]
        added = 0
        # 按维度分组，每组按 z_score 降序取前 3
        by_dim: Dict[str, List] = defaultdict(list)
        for d in deviations:
            by_dim[d["dimension"]].append(d)

        dim_labels = {
            "window_packets": "窗口包数",
            "window_bytes": "窗口字节数",
            "window_syn": "窗口SYN数",
            "window_dports": "窗口目的端口数",
        }
        for dim, devs in by_dim.items():
            for d in sorted(devs, key=lambda x: x["z_score"], reverse=True)[:3]:
                alerts.append({
                    "type": "BASELINE_DEVIATION",
                    "severity": d["severity"],
                    "src_ip": "",
                    "dimension": dim,
                    "dimension_label": dim_labels.get(dim, dim),
                    "value": d["value"],
                    "baseline_median": d["baseline_median"],
                    "z_score": d["z_score"],
                    "window_index": d["window_index"],
                    "detector": self.RULE_NAMES["BASELINE_DEVIATION"],
                    "description": (f"时序基线偏差：{dim_labels.get(dim, dim)}={d['value']}，"
                                    f"基线中位数={d['baseline_median']}，z-score={d['z_score']}（阈值 {self.baseline.sigma}σ）"),
                })
                added += 1

        # P1-6: 合并多维度联合告警（一个窗口多维度同时偏差，严重度提升）
        multi_alerts = baseline_result.get("multi_dim_alerts", [])
        for ma in multi_alerts:
            alerts.append({
                "type": "BASELINE_MULTI_DIM",
                "severity": ma["severity"],
                "src_ip": "",
                "window_index": ma["window_index"],
                "dimensions": ma["dimensions"],
                "dimension_count": ma["dimension_count"],
                "max_z_score": ma["max_z_score"],
                "detector": self.RULE_NAMES["BASELINE_DEVIATION"],
                "description": ma["description"],
            })
            added += 1

        anomalies["alerts"] = self._sort_alerts(alerts)
        anomalies["total_alerts"] = len(alerts)
        for sev in anomalies["severity_summary"]:
            anomalies["severity_summary"][sev] = sum(1 for a in alerts if a["severity"] == sev)
        anomalies["baseline_deviations_added"] = added
        anomalies["baseline_multi_dim_alerts"] = len(multi_alerts)
        return anomalies

    def _merge_ml_anomalies(self, anomalies: Dict[str, Any],
                              ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """将孤立森林异常窗口合并进告警列表（最多 5 条，按异常分取最异常）"""
        anoms = ml_result.get("anomalies", [])
        if not anoms:
            return anomalies
        alerts = anomalies["alerts"]
        added = 0
        for d in sorted(anoms, key=lambda x: x["anomaly_score"])[:5]:
            alerts.append({
                "type": "ML_ANOMALY",
                "severity": d["severity"],
                "src_ip": "",
                "dimension": d["dimension"],
                "anomaly_score": d["anomaly_score"],
                "score_threshold": d["score_threshold"],
                "window_index": d["window_index"],
                "detector": "isolation-forest-unsupervised",
                "description": (f"机器学习异常检测：窗口{d['dimension']}异常，"
                                f"异常分={d['anomaly_score']}（阈值 {d['score_threshold']}），"
                                f"孤立森林对多维窗口特征联合建模捕获耦合异常"),
            })
            added += 1
        anomalies["alerts"] = self._sort_alerts(alerts)
        anomalies["total_alerts"] = len(alerts)
        for sev in anomalies["severity_summary"]:
            anomalies["severity_summary"][sev] = sum(1 for a in alerts if a["severity"] == sev)
        anomalies["ml_anomalies_added"] = added
        return anomalies

    @staticmethod
    def _sort_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按严重级别排序"""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(alerts, key=lambda x: order.get(x.get("severity"), 4))

    def _detect_anomalies(self, packets: List[PacketInfo], flows: List[NetworkFlow]) -> Dict[str, Any]:
        """
        基于规则的异常检测（阈值全部参数化，支持 .env 覆盖）
        检测：SYN flood、端口扫描、DNS隧道、异常大流量、RST风暴
        告警结构含证据链字段：detector / time_window / rule_threshold
        """
        t = self._t
        alerts = []

        def _time_window(pkts):
            if not pkts:
                return ""
            return f"{pkts[0].timestamp} ~ {pkts[-1].timestamp}"

        # 1. SYN Flood检测（状态化握手校验）
        # 特征：发出的SYN 远多于 收到的SYN-ACK（握手无法完成）
        # net_syn = 发出SYN数 - 作为目标收到的SYN-ACK数，避免把正常浏览握手误判
        syn_sent: Dict[str, int] = defaultdict(int)
        synack_recv: Dict[str, int] = defaultdict(int)
        syn_packets: Dict[str, List] = defaultdict(list)
        for p in packets:
            if p.protocol == "TCP" and "SYN" in p.flags:
                if "ACK" in p.flags:
                    # SYN-ACK（响应方向）：其 dst_ip 是发起方
                    synack_recv[p.dst_ip] += 1
                else:
                    syn_sent[p.src_ip] += 1
                    syn_packets[p.src_ip].append(p)

        for src, count in syn_sent.items():
            net_syn = count - synack_recv.get(src, 0)
            if net_syn >= t["syn_flood_min_count"]:
                alerts.append({
                    "type": "SYN_FLOOD_SUSPECTED",
                    "severity": "HIGH" if net_syn > t["syn_flood_high_count"] else "MEDIUM",
                    "src_ip": src,
                    "syn_count": count,
                    "syn_ack_received": synack_recv.get(src, 0),
                    "unanswered_syn": net_syn,
                    "detector": self.RULE_NAMES["SYN_FLOOD_SUSPECTED"],
                    "rule_threshold": {"syn_flood_min_count": t["syn_flood_min_count"]},
                    "time_window": _time_window(syn_packets[src]),
                    "description": f"源IP {src} 发出 {count} 个SYN，仅收到 {synack_recv.get(src, 0)} 个SYN-ACK，"
                                   f"未完成握手 {net_syn} 个，疑似SYN洪水攻击"
                })

        # 2. 端口扫描检测（方向化：只统计发起方向的 SYN 探测）
        # 仅对 TCP SYN（无ACK）探测统计目的端口，响应方向的包（SA/PA等）不计数
        ports_by_src = defaultdict(set)
        port_packets: Dict[str, List] = defaultdict(list)
        for p in packets:
            if p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags and p.src_ip and p.dst_port > 0:
                ports_by_src[p.src_ip].add(p.dst_port)
                port_packets[p.src_ip].append(p)

        for src, ports in ports_by_src.items():
            if len(ports) >= t["port_scan_min_ports"]:
                alerts.append({
                    "type": "PORT_SCAN_SUSPECTED",
                    "severity": "HIGH" if len(ports) > t["port_scan_high_ports"] else "MEDIUM",
                    "src_ip": src,
                    "unique_ports_scanned": len(ports),
                    "sample_ports": sorted(list(ports))[:20],
                    "detector": self.RULE_NAMES["PORT_SCAN_SUSPECTED"],
                    "rule_threshold": {"port_scan_min_ports": t["port_scan_min_ports"]},
                    "time_window": _time_window(port_packets[src]),
                    "description": f"源IP {src} 访问了 {len(ports)} 个不同端口，疑似端口扫描"
                })

        # 3. DNS隧道检测
        dns_long_queries = defaultdict(int)
        dns_packets: Dict[str, List] = defaultdict(list)
        for p in packets:
            if p.protocol == "DNS" and p.dns_query:
                query = p.dns_query.rstrip('.')
                if len(query) > t["dns_tunnel_max_query_len"]:
                    dns_long_queries[p.src_ip] += 1
                    dns_packets[p.src_ip].append(p)

        for src, count in dns_long_queries.items():
            if count >= t["dns_tunnel_min_count"]:
                alerts.append({
                    "type": "DNS_TUNNEL_SUSPECTED",
                    "severity": "HIGH" if count > t["dns_tunnel_high_count"] else "MEDIUM",
                    "src_ip": src,
                    "suspicious_query_count": count,
                    "detector": self.RULE_NAMES["DNS_TUNNEL_SUSPECTED"],
                    "rule_threshold": {"dns_tunnel_max_query_len": t["dns_tunnel_max_query_len"]},
                    "time_window": _time_window(dns_packets[src]),
                    "description": f"源IP {src} 发送了 {count} 个超长DNS查询（>{t['dns_tunnel_max_query_len']}字符），疑似DNS隧道"
                })

        # 4. 异常大流量流检测
        for flow in flows:
            threshold_bytes = t["large_flow_min_mb"] * 1024 * 1024
            if flow.total_bytes > threshold_bytes:
                alerts.append({
                    "type": "LARGE_DATA_TRANSFER",
                    "severity": "MEDIUM",
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "bytes_transferred": flow.total_bytes,
                    "detector": self.RULE_NAMES["LARGE_DATA_TRANSFER"],
                    "rule_threshold": {"large_flow_min_mb": t["large_flow_min_mb"]},
                    "time_window": _time_window([p for p in packets if p.src_ip == flow.src_ip and p.dst_ip == flow.dst_ip][:10]),
                    "description": f"流 {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                                   f"传输了 {flow.total_bytes/1024/1024:.1f}MB 数据，需关注是否为数据渗出"
                })

        # 5. RST风暴检测（可能是端口扫描或拒绝服务）
        rst_by_src = defaultdict(int)
        rst_packets: Dict[str, List] = defaultdict(list)
        for p in packets:
            if p.protocol == "TCP" and "RST" in p.flags:
                rst_by_src[p.src_ip] += 1
                rst_packets[p.src_ip].append(p)

        for src, count in rst_by_src.items():
            if count >= t["rst_storm_min_count"]:
                alerts.append({
                    "type": "RST_STORM",
                    "severity": "LOW",
                    "src_ip": src,
                    "rst_count": count,
                    "detector": self.RULE_NAMES["RST_STORM"],
                    "rule_threshold": {"rst_storm_min_count": t["rst_storm_min_count"]},
                    "time_window": _time_window(rst_packets[src]),
                    "description": f"源IP {src} 发送了 {count} 个RST包，可能是扫描或异常连接"
                })

        return {
            "total_alerts": len(alerts),
            "alerts": self._sort_alerts(alerts),
            "severity_summary": {
                "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in alerts if a["severity"] == "LOW"),
            },
        }
