"""
共享规则检测模块

将 analyze_packets._detect_anomalies 与 analyze_stream 内联规则检测
提取为共享的 RuleDetector，消除双路径维护不一致风险。

历史背景：
- v1.0: analyze_packets 实现完整 11 条规则
- v2.0: analyze_stream 为支持 GB 级 PCAP 新增流式实现，但只移植了 5 条 TCP 规则
- v3.4.3: 把 UDP/QUIC 6 条规则复制到 analyze_stream，导致两份相同逻辑
- 本模块：提取共享 RuleDetector，两条路径共用同一份规则代码

设计原则：
- RuleDetector 是纯函数式：输入累加器状态 + 阈值，输出 alerts 列表
- 不持有任何状态，不依赖 TrafficAnalyzer 的实例变量
- 时间窗统一使用 [first_ts, last_ts] 格式，调用方负责转换
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict


@dataclass
class RuleAccumulatorState:
    """规则检测所需的累加器状态（两条路径共用）。

    所有时间戳字段统一为 [first_ts, last_ts] 格式，空列表表示无数据。
    flows 字段使用流式字典格式：key=(protocol, lo_ep, hi_ep), value=流信息dict。
    """
    # TCP 规则
    syn_sent: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    synack_recv: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    syn_ts: Dict[str, list] = field(default_factory=dict)
    ports_by_src: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    port_ts: Dict[str, list] = field(default_factory=dict)
    dns_long: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_ts: Dict[str, list] = field(default_factory=dict)
    rst: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    rst_ts: Dict[str, list] = field(default_factory=dict)
    flows: Dict[tuple, dict] = field(default_factory=dict)

    # UDP / DNS 放大
    udp_by_dst: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    udp_ts: Dict[str, list] = field(default_factory=dict)
    dns_req_bytes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_resp_bytes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_resp_count: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_resp_ts: Dict[str, list] = field(default_factory=dict)

    # QUIC
    quic_src_ports: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    quic_src_ts: Dict[str, list] = field(default_factory=dict)
    quic_flows: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    quic_flow_ts: Dict[str, list] = field(default_factory=dict)
    quic_large: int = 0
    quic_total: int = 0
    quic_all_ts: list = field(default_factory=list)
    quic_unknown_versions: Set[str] = field(default_factory=set)


def _tw(ts_list: list) -> str:
    """将 [first, last] 时间戳格式化为时间窗字符串。"""
    if not ts_list or len(ts_list) < 2:
        return ""
    return f"{ts_list[0]} ~ {ts_list[1]}"


class RuleDetector:
    """共享规则检测器：11 条阈值规则，输入累加器状态，输出 alerts。

    RULE_NAMES 为全部 11 条规则的 detector 标识，统一使用 rule-based- 前缀。
    detect() 中所有告警的 detector 字段均通过 RULE_NAMES 引用，禁止硬编码。
    """

    # 全部 11 条规则的 detector 标识（统一 rule-based- 前缀）
    RULE_NAMES = {
        "SYN_FLOOD_SUSPECTED": "rule-based-syn-flood",
        "PORT_SCAN_SUSPECTED": "rule-based-port-scan",
        "DNS_TUNNEL_SUSPECTED": "rule-based-dns-tunnel",
        "LARGE_DATA_TRANSFER": "rule-based-large-transfer",
        "RST_STORM": "rule-based-rst-storm",
        "UDP_FLOOD_SUSPECTED": "rule-based-udp-flood",
        "DNS_AMPLIFICATION_SUSPECTED": "rule-based-dns-amplification",
        "QUIC_CONNECTION_FLOOD": "rule-based-quic-connection-flood",
        "QUIC_LONG_FLOW_ANOMALY": "rule-based-quic-long-flow",
        "QUIC_INITIAL_RATIO_ANOMALY": "rule-based-quic-initial-ratio",
        "QUIC_UNKNOWN_VERSION": "rule-based-quic-version",
    }

    def __init__(self, thresholds: Dict[str, Any]):
        """
        :param thresholds: 规则阈值字典，来自 settings（与 TrafficAnalyzer._t 同结构）
        """
        self._t = thresholds

    def detect(self, state: RuleAccumulatorState) -> List[Dict[str, Any]]:
        """执行全部 11 条规则检测，返回 alerts 列表。

        :param state: 累加器状态
        :return: 告警列表，每条告警含 type/severity/detector/time_window/rule_threshold/description 等字段
        """
        alerts = []
        t = self._t

        # 规则 1: SYN Flood（状态化握手校验）
        for src, count in state.syn_sent.items():
            net = count - state.synack_recv.get(src, 0)
            if net >= t["syn_flood_min_count"]:
                alerts.append({
                    "type": "SYN_FLOOD_SUSPECTED",
                    "severity": "HIGH" if net > t["syn_flood_high_count"] else "MEDIUM",
                    "src_ip": src,
                    "syn_count": count,
                    "syn_ack_received": state.synack_recv.get(src, 0),
                    "unanswered_syn": net,
                    "detector": self.RULE_NAMES["SYN_FLOOD_SUSPECTED"],
                    "rule_threshold": {"syn_flood_min_count": t["syn_flood_min_count"]},
                    "time_window": _tw(state.syn_ts.get(src, [])),
                    "description": f"源IP {src} 发出 {count} 个SYN，仅收到 {state.synack_recv.get(src, 0)} 个SYN-ACK，"
                                   f"未完成握手 {net} 个，疑似SYN洪水攻击",
                })

        # 规则 2: 端口扫描（方向化）
        for src, ports in state.ports_by_src.items():
            if len(ports) >= t["port_scan_min_ports"]:
                alerts.append({
                    "type": "PORT_SCAN_SUSPECTED",
                    "severity": "HIGH" if len(ports) > t["port_scan_high_ports"] else "MEDIUM",
                    "src_ip": src,
                    "unique_ports_scanned": len(ports),
                    "sample_ports": sorted(list(ports))[:20],
                    "detector": self.RULE_NAMES["PORT_SCAN_SUSPECTED"],
                    "rule_threshold": {"port_scan_min_ports": t["port_scan_min_ports"]},
                    "time_window": _tw(state.port_ts.get(src, [])),
                    "description": f"源IP {src} 访问了 {len(ports)} 个不同端口，疑似端口扫描",
                })

        # 规则 3: DNS 隧道
        for src, count in state.dns_long.items():
            if count >= t["dns_tunnel_min_count"]:
                alerts.append({
                    "type": "DNS_TUNNEL_SUSPECTED",
                    "severity": "HIGH" if count > t["dns_tunnel_high_count"] else "MEDIUM",
                    "src_ip": src,
                    "suspicious_query_count": count,
                    "detector": self.RULE_NAMES["DNS_TUNNEL_SUSPECTED"],
                    "rule_threshold": {"dns_tunnel_max_query_len": t["dns_tunnel_max_query_len"]},
                    "time_window": _tw(state.dns_ts.get(src, [])),
                    "description": f"源IP {src} 发送了 {count} 个超长DNS查询（>{t['dns_tunnel_max_query_len']}字符），疑似DNS隧道",
                })

        # 规则 4: 大流量传输（用主导方向）
        for f in state.flows.values():
            if f["bytes"] > t["large_flow_min_mb"] * 1024 * 1024:
                _ds, _dsp, _dd, _ddp = self._dom_direction(f)
                alerts.append({
                    "type": "LARGE_DATA_TRANSFER",
                    "severity": "MEDIUM",
                    "src_ip": _ds, "dst_ip": _dd,
                    "src_port": _dsp, "dst_port": _ddp,
                    "bytes_transferred": f["bytes"],
                    "detector": self.RULE_NAMES["LARGE_DATA_TRANSFER"],
                    "rule_threshold": {"large_flow_min_mb": t["large_flow_min_mb"]},
                    "time_window": f"{f['first']} ~ {f['last']}",
                    "description": f"流 {_ds}:{_dsp} -> {_dd}:{_ddp} "
                                   f"传输了 {f['bytes']/1024/1024:.1f}MB 数据，需关注是否为数据渗出",
                })

        # 规则 5: RST 风暴
        for src, count in state.rst.items():
            if count >= t["rst_storm_min_count"]:
                alerts.append({
                    "type": "RST_STORM",
                    "severity": "LOW",
                    "src_ip": src,
                    "rst_count": count,
                    "detector": self.RULE_NAMES["RST_STORM"],
                    "rule_threshold": {"rst_storm_min_count": t["rst_storm_min_count"]},
                    "time_window": _tw(state.rst_ts.get(src, [])),
                    "description": f"源IP {src} 发送了 {count} 个RST包，可能是扫描或异常连接",
                })

        # 规则 6: UDP Flood
        for dst, count in state.udp_by_dst.items():
            if count >= t["udp_flood_min_packets"]:
                alerts.append({
                    "type": "UDP_FLOOD_SUSPECTED",
                    "severity": "HIGH" if count > t["udp_flood_high_packets"] else "MEDIUM",
                    "dst_ip": dst,
                    "udp_packet_count": count,
                    "detector": self.RULE_NAMES["UDP_FLOOD_SUSPECTED"],
                    "rule_threshold": {"udp_flood_min_packets": t["udp_flood_min_packets"]},
                    "time_window": _tw(state.udp_ts.get(dst, [])),
                    "description": f"目标IP {dst} 收到 {count} 个UDP包，疑似UDP洪水攻击",
                })

        # 规则 7: DNS 放大（响应优先判断）
        for target, resp_bytes in state.dns_resp_bytes.items():
            req_bytes = state.dns_req_bytes.get(target, 1)
            ratio = resp_bytes / req_bytes if req_bytes > 0 else float(resp_bytes)
            if (ratio >= t["dns_amp_min_ratio"]
                    and state.dns_resp_count[target] >= t["dns_amp_min_responses"]):
                alerts.append({
                    "type": "DNS_AMPLIFICATION_SUSPECTED",
                    "severity": "HIGH",
                    "target_ip": target,
                    "amplification_ratio": round(ratio, 2),
                    "response_bytes": resp_bytes,
                    "request_bytes": req_bytes,
                    "response_count": state.dns_resp_count[target],
                    "detector": self.RULE_NAMES["DNS_AMPLIFICATION_SUSPECTED"],
                    "rule_threshold": {"dns_amp_min_ratio": t["dns_amp_min_ratio"]},
                    "time_window": _tw(state.dns_resp_ts.get(target, [])),
                    "description": f"目标IP {target} DNS响应/请求字节比={ratio:.1f}x，"
                                   f"响应{state.dns_resp_count[target]}个包，疑似DNS放大攻击",
                })

        # 规则 8: QUIC/HTTP3 异常（4 条子规则）
        if state.quic_total > 0:
            # 8a. QUIC 连接风暴
            for src, ports in state.quic_src_ports.items():
                if len(ports) >= t["quic_flood_min_connections"]:
                    alerts.append({
                        "type": "QUIC_CONNECTION_FLOOD",
                        "severity": "HIGH",
                        "src_ip": src,
                        "unique_quic_connections": len(ports),
                        "detector": self.RULE_NAMES["QUIC_CONNECTION_FLOOD"],
                        "rule_threshold": {"quic_flood_min_connections": t["quic_flood_min_connections"]},
                        "time_window": _tw(state.quic_src_ts.get(src, [])),
                        "description": f"源IP {src} 发起 {len(ports)} 条不同QUIC连接（源端口），"
                                       f"疑似QUIC连接洪水",
                    })

            # 8b. QUIC 长流异常
            for flow_key, count in state.quic_flows.items():
                if count >= t["quic_long_flow_min_packets"]:
                    alerts.append({
                        "type": "QUIC_LONG_FLOW_ANOMALY",
                        "severity": "MEDIUM",
                        "flow": flow_key,
                        "packet_count": count,
                        "detector": self.RULE_NAMES["QUIC_LONG_FLOW_ANOMALY"],
                        "rule_threshold": {"quic_long_flow_min_packets": t["quic_long_flow_min_packets"]},
                        "time_window": _tw(state.quic_flow_ts.get(flow_key, [])),
                        "description": f"QUIC流 {flow_key} 持续 {count} 个包，"
                                       f"疑似加密隧道或数据外泄",
                    })

            # 8c. QUIC 初始包比例异常
            quic_initial_ratio = state.quic_large / state.quic_total if state.quic_total else 0
            if quic_initial_ratio >= t["quic_initial_ratio_threshold"]:
                alerts.append({
                    "type": "QUIC_INITIAL_RATIO_ANOMALY",
                    "severity": "MEDIUM",
                    "large_packet_ratio": round(quic_initial_ratio, 3),
                    "total_quic_packets": state.quic_total,
                    "large_packet_count": state.quic_large,
                    "detector": self.RULE_NAMES["QUIC_INITIAL_RATIO_ANOMALY"],
                    "rule_threshold": {"quic_initial_ratio_threshold": t["quic_initial_ratio_threshold"]},
                    "time_window": _tw(state.quic_all_ts),
                    "description": f"QUIC大包（疑似初始包）占比={quic_initial_ratio:.1%}，"
                                   f"正常应<5%，疑似QUIC隧道或异常握手",
                })

            # 8d. QUIC 未知版本
            if state.quic_unknown_versions:
                alerts.append({
                    "type": "QUIC_UNKNOWN_VERSION",
                    "severity": "LOW",
                    "unknown_versions": sorted(state.quic_unknown_versions),
                    "detector": self.RULE_NAMES["QUIC_UNKNOWN_VERSION"],
                    "description": f"检测到未知QUIC版本号: {', '.join(sorted(state.quic_unknown_versions))}，"
                                   f"可能是实验性协议或异常客户端",
                })

        return alerts

    @staticmethod
    def _dom_direction(f: dict) -> Tuple[str, int, str, int]:
        """获取流的主导方向（按真实包统计的包数最多者）。

        与 analyze_stream._dom 和 _detect_anomalies 的方向修复逻辑一致。
        """
        dirs = f.get("dirs") or {}
        if not dirs:
            return f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"]
        dom = max(dirs.items(), key=lambda kv: (kv[1]["count"], kv[0]))[0]
        return dom
