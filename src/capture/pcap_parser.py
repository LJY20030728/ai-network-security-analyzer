"""
PCAP文件解析模块
支持读取Wireshark导出的PCAP/PCAPNG文件，进行离线分析
"""
import warnings
import logging
# 离线解析不依赖 libpcap 驱动；抑制 "No libpcap provider" 无影响警告（仅实时抓包才需要 Npcap）
warnings.filterwarnings("ignore", message=".*libpcap provider.*")
for _lg in ("scapy", "scapy.runtime", "scapy.loading"):
    logging.getLogger(_lg).setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import json
from loguru import logger
from .packet_parser import PacketInfo, PacketParser


class PcapParser:
    """
    PCAP文件解析器
    可以读取你用Wireshark抓的包文件，进行离线分析
    """

    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.raw_packets = []

    def iter_packets(self, filepath: str):
        """
        流式解析 PCAP/PCAPNG（PcapReader 逐包迭代，内存 O(1)，支持 GB 级大文件）
        :param filepath: 文件路径
        :yield: PacketInfo
        """
        from scapy.utils import PcapReader, PcapNgReader
        parser = PacketParser()
        reader = None
        # 优先标准 pcap，失败回退 pcapng
        try:
            reader = PcapReader(filepath)
        except Exception:
            try:
                reader = PcapNgReader(filepath)
            except Exception as e:
                logger.error(f"流式解析失败（非 PCAP/PCAPNG 或文件损坏）: {e}")
                return
        n = 0
        with reader:
            for pkt in reader:
                yield parser.parse(pkt)
                n += 1
                if n % 10000 == 0:
                    logger.info(f"流式解析进度: {n} 包")
        logger.info(f"流式解析完成 | 共 {n} 个数据包")

    def parse_file(self, filepath: str, count: Optional[int] = None) -> List[PacketInfo]:
        """
        解析PCAP/PCAPNG文件
        :param filepath: 文件路径
        :param count: 读取的包数量上限，None表示全部
        :return: 解析后的数据包列表
        """
        logger.info(f"开始解析PCAP文件: {filepath}")

        if count:
            self.raw_packets = rdpcap(filepath, count=count)
        else:
            self.raw_packets = rdpcap(filepath)

        logger.info(f"文件读取完成，共 {len(self.raw_packets)} 个数据包，开始解析...")

        # 复用PacketParser的解析逻辑
        parser = PacketParser()
        self.packets = []
        for i, pkt in enumerate(self.raw_packets):
            info = parser.parse(pkt)
            self.packets.append(info)
            if (i + 1) % 1000 == 0:
                logger.info(f"已解析 {i+1}/{len(self.raw_packets)} 个包")

        logger.info(f"PCAP解析完成 | 共 {len(self.packets)} 个数据包")
        return self.packets

    def filter_by_protocol(self, protocol: str) -> List[PacketInfo]:
        """按协议过滤"""
        return [p for p in self.packets if p.protocol.upper() == protocol.upper()]

    def filter_by_ip(self, ip: str) -> List[PacketInfo]:
        """按IP过滤（源或目的）"""
        return [p for p in self.packets if p.src_ip == ip or p.dst_ip == ip]

    def filter_by_port(self, port: int) -> List[PacketInfo]:
        """按端口过滤（源或目的）"""
        return [p for p in self.packets if p.src_port == port or p.dst_port == port]

    def get_tcp_flows(self) -> Dict[str, List[PacketInfo]]:
        """
        提取所有TCP流（按四元组分流）
        对应Wireshark的"Follow TCP Stream"功能
        """
        flows = {}
        for p in self.packets:
            if p.protocol == "TCP" and p.src_ip and p.dst_ip:
                # 规范化流标识（不区分方向）
                ep1 = f"{p.src_ip}:{p.src_port}"
                ep2 = f"{p.dst_ip}:{p.dst_port}"
                flow_key = " <-> ".join(sorted([ep1, ep2]))
                if flow_key not in flows:
                    flows[flow_key] = []
                flows[flow_key].append(p)
        return flows

    def get_syn_flood_candidates(self, syn_threshold: int = 50) -> List[Dict[str, Any]]:
        """
        检测SYN洪水攻击嫌疑
        统计每个源IP发送的SYN包数量（无ACK响应）
        """
        syn_stats = {}
        for p in self.packets:
            if p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags:
                src = p.src_ip
                if src not in syn_stats:
                    syn_stats[src] = {"syn_count": 0, "dst_ips": set()}
                syn_stats[src]["syn_count"] += 1
                syn_stats[src]["dst_ips"].add(p.dst_ip)

        candidates = []
        for src, stats in syn_stats.items():
            if stats["syn_count"] >= syn_threshold:
                candidates.append({
                    "src_ip": src,
                    "syn_count": stats["syn_count"],
                    "target_count": len(stats["dst_ips"]),
                    "risk": "HIGH" if stats["syn_count"] > 200 else "MEDIUM"
                })
        return sorted(candidates, key=lambda x: x["syn_count"], reverse=True)

    def get_port_scan_candidates(self, port_threshold: int = 20) -> List[Dict[str, Any]]:
        """
        检测端口扫描嫌疑
        统计每个源IP访问的不同目的端口数量
        """
        scan_stats = {}
        for p in self.packets:
            if p.protocol in ("TCP", "UDP") and p.src_ip and p.dst_port > 0:
                src = p.src_ip
                if src not in scan_stats:
                    scan_stats[src] = {"ports": set(), "packets": 0, "dst_ips": set()}
                scan_stats[src]["ports"].add(p.dst_port)
                scan_stats[src]["packets"] += 1
                scan_stats[src]["dst_ips"].add(p.dst_ip)

        candidates = []
        for src, stats in scan_stats.items():
            if len(stats["ports"]) >= port_threshold:
                candidates.append({
                    "src_ip": src,
                    "unique_ports": len(stats["ports"]),
                    "packet_count": stats["packets"],
                    "target_count": len(stats["dst_ips"]),
                    "top_ports": sorted(list(stats["ports"]))[:10],
                    "risk": "HIGH" if len(stats["ports"]) > 100 else "MEDIUM"
                })
        return sorted(candidates, key=lambda x: x["unique_ports"], reverse=True)

    def get_dns_tunneling_candidates(self, query_length_threshold: int = 30) -> List[Dict[str, Any]]:
        """
        检测DNS隧道嫌疑
        统计异常长的DNS查询（DNS隧道通常用子域名编码数据）
        """
        dns_queries = {}
        for p in self.packets:
            if p.protocol == "DNS" and p.dns_query:
                query = p.dns_query.rstrip('.')
                if len(query) > query_length_threshold:
                    src = p.src_ip
                    if src not in dns_queries:
                        dns_queries[src] = {"count": 0, "queries": []}
                    dns_queries[src]["count"] += 1
                    dns_queries[src]["queries"].append(query)

        candidates = []
        for src, stats in dns_queries.items():
            candidates.append({
                "src_ip": src,
                "suspicious_query_count": stats["count"],
                "sample_queries": stats["queries"][:5],
                "risk": "HIGH" if stats["count"] > 20 else "MEDIUM"
            })
        return sorted(candidates, key=lambda x: x["suspicious_query_count"], reverse=True)

    def generate_analysis_report(self) -> Dict[str, Any]:
        """
        生成综合分析报告
        包含流量概览、协议分布、异常检测结果
        """
        report = {
            "summary": {
                "total_packets": len(self.packets),
                "time_range": {
                    "start": self.packets[0].timestamp if self.packets else "",
                    "end": self.packets[-1].timestamp if self.packets else ""
                },
                "protocol_distribution": {},
                "total_bytes": sum(p.length for p in self.packets),
            },
            "anomaly_detection": {
                "syn_flood_candidates": self.get_syn_flood_candidates(),
                "port_scan_candidates": self.get_port_scan_candidates(),
                "dns_tunneling_candidates": self.get_dns_tunneling_candidates(),
            },
            "top_talkers": self._get_top_talkers(),
        }

        # 协议分布
        for p in self.packets:
            report["summary"]["protocol_distribution"][p.protocol] = \
                report["summary"]["protocol_distribution"].get(p.protocol, 0) + 1

        return report

    def _get_top_talkers(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """获取通信量TOP IP对"""
        flow_stats = {}
        for p in self.packets:
            if p.src_ip and p.dst_ip:
                key = f"{p.src_ip} -> {p.dst_ip}"
                if key not in flow_stats:
                    flow_stats[key] = {"packets": 0, "bytes": 0}
                flow_stats[key]["packets"] += 1
                flow_stats[key]["bytes"] += p.length
        sorted_flows = sorted(flow_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
        return [{"flow": k, **v} for k, v in sorted_flows[:top_n]]

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """转换为字典列表"""
        parser = PacketParser()
        parser.captured_packets = self.packets
        return parser.to_dict_list()

    def to_json(self, filepath: str):
        """导出为JSON"""
        data = self.to_dict_list()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"已导出 {len(data)} 条记录到 {filepath}")
