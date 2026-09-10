"""
数据包解析模块
从抓包文件或内存中解析网络数据包，提取关键字段
（原实时抓包功能已移除，本模块专注 PCAP 离线解析场景）
"""
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import json
from loguru import logger


@dataclass
class PacketInfo:
    """标准化的数据包信息结构"""
    timestamp: str = ""
    protocol: str = ""          # TCP/UDP/ICMP/ARP/DNS/OTHER
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    length: int = 0
    flags: str = ""             # TCP标志位: SYN/ACK/FIN/RST/PSH
    payload_size: int = 0
    tcp_window: int = 0          # TCP窗口大小（CIC特征需要）
    raw_summary: str = ""       # Scapy摘要信息
    dns_query: str = ""         # DNS查询域名
    dns_response: str = ""      # DNS响应IP


class PacketParser:
    """
    数据包解析器
    将 Scapy 包对象转换为结构化的 PacketInfo
    """

    def __init__(self):
        self.captured_packets: List[PacketInfo] = []

    def parse(self, packet) -> PacketInfo:
        """
        解析单个数据包，提取关键字段
        :param packet: Scapy 包对象
        :return: 标准化的 PacketInfo
        """
        info = PacketInfo()
        info.timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        info.length = len(packet)
        info.raw_summary = packet.summary()

        # ARP层
        if ARP in packet:
            info.protocol = "ARP"
            info.src_ip = packet[ARP].psrc
            info.dst_ip = packet[ARP].pdst
            return info

        # IP层
        if IP in packet:
            info.src_ip = packet[IP].src
            info.dst_ip = packet[IP].dst

            # TCP层
            if TCP in packet:
                info.protocol = "TCP"
                info.src_port = packet[TCP].sport
                info.dst_port = packet[TCP].dport
                # 提取TCP标志位
                flags = []
                if packet[TCP].flags.S: flags.append("SYN")
                if packet[TCP].flags.A: flags.append("ACK")
                if packet[TCP].flags.F: flags.append("FIN")
                if packet[TCP].flags.R: flags.append("RST")
                if packet[TCP].flags.P: flags.append("PSH")
                if packet[TCP].flags.U: flags.append("URG")
                info.flags = ",".join(flags)
                # TCP窗口大小（CIC流特征需要）
                info.tcp_window = int(packet[TCP].window)
                # 载荷大小
                if Raw in packet:
                    info.payload_size = len(packet[Raw].load)

            # UDP层
            elif UDP in packet:
                info.protocol = "UDP"
                info.src_port = packet[UDP].sport
                info.dst_port = packet[UDP].dport
                if Raw in packet:
                    info.payload_size = len(packet[Raw].load)

                # DNS层（DNS基于UDP）
                if DNS in packet:
                    info.protocol = "DNS"
                    if packet[DNS].qd:
                        info.dns_query = packet[DNS].qd.qname.decode(errors='ignore')
                    if packet[DNS].qr == 1 and packet[DNS].ancount > 0 and packet[DNS].an:
                        try:
                            info.dns_response = packet[DNS].an.rdata
                            if isinstance(info.dns_response, bytes):
                                info.dns_response = info.dns_response.decode(errors='ignore')
                        except Exception:
                            pass

            # ICMP层
            elif ICMP in packet:
                info.protocol = "ICMP"
                icmp_type = packet[ICMP].type
                type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable",
                           11: "Time Exceeded", 5: "Redirect"}
                info.flags = type_map.get(icmp_type, f"Type-{icmp_type}")

            else:
                info.protocol = "OTHER"

        return info

    def parse_list(self, packets: List, progress_interval: int = 1000) -> List[PacketInfo]:
        """批量解析包对象列表，返回 PacketInfo 列表"""
        self.captured_packets = []
        total = len(packets)
        for i, pkt in enumerate(packets):
            self.captured_packets.append(self.parse(pkt))
            if (i + 1) % progress_interval == 0:
                logger.info(f"已解析 {i+1}/{total} 个包")
        return self.captured_packets

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """将解析的包转换为字典列表（便于JSON序列化）"""
        return [
            {
                "timestamp": p.timestamp,
                "protocol": p.protocol,
                "src_ip": p.src_ip,
                "src_port": p.src_port,
                "dst_ip": p.dst_ip,
                "dst_port": p.dst_port,
                "length": p.length,
                "flags": p.flags,
                "payload_size": p.payload_size,
                "dns_query": p.dns_query,
                "dns_response": p.dns_response,
            }
            for p in self.captured_packets
        ]

    def to_json(self, filepath: str):
        """导出为JSON文件"""
        data = self.to_dict_list()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"已导出 {len(data)} 条记录到 {filepath}")

    def get_protocol_stats(self) -> Dict[str, int]:
        """统计各协议包数量"""
        stats = {}
        for p in self.captured_packets:
            stats[p.protocol] = stats.get(p.protocol, 0) + 1
        return dict(sorted(stats.items(), key=lambda x: x[1], reverse=True))

    def get_top_talkers(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """统计通信量最大的IP对"""
        flow_stats = {}
        for p in self.captured_packets:
            if p.src_ip and p.dst_ip:
                key = f"{p.src_ip} -> {p.dst_ip}"
                if key not in flow_stats:
                    flow_stats[key] = {"packets": 0, "bytes": 0}
                flow_stats[key]["packets"] += 1
                flow_stats[key]["bytes"] += p.length

        sorted_flows = sorted(flow_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
        return [{"flow": k, **v} for k, v in sorted_flows[:top_n]]
