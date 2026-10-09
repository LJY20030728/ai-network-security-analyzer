"""
数据包解析模块
从抓包文件或内存中解析网络数据包，提取关键字段
（原实时抓包功能已移除，本模块专注 PCAP 离线解析场景）
"""
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
from typing import List, Dict, Any
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


def _first_dns_rdata(dns) -> str:
    """
    从 DNS 应答段安全提取首条记录的 rdata 文本。

    兼容 scapy 2.7 的两个行为变化：
      1. `dns.ancount` 可能为 None（字段未解析）—— 调用方必须先做 `or 0` 处理
      2. `dns.an` 已改为 PacketListField，是**列表**而非单条记录，
         因此 `dns.an.rdata` 会抛 AttributeError。旧代码把这句包在 try 里，
         结果是真实流量上 dns_response 永远为空（静默数据丢失）。

    返回空字符串表示无法提取，绝不抛异常 —— 单个字段解析失败
    不应影响整个数据包（乃至整个 PCAP）的解析。
    """
    try:
        an = dns.an
        if not an:
            return ""
        rec = an[0] if isinstance(an, list) else an
        if rec is None:
            return ""
        rdata = getattr(rec, "rdata", None)
        if rdata is None:
            return ""
        if isinstance(rdata, bytes):
            return rdata.decode("utf-8", errors="ignore")
        return str(rdata)
    except Exception:
        return ""


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
                    # 查询域名：qd 在 scapy 2.7 亦是 PacketListField，需判空后取首条
                    if packet[DNS].qd:
                        try:
                            info.dns_query = packet[DNS].qd.qname.decode(errors='ignore')
                        except Exception:
                            info.dns_query = ""
                    # 应答记录提取。
                    # 不再依赖 ancount 字段：
                    #   · 内存中构造的包 ancount 恒为 None（scapy 惰性填充）
                    #   · 畸形/截断包也可能给出错误的计数值
                    # 改为直接判断 an 段是否有内容（an 在 scapy 2.7 是列表）。
                    # 这样既不会因 None 抛 TypeError 中断解析，也不受计数字段误导。
                    if packet[DNS].qr == 1:
                        info.dns_response = _first_dns_rdata(packet[DNS])

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
