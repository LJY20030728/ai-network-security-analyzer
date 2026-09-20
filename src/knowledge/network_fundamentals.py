"""
网络基础知识库
============
包含路由协议、网络设备、TCP/IP协议栈、常见端口等基础知识
用于PCAP分析时的协议识别和异常解释
"""

NETWORK_KNOWLEDGE = [
    # ========== 路由协议 ==========
    {
        "title": "OSPF路由协议 - 开放最短路径优先",
        "content": """
OSPF（Open Shortest Path First）是一种链路状态路由协议，广泛应用于企业内网。

**工作原理：**
- 使用Dijkstra算法计算最短路径
- 协议号：89（IP层协议号）
- 组播地址：224.0.0.5（所有OSPF路由器）、224.0.0.6（DR/BDR）
- 度量值：开销（Cost）= 100Mbps / 接口带宽

**PCAP分析特征：**
- 协议字段显示为89
- 常见组播目标IP：224.0.0.5
- OSPF包类型：Hello(1)、DD(2)、LSR(3)、LSU(4)、LSAck(5)
- Hello包间隔：10秒（多路访问网络）
- 邻接状态：Down → Init → 2-Way → ExStart → Exchange → Loading → Full

**异常检测：**
- 短时间大量OSPF Hello包 → 可能是路由扫描或DoS
- 不同子网的OSPF包 → 可能是路由欺骗
- 频繁的LSA更新 → 可能是路由抖动或攻击
""",
        "category": "routing_protocol",
    },
    {
        "title": "BGP路由协议 - 边界网关协议",
        "content": """
BGP（Border Gateway Protocol）是互联网的核心路由协议，用于AS（自治系统）之间的路由交换。

**工作原理：**
- TCP端口：179
- 路径矢量协议，使用AS-Path作为度量
- 建立TCP连接后交换路由信息
- 支持路由策略和过滤

**PCAP分析特征：**
- TCP目标端口：179
- BGP消息类型：Open(1)、Update(2)、Notification(3)、Keepalive(4)、Route-Refresh(5)
- Keepalive间隔：60秒
- Hold Time：180秒

**异常检测：**
- 大量BGP Update包 → 路由抖动或攻击
- 异常AS-Path → 路由欺骗或前缀劫持
- 频繁连接建立/断开 → BGP会话不稳定
""",
        "category": "routing_protocol",
    },
    {
        "title": "RIP路由协议 - 路由信息协议",
        "content": """
RIP（Routing Information Protocol）是一种距离矢量路由协议，使用跳数作为度量。

**工作原理：**
- UDP端口：520
- 最大跳数：15（16表示不可达）
- 更新周期：30秒
- 使用广播或组播224.0.0.9发送更新

**PCAP分析特征：**
- UDP目标端口：520
- 源端口：520
- 常见目标IP：255.255.255.255或224.0.0.9

**异常检测：**
- 大量RIP更新包 → 路由扫描
- 跳数超过15 → 可能是路由环路
""",
        "category": "routing_protocol",
    },
    # ========== 网络设备 ==========
    {
        "title": "网络设备类型与功能",
        "content": """
常见网络设备及其在流量中的特征：

**路由器（Router）：**
- 工作在网络层（OSI第3层）
- 转发IP包，基于路由表
- TTL值每跳减1
- 常见协议：OSPF、BGP、RIP、ICMP

**交换机（Switch）：**
- 工作在数据链路层（OSI第2层）
- 基于MAC地址转发帧
- VLAN标记：802.1Q（TPID=0x8100）
- STP协议：组播01:80:c2:00:00:00

**防火墙（Firewall）：**
- 工作在网络层和传输层
- 基于规则过滤流量
- 常见部署：透明模式、路由模式
- 日志特征：拒绝的连接尝试

**入侵检测系统（IDS）/入侵防御系统（IPS）：**
- IDS：只检测，不阻断
- IPS：检测并阻断
- 常见部署：旁路镜像（IDS）、串联部署（IPS）

**负载均衡器（Load Balancer）：**
- 分发流量到多个后端服务器
- 常见算法：轮询、最少连接、哈希
- 健康检查：定期探测后端服务
""",
        "category": "network_device",
    },
    # ========== TCP/IP协议栈 ==========
    {
        "title": "TCP协议 - 传输控制协议",
        "content": """
TCP（Transmission Control Protocol）是面向连接的可靠传输协议。

**三次握手：**
1. SYN（同步）→ 客户端发送SYN
2. SYN-ACK（同步确认）→ 服务器回复SYN+ACK
3. ACK（确认）→ 客户端回复ACK，连接建立

**四次挥手：**
1. FIN（结束）→ 主动方发送FIN
2. ACK → 被动方回复ACK
3. FIN → 被动方发送FIN
4. ACK → 主动方回复ACK，连接关闭

**标志位：**
- SYN：同步，用于建立连接
- ACK：确认
- FIN：结束，用于关闭连接
- RST：复位，强制关闭连接
- PSH：推送，立即发送数据
- URG：紧急

**PCAP分析特征：**
- 源端口、目标端口
- 序列号、确认号
- 窗口大小
- 标志位组合

**异常检测：**
- 大量SYN包无ACK → SYN Flood攻击
- 大量RST包 → 连接重置攻击
- 异常标志位组合（如NULL扫描、XMAS扫描）
- 短连接大量建立 → 端口扫描
""",
        "category": "transport_protocol",
    },
    {
        "title": "UDP协议 - 用户数据报协议",
        "content": """
UDP（User Datagram Protocol）是无连接的不可靠传输协议。

**特点：**
- 无连接，不需要握手
- 不保证可靠交付
- 头部开销小（8字节）
- 支持广播和组播

**常见应用：**
- DNS：端口53
- DHCP：端口67/68
- NTP：端口123
- SNMP：端口161/162
- VoIP/RTP：动态端口

**PCAP分析特征：**
- 源端口、目标端口
- 长度、校验和
- 无连接状态

**异常检测：**
- 大量UDP小包 → UDP Flood攻击
- 异常目标端口 → UDP端口扫描
- DNS放大攻击 → 大量小UDP请求到DNS服务器
""",
        "category": "transport_protocol",
    },
    {
        "title": "ICMP协议 - 互联网控制报文协议",
        "content": """
ICMP（Internet Control Message Protocol）用于网络控制和错误报告。

**常见类型：**
- Echo Request（类型8）：Ping请求
- Echo Reply（类型0）：Ping响应
- Destination Unreachable（类型3）：目标不可达
- Time Exceeded（类型11）：TTL超时（Traceroute）
- Redirect（类型5）：重定向

**PCAP分析特征：**
- 类型、代码
- 校验和
- 数据部分（Ping负载）

**异常检测：**
- 大量ICMP Echo Request → Ping Flood攻击
- ICMP隧道 → 利用ICMP包传输数据
- 异常ICMP类型 → 可能是网络探测或攻击
""",
        "category": "network_protocol",
    },
    {
        "title": "ARP协议 - 地址解析协议",
        "content": """
ARP（Address Resolution Protocol）用于将IP地址解析为MAC地址。

**工作原理：**
1. 主机发送ARP请求："谁是192.168.1.1？请告诉192.168.1.100"
2. 目标主机回复ARP响应："192.168.1.1的MAC是aa:bb:cc:dd:ee:ff"

**报文类型：**
- ARP请求（操作码1）
- ARP响应（操作码2）

**PCAP分析特征：**
- 以太网类型：0x0806
- 发送端IP、发送端MAC
- 目标IP、目标MAC（请求时为0）

**异常检测：**
- ARP欺骗 → 伪造网关MAC地址
- 大量ARP请求 → ARP扫描
- 免费ARP → 网络宣告或攻击
""",
        "category": "network_protocol",
    },
    # ========== 常见端口和服务 ==========
    {
        "title": "常见端口与服务对照表",
        "content": """
常用TCP/UDP端口及其对应服务：

**常用TCP端口：**
- 21: FTP（文件传输协议）
- 22: SSH（安全外壳）
- 23: Telnet（远程登录，明文）
- 25: SMTP（简单邮件传输协议）
- 53: DNS（域名系统，也用UDP）
- 80: HTTP（超文本传输协议）
- 110: POP3（邮局协议版本3）
- 143: IMAP（互联网消息访问协议）
- 443: HTTPS（HTTP安全）
- 3306: MySQL数据库
- 3389: RDP（远程桌面协议）
- 8080: HTTP代理/备用Web服务

**常用UDP端口：**
- 53: DNS
- 67/68: DHCP（动态主机配置协议）
- 69: TFTP（简单文件传输协议）
- 123: NTP（网络时间协议）
- 161/162: SNMP（简单网络管理协议）
- 500: IKE（IPsec密钥交换）

**异常检测：**
- 连接到非常见端口 → 可能是漏洞利用
- 端口扫描 → 短时间大量不同端口的SYN包
- 非标准端口的服务 → 可能是隐蔽通道
""",
        "category": "common_port",
    },
    # ========== 网络安全 ==========
    {
        "title": "常见网络攻击类型与检测特征",
        "content": """
常见网络攻击及其PCAP检测特征：

**1. 端口扫描：**
- SYN扫描：大量SYN包，目标端口不同，源IP相同
- Connect扫描：完成完整三次握手
- FIN扫描：只发FIN包，不建立连接
- XMAS扫描：FIN+PSH+URG标志位
- Null扫描：无标志位

**2. DoS/DDoS攻击：**
- SYN Flood：大量SYN包，无ACK回复
- UDP Flood：大量UDP小包
- ICMP Flood：大量Ping包
- HTTP Flood：大量HTTP请求

**3. 中间人攻击（MITM）：**
- ARP欺骗：伪造网关MAC
- DNS欺骗：伪造DNS响应
- SSL劫持：伪造证书

**4. 数据渗漏：**
- DNS隧道：异常长的DNS查询
- HTTP隧道：异常HTTP请求
- ICMP隧道：ICMP包携带数据

**5. 暴力破解：**
- SSH暴力破解：大量SSH连接尝试
- RDP暴力破解：大量RDP连接尝试
- Web登录暴力破解：大量POST请求到登录接口
""",
        "category": "security_attack",
    },
    {
        "title": "网络流量分析指标与基线",
        "content": """
网络流量分析的关键指标和基线方法：

**基础指标：**
- 包数（Packets）：单位时间内的数据包数量
- 字节数（Bytes）：单位时间内的数据量
- 流数（Flows）：唯一的源IP+源端口+目的IP+目的端口组合
- 会话数（Sessions）：完整的双向通信

**统计特征：**
- 包大小分布：平均、中位数、标准差
- 包间隔时间：平均、最小、最大
- 上下行比：上行字节/下行字节
- 连接持续时间：平均、分布

**基线方法：**
- 中位数+MAD（绝对中位差）：抗异常值干扰
- 均值+标准差：正态分布假设
- EWMA（指数加权移动平均）：捕捉趋势变化
- STL分解：分离趋势、季节性、残差

**异常判定：**
- 超过基线±3σ → 异常
- 超过基线±2σ → 警告
- 变化率超过50% → 显著变化
""",
        "category": "traffic_analysis",
    },
    {
        "title": "VLAN与网络分段",
        "content": """
VLAN（虚拟局域网）是网络分段的重要技术。

**工作原理：**
- 802.1Q标签：在以太网帧头插入4字节VLAN标签
- TPID（标签协议标识符）：0x8100
- TCI（标签控制信息）：包含PCP（优先级）、CFI（规范格式指示）、VID（VLAN ID）
- VLAN ID范围：1-4094

**PCAP分析特征：**
- 以太网类型字段：0x8100（表示有VLAN标签）
- 标签嵌套：QinQ（双层VLAN标签）

**安全意义：**
- 网络分段：不同VLAN之间默认隔离
- 广播域控制：VLAN限制广播范围
- 安全策略：不同VLAN应用不同安全策略

**异常检测：**
- VLAN跳跃攻击：利用双标签绕过VLAN隔离
- 未授权VLAN访问：跨VLAN流量
- 异常VLAN ID：不在规划范围内的VLAN
""",
        "category": "network_segment",
    },
]


def get_network_knowledge() -> list:
    """获取网络基础知识条目"""
    return NETWORK_KNOWLEDGE


def get_knowledge_count() -> int:
    """获取知识条目数量"""
    return len(NETWORK_KNOWLEDGE)
