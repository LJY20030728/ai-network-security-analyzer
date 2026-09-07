"""
MITRE ATT&CK 知识库
内置常见攻击技术的描述、检测方法和缓解措施
数据来源于 MITRE ATT&CK 框架（https://attack.mitre.org/）
"""
from typing import List, Dict, Any, Optional


# MITRE ATT&CK 常见技术条目（精选网络流量分析相关的技术）
MITRE_ATTACK_TECHNIQUES = [
    {
        "id": "T1046",
        "name": "网络服务扫描",
        "tactic": "侦察",
        "description": "攻击者通过扫描目标网络的开放端口和服务，收集目标环境信息。常见方式包括SYN扫描、UDP扫描、ACK扫描等。",
        "detection": "检测短时间内来自同一源IP的大量SYN包，且覆盖多个目的端口；检测无ACK响应的半开连接尝试。",
        "mitigation": "部署IDS/IPS检测扫描行为；限制内网横向扫描；关闭不必要的服务端口。",
        "traffic_indicators": "同一源IP在短时间内向多个目的IP/端口发送SYN包；SYN/ACK比例异常；扫描特征的端口序列（如按顺序1-10000）"
    },
    {
        "id": "T1071",
        "name": "应用层协议",
        "tactic": "命令与控制",
        "description": "攻击者使用常见应用层协议（HTTP/HTTPS/DNS等）进行命令控制通信，以混入正常流量逃避检测。",
        "detection": "检测异常的协议使用模式，如DNS查询长度异常、HTTP请求中包含编码数据、非标准端口使用标准协议等。",
        "mitigation": "实施网络分段；监控出站流量；使用代理服务器过滤恶意域名；部署SSL/TLS解密检查。",
        "traffic_indicators": "DNS查询名异常长（>30字符）；HTTP User-Agent异常；与已知C2服务器的通信； beaconing特征（固定间隔的心跳包）"
    },
    {
        "id": "T1048",
        "name": "数据从网络中渗出",
        "tactic": "渗出",
        "description": "攻击者通过网络将窃取的数据传输到外部服务器，可能使用加密、编码或协议隧道等方式隐藏。",
        "detection": "检测异常的大流量出站传输；检测非工作时间的大量数据传输；检测到已知恶意IP的出站连接。",
        "mitigation": "实施数据丢失防护（DLP）；限制出站流量；监控异常数据传输模式。",
        "traffic_indicators": "单一会话传输大量数据（>100MB）；非业务时段的大流量出站；上传/下载流量比例异常；数据传输到陌生地理位置"
    },
    {
        "id": "T1090",
        "name": "代理",
        "tactic": "命令与控制",
        "description": "攻击者使用内部代理服务器或多级代理进行流量转发，隐藏真实C2服务器地址。",
        "detection": "检测链式代理连接；检测内部主机之间的异常代理通信；检测TOR或VPN使用。",
        "mitigation": "限制代理服务器使用；监控代理日志；阻断已知匿名代理服务。",
        "traffic_indicators": "内部主机连接到已知代理端口（如9050/TOR）；多跳代理链；加密流量中异常的握手特征"
    },
    {
        "id": "T1572",
        "name": "协议隧道",
        "tactic": "命令与控制",
        "description": "攻击者将恶意数据封装在合法协议中传输，如DNS隧道、HTTP隧道、ICMP隧道等。",
        "detection": "检测DNS查询中异常长的子域名；检测ICMP包中包含异常载荷；检测HTTP请求中编码的恶意数据。",
        "mitigation": "监控DNS查询长度和频率；限制ICMP出站；部署深度包检测（DPI）。",
        "traffic_indicators": "DNS查询名长度>30字符且包含随机字符串；DNS TXT记录包含大量数据；ICMP包载荷异常大；HTTP POST body包含Base64编码数据"
    },
    {
        "id": "T1110",
        "name": "暴力破解",
        "tactic": "凭证访问",
        "description": "攻击者通过大量尝试用户名密码组合来获取账户凭证，常见于SSH、RDP、FTP等服务。",
        "detection": "检测短时间内大量失败的登录尝试；检测来自同一IP的多次认证失败；检测异常时间的登录尝试。",
        "mitigation": "实施账户锁定策略；使用多因素认证（MFA）；限制登录尝试次数；部署fail2ban等工具。",
        "traffic_indicators": "同一源IP在短时间内建立大量到22/3389端口的连接；大量RST包（认证失败后断开）；登录尝试间隔规律性"
    },
    {
        "id": "T1498",
        "name": "网络拒绝服务",
        "tactic": "影响",
        "description": "攻击者通过大量流量或请求耗尽目标网络带宽或服务资源，导致合法用户无法访问。",
        "detection": "检测流量突增；检测来自大量源IP的SYN flood；检测应用层DDoS（大量HTTP请求）。",
        "mitigation": "部署DDoS防护服务；配置SYN cookie；实施流量清洗；使用CDN分散流量。",
        "traffic_indicators": "SYN包数量远超ACK包；大量半开连接；来自分布式源IP的流量汇聚；带宽利用率接近100%"
    },
    {
        "id": "T1021",
        "name": "远程服务",
        "tactic": "横向移动",
        "description": "攻击者使用合法的远程服务（SSH、RDP、SMB等）在内网中横向移动，访问其他系统。",
        "detection": "检测异常的远程登录；检测非工作时间的远程访问；检测横向移动的连接模式。",
        "mitigation": "限制远程服务访问；实施最小权限原则；监控远程登录日志；使用跳板机。",
        "traffic_indicators": "一台主机连接到多台内部主机的22/3389/445端口；异常账户的远程登录；非业务时段的内部远程连接"
    },
    {
        "id": "T1005",
        "name": "数据从本地系统窃取",
        "tactic": "收集",
        "description": "攻击者从受感染的本地系统中收集敏感数据，如文件、配置、凭证等，为后续渗出做准备。",
        "detection": "检测异常的文件访问模式；检测大量文件读取；检测归档工具（zip/tar）的异常使用。",
        "mitigation": "实施文件访问审计；监控敏感文件访问；使用EDR工具检测异常行为。",
        "traffic_indicators": "内部主机异常访问文件服务器；大量SMB读请求；敏感目录的访问模式异常"
    },
    {
        "id": "T1082",
        "name": "系统信息发现",
        "tactic": "发现",
        "description": "攻击者收集受感染系统的详细信息，包括操作系统版本、安装软件、网络配置等，为后续攻击做准备。",
        "detection": "检测系统信息枚举命令的执行；检测异常的注册表访问；检测WMI查询异常。",
        "mitigation": "监控系统命令执行；实施应用白名单；限制WMI访问。",
        "traffic_indicators": "主机发送异常的系统信息查询；大量NetBIOS/SMB枚举请求；LDAP查询异常"
    }
]


# 常见攻击类型与处置手册
INCIDENT_RESPONSE_PLAYBOOKS = [
    {
        "title": "端口扫描事件处置手册",
        "category": "reconnaissance",
        "content": """## 端口扫描事件处置手册

### 1. 确认扫描行为
- 检查源IP是否为内部授权的 vulnerability scanner（如Nessus、Qualys）
- 确认扫描时间是否在授权窗口内
- 分析扫描的端口范围和目标系统

### 2. 遏制措施
- 如果是未授权扫描：
  - 在防火墙阻断源IP
  - 检查源主机是否已被攻陷（内网扫描通常是入侵的迹象）
  - 隔离可疑源主机进行取证

### 3. 调查方向
- 检查被扫描主机是否存在已知漏洞
- 查看扫描后是否有后续的漏洞利用尝试
- 检查所有被扫描主机的认证日志
- 溯源扫描源IP的真实身份

### 4. 恢复与改进
- 修补被扫描系统发现的漏洞
- 部署IDS规则检测内网横向扫描
- 实施网络分段，限制扫描范围
- 定期进行授权的漏洞扫描和渗透测试
"""
    },
    {
        "title": "DDoS攻击事件处置手册",
        "category": "dos",
        "content": """## DDoS攻击事件处置手册

### 1. 攻击确认与分类
- 确认攻击类型：网络层（SYN flood/UDP flood/ICMP flood）还是应用层（HTTP flood）
- 评估攻击流量大小和影响范围
- 识别攻击源特征（分布式还是单源）

### 2. 紧急遏制
- 网络层DDoS：
  - 启用SYN Cookie
  - 在边界路由器配置流量过滤
  - 切换到DDoS清洗服务（如Cloudflare、阿里云盾）
  - 上游运营商协助黑洞路由
- 应用层DDoS：
  - 启用WAF的CC防护
  - 实施验证码/JS挑战
  - 限制单IP请求频率
  - 静态资源CDN缓存

### 3. 调查与溯源
- 保存攻击流量PCAP用于取证
- 分析攻击源IP分布（是否为僵尸网络）
- 检查是否有攻击伴随的入侵尝试
- 记录攻击时间线

### 4. 恢复与改进
- 攻击停止后逐步恢复服务
- 评估攻击造成的业务损失
- 完善DDoS防护预案
- 考虑购买专业DDoS防护服务
- 定期进行DDoS演练
"""
    },
    {
        "title": "DNS隧道检测与处置手册",
        "category": "c2",
        "content": """## DNS隧道检测与处置手册

### 1. DNS隧道特征识别
- 异常长的DNS查询名（>30字符），通常包含Base64/十六进制编码
- 高频DNS查询（同一源IP每分钟>100次查询）
- 查询同一域名的大量随机子域名
- DNS TXT记录响应包含大量数据
- 非标准DNS端口的DNS流量

### 2. 确认隧道
- 检查可疑域名的WHOIS信息（新注册、隐私保护）
- 解码DNS查询中的数据，确认是否包含加密/编码的C2通信
- 检查主机是否有异常进程或恶意软件
- 对比已知DNS隧道工具特征（iodine、dnscat2、DNSCat等）

### 3. 遏制措施
- 在DNS服务器上阻断可疑域名
- 在防火墙阻断可疑源IP的出站DNS
- 隔离受感染主机进行恶意软件清除
- 检查内网其他主机是否有类似行为

### 4. 调查与修复
- 取证分析受感染主机，确定入侵入口
- 检查数据是否被窃取（DNS隧道常用于数据渗出）
- 修复被利用的漏洞
- 重置可能泄露的凭证

### 5. 长期防护
- 部署DNS安全监控（如Darktrace、ExtraHop）
- 实施DNS查询长度和频率限制
- 使用企业级DNS过滤服务
- 定期审计DNS日志
"""
    },
    {
        "title": "暴力破解攻击处置手册",
        "category": "credential_access",
        "content": """## 暴力破解攻击处置手册

### 1. 攻击确认
- 识别攻击目标服务（SSH/RDP/FTP/数据库/Web登录）
- 统计失败登录尝试次数和频率
- 确认攻击源IP（单源还是分布式）
- 检查是否有成功登录的记录

### 2. 紧急遏制
- 在防火墙/安全组阻断攻击源IP
- 临时锁定被攻击的账户（如果策略允许）
- 启用账户锁定策略（5次失败锁定30分钟）
- 如果有成功登录：立即禁用该账户，强制重置密码

### 3. 调查
- 检查所有被尝试账户的登录日志
- 如果有成功登录：
  - 检查登录后的操作记录
  - 检查是否有数据访问或修改
  - 检查是否有后门或持久化
  - 检查是否有横向移动
- 溯源攻击源（TOR/代理/真实IP）
- 保存日志用于取证

### 4. 恢复
- 确认无持久化后恢复被锁定账户
- 强制所有相关账户重置密码
- 启用多因素认证（MFA）
- 恢复正常服务

### 5. 长期改进
- 所有远程服务强制MFA
- 部署fail2ban或类似自动封禁工具
- 使用非标准端口（安全通过隐蔽性，仅辅助手段）
- 实施IP白名单限制远程服务访问
- 定期审计认证日志
"""
    }
]


# 网络协议知识库
PROTOCOL_KNOWLEDGE = [
    {
        "title": "TCP三次握手与连接管理",
        "category": "protocol",
        "content": """## TCP三次握手与连接管理

### 三次握手过程
1. 客户端发送 SYN (seq=x) → 服务端
2. 服务端响应 SYN+ACK (seq=y, ack=x+1) → 客户端
3. 客户端发送 ACK (ack=y+1) → 服务端
连接建立完成

### 四次挥手过程
1. 主动方发送 FIN → 被动方
2. 被动方发送 ACK
3. 被动方发送 FIN
4. 主动方发送 ACK

### 安全分析要点
- SYN flood攻击：大量SYN无ACK，耗尽半开连接队列
- 异常：SYN/ACK比例严重失衡
- 端口扫描：大量SYN到不同端口，无后续ACK
- 检测：监控半开连接数量、SYN速率
"""
    },
    {
        "title": "DNS协议安全分析",
        "category": "protocol",
        "content": """## DNS协议安全分析

### DNS基本流程
1. 客户端向DNS服务器发送查询（UDP 53端口）
2. DNS服务器递归/迭代查询
3. 返回解析结果

### 安全威胁
1. **DNS隧道**：利用DNS协议传输非DNS数据，常见于C2通信和数据渗出
   - 特征：查询名异常长（>30字符）、高频查询、随机子域名
2. **DNS劫持**：篡改DNS响应，将用户导向恶意网站
3. **DNS放大攻击**：利用开放递归服务器进行DDoS反射放大
4. **DNS投毒**：污染DNS缓存，返回错误解析结果

### 检测方法
- 监控DNS查询长度分布
- 统计单IP DNS查询频率
- 检查DNS响应中的TXT记录大小
- 对比已知恶意域名库
"""
    },
    {
        "title": "HTTP/HTTPS流量安全分析",
        "category": "protocol",
        "content": """## HTTP/HTTPS流量安全分析

### HTTP请求结构
- 请求行：METHOD PATH HTTP/1.1
- 请求头：Host、User-Agent、Cookie、Authorization等
- 请求体：POST数据

### 安全威胁
1. **SQL注入**：URL参数或POST body中包含SQL语法
2. **XSS**：参数中包含<script>等HTML标签
3. **Web Shell**：异常的POST请求到可疑URL
4. **C2通信**：beaconing特征（固定间隔请求）、异常User-Agent
5. **数据渗出**：大体积POST出站请求

### HTTPS分析限制
- 加密流量无法直接查看内容
- 可分析：SNI（服务器名称指示）、证书信息、握手特征、流量模式
- 检测：已知恶意域名的SNI、异常证书、JA3指纹匹配

### 检测要点
- 监控异常HTTP方法（PUT/DELETE到非API路径）
- 检查User-Agent异常（空、已知工具特征）
- 分析请求间隔的规律性（beaconing）
- 监控大体积出站POST
"""
    }
]


def get_all_knowledge() -> List[Dict[str, str]]:
    """获取所有知识库条目（用于初始化RAG）"""
    all_items = []

    # MITRE ATT&CK
    for tech in MITRE_ATTACK_TECHNIQUES:
        all_items.append({
            "title": f"MITRE ATT&CK {tech['id']} - {tech['name']}",
            "content": f"战术: {tech['tactic']}\n\n描述: {tech['description']}\n\n检测方法: {tech['detection']}\n\n缓解措施: {tech['mitigation']}\n\n流量特征: {tech['traffic_indicators']}",
            "category": "mitre_attack"
        })

    # 事件处置手册
    all_items.extend(INCIDENT_RESPONSE_PLAYBOOKS)

    # 协议知识
    all_items.extend(PROTOCOL_KNOWLEDGE)

    return all_items


def get_technique_by_id(tech_id: str) -> Optional[Dict[str, Any]]:
    """根据技术ID查询MITRE ATT&CK技术"""
    for tech in MITRE_ATTACK_TECHNIQUES:
        if tech["id"].upper() == tech_id.upper():
            return tech
    return None


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """按战术查询MITRE ATT&CK技术"""
    return [t for t in MITRE_ATTACK_TECHNIQUES if t["tactic"] == tactic]
