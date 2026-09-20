"""
Web安全与应用层攻击知识库
========================
包含常见Web攻击类型、攻击特征、检测方法等
"""

WEB_SECURITY_KNOWLEDGE = [
    # ========== Web攻击类型 ==========
    {
        "title": "SQL注入攻击",
        "content": """
SQL注入（SQL Injection）是最常见的Web攻击方式之一。

**工作原理：**
- 攻击者把SQL命令插入到Web表单的输入域或页面请求的查询字符串
- 欺骗服务器执行恶意的SQL命令
- 全球约70%的Web攻击来自XSS和SQL注入

**攻击类型：**
- 联合查询注入（UNION-based）
- 布尔盲注（Boolean-based blind）
- 时间盲注（Time-based blind）
- 报错注入（Error-based）
- 堆叠查询注入（Stacked queries）

**PCAP分析特征：**
- HTTP请求参数中包含SQL关键字：SELECT、UNION、DROP、DELETE、INSERT
- 异常长的URL参数
- 频繁的数据库错误响应
- 常见注入点：登录框、搜索框、URL参数

**检测方法：**
- 检测HTTP请求中的SQL特征字符串
- 监控异常的数据库错误响应
- 检测布尔盲注的响应长度差异
- 检测时间盲注的响应延迟
""",
        "category": "web_attack",
    },
    {
        "title": "XSS跨站脚本攻击",
        "content": """
XSS（Cross-Site Scripting）跨站脚本攻击。

**工作原理：**
- 恶意攻击者利用网站没有对用户提交数据进行转义处理或过滤不足的缺点
- 添加恶意代码，嵌入到Web页面中
- 其他用户访问时会执行相应的嵌入代码

**攻击类型：**
- 存储型XSS：恶意脚本存储在服务器中（危害最大）
- 反射型XSS：恶意脚本从当前请求中反射回来
- DOM型XSS：恶意脚本在客户端DOM中执行

**PCAP分析特征：**
- HTTP响应中包含<script>标签或javascript:伪协议
- HTTP请求参数中包含<script>、onclick、onload等事件
- 异常的JavaScript代码长度
- Cookie窃取：document.cookie相关代码

**检测方法：**
- 检测HTTP响应中的可疑脚本标签
- 检测请求参数中的HTML/JavaScript特殊字符
- 监控异常的Cookie外发行为
""",
        "category": "web_attack",
    },
    {
        "title": "CSRF跨站请求伪造",
        "content": """
CSRF（Cross-Site Request Forgery）跨站请求伪造。

**工作原理：**
- 攻击者诱导已登录用户访问恶意网站
- 利用用户的身份，在用户不知情的情况下向目标网站发送请求
- 目标网站无法区分请求是用户主动发起的还是被伪造的

**与XSS的区别：**
- XSS：偷取用户的Cookie，以用户身份执行操作
- CSRF：利用用户的登录状态，伪造用户的请求

**PCAP分析特征：**
- 跨域请求：Referer来自非目标网站
- 请求内容与用户平时操作不符
- 敏感操作的请求没有CSRF令牌
- 短时间内大量不同来源的相同请求

**检测方法：**
- 检查Referer头是否来自可信域名
- 验证CSRF令牌的存在和有效性
- 监控敏感操作的异常请求来源
""",
        "category": "web_attack",
    },
    {
        "title": "命令注入攻击",
        "content": """
命令注入（Command Injection）攻击。

**工作原理：**
- 攻击者通过Web应用的输入字段，注入操作系统命令
- 应用程序直接将用户输入拼接为系统命令执行
- 攻击者可以执行任意操作系统命令

**常见注入字符：**
- 分号（;）：分隔命令
- 管道（|）：前一个命令的输出作为后一个命令的输入
- 逻辑与（&&）：前一个命令成功则执行后一个
- 逻辑或（||）：前一个命令失败则执行后一个
- 反引号（`）：执行命令并替换结果
- $()：执行命令并替换结果

**PCAP分析特征：**
- HTTP请求参数中包含系统命令：ls、dir、ping、whoami、cat、type
- 异常长的命令行参数
- 服务器响应中包含命令执行结果

**检测方法：**
- 检测请求参数中的命令分隔符和关键字
- 监控异常的系统调用
""",
        "category": "web_attack",
    },
    # ========== 网络安全工具 ==========
    {
        "title": "Wireshark网络封包分析工具",
        "content": """
Wireshark是最流行的网络封包分析软件。

**主要功能：**
- 截取网络封包（实时抓包）
- 显示详细的协议信息
- 支持数百种协议的解析
- 提供图形化界面
- 支持过滤、搜索、着色规则

**常用过滤语法：**
- ip.addr == 192.168.1.1：按IP地址过滤
- tcp.port == 80：按TCP端口过滤
- http：只显示HTTP协议
- tcp.flags.syn == 1：只显示SYN包
- http.request.method == "POST"：只显示POST请求

**应用场景：**
- 网络故障排查
- 安全事件分析
- 协议开发和调试
- 学习网络协议

**在本项目中的应用：**
- PCAP文件解析
- 协议识别
- 流量统计和分析
""",
        "category": "security_tool",
    },
    {
        "title": "Nmap网络扫描工具",
        "content": """
Nmap（Network Mapper）是开源的网络扫描和安全审计工具。

**主要功能：**
- 主机发现：探测网络上哪些主机在线
- 端口扫描：探测主机上哪些端口开放
- 版本探测：探测端口上运行的服务版本
- OS探测：探测目标操作系统类型
- 脚本扫描：使用NSE脚本进行高级检测

**常用扫描类型：**
- SYN扫描（半开扫描）：只发送SYN包，不完成三次握手
- Connect扫描（全开扫描）：完成完整三次握手
- FIN扫描：只发送FIN包
- XMAS扫描：FIN+PSH+URG标志位
- Null扫描：无标志位

**PCAP分析特征：**
- 大量SYN包到不同端口（SYN扫描）
- 短时间内来自同一源IP的大量连接尝试
- 异常的TCP标志位组合（FIN/XMAS/Null扫描）

**在本项目中的应用：**
- 端口扫描检测
- 侦察行为识别
""",
        "category": "security_tool",
    },
    {
        "title": "Tcpdump命令行抓包工具",
        "content": """
Tcpdump是Linux/Unix下的命令行网络抓包工具。

**主要功能：**
- 命令行式的数据包捕获
- 支持复杂的过滤表达式
- 可以保存和读取PCAP文件
- 轻量级，资源占用少

**常用过滤语法：**
- host 192.168.1.1：按主机过滤
- port 80：按端口过滤
- tcp：只显示TCP协议
- icmp：只显示ICMP协议
- net 192.168.1.0/24：按子网过滤

**与Wireshark的区别：**
- Tcpdump：命令行，适合服务器环境
- Wireshark：图形化，适合桌面环境
- 两者都使用libpcap库

**在本项目中的应用：**
- 服务器端抓包
- 脚本化的流量分析
""",
        "category": "security_tool",
    },
    {
        "title": "Snort入侵检测系统",
        "content": """
Snort是开源的网络入侵检测系统（IDS）和入侵防御系统（IPS）。

**主要功能：**
- 实时流量分析
- 数据包日志记录
- 基于规则的入侵检测
- 协议分析
- 内容搜索和匹配

**三种工作模式：**
- 嗅探模式：只读取数据包并显示
- 日志模式：将数据包记录到磁盘
- NIDS模式：网络入侵检测模式

**规则语法：**
```
alert tcp any any -> any 80 (content:"/etc/passwd"; msg:"Attempted access to /etc/passwd";)
```

**在本项目中的应用：**
- 规则引擎检测
- 签名匹配
- 已知攻击识别
""",
        "category": "security_tool",
    },
    {
        "title": "Metasploit渗透测试框架",
        "content": """
Metasploit是最流行的开源渗透测试框架。

**主要功能：**
- 漏洞利用（Exploit）：利用已知漏洞攻击目标
-  payload生成：生成攻击载荷
- 后渗透测试：获取权限后的横向移动
- 辅助模块：扫描、枚举、嗅探等

**组成部分：**
- msfconsole：命令行控制台
- msfvenom：payload生成器
- meterpreter：高级payload
- exploit：漏洞利用模块

**PCAP分析特征：**
- 异常的HTTP请求模式（漏洞利用尝试）
- 反向连接到可疑端口
- meterpreter通信特征
- 异常的编码或混淆数据

**检测方法：**
- 检测已知exploit的特征字符串
- 监控异常的出站连接
- 检测meterpreter的心跳包
""",
        "category": "security_tool",
    },
    {
        "title": "Burp Suite Web安全测试工具",
        "content": """
Burp Suite是Web应用安全测试的首选工具。

**主要功能：**
- Proxy代理：拦截和修改HTTP请求
- Scanner扫描器：自动发现Web漏洞
- Intruder入侵：暴力破解和模糊测试
- Repeater重放：手动修改和重放请求
- Decoder解码器：编码和解码

**工作原理：**
- 作为代理服务器，拦截浏览器和服务器之间的流量
- 可以修改请求和响应内容
- 支持插件扩展

**PCAP分析特征：**
- 大量相似的HTTP请求（Intruder暴力破解）
- 请求参数中有异常的Payload
- 异常的User-Agent（Burp Suite默认UA）

**在本项目中的应用：**
- Web漏洞检测
- SQL注入/XSS攻击识别
- 暴力破解行为分析
""",
        "category": "security_tool",
    },
    {
        "title": "Suricata下一代入侵检测系统",
        "content": """
Suricata是开源的下一代入侵检测和防御系统。

**与Snort的区别：**
- 多线程架构：性能更高
- 支持IP和HTTP日志
- 支持Lua脚本扩展
- 内置HTTPS/TLS检测

**主要功能：**
- 实时入侵检测
- 协议解析
- 内存马检测
- 文件提取

**规则语法：**
与Snort兼容，但增加了更多协议关键字。

**在本项目中的应用：**
- 高性能入侵检测
- 多线程流量分析
""",
        "category": "security_tool",
    },
    # ========== 加密协议 ==========
    {
        "title": "SSL/TLS加密协议",
        "content": """
SSL（Secure Sockets Layer）和TLS（Transport Layer Security）是用于Web通信的加密协议。

**版本演进：**
- SSL 1.0/2.0/3.0：已废弃
- TLS 1.0/1.1：已废弃
- TLS 1.2：当前主流
- TLS 1.3：最新版本，更快更安全

**工作原理：**
1. 握手阶段：协商加密算法、交换密钥
2. 证书验证：服务器出示证书，客户端验证
3. 加密传输：使用会话密钥加密应用数据

**PCAP分析特征：**
- TCP端口：443（HTTPS）
- 握手阶段可见：Client Hello、Server Hello、Certificate、Key Exchange
- 应用数据加密，无法直接解析内容

**异常检测：**
- 弱加密套件：使用已废弃的SSLv3或TLS1.0
- 证书问题：自签名证书、过期证书、域名不匹配
- 异常的握手失败：可能是中间人攻击或扫描
""",
        "category": "encryption_protocol",
    },
    {
        "title": "IPsec VPN协议",
        "content": """
IPsec（Internet Protocol Security）是网络层的安全协议套件。

**主要协议：**
- AH（Authentication Header）：认证头，提供完整性和认证
- ESP（Encapsulating Security Payload）：封装安全载荷，提供加密和完整性
- IKE（Internet Key Exchange）：互联网密钥交换，用于协商安全关联

**工作模式：**
- 传输模式：只加密 payload，保留原IP头
- 隧道模式：加密整个IP包，加新的IP头（VPN常用）

**PCAP分析特征：**
- IP协议号：50（ESP）、51（AH）
- UDP端口：500（IKEv1）、4500（IKEv2/NAT-T）
- ESP包：加密的 payload，无法直接解析内容

**与SSL VPN的区别：**
- IPsec VPN：网络层，加密整个网络流量，适合站点到站点
- SSL VPN：应用层，加密单个会话，适合远程用户访问
""",
        "category": "encryption_protocol",
    },
    # ========== 恶意软件 ==========
    {
        "title": "恶意软件类型与特征",
        "content": """
常见恶意软件类型及其网络特征：

**病毒（Virus）：**
- 需要宿主文件，感染可执行文件
- 网络特征：异常的文件上传/下载
- 传播方式：通过文件共享、邮件附件

**木马（Trojan）：**
- 伪装成合法软件，实际执行恶意功能
- 网络特征：连接到C2服务器（命令与控制）
- 常见端口：8080、4444、12345等

**勒索软件（Ransomware）：**
- 加密用户文件，索要赎金
- 网络特征：加密前的文件窃取流量
- 常见行为：连接到勒索服务器支付赎金

**蠕虫（Worm）：**
- 自我复制，通过网络传播
- 网络特征：大量扫描包，寻找漏洞
- 传播速度极快

**间谍软件（Spyware）：**
- 窃取用户信息和数据
- 网络特征：异常的数据外发流量
- 常见目标：浏览器历史、键盘记录、屏幕截图

**网络检测要点：**
- 异常的出站连接（到未知IP/域名）
- 定期的心跳包（C2通信）
- 异常大的数据上传量
- 扫描行为（端口扫描、漏洞扫描）
""",
        "category": "malware",
    },
]


def get_web_security_knowledge() -> list:
    """获取Web安全知识条目"""
    return WEB_SECURITY_KNOWLEDGE


def get_knowledge_count() -> int:
    """获取知识条目数量"""
    return len(WEB_SECURITY_KNOWLEDGE)
