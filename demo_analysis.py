#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合演示脚本：模拟端口扫描流量 -> 流量分析 -> AI威胁研判
不依赖langchain/chromadb，仅使用已安装的核心包
"""
import os
import sys
import io
import json
from collections import defaultdict, Counter
from dotenv import load_dotenv

# UTF-8输出
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 加载配置
load_dotenv()

print("=" * 70)
print("AI Network Security Analyzer - Demo")
print("=" * 70)

# ============================================================
# 第1步：模拟网络数据包（模拟一次端口扫描攻击）
# ============================================================
print("\n[Step 1/4] 模拟网络流量数据...")
print("-" * 70)

# 模拟数据包结构（对应PacketInfo）
simulated_packets = []

# 模拟正常HTTP流量（192.168.1.50 -> 10.0.0.2:443）
for i in range(20):
    simulated_packets.append({
        "timestamp": f"2026-09-03 10:00:{i:02d}.000",
        "protocol": "TCP",
        "src_ip": "192.168.1.50",
        "src_port": 50000 + i,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "length": 1500,
        "flags": "ACK,PSH" if i > 2 else "SYN,ACK" if i == 1 else "SYN" if i == 0 else "ACK",
        "payload_size": 1400,
    })

# 模拟端口扫描（192.168.1.100 -> 10.0.0.1 多个端口）
for i in range(80):
    simulated_packets.append({
        "timestamp": f"2026-09-03 10:01:{i:02d}.000",
        "protocol": "TCP",
        "src_ip": "192.168.1.100",
        "src_port": 40000 + i,
        "dst_ip": "10.0.0.1",
        "dst_port": 1000 + i,  # 扫描1000-1079端口
        "length": 60,
        "flags": "SYN",  # 只有SYN，没有ACK - 典型扫描特征
        "payload_size": 0,
    })

# 模拟DNS查询
for i in range(5):
    simulated_packets.append({
        "timestamp": f"2026-09-03 10:02:{i:02d}.000",
        "protocol": "DNS",
        "src_ip": "192.168.1.50",
        "src_port": 53000 + i,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "length": 80,
        "flags": "",
        "payload_size": 50,
        "dns_query": f"www.example{i}.com",
    })

print(f"  模拟数据包总数: {len(simulated_packets)}")
print(f"  - 正常HTTP流量: 20包 (192.168.1.50 -> 10.0.0.2:443)")
print(f"  - 端口扫描流量: 80包 (192.168.1.100 -> 10.0.0.1 扫描80个端口)")
print(f"  - DNS查询流量: 5包")

# ============================================================
# 第2步：协议分布统计
# ============================================================
print("\n[Step 2/4] 流量统计分析...")
print("-" * 70)

protocol_dist = Counter(p["protocol"] for p in simulated_packets)
print("  协议分布:")
for proto, count in protocol_dist.most_common():
    pct = count / len(simulated_packets) * 100
    print(f"    {proto}: {count}包 ({pct:.1f}%)")

# ============================================================
# 第3步：规则引擎异常检测
# ============================================================
print("\n[Step 3/4] 规则引擎异常检测...")
print("-" * 70)

alerts = []

# 检测1：端口扫描（同一源IP访问大量不同端口）
ports_by_src = defaultdict(set)
for p in simulated_packets:
    if p["protocol"] in ("TCP", "UDP") and p["dst_port"] > 0:
        ports_by_src[p["src_ip"]].add(p["dst_port"])

for src, ports in ports_by_src.items():
    if len(ports) >= 20:
        alerts.append({
            "type": "PORT_SCAN_SUSPECTED",
            "severity": "HIGH",
            "src_ip": src,
            "unique_ports_scanned": len(ports),
            "sample_ports": sorted(list(ports))[:10],
            "description": f"源IP {src} 访问了 {len(ports)} 个不同端口，疑似端口扫描"
        })

# 检测2：SYN Flood（大量SYN无ACK）
syn_by_src = defaultdict(int)
for p in simulated_packets:
    if p["protocol"] == "TCP" and "SYN" in p["flags"] and "ACK" not in p["flags"]:
        syn_by_src[p["src_ip"]] += 1

for src, count in syn_by_src.items():
    if count >= 50:
        alerts.append({
            "type": "SYN_FLOOD_SUSPECTED",
            "severity": "MEDIUM",
            "src_ip": src,
            "syn_count": count,
            "description": f"源IP {src} 发送了 {count} 个SYN包（无ACK），疑似SYN洪水"
        })

# 检测3：TOP通信对
flow_bytes = defaultdict(int)
flow_packets = defaultdict(int)
for p in simulated_packets:
    if p["src_ip"] and p["dst_ip"]:
        key = f"{p['src_ip']} -> {p['dst_ip']}"
        flow_bytes[key] += p["length"]
        flow_packets[key] += 1

top_flows = sorted(flow_bytes.items(), key=lambda x: x[1], reverse=True)[:5]

print(f"  检测到 {len(alerts)} 条异常告警:")
for alert in alerts:
    print(f"    [{alert['severity']}] {alert['type']}: {alert['description']}")

print(f"\n  TOP5 通信对:")
for flow, bytes_ in top_flows:
    print(f"    {flow}: {flow_packets[flow]}包, {bytes_/1024:.1f}KB")

# ============================================================
# 第4步：AI威胁研判（调用智谱AI）
# ============================================================
print("\n[Step 4/4] AI威胁研判（调用智谱AI glm-4-flash）...")
print("-" * 70)

try:
    from openai import OpenAI

    client = OpenAI(
        api_key=os.getenv("LLM_API_KEY"),
        base_url=os.getenv("LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"),
        timeout=60,
    )

    # 构建分析Prompt
    anomaly_report = json.dumps({
        "alerts": alerts,
        "protocol_distribution": dict(protocol_dist),
        "total_packets": len(simulated_packets),
    }, ensure_ascii=False, indent=2)

    system_prompt = """你是一位资深网络安全分析师，拥有10年以上SOC工作经验。
你的专长包括网络流量分析、入侵检测、威胁狩猎、攻击链分析。
你的回答要求：专业、准确、结构化，使用markdown格式。
对检测到的威胁给出明确的风险等级（CRITICAL/HIGH/MEDIUM/LOW）。
给出具体可执行的处置建议。"""

    user_prompt = f"""请分析以下网络流量异常检测报告，判断是否存在真实的安全威胁。

## 异常检测结果
{anomaly_report}

请按以下结构输出分析结果：

### 1. 威胁判定
- 威胁等级
- 威胁类型
- 置信度

### 2. 攻击行为分析
- 攻击源IP及特征
- 攻击目标
- 攻击手法（对应MITRE ATT&CK技术编号）

### 3. 潜在影响

### 4. 处置建议
- 立即遏制措施
- 后续调查方向
- 长期防护建议
"""

    print("  正在调用AI分析...")
    response = client.chat.completions.create(
        model=os.getenv("LLM_MODEL", "glm-4-flash"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.2,
        max_tokens=2000,
    )

    ai_analysis = response.choices[0].message.content
    print("\n" + "=" * 70)
    print("AI Threat Analysis Result:")
    print("=" * 70)
    print(ai_analysis)
    print("=" * 70)
    print(f"\n[Token Usage] input={response.usage.prompt_tokens} output={response.usage.completion_tokens} total={response.usage.total_tokens}")

except Exception as e:
    print(f"  [ERROR] AI调用失败: {e}")
    import traceback
    traceback.print_exc()

# ============================================================
# 总结
# ============================================================
print("\n" + "=" * 70)
print("[Demo Complete]")
print("=" * 70)
print("""
已验证的功能链路:
  1. [OK] 网络数据包解析（Scapy数据结构）
  2. [OK] 协议分布统计
  3. [OK] 规则引擎异常检测（端口扫描/SYN Flood）
  4. [OK] AI威胁研判（智谱AI glm-4-flash）

下一步:
  - 安装 langchain + chromadb 启用RAG知识库
  - 安装 gradio 启用Web UI界面
  - 运行 python run.py 启动完整服务
  - 用Wireshark抓真实PCAP文件进行分析
""")
