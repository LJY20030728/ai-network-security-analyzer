"""
RAG检索质量评测
================
黄金问答集 + Recall@k计算
用于量化评估知识库检索效果
"""
from typing import List, Dict, Tuple
from loguru import logger


# ============================================================
# 黄金问答集：每条问题对应正确的知识条目标题（精确匹配）
# ============================================================
GOLDEN_QUESTIONS = [
    # --- 路由协议 ---
    {
        "question": "OSPF路由协议使用哪个协议号？",
        "expected_title": "OSPF路由协议 - 开放最短路径优先",
        "category": "routing_protocol",
    },
    {
        "question": "BGP协议运行在哪个TCP端口上？",
        "expected_title": "BGP路由协议 - 边界网关协议",
        "category": "routing_protocol",
    },
    {
        "question": "RIP协议的最大跳数是多少？",
        "expected_title": "RIP路由协议 - 路由信息协议",
        "category": "routing_protocol",
    },

    # --- 传输协议 ---
    {
        "question": "TCP三次握手的过程是什么？",
        "expected_title": "TCP协议 - 传输控制协议",
        "category": "transport_protocol",
    },
    {
        "question": "UDP协议的特点是什么？",
        "expected_title": "UDP协议 - 用户数据报协议",
        "category": "transport_protocol",
    },
    {
        "question": "ICMP协议的Echo Request类型号是多少？",
        "expected_title": "ICMP协议 - 互联网控制报文协议",
        "category": "network_protocol",
    },
    {
        "question": "ARP协议的作用是什么？",
        "expected_title": "ARP协议 - 地址解析协议",
        "category": "network_protocol",
    },

    # --- 网络设备 ---
    {
        "question": "路由器工作在OSI模型的哪一层？",
        "expected_title": "网络设备类型与功能",
        "category": "network_device",
    },
    {
        "question": "VLAN的802.1Q标签TPID值是多少？",
        "expected_title": "VLAN与网络分段",
        "category": "network_segment",
    },

    # --- 常见端口 ---
    {
        "question": "SSH服务默认使用哪个端口？",
        "expected_title": "常见端口与服务对照表",
        "category": "common_port",
    },
    {
        "question": "RDP远程桌面协议默认端口是多少？",
        "expected_title": "常见端口与服务对照表",
        "category": "common_port",
    },

    # --- 网络攻击 ---
    {
        "question": "什么是SYN Flood攻击？",
        "expected_title": "常见网络攻击类型与检测特征",
        "category": "security_attack",
    },
    {
        "question": "端口扫描的类型有哪些？",
        "expected_title": "常见网络攻击类型与检测特征",
        "category": "security_attack",
    },
    {
        "question": "网络流量分析的基线方法有哪些？",
        "expected_title": "网络流量分析指标与基线",
        "category": "traffic_analysis",
    },

    # --- MITRE ATT&CK ---
    {
        "question": "T1046是什么攻击技术？",
        "expected_title": "MITRE ATT&CK T1046 - 网络服务扫描",
        "category": "mitre_attack",
    },
    {
        "question": "T1110暴力破解攻击如何检测？",
        "expected_title": "MITRE ATT&CK T1110 - 暴力破解",
        "category": "mitre_attack",
    },
    {
        "question": "T1498网络拒绝服务攻击的特征是什么？",
        "expected_title": "MITRE ATT&CK T1498 - 网络拒绝服务",
        "category": "mitre_attack",
    },
    {
        "question": "T1572协议隧道是什么？",
        "expected_title": "MITRE ATT&CK T1572 - 协议隧道",
        "category": "mitre_attack",
    },

    # --- 处置手册 ---
    {
        "question": "端口扫描事件如何处置？",
        "expected_title": "端口扫描事件处置手册",
        "category": "response_playbook",
    },
    {
        "question": "DDoS攻击的应急响应步骤是什么？",
        "expected_title": "DDoS攻击事件处置手册",
        "category": "response_playbook",
    },
    {
        "question": "DNS隧道如何检测和处置？",
        "expected_title": "DNS隧道检测与处置手册",
        "category": "response_playbook",
    },

    # --- Web安全 ---
    {
        "question": "什么是SQL注入攻击？",
        "expected_title": "SQL注入攻击",
        "category": "web_attack",
    },
    {
        "question": "XSS跨站脚本攻击有哪些类型？",
        "expected_title": "XSS跨站脚本攻击",
        "category": "web_attack",
    },
    {
        "question": "CSRF和XSS有什么区别？",
        "expected_title": "CSRF跨站请求伪造",
        "category": "web_attack",
    },
    {
        "question": "命令注入攻击常用的分隔符有哪些？",
        "expected_title": "命令注入攻击",
        "category": "web_attack",
    },

    # --- 安全工具 ---
    {
        "question": "Wireshark的主要功能是什么？",
        "expected_title": "Wireshark网络封包分析工具",
        "category": "security_tool",
    },
    {
        "question": "Nmap的SYN扫描是什么原理？",
        "expected_title": "Nmap网络扫描工具",
        "category": "security_tool",
    },
    {
        "question": "Snort有哪三种工作模式？",
        "expected_title": "Snort入侵检测系统",
        "category": "security_tool",
    },

    # --- 加密协议 ---
    {
        "question": "TLS握手过程是怎样的？",
        "expected_title": "SSL/TLS加密协议",
        "category": "encryption_protocol",
    },
    {
        "question": "IPsec和SSL VPN有什么区别？",
        "expected_title": "IPsec VPN协议",
        "category": "encryption_protocol",
    },

    # --- 恶意软件 ---
    {
        "question": "勒索软件的网络特征是什么？",
        "expected_title": "恶意软件类型与特征",
        "category": "malware",
    },
]


def run_rag_benchmark(rag_engine, top_k_list: List[int] = [1, 3, 5, 10]) -> Dict:
    """
    运行RAG召回率评测
    :param rag_engine: RAG引擎实例
    :param top_k_list: 要计算的k值列表
    :return: 评测结果字典
    """
    questions = GOLDEN_QUESTIONS
    total = len(questions)

    # 初始化统计
    hits = {k: 0 for k in top_k_list}
    per_category = {}
    failed_cases = []

    logger.info(f"开始RAG召回率评测 | 总问题数: {total}")

    for i, q in enumerate(questions):
        question = q["question"]
        expected = q["expected_title"]
        category = q["category"]

        # 检索前10个结果（足够覆盖所有k值）
        results = rag_engine.search(question, top_k=10, use_hybrid=True)

        # 提取检索到的标题
        retrieved_titles = []
        for r in results:
            meta = r.get("metadata", {}) or {}
            title = meta.get("title", "")
            retrieved_titles.append(title)

        # 计算每个k值的命中情况
        for k in top_k_list:
            top_k_titles = retrieved_titles[:k]
            if expected in top_k_titles:
                hits[k] += 1

        # 分类统计
        if category not in per_category:
            per_category[category] = {"total": 0, "hits@5": 0}
        per_category[category]["total"] += 1
        if expected in retrieved_titles[:5]:
            per_category[category]["hits@5"] += 1

        # 记录失败案例
        if expected not in retrieved_titles[:5]:
            failed_cases.append({
                "question": question,
                "expected": expected,
                "retrieved_top3": retrieved_titles[:3],
            })

        # 进度日志
        if (i + 1) % 10 == 0:
            logger.info(f"  进度: {i+1}/{total}")

    # 计算Recall@k
    recall_results = {}
    for k in top_k_list:
        recall = hits[k] / total if total > 0 else 0
        recall_results[f"recall@{k}"] = round(recall * 100, 1)

    # 分类统计
    category_stats = {}
    for cat, stats in per_category.items():
        rate = stats["hits@5"] / stats["total"] if stats["total"] > 0 else 0
        category_stats[cat] = {
            "total": stats["total"],
            "hits@5": stats["hits@5"],
            "recall@5": round(rate * 100, 1),
        }

    result = {
        "total_questions": total,
        "recall": recall_results,
        "category_stats": category_stats,
        "failed_cases": failed_cases,
        "failed_count": len(failed_cases),
    }

    logger.info(f"评测完成 | Recall@1: {recall_results['recall@1']}% | "
                f"Recall@5: {recall_results['recall@5']}%")

    return result


def format_benchmark_report(result: Dict) -> str:
    """格式化评测报告为Markdown"""
    lines = []
    lines.append("### 📊 RAG检索质量评测报告")
    lines.append("")
    lines.append(f"**总测试问题数**: {result['total_questions']}")
    lines.append("")

    # 总体召回率
    lines.append("#### 总体召回率")
    lines.append("")
    for k, v in result["recall"].items():
        lines.append(f"- **{k}**: {v}%")
    lines.append("")

    # 分类统计
    lines.append("#### 分类表现（Recall@5）")
    lines.append("")
    lines.append("| 类别 | 问题数 | 命中数 | Recall@5 |")
    lines.append("|------|--------|--------|----------|")
    for cat, stats in sorted(result["category_stats"].items()):
        lines.append(f"| {cat} | {stats['total']} | {stats['hits@5']} | {stats['recall@5']}% |")
    lines.append("")

    # 失败案例
    if result["failed_cases"]:
        lines.append("#### ❌ 失败案例（Top 3）")
        lines.append("")
        for i, fc in enumerate(result["failed_cases"][:3]):
            lines.append(f"**{i+1}. 问题**: {fc['question']}")
            lines.append(f"   - 期望命中: {fc['expected']}")
            lines.append(f"   - 实际Top3: {', '.join(fc['retrieved_top3']) or '无结果'}")
            lines.append("")

    return "\n".join(lines)
