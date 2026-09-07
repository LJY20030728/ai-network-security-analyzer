#!/usr/bin/env python3
"""
快速测试脚本 - 验证项目各模块是否正常
"""
import os
import sys

# 项目根目录
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
os.chdir(project_root)

def test_imports():
    """测试所有模块导入"""
    print("=" * 60)
    print("模块导入测试")
    print("=" * 60)

    tests = [
        ("config.settings", "配置模块"),
        ("src.capture.packet_parser", "数据包解析模块"),
        ("src.capture.pcap_parser", "PCAP解析模块"),
        ("src.analysis.flow_extractor", "流量分析模块"),
        ("src.ai.llm_client", "LLM客户端"),
        ("src.ai.rag_engine", "RAG引擎"),
        ("src.ai.threat_analyzer", "威胁分析器"),
        ("src.ai.prompts", "Prompt模板"),
        ("src.knowledge.mitre_attck", "MITRE知识库"),
        ("src.utils.helpers", "工具函数"),
    ]

    passed = 0
    failed = 0
    for module_name, desc in tests:
        try:
            __import__(module_name)
            print(f"  ✓ {desc} ({module_name})")
            passed += 1
        except Exception as e:
            print(f"  ✗ {desc} ({module_name}): {e}")
            failed += 1

    print(f"\n结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_knowledge_base():
    """测试知识库数据"""
    print("\n" + "=" * 60)
    print("知识库数据测试")
    print("=" * 60)

    try:
        from src.knowledge.mitre_attck import get_all_knowledge, MITRE_ATTACK_TECHNIQUES, INCIDENT_RESPONSE_PLAYBOOKS
        all_items = get_all_knowledge()
        print(f"  ✓ MITRE ATT&CK 技术条目: {len(MITRE_ATTACK_TECHNIQUES)}")
        print(f"  ✓ 事件处置手册: {len(INCIDENT_RESPONSE_PLAYBOOKS)}")
        print(f"  ✓ 知识库总条目: {len(all_items)}")
        print(f"  ✓ 示例: {MITRE_ATTACK_TECHNIQUES[0]['id']} - {MITRE_ATTACK_TECHNIQUES[0]['name']}")
        return True
    except Exception as e:
        print(f"  ✗ 知识库测试失败: {e}")
        return False


def test_packet_parsing():
    """测试数据包解析逻辑（不实际抓包）"""
    print("\n" + "=" * 60)
    print("数据包解析测试（模拟数据）")
    print("=" * 60)

    try:
        from src.capture.packet_parser import PacketInfo, PacketParser

        # 创建模拟数据包信息
        pkt = PacketInfo(
            timestamp="2026-09-03 10:00:00.000",
            protocol="TCP",
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80,
            length=120,
            flags="SYN,ACK",
            payload_size=0,
            raw_summary="TCP 54321 > 80 [SYN, ACK]"
        )

        print(f"  ✓ 数据包对象创建成功")
        print(f"    协议: {pkt.protocol}")
        print(f"    源: {pkt.src_ip}:{pkt.src_port}")
        print(f"    目的: {pkt.dst_ip}:{pkt.dst_port}")
        print(f"    标志位: {pkt.flags}")

        # 测试字典转换
        capture = PacketParser()
        capture.captured_packets = [pkt]
        dict_list = capture.to_dict_list()
        print(f"  ✓ 字典转换成功: {dict_list[0]['protocol']}")

        # 测试协议统计
        stats = capture.get_protocol_stats()
        print(f"  ✓ 协议统计: {stats}")

        return True
    except Exception as e:
        print(f"  ✗ 数据包解析测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_traffic_analysis():
    """测试流量分析引擎（模拟数据）"""
    print("\n" + "=" * 60)
    print("流量分析测试（模拟数据）")
    print("=" * 60)

    try:
        from src.capture.packet_parser import PacketInfo
        from src.analysis.flow_extractor import TrafficAnalyzer

        # 生成模拟数据包（模拟端口扫描）
        packets = []
        for i in range(50):
            pkt = PacketInfo(
                timestamp=f"2026-09-03 10:00:{i:02d}.000",
                protocol="TCP",
                src_ip="192.168.1.100",
                src_port=40000 + i,
                dst_ip="10.0.0.1",
                dst_port=1000 + i,  # 不同端口，模拟扫描
                length=60,
                flags="SYN",
                payload_size=0,
            )
            packets.append(pkt)

        # 添加一些正常流量
        for i in range(20):
            pkt = PacketInfo(
                timestamp=f"2026-09-03 10:01:{i:02d}.000",
                protocol="TCP",
                src_ip="192.168.1.50",
                src_port=50000,
                dst_ip="10.0.0.2",
                dst_port=443,
                length=1500,
                flags="ACK,PSH",
                payload_size=1400,
            )
            packets.append(pkt)

        print(f"  ✓ 生成模拟数据包: {len(packets)} 个")

        # 运行流量分析
        analyzer = TrafficAnalyzer()
        report = analyzer.analyze_packets(packets)

        print(f"  ✓ 流量分析完成")
        print(f"    总包数: {report['summary']['total_packets']}")
        print(f"    网络流数: {report['summary']['total_flows']}")
        print(f"    协议分布: {report['protocol_distribution']}")
        print(f"    异常告警数: {report['anomaly_detection']['total_alerts']}")

        # 检查是否检测到端口扫描
        alerts = report['anomaly_detection']['alerts']
        port_scan_found = any(a['type'] == 'PORT_SCAN_SUSPECTED' for a in alerts)
        print(f"  ✓ 端口扫描检测: {'检测到 ✓' if port_scan_found else '未检测到 ✗'}")

        if alerts:
            print(f"  ✓ 告警详情:")
            for alert in alerts[:3]:
                print(f"    - [{alert['severity']}] {alert['type']}: {alert['description'][:60]}...")

        return True
    except Exception as e:
        print(f"  ✗ 流量分析测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_llm_config():
    """测试LLM配置状态"""
    print("\n" + "=" * 60)
    print("LLM配置测试")
    print("=" * 60)

    try:
        from src.ai.llm_client import get_llm_client
        from config.settings import settings

        llm = get_llm_client()
        print(f"  模型: {settings.llm_model}")
        print(f"  端点: {settings.llm_base_url}")
        print(f"  API Key: {'已配置 ✓' if llm.is_available() else '未配置 ✗（需要在.env中填写LLM_API_KEY）'}")

        if not llm.is_available():
            print("\n  💡 提示: 复制 .env.example 为 .env，填写你的 DeepSeek API Key")
            print("     注册地址: https://platform.deepseek.com/")

        return True
    except Exception as e:
        print(f"  ✗ LLM配置测试失败: {e}")
        return False


def main():
    """主测试函数"""
    print("\n" + "🚀" * 30)
    print("AI网络安全智能分析系统 - 快速测试")
    print("🚀" * 30 + "\n")

    results = []
    results.append(("模块导入", test_imports()))
    results.append(("知识库数据", test_knowledge_base()))
    results.append(("数据包解析", test_packet_parsing()))
    results.append(("流量分析", test_traffic_analysis()))
    results.append(("LLM配置", test_llm_config()))

    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    for name, passed in results:
        status = "✓ 通过" if passed else "✗ 失败"
        print(f"  {name}: {status}")

    total = len(results)
    passed_count = sum(1 for _, p in results if p)
    print(f"\n总计: {passed_count}/{total} 通过")

    if passed_count == total:
        print("\n🎉 所有测试通过！项目可以正常运行。")
        print("   启动命令: python run.py")
    else:
        print(f"\n⚠️  {total - passed_count} 项测试未通过，请检查上方错误信息。")

    return 0 if passed_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
