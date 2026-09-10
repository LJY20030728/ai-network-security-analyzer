# -*- coding: utf-8 -*-
"""
P0-5 性能基准测试
测试不同大小 PCAP 的解析时间、内存峰值、检测耗时，生成基准报告。
用于简历中展示工程性能数据（如"1GB PCAP 解析耗时 XX 秒，内存峰值 XX MB"）。
"""
import os
import sys
import time
import json
import tracemalloc
import io

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_JSON = os.path.join(ROOT, "data/eval_perf/benchmark_result.json")


def benchmark_file(pcap_path: str, label: str) -> dict:
    """对单个 PCAP 文件进行基准测试"""
    from src.capture.pcap_parser import PcapParser
    from src.analysis.flow_extractor import TrafficAnalyzer

    if not os.path.exists(pcap_path):
        return {"label": label, "file": pcap_path, "error": "文件不存在"}

    file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    # 1. 解析时间 + 内存峰值
    tracemalloc.start()
    t0 = time.time()
    parser = PcapParser()
    packets = parser.parse_file(pcap_path)
    parse_time = time.time() - t0
    _, parse_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    parse_peak_mb = parse_peak / (1024 * 1024)

    # 2. 分析时间 + 内存峰值
    tracemalloc.start()
    t0 = time.time()
    analyzer = TrafficAnalyzer(use_baseline=False)
    report = analyzer.analyze_packets(packets)
    analyze_time = time.time() - t0
    _, analyze_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    analyze_peak_mb = analyze_peak / (1024 * 1024)

    total_time = parse_time + analyze_time
    total_peak_mb = max(parse_peak_mb, analyze_peak_mb)

    result = {
        "label": label,
        "file": os.path.basename(pcap_path),
        "file_size_mb": round(file_size_mb, 2),
        "total_packets": len(packets),
        "total_flows": report["summary"]["total_flows"],
        "total_bytes": report["summary"]["total_bytes"],
        "parse_time_sec": round(parse_time, 3),
        "analyze_time_sec": round(analyze_time, 3),
        "total_time_sec": round(total_time, 3),
        "parse_peak_mb": round(parse_peak_mb, 2),
        "analyze_peak_mb": round(analyze_peak_mb, 2),
        "total_peak_mb": round(total_peak_mb, 2),
        "packets_per_sec": round(len(packets) / total_time, 0) if total_time > 0 else 0,
        "mb_per_sec": round(file_size_mb / total_time, 2) if total_time > 0 else 0,
        "alerts": report["anomaly_detection"]["total_alerts"],
        "supervised_verdict": (report.get("supervised_detection") or {}).get("is_attack", None),
    }
    return result


def main():
    print("=" * 60)
    print("P0-5 性能基准测试")
    print("=" * 60)

    samples_dir = os.path.join(ROOT, "data/samples/golden")
    test_files = []

    # 收集所有可用的 pcap 文件
    if os.path.exists(samples_dir):
        for f in sorted(os.listdir(samples_dir)):
            if f.endswith(".pcap"):
                test_files.append((os.path.join(samples_dir, f), f.replace(".pcap", "")))

    if not test_files:
        print("未找到测试 PCAP 文件")
        return

    print(f"找到 {len(test_files)} 个测试文件\n")

    results = []
    for pcap_path, label in test_files:
        print(f"测试: {label}...", end=" ", flush=True)
        try:
            r = benchmark_file(pcap_path, label)
            results.append(r)
            if "error" in r:
                print(f"错误: {r['error']}")
            else:
                print(f"{r['total_packets']}包 | {r['total_time_sec']}s | "
                      f"峰值{r['total_peak_mb']}MB | {r['packets_per_sec']:.0f}包/s")
        except Exception as e:
            print(f"异常: {e}")
            results.append({"label": label, "error": str(e)})

    # 汇总统计
    valid_results = [r for r in results if "error" not in r]
    if valid_results:
        avg_time = sum(r["total_time_sec"] for r in valid_results) / len(valid_results)
        avg_peak = sum(r["total_peak_mb"] for r in valid_results) / len(valid_results)
        max_packets = max(r["total_packets"] for r in valid_results)
        max_time = max(r["total_time_sec"] for r in valid_results)

        summary = {
            "tested_files": len(valid_results),
            "avg_total_time_sec": round(avg_time, 3),
            "avg_peak_mb": round(avg_peak, 2),
            "max_packets": max_packets,
            "max_time_sec": round(max_time, 3),
            "total_packets_all": sum(r["total_packets"] for r in valid_results),
        }
    else:
        summary = {"tested_files": 0}

    output = {
        "benchmark": "PCAP 解析与分析性能基准",
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
        "summary": summary,
        "results": results,
    }

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n{'=' * 60}")
    print(f"基准测试完成！测试 {summary.get('tested_files', 0)} 个文件")
    print(f"平均耗时: {summary.get('avg_total_time_sec', 0)}s")
    print(f"平均内存峰值: {summary.get('avg_peak_mb', 0)}MB")
    print(f"总包数: {summary.get('total_packets_all', 0)}")
    print(f"结果已保存: {OUT_JSON}")
    print("=" * 60)


if __name__ == "__main__":
    main()
