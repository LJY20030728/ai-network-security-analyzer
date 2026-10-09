# -*- coding: utf-8 -*-
"""黄金样本回归验证：基线学习 + 攻击样本检测命中"""

# 受限环境（权限收紧的终端 / CI 沙箱）下 joblib 无法创建多进程命名管道，
# 会直接 PermissionError: [WinError 5]。所有评测脚本强制走线程后端，
# 保证结果可在任意环境复现（算法本身不变）。
import os as _os
_os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")
_os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
try:
    import joblib as _joblib
    _joblib.parallel_backend("threading", n_jobs=1).__enter__()
except Exception:
    pass

import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger

# Windows 控制台默认 GBK，直接打印中文/emoji 会抛 UnicodeEncodeError
try:
    from src.utils.helpers import force_utf8_stdout
    force_utf8_stdout()
except Exception:
    pass

logger.remove()  # 关闭日志噪音
logger.add(io.StringIO(), level="ERROR")

from src.capture.pcap_parser import PcapParser
from src.analysis.flow_extractor import TrafficAnalyzer

GOLDEN = "data/samples/golden"

# 期望命中映射：样本 → 期望告警类型
EXPECTED = {
    "synflood": ["SYN_FLOOD_SUSPECTED"],
    "portscan": ["PORT_SCAN_SUSPECTED"],
    "dnstunnel": ["DNS_TUNNEL_SUSPECTED"],
    "largeflow": ["LARGE_DATA_TRANSFER"],
    "rststorm": ["RST_STORM"],
}


def load_packets(name):
    parser = PcapParser()
    path = os.path.join(GOLDEN, f"{name}.pcap")
    return parser.parse_file(path)


def main():
    print("=" * 60)
    print("黄金样本回归验证")
    print("=" * 60)

    # 1. 正常流量学习基线
    print("\n[1] 学习阶段：normal.pcap → EWMA 基线")
    normal_pkts = load_packets("normal")
    analyzer = TrafficAnalyzer(use_baseline=True)
    analyzer.learn_baseline(normal_pkts)
    profile = analyzer.baseline.to_dict()
    print(f"    基线维度画像: {json.dumps({k: v['median'] for k, v in profile['profile'].items()}, ensure_ascii=False)}")

    # 2. 正常流量自测（应无告警或极少告警）
    print("\n[2] 正常流量自测（期望告警数极少）")
    normal_report = analyzer.analyze_packets(normal_pkts)
    normal_alerts = normal_report["anomaly_detection"]["alerts"]
    print(f"    normal 告警数: {len(normal_alerts)}")
    for a in normal_alerts[:5]:
        print(f"      - [{a['severity']}] {a['type']}: {a['description'][:60]}")

    # 3. 攻击样本检测
    print("\n[3] 攻击样本检测（期望全部命中对应告警）")
    results = []
    all_pass = True
    for name, expected_types in EXPECTED.items():
        pkts = load_packets(name)
        report = analyzer.analyze_packets(pkts)
        alerts = report["anomaly_detection"]["alerts"]
        hit_types = {a["type"] for a in alerts}
        missing = [e for e in expected_types if e not in hit_types]
        ok = not missing
        all_pass = all_pass and ok
        results.append({
            "sample": name,
            "packets": len(pkts),
            "alerts": len(alerts),
            "hit": sorted(hit_types),
            "missing": missing,
            "pass": ok,
        })
        status = "✅" if ok else "❌"
        print(f"    {status} {name:10s} | {len(pkts):>5}包 | 告警 {len(alerts):>2}条 | 命中: {sorted(hit_types)}")
        if missing:
            print(f"        未命中: {missing}")

    # 4. 基线偏差检测验证（对 synflood 看 window_syn 偏差）
    print("\n[4] 时序基线偏差检测（synflood 的 window_syn 应超阈值）")
    syn_pkts = load_packets("synflood")
    syn_report = analyzer.analyze_packets(syn_pkts)
    baseline_alerts = [a for a in syn_report["anomaly_detection"]["alerts"] if a["type"] == "BASELINE_DEVIATION"]
    print(f"    synflood 中基线偏差告警: {len(baseline_alerts)} 条")
    for a in baseline_alerts[:3]:
        print(f"      - [{a['severity']}] {a.get('dimension_label','')}: z={a.get('z_score')}, 值={a.get('value')}, 基线中位数={a.get('baseline_median')}")

    # 汇总
    print("\n" + "=" * 60)
    total_pass = all_pass and len(normal_alerts) <= 3
    print(f"回归结果: {'全部通过 ✅' if total_pass else '存在失败 ❌'}")
    print(f"  攻击样本命中: {sum(1 for r in results if r['pass'])}/{len(results)}")
    print(f"  正常流量误报: {len(normal_alerts)} 条（阈值 ≤3）")

    manifest = {"generated_at": "golden regression", "normal_alerts": len(normal_alerts),
                "attack_hits": results, "baseline_profile": profile["profile"]}
    with open(os.path.join(GOLDEN, "regression_result.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"  结果已写入: {GOLDEN}/regression_result.json")

    sys.exit(0 if total_pass else 1)


if __name__ == "__main__":
    main()
