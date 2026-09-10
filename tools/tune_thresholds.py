# -*- coding: utf-8 -*-
"""P0-2 规则阈值网格搜索调优（数据驱动替代拍脑袋）
两条数据源：
A. UNSW-NB15（匿名流特征，可测 LARGE 流级 + RST 窗口级近似）
B. 黄金样本（synflood/portscan/dnstunnel/rststorm pcap，可测全规则 + normal 误报约束）
输出: data/eval_cicids/threshold_tuning.json + data/eval_perf/threshold_tuning_golden.json
"""
import io, json, os, sys, itertools
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from loguru import logger
logger.remove()

CSV = os.path.join(ROOT, "data/eval_cicids/csv/UNSW_NB15_training-set.csv")
GOLDEN = os.path.join(ROOT, "data/samples/golden")

# ---------- A. UNSW 流级/窗口级 ----------
def parse_unsw(path):
    import csv
    records = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader):
            label_raw = (r.get("Label") or r.get("label") or "").strip()
            cat = (r.get("attack_cat") or "Normal").strip()
            try:
                sbytes = float(r.get("sbytes") or 0)
                dbytes = float(r.get("dbytes") or 0)
                dpkts = float(r.get("dpkts") or 0)
                spkts = float(r.get("spkts") or 0)
            except (ValueError, TypeError):
                continue
            state = (r.get("state") or "").upper()
            records.append({
                "bytes": sbytes + dbytes,
                "is_rst": "RST" in state or (r.get("res_bdy_len") == "0" and "REQ" in state),
                "label": 1 if label_raw == "1" else 0,
                "cat": cat,
            })
    return records

def eval_large(records, mb):
    tp = fp = fn = 0
    for r in records:
        hit = r["bytes"] > mb * 1024 * 1024
        if hit and r["label"] == 1: tp += 1
        elif hit and r["label"] == 0: fp += 1
        elif not hit and r["label"] == 1: fn += 1
    return _metrics(tp, fp, fn, len(records) - tp - fp - fn)

def eval_rst_window(records, cnt, win=30):
    # 合成窗口：每 win 条流一个窗口（与产品窗口近似），窗口内 RST 流数 >= cnt → 告警
    tp = fp = fn = tn = 0
    for i in range(0, len(records), win):
        w = records[i:i+win]
        rst = sum(1 for r in w if r["is_rst"])
        has_attack = any(r["label"] == 1 for r in w)
        hit = rst >= cnt
        if hit and has_attack: tp += 1
        elif hit and not has_attack: fp += 1
        elif not hit and has_attack: fn += 1
        else: tn += 1
    return _metrics(tp, fp, fn, tn)

def _metrics(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}

# ---------- B. 黄金样本全管道 ----------
def preload_golden():
    """预解析全部 golden pcap，返回 {文件名: packets}"""
    from src.capture.pcap_parser import PcapParser
    parser = PcapParser()
    cache = {}
    for fn in sorted(os.listdir(GOLDEN)):
        if not fn.endswith(".pcap"):
            continue
        cache[fn] = parser.parse_file(os.path.join(GOLDEN, fn))
    return cache

def eval_golden_rule(param_updates, preloaded):
    """修改 settings 后跑 golden 全量检测（packets 已预解析）"""
    from config.settings import settings
    from src.analysis.flow_extractor import TrafficAnalyzer
    for k, v in param_updates.items():
        setattr(settings, k, v)
    hits = 0
    nfp = 0
    total_attacks = 0
    for fn, packets in preloaded.items():
        analyzer = TrafficAnalyzer()
        report = analyzer.analyze_packets(packets)
        alerts = report["anomaly_detection"]["alerts"]
        if fn == "normal.pcap":
            nfp += len(alerts)
        else:
            total_attacks += 1
            if alerts:
                hits += 1
    return hits, nfp, total_attacks

def main():
    # A. UNSW
    print("[A] UNSW-NB15 阈值网格搜索")
    recs = parse_unsw(CSV)
    print(f"  流数: {len(recs)}, 攻击流: {sum(1 for r in recs if r['label'])}")
    best_lf, best_rst = None, None
    large_grid = [1, 2, 5, 10, 15, 20, 30, 50]
    rst_grid = [10, 20, 30, 40, 50, 60, 80, 100]
    lf_rows, rst_rows = [], []
    for mb in large_grid:
        m = eval_large(recs, mb)
        lf_rows.append({"mb": mb, **m})
        if best_lf is None or m["f1"] > best_lf["f1"]:
            best_lf = {"mb": mb, **m}
    for cnt in rst_grid:
        m = eval_rst_window(recs, cnt)
        rst_rows.append({"count": cnt, **m})
        if best_rst is None or m["f1"] > best_rst["f1"]:
            best_rst = {"count": cnt, **m}
    print(f"  LARGE 最优: {best_lf}")
    print(f"  RST 最优: {best_rst}")

    result = {
        "method": "网格搜索（数据驱动），UNSW-NB15 匿名流级",
        "caveat": "UNSW 无 IP/SYN/DNS 字段：LARGE 为流级精确；RST 为窗口级近似（产品为单源语义）",
        "large_flow": {"grid": lf_rows, "best": best_lf, "current": 10.0},
        "rst_window": {"grid": rst_rows, "best": best_rst, "current": 50},
        "recommended_updates": {"large_flow_min_mb": best_lf["mb"], "rst_storm_min_count": best_rst["count"]},
    }
    out = os.path.join(ROOT, "data/eval_cicids/threshold_tuning.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[OK] 写入 {out}")

    # B. 黄金样本
    print("\n[B] 黄金样本全管道验证（含 normal 误报约束）")
    preloaded = preload_golden()
    print(f"  预解析完成: {len(preloaded)} 个样本")
    cands = [
        {"syn_flood_min_count": [80, 100, 150], "port_scan_min_ports": [15, 20],
         "dns_tunnel_min_count": [3, 5], "rst_storm_min_count": [30, 40, 50]},
    ]
    best = None
    keys = list(cands[0].keys())
    grids = [cands[0][k] for k in keys]
    for combo in itertools.product(*grids):
        upd = dict(zip(keys, combo))
        hits, nfp, total = eval_golden_rule(upd, preloaded)
        # 目标：全部攻击命中 + normal 0 误报；优先命中，再压误报
        score = (hits * 1000) - (nfp * 500) + (total - hits) * (-100)
        row = {"params": upd, "attack_hits": hits, "attack_total": total, "normal_fp": nfp, "score": score}
        if best is None or score > best["score"]:
            best = row
        if combo == (100, 20, 5, 50):
            print(f"  当前默认 {upd} → 命中 {hits}/{total}, normal 误报 {nfp}")
    print(f"  最优: {best}")
    # 恢复默认 settings（重新加载避免污染）
    try:
        import config.settings as m
        import importlib
        importlib.reload(m)
    except Exception:
        pass
    result_g = {
        "method": "黄金样本全管道网格（syn/port/dns/rst/large 联合）",
        "constraint": "攻击样本全命中优先，normal 0 误报强约束",
        "grid": cands,
        "best": {k: v for k, v in best.items() if k != "score"},
        "recommended_updates": best["params"],
    }
    outg = os.path.join(ROOT, "data/eval_perf/threshold_tuning_golden.json")
    with io.open(outg, "w", encoding="utf-8") as f:
        json.dump(result_g, f, ensure_ascii=False, indent=2)
    print(f"[OK] 写入 {outg}")

if __name__ == "__main__":
    main()
