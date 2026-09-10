# -*- coding: utf-8 -*-
"""
P0-2 UNSW-NB15 域适应优化：监督模型训练与评测
用 UNSW-NB15 的 40+ 维数值特征训练 HistGradientBoosting，
证明监督模型在匿名化数据上远优于规则引擎（recall 0.0001 → XX%）。

输出：
- data/eval_perf/unsw_supervised_result.json（评测结果）
- models/unsw_supervised_detector.joblib（UNSW 专用模型）
"""
import csv
import io
import json
import os
import sys
import time
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

UNSW_CSV = os.path.join(ROOT, "data/eval_cicids/csv/UNSW_NB15_training-set.csv")
OUT_JSON = os.path.join(ROOT, "data/eval_perf/unsw_supervised_result.json")
MODEL_PATH = os.path.join(ROOT, "models/unsw_supervised_detector.joblib")

# 数值型特征（UNSW 49 列中，去掉 id/proto/service/state/attack_cat/label）
NUMERIC_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]

# 类别型特征（one-hot 编码）
CATEGORICAL_FEATURES = ["proto", "service", "state"]

ATTACK_CATS = ["Backdoor", "Analysis", "Fuzzers", "Shellcode", "Reconnaissance",
                "Exploits", "DoS", "Worms", "Generic"]


def load_unsw():
    """加载 UNSW-NB15 数据，返回 X（特征矩阵）、y（二分类标签）、y_cat（攻击类别）、feature_names"""
    print("[1/4] 加载 UNSW-NB15 数据...")
    t0 = time.time()

    rows = []
    with open(UNSW_CSV, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"  加载 {len(rows)} 条流，耗时 {time.time()-t0:.1f}s")

    # 提取数值特征
    X_num = []
    for row in rows:
        vec = []
        for feat in NUMERIC_FEATURES:
            try:
                vec.append(float(row.get(feat, 0) or 0))
            except (ValueError, TypeError):
                vec.append(0.0)
        X_num.append(vec)
    X_num = np.asarray(X_num, dtype=np.float64)

    # 类别型特征 one-hot 编码
    print("[2/4] 类别特征 one-hot 编码...")
    cat_data = {feat: [] for feat in CATEGORICAL_FEATURES}
    for row in rows:
        for feat in CATEGORICAL_FEATURES:
            cat_data[feat].append(row.get(feat, "") or "")

    X_cat_list = []
    all_feature_names = list(NUMERIC_FEATURES)
    for feat in CATEGORICAL_FEATURES:
        unique_vals = sorted(set(cat_data[feat]))
        val_to_idx = {v: i for i, v in enumerate(unique_vals)}
        one_hot = np.zeros((len(rows), len(unique_vals)), dtype=np.float32)
        for i, v in enumerate(cat_data[feat]):
            one_hot[i, val_to_idx[v]] = 1.0
        X_cat_list.append(one_hot)
        all_feature_names.extend([f"{feat}_{v}" for v in unique_vals])
        print(f"  {feat}: {len(unique_vals)} 个类别")

    X = np.hstack([X_num] + X_cat_list) if X_cat_list else X_num

    # 标签
    y = np.array([int(row.get("label", 0) or 0) for row in rows], dtype=np.int64)
    y_cat = [row.get("attack_cat", "") or "Normal" for row in rows]

    print(f"  特征矩阵: {X.shape[0]} x {X.shape[1]}")
    print(f"  标签分布: normal={np.sum(y==0)}, attack={np.sum(y==1)}")
    return X, y, y_cat, all_feature_names


def train_and_eval(X, y, y_cat, feature_names):
    """训练 HistGradientBoosting 并评测"""
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import classification_report, confusion_matrix

    print("[3/4] 训练 HistGradientBoosting（80/20 分层划分）...")
    Xtr, Xte, ytr, yte, cat_tr, cat_te = train_test_split(
        X, y, y_cat, test_size=0.2, stratify=y, random_state=42)
    print(f"  训练集: {Xtr.shape[0]}, 测试集: {Xte.shape[0]}")

    t0 = time.time()
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.1, max_depth=None,
        min_samples_leaf=20, random_state=42)
    clf.fit(Xtr, ytr)
    print(f"  训练完成，耗时 {time.time()-t0:.1f}s")

    # 预测
    pred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)

    # 二分类指标
    tp = int(np.sum((pred == 1) & (yte == 1)))
    fp = int(np.sum((pred == 1) & (yte == 0)))
    fn = int(np.sum((pred == 0) & (yte == 1)))
    tn = int(np.sum((pred == 0) & (yte == 0)))
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    accuracy = (tp + tn) / (tp + fp + fn + tn)

    print(f"\n[4/4] 评测结果（二分类）:")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  TP={tp}, FP={fp}, FN={fn}, TN={tn}")

    # 每类别 recall
    per_cat_recall = {}
    for cat in ATTACK_CATS + ["Normal"]:
        idx = [i for i, c in enumerate(cat_te) if c == cat]
        if idx:
            cat_pred = pred[idx]
            cat_true = yte[idx]
            # 对攻击类别，recall = 预测为攻击的比例
            if cat == "Normal":
                cr = float(np.mean(cat_pred == 0))
            else:
                cr = float(np.mean(cat_pred == 1))
            per_cat_recall[cat] = round(cr, 4)
    print(f"\n  每类别召回率:")
    for cat, r in per_cat_recall.items():
        print(f"    {cat}: {r}")

    # 对比规则引擎
    print(f"\n  === 对比 ===")
    print(f"  规则引擎 large_flow recall: 0.0001")
    print(f"  基线检测最佳 recall (sigma=2.0): 0.5045")
    print(f"  孤立森林 recall: 0.2107")
    print(f"  监督模型 recall: {recall:.4f} (提升 {recall/0.0001:.0f}x vs 规则引擎)")

    result = {
        "method": "HistGradientBoosting（UNSW-NB15 40+维数值特征+one-hot）",
        "n_flows": int(X.shape[0]),
        "n_features": int(X.shape[1]),
        "numeric_features": len(NUMERIC_FEATURES),
        "categorical_features": CATEGORICAL_FEATURES,
        "train_samples": int(Xtr.shape[0]),
        "test_samples": int(Xte.shape[0]),
        "binary": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        },
        "per_category_recall": per_cat_recall,
        "comparison": {
            "rule_engine_large_flow_recall": 0.0001,
            "baseline_best_recall_sigma2": 0.5045,
            "isolation_forest_recall": 0.2107,
            "supervised_recall": round(recall, 4),
            "improvement_vs_rule": f"{recall/0.0001:.0f}x",
        },
        "runtime_sec": round(time.time() - t0, 1),
    }

    # 保存模型
    import joblib
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({
        "model": clf,
        "feature_names": feature_names,
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "n_features": len(feature_names),
        "binary_f1": round(f1, 4),
        "binary_recall": round(recall, 4),
        "binary_precision": round(precision, 4),
    }, MODEL_PATH)
    print(f"\n  模型已保存: {MODEL_PATH}")

    # 保存评测结果
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"  评测结果已保存: {OUT_JSON}")

    return result


def main():
    print("=" * 60)
    print("P0-2 UNSW-NB15 域适应优化：监督模型训练与评测")
    print("=" * 60)
    X, y, y_cat, feature_names = load_unsw()
    result = train_and_eval(X, y, y_cat, feature_names)
    print("\n" + "=" * 60)
    print("P0-2 完成！监督模型在 UNSW-NB15 上 recall = "
          f"{result['binary']['recall']:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
