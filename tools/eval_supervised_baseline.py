# -*- coding: utf-8 -*-
"""P1-1 监督基线对比：CIC-UNSW 76维流特征
监督: HistGradientBoostingClassifier（80/20 分层划分）
对比: 现有无监督隔离森林（result_unsw_cic.json 中 流级76维: TPR 0.506 / F1 0.531）
输出: data/eval_perf/supervised_baseline.json
"""
import csv, io, json, os, sys, time
import numpy as np
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

DATA = os.path.join(ROOT, "data/eval_cicids/csv/CIC_Data.csv")
LABEL = os.path.join(ROOT, "data/eval_cicids/csv/CIC_Lable.csv")
CAT_MAP = {0: "Benign", 1: "Analysis", 2: "Backdoor", 3: "DoS", 4: "Exploits",
           5: "Fuzzers", 6: "Generic", 7: "Reconnaissance", 8: "Shellcode", 9: "Worms"}

def load_data():
    feats, labels = [], []
    with open(DATA, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        n_cols = len(header)
        for row in reader:
            if len(row) != n_cols:
                continue
            vec = []
            for v in row:
                try:
                    vec.append(float(v))
                except (ValueError, TypeError):
                    vec.append(0.0)
            feats.append(vec)
    with open(LABEL, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            try:
                labels.append(int(float(row[0])))
            except (ValueError, TypeError, IndexError):
                labels.append(0)
    n = min(len(feats), len(labels))
    X = np.asarray(feats[:n], dtype=np.float64)
    y = np.asarray(labels[:n], dtype=np.int64)
    return X, y, header

def metrics(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 4), round(r, 4), round(f1, 4)

def main():
    print("[P1-1] 监督基线评测（CIC-UNSW 76维流特征）")
    t0 = time.time()
    X, y, header = load_data()
    print(f"  加载: {X.shape[0]} 流 x {X.shape[1]} 维, 耗时 {time.time()-t0:.1f}s")

    # 分层 80/20
    from sklearn.model_selection import train_test_split
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"  划分: 训练 {Xtr.shape[0]}, 测试 {Xte.shape[0]}")

    from sklearn.ensemble import HistGradientBoostingClassifier
    t1 = time.time()
    clf = HistGradientBoostingClassifier(max_iter=250, learning_rate=0.1, random_state=42)
    clf.fit(Xtr, ytr)
    print(f"  训练完成 {time.time()-t1:.1f}s")

    # 保存模型（供产品推理使用）
    import joblib
    model_dir = os.path.join(ROOT, "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "supervised_detector.joblib")
    joblib.dump({
        "model": clf,
        "feature_names": header,
        "n_features": len(header),
        "categories": CAT_MAP,
        "train_samples": int(Xtr.shape[0]),
        "test_samples": int(Xte.shape[0]),
        "binary_f1": None,  # 后面填充
    }, model_path)
    print(f"  模型已保存: {model_path}")

    pred = clf.predict(Xte)
    bin_true = (yte != 0).astype(int)
    bin_pred = (pred != 0).astype(int)
    tp = int(np.sum((bin_pred == 1) & (bin_true == 1)))
    fp = int(np.sum((bin_pred == 1) & (bin_true == 0)))
    fn = int(np.sum((bin_pred == 0) & (bin_true == 1)))
    tn = int(np.sum((bin_pred == 0) & (bin_true == 0)))
    p, r, f1 = metrics(tp, fp, fn, tn)
    acc = (tp + tn) / (tp + fp + fn + tn)
    print(f"  二分类: P={p} R={r} F1={f1} Acc={acc:.4f}")

    # 每类别 recall（宏观）
    per_cat = {}
    for c in sorted(set(yte)):
        idx = np.where(yte == c)[0]
        c_pred = pred[idx]
        cr = float(np.mean(c_pred == c)) if len(idx) else 0.0
        per_cat[CAT_MAP.get(c, str(c))] = round(cr, 4)
    macro_recall = float(np.mean([v for k, v in per_cat.items() if k != "Benign"]))

    result = {
        "method": "HistGradientBoosting（监督）80/20 分层",
        "n_flows": int(X.shape[0]), "n_features": int(X.shape[1]),
        "binary": {"precision": p, "recall": r, "f1": f1, "accuracy": round(acc, 4),
                   "tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "per_category_recall": per_cat,
        "macro_recall_attack": round(macro_recall, 4),
        "baseline_unsupervised": {"isolation_forest_76d": {"tpr": 0.506, "f1": 0.531},
                                  "source": "data/eval_cicids/result_unsw_cic.json 流级76维"},
        "comparison_note": "监督模型为参照系：证明数据可学习性上界；产品定位为无监督冷启动（无标注也可用）",
        "runtime_sec": round(time.time() - t0, 1),
    }
    out = os.path.join(ROOT, "data/eval_perf/supervised_baseline.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[OK] 写入 {out}")

    # 更新模型文件中的 f1 指标
    model_path = os.path.join(ROOT, "models", "supervised_detector.joblib")
    if os.path.exists(model_path):
        bundle = joblib.load(model_path)
        bundle["binary_f1"] = f1
        bundle["binary_precision"] = p
        bundle["binary_recall"] = r
        bundle["accuracy"] = round(acc, 4)
        joblib.dump(bundle, model_path)
        print(f"[OK] 模型指标已更新: F1={f1} P={p} R={r}")

if __name__ == "__main__":
    main()
