# -*- coding: utf-8 -*-
"""
时间外推（Out-Of-Time, OOT）验证
================================
科学的时间泛化验证：在官方 UNSW_NB15_training-set.csv（175,341 条，较早时间窗）上
训练 HistGradientBoosting，在官方 UNSW_NB15_testing-set.csv（82,332 条，另一时间窗）上
评测。两个文件由 UNSW 官方按不同采集时间划分，天然构成时间外推测试，避免同一时间窗内
随机切分的乐观偏差。

输出：data/eval_perf/unsw_oot_result.json
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

TRAIN_CSV = os.path.join(ROOT, "data/eval_cicids/csv/UNSW_NB15_training-set.csv")
TEST_CSV = os.path.join(ROOT, "data/eval_cicids/csv/UNSW_NB15_testing-set.csv")
OUT_JSON = os.path.join(ROOT, "data/eval_perf/unsw_oot_result.json")

NUMERIC_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]
CATEGORICAL_FEATURES = ["proto", "service", "state"]
ATTACK_CATS = ["Backdoor", "Analysis", "Fuzzers", "Shellcode", "Reconnaissance",
               "Exploits", "DoS", "Worms", "Generic"]


def read_rows(path):
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def build_matrix(rows, cat_maps=None):
    Xnum = np.asarray(
        [[float(r.get(c, 0) or 0) for c in NUMERIC_FEATURES] for r in rows],
        dtype=np.float64)
    if cat_maps is None:
        cat_maps = {c: sorted({(r.get(c, "") or "") for r in rows})
                    for c in CATEGORICAL_FEATURES}
    blocks = [Xnum]
    feat_names = list(NUMERIC_FEATURES)
    n_unseen = {c: 0 for c in CATEGORICAL_FEATURES}
    for c in CATEGORICAL_FEATURES:
        vals = cat_maps[c]
        idx = {v: i for i, v in enumerate(vals)}
        oh = np.zeros((len(rows), len(vals)), dtype=np.float32)
        for i, r in enumerate(rows):
            v = r.get(c, "") or ""
            if v in idx:
                oh[i, idx[v]] = 1.0
            else:
                n_unseen[c] += 1  # 训练期未见过的取值，全 0
        blocks.append(oh)
        feat_names.extend([f"{c}_{v}" for v in vals])
    X = np.hstack(blocks)
    y = np.array([int(r.get("label", 0) or 0) for r in rows], dtype=np.int64)
    ycat = [r.get("attack_cat", "") or "Normal" for r in rows]
    return X, y, ycat, feat_names, cat_maps, n_unseen


def metrics(yte, pred):
    tp = int(np.sum((pred == 1) & (yte == 1)))
    fp = int(np.sum((pred == 1) & (yte == 0)))
    fn = int(np.sum((pred == 0) & (yte == 1)))
    tn = int(np.sum((pred == 0) & (yte == 0)))
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * r / (p + r) if p + r else 0
    acc = (tp + tn) / (tp + fp + fn + tn)
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "accuracy": round(acc, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main():
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import f1_score

    print("[1/3] 加载官方 train / test 两个时间窗...")
    tr_rows = read_rows(TRAIN_CSV)
    te_rows = read_rows(TEST_CSV)
    print(f"  train(较早): {len(tr_rows)} 条, test(较新): {len(te_rows)} 条")

    Xtr, ytr, cat_tr, feat, cat_maps, _ = build_matrix(tr_rows)
    Xte, yte, cat_te, _, _, n_unseen = build_matrix(te_rows, cat_maps)
    print(f"  特征维度: {Xtr.shape[1]}；测试集未见类别取值数: {n_unseen}")

    print("[2/3] 在整个官方 training-set 上训练...")
    t0 = time.time()
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.1, max_depth=None,
        min_samples_leaf=20, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.1,
        n_iter_no_change=10, random_state=42)
    clf.fit(Xtr, ytr)
    train_f1 = f1_score(ytr, clf.predict(Xtr))
    print(f"  训练完成 {time.time()-t0:.1f}s，训练集自身 F1={train_f1:.4f}")

    print("[3/3] 在官方 testing-set（时间外推）上评测...")
    pred = clf.predict(Xte)
    binm = metrics(yte, pred)
    print(f"  OOT  P={binm['precision']} R={binm['recall']} "
          f"F1={binm['f1']} Acc={binm['accuracy']}")

    per_cat = {}
    for cat in ATTACK_CATS + ["Normal"]:
        idx = [i for i, c in enumerate(cat_te) if c == cat]
        if idx:
            cp = pred[idx]
            cr = float(np.mean(cp == 0)) if cat == "Normal" else float(np.mean(cp == 1))
            per_cat[cat] = round(cr, 4)

    result = {
        "method": "时间外推 OOT：官方 training-set 训练 + 官方 testing-set（另一时间窗）测试",
        "train_window_rows": len(tr_rows),
        "test_window_rows": len(te_rows),
        "n_features": int(Xtr.shape[1]),
        "unseen_category_values": n_unseen,
        "train_self_f1": round(float(train_f1), 4),
        "oot": binm,
        "oot_f1_decay_vs_train_self": round(float(train_f1) - binm["f1"], 4),
        "per_category_recall_oot": per_cat,
        "runtime_sec": round(time.time() - t0, 1),
    }
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"已保存: {OUT_JSON}")


if __name__ == "__main__":
    main()
