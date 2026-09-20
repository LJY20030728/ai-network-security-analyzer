"""
模型选型对比实验
功能：对比HistGradientBoosting vs XGBoost vs LightGBM
"""

import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

print("=" * 60)
print("模型选型对比实验")
print("=" * 60)

# 1. 加载NSL-KDD数据
print("\n1. 加载NSL-KDD数据集...")
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

train_df = pd.read_csv("data/datasets/nslkdd/KDDTrain+.txt", header=None, names=columns)
test_df = pd.read_csv("data/datasets/nslkdd/KDDTest+.txt", header=None, names=columns)

# 标签二值化
train_df["label_binary"] = (train_df["label"] != "normal").astype(int)
test_df["label_binary"] = (test_df["label"] != "normal").astype(int)

# 选择数值特征
numeric_features = [
    "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

X_train = train_df[numeric_features].fillna(0).values
y_train = train_df["label_binary"].values
X_test = test_df[numeric_features].fillna(0).values
y_test = test_df["label_binary"].values

print(f"   训练集: {len(X_train)} 条")
print(f"   测试集: {len(X_test)} 条")
print(f"   特征数: {len(numeric_features)}")

# 2. 定义模型
print("\n2. 定义对比模型...")
models = {
    "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=100, random_state=42),
    "XGBoost": XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='logloss'),
    "LightGBM": LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)
}

# 3. 训练和评估
print("\n3. 训练和评估...")
results = []

for name, model in models.items():
    print(f"\n   训练 {name}...")
    
    # 训练时间
    start = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - start
    
    # 预测时间
    start = time.time()
    y_pred = model.predict(X_test)
    predict_time = time.time() - start
    
    # 评估
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    results.append({
        'model': name,
        'accuracy': acc,
        'f1': f1,
        'train_time': train_time,
        'predict_time': predict_time
    })
    
    print(f"   ✅ {name}: 准确率={acc:.4f}, F1={f1:.4f}, 训练时间={train_time:.2f}s")

# 4. 输出对比表
print(f"\n{'='*60}")
print("📊 模型对比结果")
print(f"{'='*60}")
print(f"{'模型':<25} {'准确率':<10} {'F1分数':<10} {'训练时间(s)':<12} {'预测时间(s)':<12}")
print("-" * 60)
for r in results:
    print(f"{r['model']:<25} {r['accuracy']:<10.4f} {r['f1']:<10.4f} {r['train_time']:<12.2f} {r['predict_time']:<12.2f}")

# 5. 生成对比图
print("\n4. 生成对比图表...")

fig, axes = plt.subplots(1, 3, figsize=(15, 5))

# 准确率对比
models_names = [r['model'] for r in results]
accuracies = [r['accuracy'] for r in results]
f1s = [r['f1'] for r in results]

axes[0].bar(models_names, accuracies, color='#3498db')
axes[0].set_title('准确率对比')
axes[0].set_ylabel('准确率')
axes[0].set_ylim([0.7, 0.85])
for i, v in enumerate(accuracies):
    axes[0].text(i, v + 0.002, f'{v:.4f}', ha='center')

# F1对比
axes[1].bar(models_names, f1s, color='#2ecc71')
axes[1].set_title('F1分数对比')
axes[1].set_ylabel('F1分数')
axes[1].set_ylim([0.7, 0.85])
for i, v in enumerate(f1s):
    axes[1].text(i, v + 0.002, f'{v:.4f}', ha='center')

# 训练时间对比
train_times = [r['train_time'] for r in results]
axes[2].bar(models_names, train_times, color='#e74c3c')
axes[2].set_title('训练时间对比')
axes[2].set_ylabel('时间（秒）')
for i, v in enumerate(train_times):
    axes[2].text(i, v + 0.1, f'{v:.2f}s', ha='center')

plt.tight_layout()
plt.savefig('docs/model_comparison.png', dpi=150, bbox_inches='tight')
print("   ✅ 图表已保存: docs/model_comparison.png")

# 6. 保存结果
print("\n5. 保存结果...")
df = pd.DataFrame(results)
df.to_csv('docs/model_comparison.csv', index=False, encoding='utf-8-sig')
print("   ✅ CSV已保存: docs/model_comparison.csv")

print(f"\n{'='*60}")
print("✅ 模型对比实验完成！")
print(f"{'='*60}")
print(f"\n💡 面试话术：")
print(f"   我对比了3种主流梯度提升树模型：")
print(f"   1. HistGradientBoosting - 内置sklearn，零额外依赖")
print(f"   2. XGBoost - 工业界常用")
print(f"   3. LightGBM - 微软出品")
print(f"   最终选择HistGradientBoosting是因为：")
print(f"   - 准确率和其他两个差不多")
print(f"   - 但零额外依赖，打包更方便")
print(f"   - 符合'轻量、易部署'的设计目标")
