"""
RAG效果真实对比实验
对比：直接Prompt vs RAG检索增强生成
"""

import time
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

print("=" * 70)
print("RAG效果真实对比实验")
print("=" * 70)

# 测试问题集（选5个有代表性的）
test_questions = [
    "什么是SYN Flood攻击？它的检测特征是什么？",
    "OSPF路由协议使用哪个协议号？为什么？",
    "如何检测DNS隧道？有什么特征？",
    "T1046是什么MITRE ATT&CK技术？如何防御？",
    "端口扫描有哪些类型？Nmap的SYN扫描原理是什么？"
]

print(f"\n📋 测试问题数: {len(test_questions)}")

# 初始化组件
print("\n🔧 初始化组件...")

try:
    from src.ai.llm_client import LLMClient
    from src.ai.rag_engine import RAGEngine
    
    llm = LLMClient()
    rag = RAGEngine()
    
    if not llm.is_available():
        print("❌ LLM不可用，请先配置API Key")
        exit(1)
    
    print("✅ LLM和RAG初始化完成")
except Exception as e:
    print(f"❌ 初始化失败: {e}")
    exit(1)

# 对比测试
results = []

print(f"\n{'='*70}")
print("🚀 开始对比测试...")
print(f"{'='*70}")

for i, question in enumerate(test_questions):
    print(f"\n📝 问题 {i+1}/{len(test_questions)}: {question}")
    
    # 1. 直接Prompt（不做RAG检索）
    print("   ⏱️ 直接Prompt...")
    start = time.time()
    direct_messages = [
        {"role": "system", "content": "你是一个网络安全专家，请回答用户的问题。"},
        {"role": "user", "content": question}
    ]
    direct_answer = llm.chat(direct_messages, temperature=0.3, max_tokens=500)
    direct_time = time.time() - start
    direct_len = len(direct_answer)
    
    print(f"      耗时: {direct_time:.2f}s, 回答长度: {direct_len}字")
    
    # 2. RAG检索增强
    print("   ⏱️ RAG检索增强...")
    start = time.time()
    
    # 检索相关知识
    try:
        rag_results = rag.search(question, top_k=3, use_hybrid=True)
        context = "\n\n".join([r.get("content", "") for r in rag_results])
    except Exception as e:
        context = ""
        print(f"      ⚠️ 检索失败: {e}")
    
    rag_messages = [
        {"role": "system", "content": "你是一个网络安全专家。请基于提供的知识库内容回答问题，如果知识库没有相关信息，可以基于你的知识回答，但请注明。"},
        {"role": "user", "content": f"知识库参考内容:\n{context}\n\n问题: {question}"}
    ]
    rag_answer = llm.chat(rag_messages, temperature=0.3, max_tokens=500)
    rag_time = time.time() - start
    rag_len = len(rag_answer)
    
    print(f"      耗时: {rag_time:.2f}s, 回答长度: {rag_len}字, 检索到: {len(rag_results) if 'rag_results' in dir() else 0}条知识")
    
    # 保存结果
    results.append({
        'question': question,
        'direct_time': direct_time,
        'direct_len': direct_len,
        'direct_answer': direct_answer[:200] + "...",
        'rag_time': rag_time,
        'rag_len': rag_len,
        'rag_answer': rag_answer[:200] + "...",
        'context_used': len(context) > 0
    })

# 生成对比数据
print(f"\n{'='*70}")
print("📊 对比结果")
print(f"{'='*70}")

df = pd.DataFrame(results)
print(df[['question', 'direct_time', 'direct_len', 'rag_time', 'rag_len']].to_string(index=False))

# 计算平均
avg_direct_time = df['direct_time'].mean()
avg_rag_time = df['rag_time'].mean()
avg_direct_len = df['direct_len'].mean()
avg_rag_len = df['rag_len'].mean()

print(f"\n📈 平均统计:")
print(f"   直接Prompt - 平均耗时: {avg_direct_time:.2f}s, 平均回答长度: {avg_direct_len:.0f}字")
print(f"   RAG检索   - 平均耗时: {avg_rag_time:.2f}s, 平均回答长度: {avg_rag_len:.0f}字")

# 画对比图
print(f"\n🎨 生成对比图表...")

fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# 1. 回答长度对比
axes[0, 0].bar(['直接Prompt', 'RAG检索'], [avg_direct_len, avg_rag_len], 
               color=['#e74c3c', '#2ecc71'])
axes[0, 0].set_ylabel('平均回答长度（字）')
axes[0, 0].set_title('回答长度对比')
for i, v in enumerate([avg_direct_len, avg_rag_len]):
    axes[0, 0].text(i, v + 10, f'{v:.0f}', ha='center')

# 2. 耗时对比
axes[0, 1].bar(['直接Prompt', 'RAG检索'], [avg_direct_time, avg_rag_time], 
               color=['#e74c3c', '#2ecc71'])
axes[0, 1].set_ylabel('平均耗时（秒）')
axes[0, 1].set_title('耗时对比（检索+生成）')
for i, v in enumerate([avg_direct_time, avg_rag_time]):
    axes[0, 1].text(i, v + 0.1, f'{v:.2f}s', ha='center')

# 3. 每个问题的回答长度
x = np.arange(len(df))
width = 0.35
axes[1, 0].bar(x - width/2, df['direct_len'], width, label='直接Prompt', color='#e74c3c')
axes[1, 0].bar(x + width/2, df['rag_len'], width, label='RAG检索', color='#2ecc71')
axes[1, 0].set_xticks(x)
axes[1, 0].set_xticklabels([f'问题{i+1}' for i in range(len(df))], rotation=45)
axes[1, 0].set_ylabel('回答长度（字）')
axes[1, 0].set_title('每个问题的回答长度对比')
axes[1, 0].legend()

# 4. 每个问题的耗时
axes[1, 1].bar(x - width/2, df['direct_time'], width, label='直接Prompt', color='#e74c3c')
axes[1, 1].bar(x + width/2, df['rag_time'], width, label='RAG检索', color='#2ecc71')
axes[1, 1].set_xticks(x)
axes[1, 1].set_xticklabels([f'问题{i+1}' for i in range(len(df))], rotation=45)
axes[1, 1].set_ylabel('耗时（秒）')
axes[1, 1].set_title('每个问题的耗时对比')
axes[1, 1].legend()

plt.tight_layout()
plt.savefig('docs/rag_real_comparison.png', dpi=150, bbox_inches='tight')
print("✅ 图表已保存: docs/rag_real_comparison.png")

# 保存详细结果
df.to_csv('docs/rag_real_comparison.csv', index=False, encoding='utf-8-sig')
print("✅ 详细数据已保存: docs/rag_real_comparison.csv")

print(f"\n{'='*70}")
print("✅ 真实RAG对比实验完成！")
print(f"{'='*70}")
print(f"\n💡 结论:")
print(f"   - RAG检索增加了{avg_rag_time - avg_direct_time:.2f}秒的检索时间")
print(f"   - RAG回答比直接Prompt{'更详细' if avg_rag_len > avg_direct_len else '更简洁'}（{avg_rag_len:.0f} vs {avg_direct_len:.0f}字）")
print(f"   - RAG的价值在于：回答更有依据、来源可追溯、幻觉更少")
