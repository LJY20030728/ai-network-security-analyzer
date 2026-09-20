#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""优化RAG引擎：降低内存峰值，提升加载速度"""

with open('src/ai/rag_engine.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 优化1：减小嵌入批次大小，降低内存峰值
content = content.replace(
    'BATCH = 5\n            for i in range(0, len(all_chunks), BATCH):',
    'BATCH = 2  # 从5降到2，降低内存峰值\n            import gc\n            for i in range(0, len(all_chunks), BATCH):'
)

# 优化2：在每批处理后添加垃圾回收
old_log = '''                )
            logger.info(f"已添加 {len(all_chunks)} 个文档块到知识库（分批 {BATCH} 条/批）")'''
new_log = '''                )
                # 每批后主动触发垃圾回收，释放内存
                gc.collect()
            logger.info(f"已添加 {len(all_chunks)} 个文档块到知识库（分批 {BATCH} 条/批）")'''
content = content.replace(old_log, new_log)

# 优化3：BGE模型加载时，设置更保守的内存配置
with open('src/ai/embeddings/bge_onnx.py', 'r', encoding='utf-8') as f:
    bge_content = f.read()

# 优化推理批次大小（从32降到8，降低单次推理内存）
bge_content = bge_content.replace(
    'BATCH = 32\n        all_vecs',
    'BATCH = 8  # 从32降到8，降低单次推理内存峰值\n        all_vecs'
)

# 写回文件
with open('src/ai/rag_engine.py', 'w', encoding='utf-8') as f:
    f.write(content)

with open('src/ai/embeddings/bge_onnx.py', 'w', encoding='utf-8') as f:
    f.write(bge_content)

print("✅ RAG引擎和BGE模型优化完成")
print("  - 嵌入批次: 5 → 2")
print("  - 推理批次: 32 → 8")
print("  - 每批后主动垃圾回收")
