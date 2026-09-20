#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""修复知识库UI函数，让它们返回Markdown字符串"""

with open('src/api/main_old_backup.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 定义旧的函数
old_funcs = '''                def init_kb():
                    """生成器版：分阶段输出初始化进度，避免长时间无响应"""
                    try:
                        yield {"status": "正在清除旧知识库...", "progress": "10%"}
                        rag = get_rag_engine()
                        rag.clear()
                        yield {"status": "正在加载知识条目（MITRE ATT&CK + 处置手册 + 协议知识 + 文件文档）...", "progress": "30%"}
                        items = get_all_knowledge()
                        yield {"status": f"已加载 {len(items)} 条知识，正在向量化嵌入（BGE模型，分批处理）...", "progress": "50%", "items_count": len(items)}
                        count = rag.add_knowledge_base(items)
                        yield {"status": f"嵌入完成，共 {count} 个文档块，正在统计...", "progress": "90%", "chunks_added": count}
                        stats = rag.get_stats()
                        stats["status"] = "✅ 知识库初始化完成"
                        stats["progress"] = "100%"
                        yield stats
                    except Exception as e:
                        yield {"error": str(e), "status": "❌ 初始化失败"}

                def search_kb(query):
                    if not query:
                        return {}
                    rag = get_rag_engine()
                    return rag.search(query, top_k=5)

                def import_kb(file):
                    if not file:
                        return {"error": "请先选择文档"}
                    try:
                        rag = get_rag_engine()
                        chunks = rag.add_file(file.name, source=f"user_import:{os.path.basename(file.name)}")
                        return {"status": "success", "chunks_added": chunks, "stats": rag.get_stats()}
                    except Exception as e:
                        return {"error": str(e)}'''

# 定义新的函数
new_funcs = '''                def _format_kb_stats(stats):
                    """将知识库统计字典格式化为友好的Markdown"""
                    if not stats or not isinstance(stats, dict):
                        return "暂无数据"
                    if "error" in stats:
                        return f"❌ **错误**: {stats['error']}"
                    
                    lines = []
                    lines.append("### 📊 知识库状态")
                    lines.append("")
                    
                    if "status" in stats:
                        lines.append(f"**状态**: {stats['status']}")
                    if "progress" in stats:
                        lines.append(f"**进度**: {stats['progress']}")
                    if "chunks" in stats:
                        lines.append(f"**文档块数**: {stats['chunks']}")
                    if "documents" in stats:
                        lines.append(f"**文档数**: {stats['documents']}")
                    if "items_count" in stats:
                        lines.append(f"**知识条目数**: {stats['items_count']}")
                    if "chunks_added" in stats:
                        lines.append(f"**新增块数**: {stats['chunks_added']}")
                    
                    return "\\n".join(lines)

                def init_kb():
                    """生成器版：分阶段输出初始化进度，避免长时间无响应"""
                    try:
                        yield _format_kb_stats({"status": "正在清除旧知识库...", "progress": "10%"})
                        rag = get_rag_engine()
                        rag.clear()
                        yield _format_kb_stats({"status": "正在加载知识条目...", "progress": "30%"})
                        items = get_all_knowledge()
                        yield _format_kb_stats({"status": f"已加载 {len(items)} 条知识，正在向量化嵌入...", "progress": "50%", "items_count": len(items)})
                        count = rag.add_knowledge_base(items)
                        yield _format_kb_stats({"status": f"嵌入完成，共 {count} 个文档块，正在统计...", "progress": "90%", "chunks_added": count})
                        stats = rag.get_stats()
                        stats["status"] = "✅ 知识库初始化完成"
                        stats["progress"] = "100%"
                        yield _format_kb_stats(stats)
                    except Exception as e:
                        yield _format_kb_stats({"error": str(e), "status": "❌ 初始化失败"})

                def search_kb(query):
                    if not query:
                        return "请输入搜索关键词"
                    rag = get_rag_engine()
                    results = rag.search(query, top_k=5)
                    if not results:
                        return "暂无结果"
                    lines = [f"### 🔍 搜索结果（{len(results)}条）", ""]
                    for i, r in enumerate(results[:5], 1):
                        if isinstance(r, dict):
                            content = r.get("content", r.get("text", str(r)))[:200]
                            source = r.get("source", "未知来源")
                            lines.append(f"**{i}. {source}**")
                            lines.append(f"  > {content}...")
                            lines.append("")
                    return "\\n".join(lines)

                def import_kb(file):
                    if not file:
                        return "请先选择文档"
                    try:
                        rag = get_rag_engine()
                        chunks = rag.add_file(file.name, source=f"user_import:{os.path.basename(file.name)}")
                        stats = rag.get_stats()
                        lines = ["### ✅ 导入成功", ""]
                        lines.append(f"**新增文档块**: {chunks}")
                        lines.append(f"**总文档块**: {stats.get('chunks', 'N/A')}")
                        return "\\n".join(lines)
                    except Exception as e:
                        return f"❌ **导入失败**: {str(e)}"'''

# 检查旧函数是否存在
if old_funcs in content:
    content = content.replace(old_funcs, new_funcs)
    with open('src/api/main_old_backup.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ 已替换知识库函数")
else:
    print("❌ 未找到旧函数")
    # 打印附近的内容，帮助调试
    idx = content.find("def init_kb():")
    if idx > 0:
        print("附近内容:")
        print(content[idx:idx+500])
