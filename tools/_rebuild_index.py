# -*- coding: utf-8 -*-
"""重建 RAG 索引（内存安全版：限线程 + 分批嵌入）"""

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

import io, os, sys, time

# Windows 控制台默认 GBK，直接打印中文/emoji 会抛 UnicodeEncodeError
try:
    from src.utils.helpers import force_utf8_stdout
    force_utf8_stdout()
except Exception:
    pass
os.environ["OMP_NUM_THREADS"] = "2"
os.environ["OMP_WAIT_POLICY"] = "PASSIVE"
os.environ["MKL_NUM_THREADS"] = "2"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
LOG = os.path.join(ROOT, "data", "knowledge", "rebuild_log.txt")
def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with io.open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
if os.path.exists(LOG):
    os.remove(LOG)
try:
    from loguru import logger
    logger.remove()
    from src.ai.rag_engine import get_rag_engine
    from src.knowledge.mitre_attck import get_all_knowledge
    log("加载知识库条目...")
    items = get_all_knowledge()
    log("条目数: %d, 总字符 %.0fKB" % (len(items), sum(len(i['content']) for i in items)/1024))
    rag = get_rag_engine()
    log("清空旧索引...")
    rag.clear()
    t0 = time.time()
    total = 0
    BATCH = 5
    for i in range(0, len(items), BATCH):
        part = items[i:i+BATCH]
        try:
            n = rag.add_knowledge_base(part)
        except Exception as e:
            log("批次失败 %d-%d: %s" % (i, i+len(part), str(e)[:200]))
            raise
        total += n
        log("批次 %d/%d 完成, 累计 %d 条" % (i//BATCH+1, (len(items)+BATCH-1)//BATCH, total))
    dt = time.time() - t0
    log("索引完成: %d 条, 耗时 %.1fs" % (total, dt))
    log("统计: %s" % (rag.get_stats(),))
    log("--- 检索验证 ---")
    for q in ["DNS隧道检测", "数据渗出 exfiltration", "横向移动", "powershell 执行", "权限提升"]:
        r = rag.search(q, top_k=3)
        titles = [x.get("metadata", {}).get("title", "?")[:50] for x in r]
        log("Q[%s] -> %s" % (q, titles))
    log("REBUILD_OK")
except Exception as e:
    log("REBUILD_FAIL: %s" % e)
    import traceback
    log(traceback.format_exc()[:1500])
