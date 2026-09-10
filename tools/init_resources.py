"""
资源初始化脚本 - 下载运行所需的大文件（BGE 模型、MITRE ATT&CK 数据）

这些文件因为体积较大，不包含在 GitHub 仓库中。
首次运行前请执行此脚本下载。

用法:
    python tools/init_resources.py
"""
import os
import sys
import urllib.request
import zipfile
import json
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent

# 需要下载的资源
RESOURCES = [
    {
        "name": "BGE 中文嵌入模型 (ONNX)",
        "url": "https://huggingface.co/BAAI/bge-small-zh-v1.5/resolve/main/onnx/model.onnx",
        "path": "models/bge-small-zh-v1.5/model.onnx",
        "size_mb": 90,
        "description": "RAG 检索的中文嵌入模型，本地推理不依赖外部服务",
    },
    {
        "name": "BGE 模型配置文件",
        "url": "https://huggingface.co/BAAI/bge-small-zh-v1.5/resolve/main/config.json",
        "path": "models/bge-small-zh-v1.5/config.json",
        "size_mb": 0.001,
        "description": "BGE 模型配置",
    },
    {
        "name": "BGE 分词器",
        "url": "https://huggingface.co/BAAI/bge-small-zh-v1.5/resolve/main/tokenizer.json",
        "path": "models/bge-small-zh-v1.5/tokenizer.json",
        "size_mb": 1,
        "description": "BGE 分词器",
    },
    {
        "name": "MITRE ATT&CK 企业攻击矩阵",
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "path": "data/knowledge/mitre_attck/enterprise-attack.json",
        "size_mb": 51,
        "description": "MITRE ATT&CK 知识库，用于攻击链映射和 IOC 关联",
    },
]


def download_file(url: str, dest_path: Path, description: str = "") -> bool:
    """下载文件，带进度显示"""
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    if dest_path.exists():
        print(f"  [跳过] 已存在: {dest_path.name}")
        return True

    print(f"  [下载] {description}")
    print(f"         URL: {url}")
    print(f"         目标: {dest_path}")

    try:
        # 带进度的下载
        def report_progress(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                percent = min(100, downloaded * 100 / total_size)
                mb_downloaded = downloaded / (1024 * 1024)
                mb_total = total_size / (1024 * 1024)
                sys.stdout.write(
                    f"\r         进度: {percent:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)"
                )
                sys.stdout.flush()

        urllib.request.urlretrieve(url, str(dest_path), reporthook=report_progress)
        print()  # 换行
        print(f"  [完成] {dest_path.name}")
        return True
    except Exception as e:
        print(f"\n  [失败] {e}")
        if dest_path.exists():
            dest_path.unlink()
        return False


def init_chroma_db():
    """初始化 ChromaDB 向量库（从 MITRE ATT&CK 和安全知识库构建）"""
    print("\n=== 初始化向量库 ===")
    chroma_path = PROJECT_ROOT / "data" / "chroma_db"
    if chroma_path.exists() and any(chroma_path.iterdir()):
        print("  [跳过] 向量库已存在")
        return

    print("  正在构建向量库（首次运行需要几分钟）...")
    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from src.ai.rag_engine import RAGEngine
        rag = RAGEngine()
        rag.initialize_knowledge_base()
        print("  [完成] 向量库初始化成功")
    except Exception as e:
        print(f"  [警告] 向量库初始化失败: {e}")
        print("         可以稍后在应用中手动初始化")


def main():
    print("=" * 60)
    print("  AI Network Security Analyzer - 资源初始化")
    print("=" * 60)
    print()

    # 检查是否已有资源
    all_exist = True
    for res in RESOURCES:
        path = PROJECT_ROOT / res["path"]
        if not path.exists():
            all_exist = False
            break

    if all_exist:
        print("所有资源已存在，无需下载。")
        print()
        init_chroma_db()
        return

    print("以下资源需要下载（约 140 MB）：")
    print()
    for res in RESOURCES:
        path = PROJECT_ROOT / res["path"]
        status = "已存在" if path.exists() else "需下载"
        print(f"  [{status}] {res['name']} ({res['size_mb']} MB)")
        print(f"         {res['description']}")
    print()

    confirm = input("是否开始下载？(y/n): ").strip().lower()
    if confirm != "y":
        print("已取消。")
        return

    print()
    print("=== 开始下载 ===")
    print()

    success_count = 0
    for res in RESOURCES:
        path = PROJECT_ROOT / res["path"]
        if path.exists():
            print(f"[跳过] {res['name']}")
            success_count += 1
            continue

        if download_file(res["url"], path, res["name"]):
            success_count += 1
        print()

    print(f"=== 下载完成: {success_count}/{len(RESOURCES)} ===")
    print()

    if success_count == len(RESOURCES):
        init_chroma_db()
        print()
        print("=" * 60)
        print("  初始化完成！可以启动应用了。")
        print("  启动命令: python desktop_app.py")
        print("=" * 60)
    else:
        print("部分资源下载失败，请检查网络连接后重试。")
        print("也可以手动下载后放到对应目录。")


if __name__ == "__main__":
    main()
