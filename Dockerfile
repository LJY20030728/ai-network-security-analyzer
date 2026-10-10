# AI网络安全智能分析系统 - Docker 部署
# 构建: docker build -t ai-nsa:3.4.2 .
# 运行: docker compose up -d  （映射 8080 端口 + 挂载数据目录）
#
# 版本号与 config/settings.py 的 settings.version、pyproject.toml、installer.iss 保持一致。
#
# 【安全】本次修正三处：
#   1. 入口文件：原先 COPY/CMD 引用 run_dev.py——该文件在仓库中**不存在**，
#      构建必然失败。现改为仓库真实入口 run.py。
#   2. 监听地址：原先 main() 硬编码 127.0.0.1，使 HOST=0.0.0.0 从未生效，
#      容器端口映射实际不可达。现已支持 HOST 环境变量（主程序侧修复）。
#   3. 运行用户：原先以 root 运行。现创建非 root 用户 nsa 并切换。
FROM python:3.11-slim

LABEL maintainer="nsa-project" \
      description="AI网络安全智能分析系统（PCAP离线分析 + 三引擎 Stacking 融合检测 + LLM威胁研判 + RAG安全知识问答）" \
      version="3.4.2"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# 系统依赖（scapy可能需要libpcap，pillow需要libjpeg）
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libjpeg62-turbo \
    && rm -rf /var/lib/apt/lists/*

# 依赖层（利用 Docker 层缓存，requirements.txt 不变时不重新安装）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码
COPY config ./config
COPY src ./src
COPY tools ./tools
COPY models ./models
COPY run.py ./
COPY .env.example ./.env.example

# 知识文档（攻击类型知识库，RAG初始化用）
COPY data/knowledge ./data/knowledge

# 数据目录（挂载卷，便于持久化与取证导出）
RUN mkdir -p /app/data && chmod -R a+rw /app/data

# 端口：FastAPI/Gradio
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)" || exit 1

# 【安全】非 root 运行：容器被攻破时限制影响面
RUN useradd --create-home --shell /bin/bash nsa \
    && chown -R nsa:nsa /app
USER nsa

# 启动：uvicorn 单进程（内嵌 Gradio 同进程挂载）
CMD ["python", "run.py"]
