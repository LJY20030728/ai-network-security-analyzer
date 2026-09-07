# P2: Docker 化部署（AI网络安全智能分析系统）
# 构建: docker build -t ai-nsa:1.1.0 .
# 运行: docker compose up -d  （自动映射 8080 端口 + 挂载数据目录）
FROM python:3.11-slim

LABEL maintainer="nsa-project" \
      description="AI网络安全智能分析系统（PCAP离线分析 + 规则引擎 + 时序基线 + LLM研判 + RAG）"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 依赖层（利用 Docker 层缓存）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码
COPY config ./config
COPY src ./src
COPY tools ./tools
COPY run_dev.py ./
COPY .env.example ./.env.example

# 数据目录（挂载卷，便于持久化与取证导出）
RUN mkdir -p /app/data && chmod -R a+rw /app/data

# 端口：FastAPI/Gradio
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)" || exit 1

# 启动：uvicorn 单进程（内嵌 Gradio 同进程挂载）
CMD ["python", "run_dev.py"]
