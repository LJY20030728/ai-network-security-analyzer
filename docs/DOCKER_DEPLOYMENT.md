# Docker 部署指南

本项目支持 Docker 容器化部署，适用于服务器环境和跨平台分发。

---

## 快速开始

### 方式一：docker compose（推荐）

```bash
# 1. 克隆项目
git clone https://github.com/LJY20030728/ai-network-security-analyzer.git
cd ai-network-security-analyzer

# 2. 配置环境变量（复制示例并修改）
cp .env.example .env
# 编辑 .env，填入你的 LLM_API_KEY

# 3. 构建并启动
docker compose up -d --build

# 4. 查看日志
docker compose logs -f

# 5. 访问服务
# 浏览器打开 http://localhost:8080
```

### 方式二：docker build + docker run

```bash
# 1. 构建镜像
docker build -t ai-nsa:2.1.0 .

# 2. 运行容器
docker run -d \
  --name ai-nsa \
  -p 8080:8080 \
  -e LLM_API_KEY="你的API Key" \
  -e LLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4" \
  -e LLM_MODEL="glm-4-flash" \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  ai-nsa:2.1.0

# 3. 访问服务
# 浏览器打开 http://localhost:8080
```

---

## 环境变量配置

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| `LLM_API_KEY` | ✅ 是 | - | 大模型 API Key（支持智谱/DeepSeek/硅基流动/通义千问/Ollama） |
| `LLM_BASE_URL` | ❌ 否 | `https://open.bigmodel.cn/api/paas/v4` | 大模型 API 端点 |
| `LLM_MODEL` | ❌ 否 | `glm-4-flash` | 大模型名称 |
| `EMBEDDING_MODEL` | ❌ 否 | `BAAI/bge-small-zh-v1.5` | 向量嵌入模型（本地运行） |
| `API_AUTH_TOKEN` | ❌ 否 | `changeme` | API 访问令牌（生产环境建议修改） |
| `HOST` | ❌ 否 | `0.0.0.0` | 服务绑定地址（Docker 环境必须为 0.0.0.0） |
| `PORT` | ❌ 否 | `8080` | 服务端口 |
| `LOG_LEVEL` | ❌ 否 | `warning` | 日志级别 |

### 支持的大模型平台

1. **智谱AI BigModel**（推荐，GLM-4-Flash 永久免费）
   ```
   LLM_BASE_URL=https://open.bigmodel.cn/api/paas/v4
   LLM_MODEL=glm-4-flash
   ```

2. **硅基流动 SiliconFlow**（免费额度充足，国内直连快）
   ```
   LLM_BASE_URL=https://api.siliconflow.cn/v1
   LLM_MODEL=Qwen/Qwen2.5-7B-Instruct
   ```

3. **DeepSeek**（便宜，注册送额度）
   ```
   LLM_BASE_URL=https://api.deepseek.com
   LLM_MODEL=deepseek-chat
   ```

4. **通义千问（阿里云百炼）**
   ```
   LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
   LLM_MODEL=qwen-turbo
   ```

5. **Ollama 本地模型**（完全免费，无需 API Key）
   ```
   LLM_API_KEY=ollama
   LLM_BASE_URL=http://host.docker.internal:11434/v1
   LLM_MODEL=qwen2.5:7b
   ```
   > 注意：Ollama 运行在宿主机时，Docker 容器内需使用 `host.docker.internal` 访问宿主机服务。

---

## 数据持久化

Docker 容器删除后，容器内的数据会丢失。通过数据卷挂载可以持久化数据：

```yaml
volumes:
  - ./data:/app/data
```

挂载的 `data/` 目录包含：

| 子目录 | 说明 |
|--------|------|
| `data/db/` | SQLite 数据库（历史记录/对话/基线） |
| `data/chroma_db/` | ChromaDB 向量数据库 |
| `data/reports/` | 生成的取证报告 HTML |
| `data/baselines/` | 用户学习的时序基线 |
| `data/knowledge/` | 知识文档（攻击类型知识库，已打包进镜像） |
| `data/samples/analyzed/` | 持久化的 PCAP 文件（重新分析用） |

### BGE 模型文件

BGE 嵌入模型（约 90MB）**没有打包进镜像**（减小镜像体积），首次启动时会自动下载到 `data/` 目录。如果需要离线部署，可以提前下载：

```bash
# 在宿主机 data 目录下创建模型目录
mkdir -p data/models/bge-small-zh-v1.5
# 从 HuggingFace 或 ModelScope 下载模型文件到该目录
```

---

## 常用命令

```bash
# 查看容器状态
docker compose ps

# 查看日志
docker compose logs -f

# 查看最近100行日志
docker compose logs --tail 100

# 停止容器
docker compose down

# 停止并删除数据卷（谨慎！会删除所有数据）
docker compose down -v

# 重新构建镜像（代码更新后）
docker compose build --no-cache

# 进入容器调试
docker compose exec nsa bash

# 查看健康检查状态
docker inspect --format='{{.State.Health.Status}}' ai-nsa
```

---

## 端口与防火墙

确保服务器防火墙开放 8080 端口：

```bash
# Ubuntu/Debian
sudo ufw allow 8080/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

---

## 生产环境建议

1. **使用 Nginx 反向代理**（支持 HTTPS、负载均衡）
   ```nginx
   server {
       listen 443 ssl;
       server_name your-domain.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

2. **修改默认 API 令牌**
   ```yaml
   environment:
     - API_AUTH_TOKEN=your-strong-random-token
   ```

3. **限制容器资源**
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '2.0'
         memory: 1G
       reservations:
         cpus: '0.5'
         memory: 256M
   ```

4. **定期备份数据**
   ```bash
   # 备份 data 目录
   tar -czf backup-$(date +%Y%m%d).tar.gz data/
   ```

---

## 故障排查

### 1. 容器启动后无法访问

```bash
# 检查容器状态
docker compose ps

# 查看日志
docker compose logs nsa

# 检查端口监听
docker compose exec nsa netstat -tlnp | grep 8080
```

常见原因：
- `HOST` 环境变量不是 `0.0.0.0`（已修复，默认值为 0.0.0.0）
- 防火墙未开放 8080 端口
- 端口被其他进程占用

### 2. LLM API 调用失败

```bash
# 检查环境变量是否正确注入
docker compose exec nsa env | grep LLM

# 测试 API 连通性
docker compose exec nsa python -c "
import os
import httpx
resp = httpx.get(os.getenv('LLM_BASE_URL', '') + '/models', 
                  headers={'Authorization': 'Bearer ' + os.getenv('LLM_API_KEY', '')},
                  timeout=10)
print(resp.status_code, resp.text[:200])
"
```

### 3. 健康检查失败

```bash
# 手动测试健康检查接口
docker compose exec nsa python -c "
import urllib.request
resp = urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)
print(resp.read().decode())
"
```

### 4. 权限问题（数据目录不可写）

```bash
# 修改 data 目录权限
chmod -R 777 data/

# 或者在 docker-compose.yml 中指定用户
user: "1000:1000"
```

---

## 镜像体积优化

当前镜像约 1.2GB（含 Python 运行时 + 所有依赖）。如需进一步减小体积：

1. **使用多阶段构建**（编译依赖与运行时分离）
2. **使用 alpine 基础镜像**（需注意 scapy 等库的兼容性）
3. **排除不必要的依赖**（如 pywebview 在服务器环境不需要）

---

## 版本信息

- 镜像版本：2.1.0
- Python 版本：3.11-slim
- 基础镜像：python:3.11-slim
- 暴露端口：8080
- 健康检查：/api/health

---

## 相关文档

- [README.md](../README.md) - 项目主文档
- [CHANGELOG.md](../CHANGELOG.md) - 更新日志
- [.env.example](../.env.example) - 环境变量配置示例
