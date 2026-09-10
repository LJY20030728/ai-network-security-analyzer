"""
项目配置管理
使用 pydantic-settings 从环境变量和 .env 文件加载配置

API Key 安全策略：
- 绝不把 API Key 写死在代码/打包产物中
- 运行时按以下优先级自动查找 .env 文件：
  1. 程序（exe/python）同级目录下的 .env —— 打包部署后推荐位置
  2. 当前工作目录下的 .env
  3. 项目源码根目录下的 .env —— 开发模式位置
- 找不到 .env 时系统仍可启动，AI 功能会提示未配置
"""
import sys
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


def find_env_file() -> str:
    """按优先级查找 .env 配置文件（返回第一个存在的路径）"""
    candidates = []

    # 1. 程序入口同级目录（PyInstaller 打包后为 exe 所在目录；开发时为解释器目录）
    try:
        candidates.append(str(Path(sys.executable).resolve().parent / ".env"))
    except Exception:
        pass

    # 2. 当前工作目录
    try:
        candidates.append(str(Path.cwd() / ".env"))
    except Exception:
        pass

    # 3. 项目源码根目录（config 的上一级）
    try:
        candidates.append(str(Path(__file__).resolve().parent.parent / ".env"))
    except Exception:
        pass

    for path in candidates:
        if Path(path).exists():
            return path

    # 兜底：相对路径 .env（pydantic-settings 会尝试从工作目录读取）
    return ".env"


class Settings(BaseSettings):
    """全局配置类"""

    model_config = SettingsConfigDict(
        env_file=find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # ===== 项目基本信息 =====
    project_name: str = "AI Network Security Analyzer"
    debug: bool = True
    log_level: str = "INFO"

    # ===== 大模型配置 =====
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com"
    llm_model: str = "deepseek-chat"
    embedding_model: str = "BAAI/bge-small-zh-v1.5"

    # ===== 本地 API 安全 =====
    # 保护本机 /api/* 接口的访问令牌（外部调用需携带 X-API-Token 头）
    # 为空时首次启动自动生成并写入 .env；Gradio UI（进程内调用）不受影响
    api_auth_token: str = ""

    # ===== 上传与资源限制 =====
    max_upload_mb: int = 200  # 单个 PCAP 上传上限（MB）

    # ===== 抓包配置 =====
    capture_interface: Optional[str] = None
    capture_filter: str = "tcp or udp or icmp"
    capture_packet_limit: int = 1000

    # ===== 数据库配置 =====
    chroma_persist_dir: str = ""  # 运行时由 src.utils.paths 解析为绝对路径（打包鲁棒）

    # ===== 分析配置 =====
    flow_timeout: int = 60  # 网络流超时时间（秒）
    anomaly_threshold: float = 0.7  # 异常检测阈值

    # ===== 规则引擎阈值（均可通过 .env 覆盖）=====
    # 以下硬编码阈值全部参数化，避免"正常流量误报/攻击流量漏报"不可调
    syn_flood_min_count: int = 80     # SYN包(无ACK)数量 >= 该值 触发告警
    syn_flood_high_count: int = 500    # 超过则升级为 HIGH
    port_scan_min_ports: int = 15      # 单源访问不同端口数 >= 该值 触发告警
    port_scan_high_ports: int = 100    # 超过则升级为 HIGH
    dns_tunnel_max_query_len: int = 30 # DNS查询域名长度 > 该值 记为可疑
    dns_tunnel_min_count: int = 3      # 可疑DNS查询数 >= 该值 触发告警
    dns_tunnel_high_count: int = 20    # 超过则升级为 HIGH
    large_flow_min_mb: float = 10.0    # 单流字节数 > 该值(MB) 触发告警
    rst_storm_min_count: int = 30      # 单源RST包数 >= 该值 触发告警

    # ===== EWMA 时序基线引擎（学习-检测两阶段）=====
    baseline_alpha: float = 0.1        # EWMA 平滑系数
    baseline_sigma: float = 3.0        # z-score 告警阈值（MAD 鲁棒尺度）
    baseline_window_sec: int = 10      # 时间窗聚合粒度（秒）
    baseline_min_windows: int = 20     # 学习阶段最少时间窗数量
    baseline_online_update: bool = True   # 检测阶段 EWMA 在线滚动更新（偏差窗口不更新，防污染）
    baseline_drift_window: int = 10      # 漂移检测：最近 N 个窗口与基线分布做 KS 检验
    baseline_drift_alpha: float = 0.05   # KS 检验显著性水平
    # ===== ML 检测引擎（L2：孤立森林无监督异常检测，第三轨）=====
    ml_engine_enabled: bool = False   # 是否启用 ML 检测（默认关；评测/深度部署时开启）
    ml_contamination: float = 0.10    # 孤立森林异常比例先验
    ml_random_state: int = 42         # 固定随机种子（评测可复现）
    ml_max_samples: int = 256         # 单棵树采样数

    # ===== LLM 多采样投票（L3：治非确定性）=====
    llm_vote_samples: int = 3         # 投票采样次数
    llm_vote_temperatures: str = '0.1,0.4,0.7'   # 各次采样温度（逗号分隔）

    # ===== P1-3: DPAPI 加密存储（运行时覆盖 .env）=====
    secure_store_enabled: bool = True   # 是否启用加密存储（Windows 下默认开启）

    def model_post_init(self, __context) -> None:
        """P1-3: 初始化后从加密存储读取 API Key（优先加密存储，回退 .env）"""
        try:
            if self.secure_store_enabled:
                import sys
                if sys.platform == "win32":
                    from src.security.secure_store import get_secure_store
                    ss = get_secure_store()
                    encrypted_key = ss.get("LLM_API_KEY")
                    if encrypted_key:
                        self.llm_api_key = encrypted_key
                    encrypted_url = ss.get("LLM_BASE_URL")
                    if encrypted_url:
                        self.llm_base_url = encrypted_url
                    encrypted_model = ss.get("LLM_MODEL")
                    if encrypted_model:
                        self.llm_model = encrypted_model
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"从加密存储读取配置失败，回退 .env: {e}")


# 全局配置单例
settings = Settings()
