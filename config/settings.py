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

配置按功能分组：
- 项目基本信息
- API服务配置
- LLM大模型配置
- 分析引擎配置（规则引擎、基线引擎、ML引擎）
- 存储配置
- 安全配置
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


class APISettings(BaseSettings):
    """API服务配置"""
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    api_auth_token: str = ""
    max_upload_mb: int = 200  # 单个 PCAP 上传上限（MB）
    request_timeout: int = 300  # 请求超时（秒）


class LLMSettings(BaseSettings):
    """大模型配置"""
    llm_api_key: str = ""
    llm_base_url: str = "https://open.bigmodel.cn/api/paas/v4"
    llm_model: str = "glm-4.5-air"
    embedding_model: str = "BAAI/bge-small-zh-v1.5"
    llm_vote_samples: int = 3
    llm_vote_temperatures: str = "0.1,0.4,0.7"
    llm_timeout: int = 60  # LLM API 超时（秒）


class AnalysisSettings(BaseSettings):
    """分析引擎配置"""
    # 通用分析
    flow_timeout: int = 60  # 网络流超时时间（秒）
    anomaly_threshold: float = 0.7  # 异常检测阈值

    # 三引擎 Stacking 融合（规则 + 基线 + 孤立森林）
    # 默认开启：三引擎全部无外部模型依赖，开箱即用
    stacking_fusion_enabled: bool = True

    # 规则引擎阈值
    syn_flood_min_count: int = 80
    syn_flood_high_count: int = 500
    port_scan_min_ports: int = 15
    port_scan_high_ports: int = 100
    dns_tunnel_max_query_len: int = 30
    dns_tunnel_min_count: int = 3
    dns_tunnel_high_count: int = 20
    large_flow_min_mb: float = 10.0
    rst_storm_min_count: int = 30

    # UDP/QUIC 攻击检测阈值（v3.4.0 新增）
    udp_flood_min_packets: int = 100
    udp_flood_high_packets: int = 500
    dns_amp_min_ratio: float = 5.0
    dns_amp_min_responses: int = 5
    quic_flood_min_connections: int = 50
    quic_long_flow_min_packets: int = 200
    quic_initial_ratio_threshold: float = 0.3
    quic_unknown_version_alert: bool = True

    # EWMA 时序基线引擎
    baseline_alpha: float = 0.1
    baseline_sigma: float = 3.0
    baseline_window_sec: int = 10
    baseline_min_windows: int = 20
    baseline_online_update: bool = True
    baseline_drift_window: int = 10
    baseline_drift_alpha: float = 0.05

    # ML 检测引擎（孤立森林）
    ml_engine_enabled: bool = True
    ml_contamination: float = 0.10
    ml_random_state: int = 42
    ml_max_samples: int = 256
    ml_n_jobs: int = 1


class StorageSettings(BaseSettings):
    """存储配置"""
    chroma_persist_dir: str = ""
    db_path: str = ""
    reports_dir: str = ""
    baselines_dir: str = ""
    samples_dir: str = ""


class SecuritySettings(BaseSettings):
    """安全配置"""
    secure_store_enabled: bool = True
    capture_interface: Optional[str] = None
    capture_filter: str = "tcp or udp or icmp"
    capture_packet_limit: int = 1000


class ProjectSettings(BaseSettings):
    """项目基本信息"""
    project_name: str = "AI Network Security Analyzer"
    debug: bool = True
    log_level: str = "INFO"
    version: str = "3.3.0"


class Settings(BaseSettings):
    """
    全局配置类（统一入口，保持向后兼容）
    
    为了保持向后兼容，所有原有配置项仍然可以通过 settings.xxx 直接访问。
    新代码建议按分组访问：settings.api.xxx, settings.llm.xxx 等。
    """

    model_config = SettingsConfigDict(
        env_file=find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # ===== 项目基本信息（平铺，向后兼容）=====
    project_name: str = "AI Network Security Analyzer"
    debug: bool = True
    log_level: str = "INFO"
    version: str = "3.3.0"

    # ===== 大模型配置（平铺，向后兼容）=====
    llm_api_key: str = ""
    llm_base_url: str = "https://open.bigmodel.cn/api/paas/v4"
    llm_model: str = "glm-4.5-air"
    embedding_model: str = "BAAI/bge-small-zh-v1.5"

    # ===== API 安全（平铺，向后兼容）=====
    api_auth_token: str = ""

    # ===== 上传与资源限制（平铺，向后兼容）=====
    max_upload_mb: int = 200

    # ===== 抓包配置（平铺，向后兼容）=====
    capture_interface: Optional[str] = None
    capture_filter: str = "tcp or udp or icmp"
    capture_packet_limit: int = 1000

    # ===== 数据库配置（平铺，向后兼容）=====
    chroma_persist_dir: str = ""

    # ===== 分析配置（平铺，向后兼容）=====
    flow_timeout: int = 60
    anomaly_threshold: float = 0.7

    # ===== 三引擎 Stacking 融合（平铺，向后兼容）=====
    # 引擎：规则（阈值）+ 时序基线（EWMA）+ 孤立森林（无监督）
    # 三者结论由 Stacking 元学习器融合（models/stacking_meta_learner.joblib）。
    # 元学习器不可用时自动回退固定权重，并通过 confidence_source 如实标注来源。
    stacking_fusion_enabled: bool = True

    # ===== 规则引擎阈值（平铺，向后兼容）=====
    syn_flood_min_count: int = 80
    syn_flood_high_count: int = 500
    port_scan_min_ports: int = 15
    port_scan_high_ports: int = 100
    dns_tunnel_max_query_len: int = 30
    dns_tunnel_min_count: int = 3
    dns_tunnel_high_count: int = 20
    large_flow_min_mb: float = 10.0
    rst_storm_min_count: int = 30

    # ===== UDP/QUIC 攻击检测阈值（v3.4.0 新增，平铺）=====
    udp_flood_min_packets: int = 100
    udp_flood_high_packets: int = 500
    dns_amp_min_ratio: float = 5.0
    dns_amp_min_responses: int = 5
    quic_flood_min_connections: int = 50
    quic_long_flow_min_packets: int = 200
    quic_initial_ratio_threshold: float = 0.3
    quic_unknown_version_alert: bool = True

    # ===== EWMA 时序基线引擎（平铺，向后兼容）=====
    baseline_alpha: float = 0.1
    baseline_sigma: float = 3.0
    baseline_window_sec: int = 10
    baseline_min_windows: int = 20
    baseline_online_update: bool = True
    baseline_drift_window: int = 10
    baseline_drift_alpha: float = 0.05

    # ===== ML 检测引擎（平铺，向后兼容）=====
    ml_engine_enabled: bool = True
    ml_contamination: float = 0.10
    ml_random_state: int = 42
    ml_max_samples: int = 256
    # 孤立森林并行度：默认 1（串行）。4 维百级窗口并行无收益，
    # 且 n_jobs=-1 在多进程受限环境会直接失败。需要时显式调大。
    ml_n_jobs: int = 1

    # ===== LLM 多采样投票（平铺，向后兼容）=====
    llm_vote_samples: int = 3
    llm_vote_temperatures: str = "0.1,0.4,0.7"

    # ===== DPAPI 加密存储（平铺，向后兼容）=====
    secure_store_enabled: bool = True

    def model_post_init(self, __context) -> None:
        """初始化后从加密存储读取 API Key（优先加密存储，回退 .env）"""
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
