"""
错误码定义

错误码格式：{类别}_{编号}
类别：
- COMMON: 通用错误
- AUTH: 认证授权错误
- ANALYSIS: 分析引擎错误
- BASELINE: 基线管理错误
- KNOWLEDGE: 知识库错误
- REPORT: 报告生成错误
- HISTORY: 历史记录错误
- EXTERNAL: 外部服务错误
- CONFIG: 配置错误
"""

from enum import Enum


class ErrorCode(str, Enum):
    """错误码枚举"""
    
    # ===== 通用错误 =====
    INTERNAL_ERROR = "COMMON_001"           # 内部错误
    INVALID_PARAMETER = "COMMON_002"        # 参数错误
    RESOURCE_NOT_FOUND = "COMMON_003"       # 资源不存在
    OPERATION_FAILED = "COMMON_004"        # 操作失败
    FILE_TOO_LARGE = "COMMON_005"          # 文件过大
    INVALID_FILE_TYPE = "COMMON_006"       # 文件类型不支持
    
    # ===== 认证授权错误 =====
    UNAUTHORIZED = "AUTH_001"              # 未认证
    FORBIDDEN = "AUTH_002"                 # 无权限
    
    # ===== 分析引擎错误 =====
    ANALYSIS_FAILED = "ANALYSIS_001"       # 分析失败
    PCAP_PARSE_ERROR = "ANALYSIS_002"      # PCAP解析失败
    FEATURE_EXTRACTION_ERROR = "ANALYSIS_003"  # 特征提取失败
    DETECTION_ERROR = "ANALYSIS_004"       # 检测引擎错误
    
    # ===== 基线管理错误 =====
    BASELINE_NOT_FOUND = "BASELINE_001"    # 基线不存在
    BASELINE_TRAINING_FAILED = "BASELINE_002"  # 基线训练失败
    BASELINE_INVALID_DATA = "BASELINE_003"   # 基线数据无效
    BASELINE_DELETE_FAILED = "BASELINE_004"  # 基线删除失败
    
    # ===== 知识库错误 =====
    KNOWLEDGE_NOT_INITIALIZED = "KNOWLEDGE_001"  # 知识库未初始化
    KNOWLEDGE_SEARCH_FAILED = "KNOWLEDGE_002"    # 知识库搜索失败
    KNOWLEDGE_EMBEDDING_ERROR = "KNOWLEDGE_003"  # 向量嵌入错误
    
    # ===== 报告生成错误 =====
    REPORT_GENERATION_FAILED = "REPORT_001"   # 报告生成失败
    REPORT_NOT_FOUND = "REPORT_002"          # 报告不存在
    REPORT_SAVE_FAILED = "REPORT_003"        # 报告保存失败
    
    # ===== 历史记录错误 =====
    HISTORY_NOT_FOUND = "HISTORY_001"       # 历史记录不存在
    HISTORY_QUERY_FAILED = "HISTORY_002"    # 历史记录查询失败
    
    # ===== 外部服务错误 =====
    LLM_API_ERROR = "EXTERNAL_001"          # LLM API调用失败
    LLM_API_TIMEOUT = "EXTERNAL_002"        # LLM API超时
    LLM_AUTH_ERROR = "EXTERNAL_003"         # LLM API认证失败
    EMBEDDING_MODEL_ERROR = "EXTERNAL_004"  # 嵌入模型错误
    
    # ===== 配置错误 =====
    CONFIG_MISSING = "CONFIG_001"           # 配置缺失
    CONFIG_INVALID = "CONFIG_002"           # 配置无效
