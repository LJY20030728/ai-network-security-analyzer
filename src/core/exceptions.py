"""
统一异常体系

所有业务异常都继承自 AppError，包含：
- error_code: 错误码（用于API响应）
- message: 用户友好的错误信息
- detail: 详细错误信息（调试用）
- status_code: HTTP状态码
"""

from typing import Any, Dict, Optional
from .errors import ErrorCode


class AppError(Exception):
    """应用异常基类"""
    
    status_code: int = 500
    error_code: ErrorCode = ErrorCode.INTERNAL_ERROR
    default_message: str = "内部错误"
    
    def __init__(
        self,
        message: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
        error_code: Optional[ErrorCode] = None,
        status_code: Optional[int] = None,
    ):
        self.message = message or self.default_message
        self.detail = detail or {}
        self.error_code = error_code or self.error_code
        self.status_code = status_code or self.status_code
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为API响应字典"""
        return {
            "error": {
                "code": self.error_code.value,
                "message": self.message,
                "detail": self.detail,
            }
        }


# ===== 400 客户端错误 =====

class BadRequestError(AppError):
    """请求参数错误"""
    status_code = 400
    error_code = ErrorCode.INVALID_PARAMETER
    default_message = "请求参数错误"


class NotFoundError(AppError):
    """资源不存在"""
    status_code = 404
    error_code = ErrorCode.RESOURCE_NOT_FOUND
    default_message = "资源不存在"


class FileTooLargeError(AppError):
    """文件过大"""
    status_code = 413
    error_code = ErrorCode.FILE_TOO_LARGE
    default_message = "文件过大"


class InvalidFileTypeError(AppError):
    """文件类型不支持"""
    status_code = 415
    error_code = ErrorCode.INVALID_FILE_TYPE
    default_message = "文件类型不支持"


# ===== 401/403 认证授权错误 =====

class UnauthorizedError(AppError):
    """未认证"""
    status_code = 401
    error_code = ErrorCode.UNAUTHORIZED
    default_message = "未认证或认证已过期"


class ForbiddenError(AppError):
    """无权限"""
    status_code = 403
    error_code = ErrorCode.FORBIDDEN
    default_message = "没有权限执行此操作"


# ===== 分析引擎错误 =====

class AnalysisError(AppError):
    """分析失败"""
    status_code = 500
    error_code = ErrorCode.ANALYSIS_FAILED
    default_message = "流量分析失败"


class PCAPParseError(AnalysisError):
    """PCAP解析失败"""
    error_code = ErrorCode.PCAP_PARSE_ERROR
    default_message = "PCAP文件解析失败"


class FeatureExtractionError(AnalysisError):
    """特征提取失败"""
    error_code = ErrorCode.FEATURE_EXTRACTION_ERROR
    default_message = "特征提取失败"


class DetectionEngineError(AnalysisError):
    """检测引擎错误"""
    error_code = ErrorCode.DETECTION_ERROR
    default_message = "检测引擎运行错误"


# ===== 基线管理错误 =====

class BaselineError(AppError):
    """基线管理错误"""
    status_code = 400
    error_code = ErrorCode.BASELINE_NOT_FOUND
    default_message = "基线管理错误"


class BaselineNotFoundError(BaselineError):
    """基线不存在"""
    error_code = ErrorCode.BASELINE_NOT_FOUND
    default_message = "基线不存在"


class BaselineTrainingError(BaselineError):
    """基线训练失败"""
    error_code = ErrorCode.BASELINE_TRAINING_FAILED
    default_message = "基线训练失败"


class BaselineInvalidDataError(BaselineError):
    """基线数据无效"""
    error_code = ErrorCode.BASELINE_INVALID_DATA
    default_message = "基线数据无效，需要足够的正常流量样本"


# ===== 知识库错误 =====

class KnowledgeBaseError(AppError):
    """知识库错误"""
    status_code = 500
    error_code = ErrorCode.KNOWLEDGE_NOT_INITIALIZED
    default_message = "知识库错误"


class KnowledgeNotInitializedError(KnowledgeBaseError):
    """知识库未初始化"""
    error_code = ErrorCode.KNOWLEDGE_NOT_INITIALIZED
    default_message = "知识库未初始化，请先初始化知识库"


class KnowledgeSearchError(KnowledgeBaseError):
    """知识库搜索失败"""
    error_code = ErrorCode.KNOWLEDGE_SEARCH_FAILED
    default_message = "知识库搜索失败"


# ===== 报告生成错误 =====

class ReportError(AppError):
    """报告生成错误"""
    status_code = 500
    error_code = ErrorCode.REPORT_GENERATION_FAILED
    default_message = "报告生成错误"


class ReportNotFoundError(ReportError):
    """报告不存在"""
    status_code = 404
    error_code = ErrorCode.REPORT_NOT_FOUND
    default_message = "报告不存在"


# ===== 历史记录错误 =====

class HistoryError(AppError):
    """历史记录错误"""
    status_code = 500
    error_code = ErrorCode.HISTORY_QUERY_FAILED
    default_message = "历史记录查询错误"


class HistoryNotFoundError(HistoryError):
    """历史记录不存在"""
    status_code = 404
    error_code = ErrorCode.HISTORY_NOT_FOUND
    default_message = "历史记录不存在"


# ===== 外部服务错误 =====

class ExternalServiceError(AppError):
    """外部服务错误"""
    status_code = 502
    error_code = ErrorCode.LLM_API_ERROR
    default_message = "外部服务调用失败"


class LLMAPIError(ExternalServiceError):
    """LLM API调用失败"""
    error_code = ErrorCode.LLM_API_ERROR
    default_message = "大模型API调用失败"


class LLMAPITimeoutError(ExternalServiceError):
    """LLM API超时"""
    error_code = ErrorCode.LLM_API_TIMEOUT
    default_message = "大模型API调用超时"


class LLMAuthError(ExternalServiceError):
    """LLM API认证失败"""
    status_code = 401
    error_code = ErrorCode.LLM_AUTH_ERROR
    default_message = "大模型API认证失败，请检查API Key配置"


# ===== 配置错误 =====

class ConfigError(AppError):
    """配置错误"""
    status_code = 500
    error_code = ErrorCode.CONFIG_MISSING
    default_message = "配置错误"


class ConfigMissingError(ConfigError):
    """配置缺失"""
    error_code = ErrorCode.CONFIG_MISSING
    default_message = "缺少必要配置项"


class ConfigInvalidError(ConfigError):
    """配置无效"""
    error_code = ErrorCode.CONFIG_INVALID
    default_message = "配置值无效"
