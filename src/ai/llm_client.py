"""
大模型API客户端
封装 DeepSeek / 通义千问 等OpenAI兼容接口的调用
支持流式输出、重试、错误处理
"""
from openai import OpenAI
from typing import List, Dict, Any, Optional, Generator
from loguru import logger
import json
import time
import hashlib
import threading
from config.settings import settings


class LLMClient:
    """
    大模型客户端
    使用 OpenAI SDK 调用兼容接口（DeepSeek、通义千问等都兼容OpenAI格式）
    """

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 model: Optional[str] = None):
        self.api_key = api_key or settings.llm_api_key
        self.base_url = base_url or settings.llm_base_url
        self.model = model or settings.llm_model

        # P1-3: LLM 结果缓存（TTL 30 分钟, 上限 256 条, 线程安全）
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 30 * 60
        self._cache_max = 256

        if not self.api_key or self.api_key.startswith("sk-xxxx"):
            logger.warning("未配置有效的LLM_API_KEY，大模型功能将不可用")
            self.client = None
        else:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=60,
                max_retries=3
            )
            logger.info(f"LLM客户端初始化完成 | 模型: {self.model} | 端点: {self.base_url}")

    def is_available(self) -> bool:
        """检查大模型是否可用"""
        return self.client is not None

    # ---- P1-3 结果缓存 ----
    def _cache_key(self, messages, temperature, max_tokens) -> str:
        raw = json.dumps(messages, ensure_ascii=False, sort_keys=True) + f"|{temperature}|{max_tokens}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _cache_get(self, key: str):
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            ts, value = item
            if time.time() - ts >= self._cache_ttl:
                self._cache.pop(key, None)
                return None
            return value

    def _cache_set(self, key: str, value: str) -> None:
        with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                self._cache.pop(next(iter(self._cache)), None)
            self._cache[key] = (time.time(), value)

    def cache_size(self) -> int:
        with self._cache_lock:
            return len(self._cache)

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.3,
             max_tokens: int = 2048) -> str:
        """
        非流式对话（P1-3 带结果缓存：相同 prompt 秒回，二次分析不重复调用）
        :param messages: 消息列表 [{"role": "system/user/assistant", "content": "..."}]
        :param temperature: 温度，0=确定性，1=创造性
        :param max_tokens: 最大生成token数
        :return: 模型回复文本
        """
        if not self.is_available():
            return "[错误] 未配置大模型API Key，请在.env文件中设置LLM_API_KEY"

        key = self._cache_key(messages, temperature, max_tokens)
        hit = self._cache_get(key)
        if hit is not None:
            logger.debug(f"LLM 缓存命中 | key={key[:8]} | 缓存 {self.cache_size()} 条")
            return hit

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = response.choices[0].message.content
            logger.debug(f"LLM调用完成 | 输入tokens: {response.usage.prompt_tokens} | "
                        f"输出tokens: {response.usage.completion_tokens}")
            if content and not content.startswith("[大模型调用失败]"):
                self._cache_set(key, content)
            return content
        except Exception as e:
            logger.error(f"LLM调用失败: {e}")
            return f"[大模型调用失败] {str(e)}"

    def chat_stream(self, messages: List[Dict[str, str]], temperature: float = 0.3,
                    max_tokens: int = 2048) -> Generator[str, None, None]:
        """
        流式对话（逐字输出）
        :return: 生成器，逐块yield文本
        """
        if not self.is_available():
            yield "[错误] 未配置大模型API Key，请在.env文件中设置LLM_API_KEY"
            return

        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"LLM流式调用失败: {e}")
            yield f"\n[流式调用中断] {str(e)}"

    def simple_chat(self, user_message: str, system_prompt: Optional[str] = None,
                    temperature: float = 0.3) -> str:
        """
        简单对话封装
        :param user_message: 用户消息
        :param system_prompt: 系统提示词
        :return: 模型回复
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_message})
        return self.chat(messages, temperature=temperature)

    def count_tokens(self, text: str) -> int:
        """估算文本token数（粗略估算）"""
        # 中文约1.7字符/token，英文约4字符/token
        chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        other_chars = len(text) - chinese_chars
        return int(chinese_chars / 1.7 + other_chars / 4)


# 全局单例
_llm_client: Optional[LLMClient] = None

def get_llm_client() -> LLMClient:
    """获取全局LLM客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def reset_llm_client() -> None:
    """重置 LLM 客户端单例（API Key 等配置变更后调用，下次 get 时按新配置重建）"""
    global _llm_client
    _llm_client = None
