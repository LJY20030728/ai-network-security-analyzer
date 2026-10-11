"""
大模型API客户端
封装 DeepSeek / 通义千问 等OpenAI兼容接口的调用
支持流式输出、重试、错误处理
"""
from openai import OpenAI
from typing import List, Dict, Optional, Generator
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

    # 全局语言设置（i18n）：影响所有 AI 输出的语言
    _current_language = "zh"  # 默认中文

    @classmethod
    def set_language(cls, lang: str) -> None:
        """设置全局 AI 输出语言（zh / en）"""
        if lang in ("zh", "en"):
            cls._current_language = lang
            logger.info(f"LLM 输出语言已设置为: {lang}")

    @classmethod
    def get_language(cls) -> str:
        """获取当前 AI 输出语言"""
        return cls._current_language

    def _inject_language_instruction(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """根据当前语言设置，在 system prompt 中注入语言指令。

        **不修改调用方传入的列表**：原实现在原列表上 `messages[i]['content'] = ...`
        并 `insert(0, ...)`，会污染调用方的数据（同一 messages 被复用时语言指令会
        被反复追加）。现返回浅拷贝。
        """
        lang = self._current_language
        if lang == "zh":
            instruction = "请始终使用简体中文回答。"
        else:
            instruction = "Please always respond in English."

        out = [dict(m) for m in messages]

        # 查找 system 消息
        system_idx = None
        for i, msg in enumerate(out):
            if msg.get("role") == "system":
                system_idx = i
                break

        if system_idx is not None:
            original = out[system_idx].get("content", "") or ""
            if instruction not in original:
                out[system_idx]["content"] = original + "\n\n" + instruction
        else:
            out.insert(0, {"role": "system", "content": instruction})

        return out

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
             max_tokens: int = 4096,
             no_cache: bool = False) -> str:
        """
        非流式对话（P1-3 带结果缓存：相同 prompt 秒回，二次分析不重复调用）
        :param messages: 消息列表 [{"role": "system/user/assistant", "content": "..."}]
        :param temperature: 温度，0=确定性，1=创造性
        :param max_tokens: 最大生成token数（默认4096，适配 glm-4.5-air 等推理模型：
            推理模型先输出 reasoning_content 思维链再输出正式回答，思维链可占2000+ token，
            1024/2048 会导致回答被截断甚至为空）
        :param no_cache: True 时跳过读写缓存。多温度采样投票必须用它——
            否则"多次独立采样"会命中同一条缓存而塌缩成一次调用，
            投票结果恒为全体一致（agreement 恒 1.0），使该功能名存实亡。
        :return: 模型回复文本
        """
        if not self.is_available():
            return "[错误] 未配置大模型API Key，请在.env文件中设置LLM_API_KEY"

        # i18n：注入语言指令（返回副本，不改调用方数据）
        messages = self._inject_language_instruction(messages)

        key = self._cache_key(messages, temperature, max_tokens)
        if not no_cache:
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
            choice = response.choices[0]
            content = choice.message.content
            finish_reason = getattr(choice, "finish_reason", "")
            # 推理模型（如 glm-4.5-air）先输出思维链，再输出正式回答
            reasoning_content = getattr(choice.message, "reasoning_content", None)

            logger.debug(f"LLM调用完成 | 输入tokens: {response.usage.prompt_tokens} | "
                        f"输出tokens: {response.usage.completion_tokens} | "
                        f"finish_reason: {finish_reason} | "
                        f"reasoning_content长度: {len(reasoning_content) if reasoning_content else 0}")

            # 【截断检测】finish_reason == "length" 表示 max_tokens 预算耗尽，回答被截断
            if finish_reason == "length":
                logger.warning(
                    f"LLM回答被截断！finish_reason=length, max_tokens={max_tokens}, "
                    f"实际输出={response.usage.completion_tokens}tokens, "
                    f"reasoning_content={len(reasoning_content) if reasoning_content else 0}tokens, "
                    f"content长度={len(content) if content else 0}"
                )

            # 【空内容检测】推理模型思维链吃掉全部预算时，content 可能为空
            # 空内容不应缓存（否则后续相同问题会命中空缓存），应返回明确错误
            if not content or not content.strip():
                err_msg = (
                    f"[大模型调用失败] 模型返回空内容。"
                    f"finish_reason={finish_reason or 'unknown'}, "
                    f"max_tokens={max_tokens}, "
                    f"reasoning_content={len(reasoning_content) if reasoning_content else 0}tokens。"
                    f"可能原因：推理模型思维链耗尽token预算，请增大max_tokens或换用非推理模型。"
                )
                logger.error(err_msg)
                return err_msg

            # 正常内容才缓存（空内容和失败信息不缓存）
            if not content.startswith("[大模型调用失败]") and not no_cache:
                self._cache_set(key, content)
            return content
        except Exception as e:
            logger.error(f"LLM调用失败: {e}")
            return f"[大模型调用失败] {str(e)}"

    def chat_stream(self, messages: List[Dict[str, str]], temperature: float = 0.3,
                    max_tokens: int = 4096) -> Generator[str, None, None]:
        """
        流式对话（逐字输出）
        :param max_tokens: 最大生成token数（默认4096，适配推理模型）
        :return: 生成器，逐块yield文本
        """
        if not self.is_available():
            yield "[错误] 未配置大模型API Key，请在.env文件中设置LLM_API_KEY"
            return

        # i18n：注入语言指令
        messages = self._inject_language_instruction(messages)

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
