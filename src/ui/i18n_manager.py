"""
轻量级 i18n 国际化管理器
完全兼容 Gradio 6.x，不依赖 gradio-i18n
支持中英文即时切换，语言偏好持久化
"""
import json
import os
import logging
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger(__name__)


class I18nManager:
    """i18n 管理器：加载翻译字典，管理语言切换，批量更新 Gradio 组件"""

    def __init__(self, translations_path: str, default_lang: str = "zh"):
        self.translations: Dict[str, Dict[str, str]] = {}
        self.current_lang: str = default_lang
        self.default_lang: str = default_lang
        self._components: List[Tuple[Any, str, str]] = []  # (component, field, key)
        self._load_translations(translations_path)

    def _load_translations(self, path: str):
        """加载翻译字典"""
        try:
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    self.translations = json.load(f)
                logger.info(f"i18n 翻译字典已加载: {len(self.translations.get('zh', {}))} 条中文, {len(self.translations.get('en', {}))} 条英文")
            else:
                logger.warning(f"i18n 翻译字典不存在: {path}")
        except Exception as e:
            logger.error(f"i18n 翻译字典加载失败: {e}")
            self.translations = {"zh": {}, "en": {}}

    def tr(self, key: str, lang: Optional[str] = None) -> str:
        """翻译单个文本"""
        if lang is None:
            lang = self.current_lang
        return self.translations.get(lang, {}).get(key, key)

    def register(self, component: Any, field: str, key: str):
        """注册需要翻译的组件
        Args:
            component: Gradio 组件引用
            field: 组件字段名（如 'value', 'label', 'info', 'choices'）
            key: 翻译字典中的键
        """
        self._components.append((component, field, key))

    def set_language(self, lang: str):
        """设置当前语言"""
        if lang in self.translations:
            self.current_lang = lang
        else:
            logger.warning(f"未知语言: {lang}，使用默认 {self.default_lang}")
            self.current_lang = self.default_lang

    def get_updates(self, lang: str) -> list:
        """生成所有注册组件的 gr.update 列表
        Returns:
            与注册顺序一致的 gr.update 对象列表
        """
        import gradio as gr

        self.set_language(lang)
        updates = []
        for component, field, key in self._components:
            translated = self.tr(key, lang)
            if field == "choices":
                # choices 是列表 [(显示文本, 值), ...]
                original_choices = getattr(component, "choices", [])
                new_choices = []
                for choice in original_choices:
                    if isinstance(choice, tuple) and len(choice) == 2:
                        display, value = choice
                        # 用翻译后的文本替换显示文本
                        new_display = self.tr(str(display), lang)
                        new_choices.append((new_display, value))
                    else:
                        new_choices.append(choice)
                updates.append(gr.update(choices=new_choices, interactive=True))
            elif field == "value":
                updates.append(gr.update(value=translated))
            elif field == "label":
                updates.append(gr.update(label=translated))
            elif field == "info":
                updates.append(gr.update(info=translated))
            elif field == "placeholder":
                updates.append(gr.update(placeholder=translated))
            else:
                # 通用字段
                updates.append(gr.update(**{field: translated}))
        return updates

    def get_component_outputs(self) -> list:
        """获取所有注册组件的引用列表（用于事件 outputs）"""
        return [comp for comp, _, _ in self._components]

    def save_preference(self, lang: str, config_path: str):
        """保存语言偏好到服务端配置"""
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            settings = {}
            if os.path.exists(config_path):
                # 使用 utf-8-sig 兼容带 BOM 的文件（PowerShell Out-File 会添加 BOM）
                with open(config_path, encoding="utf-8-sig") as f:
                    settings = json.load(f)
            settings["language"] = lang
            # 写入时使用 utf-8（无 BOM），避免后续读取问题
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
            logger.info(f"语言偏好已保存: {lang}")
        except Exception as e:
            logger.warning(f"保存语言偏好失败: {e}")

    @staticmethod
    def load_preference(config_path: str, default_lang: str = "zh") -> str:
        """从服务端配置加载语言偏好"""
        try:
            if os.path.exists(config_path):
                # 使用 utf-8-sig 兼容带 BOM 的文件
                with open(config_path, encoding="utf-8-sig") as f:
                    settings = json.load(f)
                return settings.get("language", default_lang)
        except Exception as e:
            logger.warning(f"加载语言偏好失败: {e}")
        return default_lang
