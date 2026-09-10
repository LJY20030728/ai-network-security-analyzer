# -*- coding: utf-8 -*-
"""
P1-3: 安全存储模块（Windows DPAPI 加密）
使用 Windows DPAPI (CryptProtectData/CryptUnprotectData) 加密存储敏感信息（API Key 等）。
无需额外依赖（pywin32），直接用 ctypes 调用 Windows API。
加密密钥绑定当前用户，其他用户无法解密。
"""
import base64
import json
import os
import sys
from typing import Any, Dict, Optional

from loguru import logger

# 仅 Windows 支持 DPAPI
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    # DPAPI 结构体
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    # 加载 crypt32.dll
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    # CRYPTPROTECT_UI_FORBIDDEN = 0x1（不显示 UI）
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    # CRYPTPROTECT_LOCAL_MACHINE = 0x4（绑定机器而非用户，可选）
    CRYPTPROTECT_LOCAL_MACHINE = 0x4


def _dpapi_encrypt(plaintext: str, description: str = "") -> Optional[str]:
    """用 DPAPI 加密字符串，返回 Base64 编码的密文"""
    if not IS_WINDOWS:
        logger.warning("非 Windows 平台，DPAPI 不可用，回退明文存储")
        return None

    try:
        data_bytes = plaintext.encode("utf-8")
        blob_in = DATA_BLOB()
        blob_in.cbData = len(data_bytes)
        blob_in.pbData = ctypes.cast(
            (ctypes.c_byte * len(data_bytes))(*data_bytes),
            ctypes.POINTER(ctypes.c_byte),
        )

        blob_out = DATA_BLOB()
        desc_w = ctypes.c_wchar_p(description) if description else None

        success = _crypt32.CryptProtectData(
            ctypes.byref(blob_in),
            desc_w,
            None,  # pOptionalEntropy
            None,  # pvReserved
            None,  # pPromptStruct
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        )

        if not success:
            err = _kernel32.GetLastError()
            logger.error(f"DPAPI 加密失败，错误码: {err}")
            return None

        # 读取加密后的数据
        encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        # 释放内存
        _kernel32.LocalFree(blob_out.pbData)

        return base64.b64encode(encrypted).decode("ascii")
    except Exception as e:
        logger.error(f"DPAPI 加密异常: {e}")
        return None


def _dpapi_decrypt(ciphertext_b64: str) -> Optional[str]:
    """用 DPAPI 解密 Base64 编码的密文，返回明文字符串"""
    if not IS_WINDOWS:
        return None

    try:
        encrypted = base64.b64decode(ciphertext_b64)
        blob_in = DATA_BLOB()
        blob_in.cbData = len(encrypted)
        blob_in.pbData = ctypes.cast(
            (ctypes.c_byte * len(encrypted))(*encrypted),
            ctypes.POINTER(ctypes.c_byte),
        )

        blob_out = DATA_BLOB()

        success = _crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,  # ppszDataDescr
            None,  # pOptionalEntropy
            None,  # pvReserved
            None,  # pPromptStruct
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        )

        if not success:
            err = _kernel32.GetLastError()
            logger.error(f"DPAPI 解密失败，错误码: {err}")
            return None

        plaintext_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        _kernel32.LocalFree(blob_out.pbData)

        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        logger.error(f"DPAPI 解密异常: {e}")
        return None


class SecureStore:
    """
    安全存储（DPAPI 加密）
    存储敏感配置（API Key、Base URL 等），加密后保存到 JSON 文件。
    Windows 下用 DPAPI 加密，非 Windows 下回退明文（开发环境）。
    """

    def __init__(self, store_path: Optional[str] = None):
        from src.utils.paths import data_dir
        from src.utils.helpers import ensure_dir
        self._store_path = store_path or os.path.join(data_dir("config"), "secure_config.json")
        ensure_dir(os.path.dirname(self._store_path))
        self._data: Dict[str, Any] = {}
        self._load()

    def _load(self):
        """加载加密配置文件"""
        try:
            if os.path.exists(self._store_path):
                with open(self._store_path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
        except Exception as e:
            logger.warning(f"加载安全配置失败: {e}")
            self._data = {}

    def _save(self):
        """保存加密配置文件"""
        try:
            with open(self._store_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存安全配置失败: {e}")

    def set(self, key: str, value: str, encrypt: bool = True) -> bool:
        """
        存储敏感值
        :param key: 配置键
        :param value: 配置值
        :param encrypt: 是否加密（默认 True）
        :return: 是否成功
        """
        if encrypt and IS_WINDOWS:
            encrypted = _dpapi_encrypt(value, description=f"AI Network Security Analyzer - {key}")
            if encrypted:
                self._data[key] = {"__encrypted__": True, "value": encrypted}
                self._save()
                return True
            logger.warning(f"DPAPI 加密失败，回退明文存储: {key}")

        # 明文存储（非 Windows 或加密失败）
        self._data[key] = {"__encrypted__": False, "value": value}
        self._save()
        return True

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        获取敏感值（自动解密）
        :param key: 配置键
        :param default: 默认值
        :return: 明文字符串
        """
        entry = self._data.get(key)
        if not entry:
            return default

        if entry.get("__encrypted__") and IS_WINDOWS:
            decrypted = _dpapi_decrypt(entry["value"])
            if decrypted is not None:
                return decrypted
            logger.warning(f"DPAPI 解密失败，尝试明文: {key}")
            return entry.get("value", default)

        return entry.get("value", default)

    def delete(self, key: str) -> bool:
        """删除配置项"""
        if key in self._data:
            del self._data[key]
            self._save()
            return True
        return False

    def has(self, key: str) -> bool:
        """检查配置项是否存在"""
        return key in self._data

    def list_keys(self) -> list:
        """列出所有配置键（不返回值）"""
        return list(self._data.keys())

    def is_encrypted(self, key: str) -> bool:
        """检查配置项是否加密"""
        entry = self._data.get(key)
        return bool(entry and entry.get("__encrypted__"))

    @property
    def dpapi_available(self) -> bool:
        """DPAPI 是否可用"""
        return IS_WINDOWS


# 全局单例
_secure_store: Optional[SecureStore] = None


def get_secure_store() -> SecureStore:
    """获取安全存储单例"""
    global _secure_store
    if _secure_store is None:
        _secure_store = SecureStore()
    return _secure_store
