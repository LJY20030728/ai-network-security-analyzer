#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智谱AI API 测试脚本
验证API Key是否有效，测试glm-4-flash模型调用
"""
import os
import sys
import io
from dotenv import load_dotenv

# 设置UTF-8输出
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 加载.env配置
load_dotenv()

api_key = os.getenv("LLM_API_KEY", "")
base_url = os.getenv("LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
model = os.getenv("LLM_MODEL", "glm-4-flash")

print("=" * 60)
print("ZhipuAI API Test")
print("=" * 60)
print(f"API Key: {api_key[:10]}...{api_key[-6:] if len(api_key) > 16 else ''}")
print(f"Base URL: {base_url}")
print(f"Model: {model}")
print("=" * 60)

if not api_key or api_key.startswith("sk-xxxx"):
    print("[ERROR] No valid LLM_API_KEY configured")
    print("Please fill in your ZhipuAI API Key in .env file")
    sys.exit(1)

try:
    from openai import OpenAI

    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=30,
    )

    print("\n[1/2] Calling ZhipuAI (non-stream)...")
    print("-" * 60)

    # 测试1：简单对话
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert. Answer concisely and professionally in Chinese."},
            {"role": "user", "content": "用一句话说明什么是端口扫描，以及如何检测？"}
        ],
        temperature=0.3,
        max_tokens=500,
    )

    answer = response.choices[0].message.content
    print(f"[AI Response]:")
    print(answer)
    print("-" * 60)
    print(f"[Token Usage] input={response.usage.prompt_tokens} output={response.usage.completion_tokens} total={response.usage.total_tokens}")

    # 测试2：流式输出
    print("\n[2/2] Testing streaming output...")
    print("-" * 60)

    stream = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "user", "content": "列举3种常见的网络攻击类型，每种一句话说明。"}
        ],
        temperature=0.3,
        max_tokens=300,
        stream=True,
    )

    print("[AI Stream Response]:")
    full_content = ""
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            content = chunk.choices[0].delta.content
            full_content += content
            print(content, end="", flush=True)
    print()
    print("-" * 60)

    print("\n" + "=" * 60)
    print("[SUCCESS] ZhipuAI API test passed!")
    print("=" * 60)
    print(f"\nYour API Key is valid. Model '{model}' works correctly.")
    print("You can now install other dependencies (scapy, fastapi, langchain, chromadb)")
    print("and launch the full AI Network Security Analyzer system.")

except ImportError as e:
    print(f"[ERROR] openai library not installed: {e}")
    print("Please run: pip install openai")
    sys.exit(1)
except Exception as e:
    print(f"\n[ERROR] Call failed: {e}")
    print("\nPossible reasons:")
    print("1. API Key is invalid or expired")
    print("2. Network connection issue")
    print("3. Incorrect model name")
    print(f"\nCurrent config: base_url={base_url}, model={model}")
    sys.exit(1)
