import os
import openai
from dotenv import load_dotenv

# 加载.env文件
load_dotenv()


def get_client():
    """获取OpenAI client，每次调用都会重新从.env文件读取配置"""
    load_dotenv()  # 重新加载.env文件
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        # 启动时不抛出异常，返回None，让调用方处理
        return None
    
    # 兼容不同版本的OpenAI库
    try:
        # 新版本
        return openai.OpenAI(api_key=api_key)
    except AttributeError:
        # 旧版本
        openai.api_key = api_key
        return openai

# 初始化默认client（可能为None）
try:
    client = get_client()
except Exception:
    client = None


def refresh_client():
    """重新初始化client，用于API Key更新后调用"""
    global client
    client = get_client()
