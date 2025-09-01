"""
AI提供商具体实现 - 实现各种AI提供商的具体接口
"""

import json
import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime

from .base import BaseAIProvider, AIRequest
from core.interfaces import AIResponse, AIProviderType
from core.exceptions import AIProviderError


class DeepSeekProvider(BaseAIProvider):
    """DeepSeek AI提供商"""
    
    def __init__(self, config: Dict[str, Any], logger=None):
        super().__init__(AIProviderType.DEEPSEEK, config, logger)
        if not self.base_url:
            self.base_url = "https://api.deepseek.com/v1"
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """执行DeepSeek API请求"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # 构建消息列表
        messages = []
        
        # 添加系统消息
        if request.system_message:
            messages.append({"role": "system", "content": request.system_message})
        
        # 添加对话历史
        for msg in request.conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # 添加当前提示
        messages.append({"role": "user", "content": request.prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_tokens or self.default_max_tokens,
            "temperature": request.temperature or self.default_temperature,
            "stream": False
        }
        
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(f"{self.base_url}/chat/completions", 
                                       headers=headers, 
                                       json=payload) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise AIProviderError(f"DeepSeek API错误 {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    if "error" in result:
                        raise AIProviderError(f"DeepSeek API错误: {result['error']['message']}")
                    
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    return AIResponse(
                        content=result["choices"][0]["message"]["content"],
                        provider=self.provider_type,
                        model=self.model,
                        tokens_used=result.get("usage", {}).get("total_tokens", 0),
                        response_time=response_time,
                        success=True
                    )
                    
        except aiohttp.ClientError as e:
            raise AIProviderError(f"DeepSeek网络错误: {str(e)}")
        except json.JSONDecodeError as e:
            raise AIProviderError(f"DeepSeek响应解析错误: {str(e)}")
    
    async def validate_api_key(self) -> bool:
        """验证DeepSeek API密钥"""
        try:
            test_request = AIRequest(
                prompt="Hello",
                max_tokens=10,
                temperature=0.1
            )
            response = await self._make_api_request(test_request)
            return response.success
        except Exception:
            return False


class OpenAIProvider(BaseAIProvider):
    """OpenAI提供商"""
    
    def __init__(self, config: Dict[str, Any], logger=None):
        super().__init__(AIProviderType.OPENAI, config, logger)
        if not self.base_url:
            self.base_url = "https://api.openai.com/v1"
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """执行OpenAI API请求"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # 构建消息列表
        messages = []
        
        if request.system_message:
            messages.append({"role": "system", "content": request.system_message})
        
        for msg in request.conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        messages.append({"role": "user", "content": request.prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_tokens or self.default_max_tokens,
            "temperature": request.temperature or self.default_temperature
        }
        
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(f"{self.base_url}/chat/completions", 
                                       headers=headers, 
                                       json=payload) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise AIProviderError(f"OpenAI API错误 {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    if "error" in result:
                        raise AIProviderError(f"OpenAI API错误: {result['error']['message']}")
                    
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    return AIResponse(
                        content=result["choices"][0]["message"]["content"],
                        provider=self.provider_type,
                        model=self.model,
                        tokens_used=result.get("usage", {}).get("total_tokens", 0),
                        response_time=response_time,
                        success=True
                    )
                    
        except aiohttp.ClientError as e:
            raise AIProviderError(f"OpenAI网络错误: {str(e)}")
        except json.JSONDecodeError as e:
            raise AIProviderError(f"OpenAI响应解析错误: {str(e)}")
    
    async def validate_api_key(self) -> bool:
        """验证OpenAI API密钥"""
        try:
            test_request = AIRequest(
                prompt="Hello",
                max_tokens=10,
                temperature=0.1
            )
            response = await self._make_api_request(test_request)
            return response.success
        except Exception:
            return False


class ClaudeProvider(BaseAIProvider):
    """Anthropic Claude提供商"""
    
    def __init__(self, config: Dict[str, Any], logger=None):
        super().__init__(AIProviderType.CLAUDE, config, logger)
        if not self.base_url:
            self.base_url = "https://api.anthropic.com/v1"
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """执行Claude API请求"""
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        # Claude使用不同的消息格式
        messages = []
        
        # 添加对话历史
        for msg in request.conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # 添加当前提示
        messages.append({"role": "user", "content": request.prompt})
        
        payload = {
            "model": self.model,
            "max_tokens": request.max_tokens or self.default_max_tokens,
            "temperature": request.temperature or self.default_temperature,
            "messages": messages
        }
        
        # 如果有系统消息，添加到payload中
        if request.system_message:
            payload["system"] = request.system_message
        
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(f"{self.base_url}/messages", 
                                       headers=headers, 
                                       json=payload) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise AIProviderError(f"Claude API错误 {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    if "error" in result:
                        raise AIProviderError(f"Claude API错误: {result['error']['message']}")
                    
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    # Claude的响应格式略有不同
                    content = result["content"][0]["text"] if result.get("content") else ""
                    
                    return AIResponse(
                        content=content,
                        provider=self.provider_type,
                        model=self.model,
                        tokens_used=result.get("usage", {}).get("input_tokens", 0) + result.get("usage", {}).get("output_tokens", 0),
                        response_time=response_time,
                        success=True
                    )
                    
        except aiohttp.ClientError as e:
            raise AIProviderError(f"Claude网络错误: {str(e)}")
        except json.JSONDecodeError as e:
            raise AIProviderError(f"Claude响应解析错误: {str(e)}")
    
    async def validate_api_key(self) -> bool:
        """验证Claude API密钥"""
        try:
            test_request = AIRequest(
                prompt="Hello",
                max_tokens=10,
                temperature=0.1
            )
            response = await self._make_api_request(test_request)
            return response.success
        except Exception:
            return False


class GeminiProvider(BaseAIProvider):
    """Google Gemini提供商"""
    
    def __init__(self, config: Dict[str, Any], logger=None):
        super().__init__(AIProviderType.GEMINI, config, logger)
        if not self.base_url:
            self.base_url = "https://generativelanguage.googleapis.com/v1beta"
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """执行Gemini API请求"""
        # Gemini使用URL参数传递API密钥
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        # 构建Gemini格式的内容
        contents = []
        
        # 添加对话历史
        for msg in request.conversation_history:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({
                "role": role,
                "parts": [{"text": msg["content"]}]
            })
        
        # 添加当前提示
        contents.append({
            "role": "user",
            "parts": [{"text": request.prompt}]
        })
        
        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": request.max_tokens or self.default_max_tokens,
                "temperature": request.temperature or self.default_temperature
            }
        }
        
        # 如果有系统消息，添加到第一个内容中
        if request.system_message:
            system_content = {
                "role": "user",
                "parts": [{"text": f"System: {request.system_message}"}]
            }
            contents.insert(0, system_content)
            payload["contents"] = contents
        
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(url, headers=headers, json=payload) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise AIProviderError(f"Gemini API错误 {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    if "error" in result:
                        raise AIProviderError(f"Gemini API错误: {result['error']['message']}")
                    
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    # 提取Gemini响应内容
                    candidates = result.get("candidates", [])
                    if not candidates:
                        raise AIProviderError("Gemini未返回有效响应")
                    
                    content = candidates[0]["content"]["parts"][0]["text"]
                    
                    # Gemini的token使用情况
                    usage_metadata = result.get("usageMetadata", {})
                    tokens_used = usage_metadata.get("totalTokenCount", 0)
                    
                    return AIResponse(
                        content=content,
                        provider=self.provider_type,
                        model=self.model,
                        tokens_used=tokens_used,
                        response_time=response_time,
                        success=True
                    )
                    
        except aiohttp.ClientError as e:
            raise AIProviderError(f"Gemini网络错误: {str(e)}")
        except json.JSONDecodeError as e:
            raise AIProviderError(f"Gemini响应解析错误: {str(e)}")
    
    async def validate_api_key(self) -> bool:
        """验证Gemini API密钥"""
        try:
            test_request = AIRequest(
                prompt="Hello",
                max_tokens=10,
                temperature=0.1
            )
            response = await self._make_api_request(test_request)
            return response.success
        except Exception:
            return False


class OllamaProvider(BaseAIProvider):
    """Ollama本地提供商"""
    
    def __init__(self, config: Dict[str, Any], logger=None):
        super().__init__(AIProviderType.OLLAMA, config, logger)
        if not self.base_url:
            self.base_url = "http://localhost:11434"
        # Ollama不需要API密钥
        self.api_key = ""
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """执行Ollama API请求"""
        headers = {
            "Content-Type": "application/json"
        }
        
        # 构建消息列表
        messages = []
        
        if request.system_message:
            messages.append({"role": "system", "content": request.system_message})
        
        for msg in request.conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        messages.append({"role": "user", "content": request.prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": request.max_tokens or self.default_max_tokens,
                "temperature": request.temperature or self.default_temperature
            }
        }
        
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(f"{self.base_url}/api/chat", 
                                       headers=headers, 
                                       json=payload) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise AIProviderError(f"Ollama API错误 {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    if "error" in result:
                        raise AIProviderError(f"Ollama API错误: {result['error']}")
                    
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    return AIResponse(
                        content=result["message"]["content"],
                        provider=self.provider_type,
                        model=self.model,
                        tokens_used=result.get("eval_count", 0) + result.get("prompt_eval_count", 0),
                        response_time=response_time,
                        success=True
                    )
                    
        except aiohttp.ClientError as e:
            raise AIProviderError(f"Ollama网络错误: {str(e)}")
        except json.JSONDecodeError as e:
            raise AIProviderError(f"Ollama响应解析错误: {str(e)}")
    
    async def validate_api_key(self) -> bool:
        """验证Ollama连接（不需要API密钥）"""
        try:
            # 检查Ollama服务是否可用
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"{self.base_url}/api/tags") as response:
                    return response.status == 200
        except Exception:
            return False


class AIProviderFactory:
    """AI提供商工厂类"""
    
    @staticmethod
    def create_provider(provider_type: AIProviderType, config: Dict[str, Any], logger=None) -> BaseAIProvider:
        """创建AI提供商实例"""
        provider_map = {
            AIProviderType.DEEPSEEK: DeepSeekProvider,
            AIProviderType.OPENAI: OpenAIProvider,
            AIProviderType.CLAUDE: ClaudeProvider,
            AIProviderType.GEMINI: GeminiProvider,
            AIProviderType.OLLAMA: OllamaProvider
        }
        
        provider_class = provider_map.get(provider_type)
        if not provider_class:
            raise AIProviderError(f"不支持的AI提供商类型: {provider_type}")
        
        return provider_class(config, logger)
    
    @staticmethod
    def get_supported_providers() -> List[AIProviderType]:
        """获取支持的提供商列表"""
        return list(AIProviderType)
    
    @staticmethod
    def get_provider_requirements(provider_type: AIProviderType) -> Dict[str, Any]:
        """获取提供商配置要求"""
        requirements = {
            AIProviderType.DEEPSEEK: {
                "required_fields": ["api_key", "model"],
                "optional_fields": ["base_url", "max_tokens", "temperature", "timeout"],
                "default_model": "deepseek-chat",
                "default_base_url": "https://api.deepseek.com/v1"
            },
            AIProviderType.OPENAI: {
                "required_fields": ["api_key", "model"],
                "optional_fields": ["base_url", "max_tokens", "temperature", "timeout"],
                "default_model": "gpt-3.5-turbo",
                "default_base_url": "https://api.openai.com/v1"
            },
            AIProviderType.CLAUDE: {
                "required_fields": ["api_key", "model"],
                "optional_fields": ["base_url", "max_tokens", "temperature", "timeout"],
                "default_model": "claude-3-sonnet-20240229",
                "default_base_url": "https://api.anthropic.com/v1"
            },
            AIProviderType.GEMINI: {
                "required_fields": ["api_key", "model"],
                "optional_fields": ["base_url", "max_tokens", "temperature", "timeout"],
                "default_model": "gemini-pro",
                "default_base_url": "https://generativelanguage.googleapis.com/v1beta"
            },
            AIProviderType.OLLAMA: {
                "required_fields": ["model"],
                "optional_fields": ["base_url", "max_tokens", "temperature", "timeout"],
                "default_model": "llama2",
                "default_base_url": "http://localhost:11434"
            }
        }
        
        return requirements.get(provider_type, {})