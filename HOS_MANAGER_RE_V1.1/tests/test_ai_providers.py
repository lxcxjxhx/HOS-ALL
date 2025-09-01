"""
AI提供商具体实现测试
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import json

from src.ai.providers import (
    DeepSeekProvider, OpenAIProvider, ClaudeProvider, 
    GeminiProvider, OllamaProvider, AIProviderFactory
)
from src.ai.base import AIRequest
from src.core.interfaces import AIResponse, AIProviderType
from src.core.exceptions import AIProviderError


class TestAIProviderFactory:
    """测试AI提供商工厂"""
    
    def test_get_supported_providers(self):
        """测试获取支持的提供商列表"""
        providers = AIProviderFactory.get_supported_providers()
        
        expected_providers = [
            AIProviderType.DEEPSEEK,
            AIProviderType.OPENAI,
            AIProviderType.CLAUDE,
            AIProviderType.GEMINI,
            AIProviderType.OLLAMA
        ]
        
        assert len(providers) == len(expected_providers)
        for provider in expected_providers:
            assert provider in providers
    
    def test_create_deepseek_provider(self):
        """测试创建DeepSeek提供商"""
        config = {
            "api_key": "test_key",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com/v1"
        }
        
        provider = AIProviderFactory.create_provider(AIProviderType.DEEPSEEK, config)
        
        assert isinstance(provider, DeepSeekProvider)
        assert provider.provider_type == AIProviderType.DEEPSEEK
        assert provider.api_key == "test_key"
        assert provider.model == "deepseek-chat"
    
    def test_create_openai_provider(self):
        """测试创建OpenAI提供商"""
        config = {
            "api_key": "test_key",
            "model": "gpt-3.5-turbo"
        }
        
        provider = AIProviderFactory.create_provider(AIProviderType.OPENAI, config)
        
        assert isinstance(provider, OpenAIProvider)
        assert provider.provider_type == AIProviderType.OPENAI
        assert provider.api_key == "test_key"
        assert provider.model == "gpt-3.5-turbo"
    
    def test_create_claude_provider(self):
        """测试创建Claude提供商"""
        config = {
            "api_key": "test_key",
            "model": "claude-3-sonnet-20240229"
        }
        
        provider = AIProviderFactory.create_provider(AIProviderType.CLAUDE, config)
        
        assert isinstance(provider, ClaudeProvider)
        assert provider.provider_type == AIProviderType.CLAUDE
        assert provider.api_key == "test_key"
        assert provider.model == "claude-3-sonnet-20240229"
    
    def test_create_gemini_provider(self):
        """测试创建Gemini提供商"""
        config = {
            "api_key": "test_key",
            "model": "gemini-pro"
        }
        
        provider = AIProviderFactory.create_provider(AIProviderType.GEMINI, config)
        
        assert isinstance(provider, GeminiProvider)
        assert provider.provider_type == AIProviderType.GEMINI
        assert provider.api_key == "test_key"
        assert provider.model == "gemini-pro"
    
    def test_create_ollama_provider(self):
        """测试创建Ollama提供商"""
        config = {
            "model": "llama2",
            "base_url": "http://localhost:11434"
        }
        
        provider = AIProviderFactory.create_provider(AIProviderType.OLLAMA, config)
        
        assert isinstance(provider, OllamaProvider)
        assert provider.provider_type == AIProviderType.OLLAMA
        assert provider.model == "llama2"
        assert provider.api_key == ""  # Ollama不需要API密钥
    
    def test_create_unsupported_provider(self):
        """测试创建不支持的提供商"""
        with pytest.raises(AIProviderError, match="不支持的AI提供商类型"):
            # 创建一个不存在的提供商类型
            class UnsupportedType:
                pass
            AIProviderFactory.create_provider(UnsupportedType(), {})
    
    def test_get_provider_requirements(self):
        """测试获取提供商配置要求"""
        # 测试DeepSeek要求
        deepseek_req = AIProviderFactory.get_provider_requirements(AIProviderType.DEEPSEEK)
        assert "api_key" in deepseek_req["required_fields"]
        assert "model" in deepseek_req["required_fields"]
        assert deepseek_req["default_model"] == "deepseek-chat"
        
        # 测试Ollama要求（不需要API密钥）
        ollama_req = AIProviderFactory.get_provider_requirements(AIProviderType.OLLAMA)
        assert "api_key" not in ollama_req["required_fields"]
        assert "model" in ollama_req["required_fields"]
        assert ollama_req["default_model"] == "llama2"


class TestDeepSeekProvider:
    """测试DeepSeek提供商"""
    
    def setup_method(self):
        """测试前准备"""
        self.config = {
            "api_key": "test_deepseek_key",
            "model": "deepseek-chat",
            "max_tokens": 1000,
            "temperature": 0.7
        }
        self.logger = Mock()
    
    def test_initialization(self):
        """测试初始化"""
        provider = DeepSeekProvider(self.config, self.logger)
        
        assert provider.provider_type == AIProviderType.DEEPSEEK
        assert provider.api_key == "test_deepseek_key"
        assert provider.model == "deepseek-chat"
        assert provider.base_url == "https://api.deepseek.com/v1"
    
    @pytest.mark.asyncio
    async def test_make_api_request_success(self):
        """测试成功的API请求"""
        provider = DeepSeekProvider(self.config, self.logger)
        
        # 模拟成功的HTTP响应
        mock_response_data = {
            "choices": [{"message": {"content": "测试响应"}}],
            "usage": {"total_tokens": 50}
        }
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response
            
            request = AIRequest(prompt="测试提示", max_tokens=100, temperature=0.5)
            response = await provider._make_api_request(request)
            
            assert response.success is True
            assert response.content == "测试响应"
            assert response.provider == AIProviderType.DEEPSEEK
            assert response.tokens_used == 50
    
    @pytest.mark.asyncio
    async def test_make_api_request_error(self):
        """测试API请求错误"""
        provider = DeepSeekProvider(self.config, self.logger)
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 400
            mock_response.text = AsyncMock(return_value="Bad Request")
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response
            
            request = AIRequest(prompt="测试提示")
            
            with pytest.raises(AIProviderError, match="DeepSeek API错误"):
                await provider._make_api_request(request)
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self):
        """测试API密钥验证成功"""
        provider = DeepSeekProvider(self.config, self.logger)
        
        # 模拟成功的验证响应
        with patch.object(provider, '_make_api_request') as mock_request:
            mock_request.return_value = AIResponse(
                content="test", provider=AIProviderType.DEEPSEEK,
                model="deepseek-chat", tokens_used=10, response_time=0.5, success=True
            )
            
            result = await provider.validate_api_key()
            assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_api_key_failure(self):
        """测试API密钥验证失败"""
        provider = DeepSeekProvider(self.config, self.logger)
        
        with patch.object(provider, '_make_api_request') as mock_request:
            mock_request.side_effect = Exception("API错误")
            
            result = await provider.validate_api_key()
            assert result is False


class TestOpenAIProvider:
    """测试OpenAI提供商"""
    
    def setup_method(self):
        """测试前准备"""
        self.config = {
            "api_key": "test_openai_key",
            "model": "gpt-3.5-turbo"
        }
        self.logger = Mock()
    
    def test_initialization(self):
        """测试初始化"""
        provider = OpenAIProvider(self.config, self.logger)
        
        assert provider.provider_type == AIProviderType.OPENAI
        assert provider.api_key == "test_openai_key"
        assert provider.model == "gpt-3.5-turbo"
        assert provider.base_url == "https://api.openai.com/v1"
    
    @pytest.mark.asyncio
    async def test_make_api_request_with_conversation_history(self):
        """测试带对话历史的API请求"""
        provider = OpenAIProvider(self.config, self.logger)
        
        mock_response_data = {
            "choices": [{"message": {"content": "OpenAI响应"}}],
            "usage": {"total_tokens": 75}
        }
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response
            
            request = AIRequest(
                prompt="当前问题",
                system_message="你是一个助手",
                conversation_history=[
                    {"role": "user", "content": "之前的问题"},
                    {"role": "assistant", "content": "之前的回答"}
                ]
            )
            
            response = await provider._make_api_request(request)
            
            assert response.success is True
            assert response.content == "OpenAI响应"
            assert response.tokens_used == 75


class TestClaudeProvider:
    """测试Claude提供商"""
    
    def setup_method(self):
        """测试前准备"""
        self.config = {
            "api_key": "test_claude_key",
            "model": "claude-3-sonnet-20240229"
        }
        self.logger = Mock()
    
    def test_initialization(self):
        """测试初始化"""
        provider = ClaudeProvider(self.config, self.logger)
        
        assert provider.provider_type == AIProviderType.CLAUDE
        assert provider.api_key == "test_claude_key"
        assert provider.model == "claude-3-sonnet-20240229"
        assert provider.base_url == "https://api.anthropic.com/v1"
    
    @pytest.mark.asyncio
    async def test_make_api_request_with_system_message(self):
        """测试带系统消息的API请求"""
        provider = ClaudeProvider(self.config, self.logger)
        
        mock_response_data = {
            "content": [{"text": "Claude响应"}],
            "usage": {"input_tokens": 20, "output_tokens": 30}
        }
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response
            
            request = AIRequest(
                prompt="测试提示",
                system_message="你是Claude助手"
            )
            
            response = await provider._make_api_request(request)
            
            assert response.success is True
            assert response.content == "Claude响应"
            assert response.tokens_used == 50  # input_tokens + output_tokens


class TestGeminiProvider:
    """测试Gemini提供商"""
    
    def setup_method(self):
        """测试前准备"""
        self.config = {
            "api_key": "test_gemini_key",
            "model": "gemini-pro"
        }
        self.logger = Mock()
    
    def test_initialization(self):
        """测试初始化"""
        provider = GeminiProvider(self.config, self.logger)
        
        assert provider.provider_type == AIProviderType.GEMINI
        assert provider.api_key == "test_gemini_key"
        assert provider.model == "gemini-pro"
        assert provider.base_url == "https://generativelanguage.googleapis.com/v1beta"
    
    @pytest.mark.asyncio
    async def test_make_api_request_gemini_format(self):
        """测试Gemini格式的API请求"""
        provider = GeminiProvider(self.config, self.logger)
        
        mock_response_data = {
            "candidates": [{
                "content": {
                    "parts": [{"text": "Gemini响应"}]
                }
            }],
            "usageMetadata": {"totalTokenCount": 60}
        }
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response
            
            request = AIRequest(prompt="测试Gemini")
            response = await provider._make_api_request(request)
            
            assert response.success is True
            assert response.content == "Gemini响应"
            assert response.tokens_used == 60


class TestOllamaProvider:
    """测试Ollama提供商"""
    
    def setup_method(self):
        """测试前准备"""
        self.config = {
            "model": "llama2",
            "base_url": "http://localhost:11434"
        }
        self.logger = Mock()
    
    def test_initialization(self):
        """测试初始化"""
        provider = OllamaProvider(self.config, self.logger)
        
        assert provider.provider_type == AIProviderType.OLLAMA
        assert provider.api_key == ""  # Ollama不需要API密钥
        assert provider.model == "llama2"
        assert provider.base_url == "http://localhost:11434"
    
    @pytest.mark.asyncio
    async def test_make_api_request_local(self):
        """测试本地Ollama API请求"""
        provider = OllamaProvider(self.config, self.logger)
        
        mock_response_data = {
            "message": {"content": "Ollama本地响应"},
            "eval_count": 25,
            "prompt_eval_count": 15
        }
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response
            
            request = AIRequest(prompt="测试Ollama")
            response = await provider._make_api_request(request)
            
            assert response.success is True
            assert response.content == "Ollama本地响应"
            assert response.tokens_used == 40  # eval_count + prompt_eval_count
    
    @pytest.mark.asyncio
    async def test_validate_api_key_ollama(self):
        """测试Ollama连接验证（不需要API密钥）"""
        provider = OllamaProvider(self.config, self.logger)
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            result = await provider.validate_api_key()
            assert result is True


class TestProviderIntegration:
    """测试提供商集成"""
    
    @pytest.mark.asyncio
    async def test_all_providers_creation(self):
        """测试所有提供商的创建"""
        configs = {
            AIProviderType.DEEPSEEK: {
                "api_key": "test_key", "model": "deepseek-chat"
            },
            AIProviderType.OPENAI: {
                "api_key": "test_key", "model": "gpt-3.5-turbo"
            },
            AIProviderType.CLAUDE: {
                "api_key": "test_key", "model": "claude-3-sonnet-20240229"
            },
            AIProviderType.GEMINI: {
                "api_key": "test_key", "model": "gemini-pro"
            },
            AIProviderType.OLLAMA: {
                "model": "llama2"
            }
        }
        
        for provider_type, config in configs.items():
            provider = AIProviderFactory.create_provider(provider_type, config)
            
            assert provider.provider_type == provider_type
            assert provider.model == config["model"]
            
            # 检查API密钥设置
            if provider_type != AIProviderType.OLLAMA:
                assert provider.api_key == "test_key"
            else:
                assert provider.api_key == ""
    
    def test_provider_info_consistency(self):
        """测试提供商信息一致性"""
        config = {"api_key": "test", "model": "test-model"}
        
        for provider_type in AIProviderFactory.get_supported_providers():
            if provider_type == AIProviderType.OLLAMA:
                config_copy = {"model": "test-model"}
            else:
                config_copy = config.copy()
            
            provider = AIProviderFactory.create_provider(provider_type, config_copy)
            info = provider.get_provider_info()
            
            assert info["provider_type"] == provider_type.value
            assert info["model"] == "test-model"
            assert "usage_stats" in info
            assert "config" in info
            assert "is_available" in info


if __name__ == "__main__":
    pytest.main([__file__])