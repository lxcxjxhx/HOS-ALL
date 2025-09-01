"""
AI基础模块测试
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from datetime import datetime

from src.ai.base import BaseAIProvider, AIProviderManager, AIRequest, AIUsageStats
from src.core.interfaces import AIResponse, AIProviderType
from src.core.exceptions import AIProviderError


class MockAIProvider(BaseAIProvider):
    """模拟AI提供商用于测试"""
    
    def __init__(self, provider_type: AIProviderType, config: dict, logger=None, should_fail=False):
        super().__init__(provider_type, config, logger)
        self.should_fail = should_fail
        self.api_call_count = 0
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """模拟API请求"""
        self.api_call_count += 1
        
        if self.should_fail:
            raise Exception("模拟API请求失败")
        
        return AIResponse(
            content=f"模拟响应: {request.prompt}",
            provider=self.provider_type,
            model=self.model,
            tokens_used=100,
            response_time=0.5,
            success=True
        )
    
    async def validate_api_key(self) -> bool:
        """模拟API密钥验证"""
        return not self.should_fail


class TestAIRequest:
    """测试AI请求数据模型"""
    
    def test_ai_request_creation(self):
        """测试AI请求创建"""
        request = AIRequest(
            prompt="测试提示",
            context={"key": "value"},
            max_tokens=1000,
            temperature=0.8
        )
        
        assert request.prompt == "测试提示"
        assert request.context == {"key": "value"}
        assert request.max_tokens == 1000
        assert request.temperature == 0.8
        assert request.conversation_history == []
        assert request.metadata == {}


class TestAIUsageStats:
    """测试AI使用统计"""
    
    def test_usage_stats_initialization(self):
        """测试使用统计初始化"""
        stats = AIUsageStats()
        
        assert stats.total_requests == 0
        assert stats.successful_requests == 0
        assert stats.failed_requests == 0
        assert stats.total_tokens_used == 0
        assert stats.total_response_time == 0.0
        assert stats.average_response_time == 0.0
        assert stats.last_request_time is None
    
    def test_update_stats_success(self):
        """测试更新成功统计"""
        stats = AIUsageStats()
        
        stats.update_stats(100, 1.5, True)
        
        assert stats.total_requests == 1
        assert stats.successful_requests == 1
        assert stats.failed_requests == 0
        assert stats.total_tokens_used == 100
        assert stats.total_response_time == 1.5
        assert stats.average_response_time == 1.5
        assert stats.last_request_time is not None
    
    def test_update_stats_failure(self):
        """测试更新失败统计"""
        stats = AIUsageStats()
        
        stats.update_stats(0, 2.0, False)
        
        assert stats.total_requests == 1
        assert stats.successful_requests == 0
        assert stats.failed_requests == 1
        assert stats.total_tokens_used == 0
        assert stats.total_response_time == 2.0
        assert stats.average_response_time == 0.0  # 没有成功请求
    
    def test_average_response_time_calculation(self):
        """测试平均响应时间计算"""
        stats = AIUsageStats()
        
        stats.update_stats(100, 1.0, True)
        stats.update_stats(200, 2.0, True)
        stats.update_stats(0, 3.0, False)  # 失败请求不计入平均时间
        
        assert stats.total_requests == 3
        assert stats.successful_requests == 2
        assert stats.failed_requests == 1
        assert stats.average_response_time == 1.5  # (1.0 + 2.0) / 2


class TestBaseAIProvider:
    """测试基础AI提供商"""
    
    def setup_method(self):
        """测试前准备"""
        self.config = {
            "api_key": "test_key",
            "base_url": "https://api.test.com",
            "model": "test-model",
            "max_tokens": 2000,
            "temperature": 0.7,
            "timeout": 30,
            "max_requests_per_minute": 60
        }
        self.logger = Mock()
    
    @pytest.mark.asyncio
    async def test_provider_initialization_success(self):
        """测试提供商成功初始化"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger)
        
        await provider.initialize()
        
        assert provider._is_initialized is True
        assert provider._is_available is True
        assert provider.api_key == "test_key"
        assert provider.model == "test-model"
    
    @pytest.mark.asyncio
    async def test_provider_initialization_failure(self):
        """测试提供商初始化失败"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger, should_fail=True)
        
        with pytest.raises(Exception):  # 可能是AIProviderError或CybersecurityPlatformError
            await provider.initialize()
    
    @pytest.mark.asyncio
    async def test_provider_missing_api_key(self):
        """测试缺少API密钥"""
        config = self.config.copy()
        del config["api_key"]
        
        provider = MockAIProvider(AIProviderType.OPENAI, config, self.logger)
        
        with pytest.raises(Exception):  # 可能是AIProviderError或CybersecurityPlatformError
            await provider.initialize()
    
    @pytest.mark.asyncio
    async def test_generate_response_success(self):
        """测试成功生成响应"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger)
        await provider.initialize()
        
        response = await provider.generate_response("测试提示")
        
        assert response.success is True
        assert response.content == "模拟响应: 测试提示"
        assert response.provider == AIProviderType.OPENAI
        assert response.tokens_used == 100
        assert provider.usage_stats.total_requests == 1
        assert provider.usage_stats.successful_requests == 1
    
    @pytest.mark.asyncio
    async def test_generate_response_with_context(self):
        """测试带上下文生成响应"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger)
        await provider.initialize()
        
        context = {
            "max_tokens": 1500,
            "temperature": 0.9,
            "system_message": "你是一个助手"
        }
        
        response = await provider.generate_response("测试提示", context)
        
        assert response.success is True
        assert provider.api_call_count == 1
    
    @pytest.mark.asyncio
    async def test_generate_response_failure(self):
        """测试生成响应失败"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger, should_fail=True)
        # 跳过初始化，直接设置状态进行测试
        provider._is_initialized = True
        provider._is_available = True
        
        with pytest.raises(AIProviderError):
            await provider.generate_response("测试提示")
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """测试请求频率限制"""
        config = self.config.copy()
        config["max_requests_per_minute"] = 2
        
        provider = MockAIProvider(AIProviderType.OPENAI, config, self.logger)
        await provider.initialize()
        
        # 前两个请求应该成功
        await provider.generate_response("测试1")
        await provider.generate_response("测试2")
        
        # 第三个请求应该被限制
        with pytest.raises(AIProviderError, match="请求频率超过限制"):
            await provider.generate_response("测试3")
    
    def test_get_provider_info(self):
        """测试获取提供商信息"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger)
        
        info = provider.get_provider_info()
        
        assert info["provider_type"] == "openai"
        assert info["model"] == "test-model"
        assert info["base_url"] == "https://api.test.com"
        assert "usage_stats" in info
        assert "config" in info
    
    def test_reset_usage_stats(self):
        """测试重置使用统计"""
        provider = MockAIProvider(AIProviderType.OPENAI, self.config, self.logger)
        
        # 模拟一些使用
        provider.usage_stats.update_stats(100, 1.0, True)
        assert provider.usage_stats.total_requests == 1
        
        # 重置统计
        provider.reset_usage_stats()
        assert provider.usage_stats.total_requests == 0


class TestAIProviderManager:
    """测试AI提供商管理器"""
    
    def setup_method(self):
        """测试前准备"""
        self.logger = Mock()
        self.manager = AIProviderManager(self.logger)
        
        self.config1 = {
            "api_key": "test_key1",
            "base_url": "https://api.test1.com",
            "model": "test-model1"
        }
        
        self.config2 = {
            "api_key": "test_key2",
            "base_url": "https://api.test2.com",
            "model": "test-model2"
        }
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self):
        """测试管理器初始化"""
        await self.manager.initialize()
        
        assert self.manager._is_initialized is True
        assert len(self.manager.providers) == 0
        assert self.manager.default_provider is None
    
    @pytest.mark.asyncio
    async def test_add_provider(self):
        """测试添加提供商"""
        await self.manager.initialize()
        
        provider = MockAIProvider(AIProviderType.OPENAI, self.config1, self.logger)
        result = await self.manager.add_provider("openai", provider)
        
        assert result is True
        assert "openai" in self.manager.providers
        assert self.manager.default_provider == "openai"
    
    @pytest.mark.asyncio
    async def test_add_multiple_providers(self):
        """测试添加多个提供商"""
        await self.manager.initialize()
        
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.config1, self.logger)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.config2, self.logger)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        assert len(self.manager.providers) == 2
        assert self.manager.default_provider == "openai"  # 第一个添加的成为默认
    
    @pytest.mark.asyncio
    async def test_remove_provider(self):
        """测试移除提供商"""
        await self.manager.initialize()
        
        provider = MockAIProvider(AIProviderType.OPENAI, self.config1, self.logger)
        await self.manager.add_provider("openai", provider)
        
        result = await self.manager.remove_provider("openai")
        
        assert result is True
        assert "openai" not in self.manager.providers
        assert self.manager.default_provider is None
    
    def test_set_default_provider(self):
        """测试设置默认提供商"""
        # 这个测试需要先添加提供商，但为了简化，我们直接测试逻辑
        self.manager.providers["test"] = Mock()
        
        result = self.manager.set_default_provider("test")
        assert result is True
        assert self.manager.default_provider == "test"
        
        result = self.manager.set_default_provider("nonexistent")
        assert result is False
    
    def test_set_fallback_order(self):
        """测试设置故障转移顺序"""
        self.manager.providers["provider1"] = Mock()
        self.manager.providers["provider2"] = Mock()
        
        self.manager.set_fallback_order(["provider2", "provider1", "nonexistent"])
        
        assert self.manager.fallback_order == ["provider2", "provider1"]
    
    @pytest.mark.asyncio
    async def test_generate_response_with_default_provider(self):
        """测试使用默认提供商生成响应"""
        await self.manager.initialize()
        
        provider = MockAIProvider(AIProviderType.OPENAI, self.config1, self.logger)
        await self.manager.add_provider("openai", provider)
        
        response = await self.manager.generate_response("测试提示")
        
        assert response.success is True
        assert response.content == "模拟响应: 测试提示"
    
    @pytest.mark.asyncio
    async def test_generate_response_with_specific_provider(self):
        """测试使用指定提供商生成响应"""
        await self.manager.initialize()
        
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.config1, self.logger)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.config2, self.logger)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        response = await self.manager.generate_response("测试提示", provider_name="deepseek")
        
        assert response.success is True
        assert response.provider == AIProviderType.DEEPSEEK
    
    def test_get_available_providers(self):
        """测试获取可用提供商"""
        # 创建模拟提供商
        available_provider = Mock()
        available_provider.is_available.return_value = True
        
        unavailable_provider = Mock()
        unavailable_provider.is_available.return_value = False
        
        self.manager.providers["available"] = available_provider
        self.manager.providers["unavailable"] = unavailable_provider
        
        available = self.manager.get_available_providers()
        
        assert "available" in available
        assert "unavailable" not in available
    
    def test_get_manager_status(self):
        """测试获取管理器状态"""
        self.manager.providers["test1"] = Mock()
        self.manager.providers["test2"] = Mock()
        self.manager.default_provider = "test1"
        self.manager.fallback_order = ["test2"]
        
        status = self.manager.get_manager_status()
        
        assert status["total_providers"] == 2
        assert status["default_provider"] == "test1"
        assert status["fallback_order"] == ["test2"]
        assert "test1" in status["providers"]
        assert "test2" in status["providers"]


if __name__ == "__main__":
    pytest.main([__file__])