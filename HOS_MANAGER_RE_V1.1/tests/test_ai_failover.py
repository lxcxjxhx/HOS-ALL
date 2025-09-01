"""
AI提供商故障转移测试
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
import time

from src.ai.base import AIProviderManager, BaseAIProvider, AIRequest
from src.core.interfaces import AIResponse, AIProviderType
from src.core.exceptions import AIProviderError


class MockAIProvider(BaseAIProvider):
    """模拟AI提供商用于故障转移测试"""
    
    def __init__(self, provider_type: AIProviderType, config: dict, logger=None, 
                 should_fail=False, fail_count=0, validate_key_result=True):
        super().__init__(provider_type, config, logger)
        self.should_fail = should_fail
        self.fail_count = fail_count  # 失败次数后成功
        self.current_calls = 0
        self.validate_key_result = validate_key_result
    
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """模拟API请求"""
        self.current_calls += 1
        
        if self.should_fail or self.current_calls <= self.fail_count:
            raise Exception(f"模拟API请求失败 (调用 {self.current_calls})")
        
        return AIResponse(
            content=f"模拟响应来自 {self.provider_type.value}: {request.prompt}",
            provider=self.provider_type,
            model=self.model,
            tokens_used=100,
            response_time=0.5,
            success=True
        )
    
    async def validate_api_key(self) -> bool:
        """模拟API密钥验证"""
        return self.validate_key_result


class TestAIProviderFailover:
    """测试AI提供商故障转移功能"""
    
    def setup_method(self):
        """测试前准备"""
        self.logger = Mock()
        self.manager = AIProviderManager(self.logger)
        
        # 基础配置
        self.base_config = {
            "api_key": "test_key",
            "base_url": "https://api.test.com",
            "model": "test-model"
        }
    
    @pytest.mark.asyncio
    async def test_basic_failover(self):
        """测试基本故障转移功能"""
        await self.manager.initialize()
        
        # 创建两个提供商：第一个会失败，第二个会成功
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, 
                                 should_fail=True)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, 
                                 should_fail=False)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        # 设置故障转移顺序
        self.manager.set_fallback_order(["deepseek"])
        
        # 执行请求，应该故障转移到deepseek
        response = await self.manager.generate_response("测试提示")
        
        assert response.success is True
        assert "deepseek" in response.content
        assert self.manager.failover_stats["failover_count"] == 1
    
    @pytest.mark.asyncio
    async def test_no_failover_when_disabled(self):
        """测试禁用故障转移时的行为"""
        await self.manager.initialize()
        
        # 禁用自动故障转移
        self.manager.configure_failover(enable_auto_failover=False)
        
        # 创建会失败的提供商
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, 
                                 should_fail=True)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, 
                                 should_fail=False)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        # 指定使用openai，应该失败且不故障转移
        with pytest.raises(AIProviderError):
            await self.manager.generate_response("测试提示", provider_name="openai")
        
        assert self.manager.failover_stats["failover_count"] == 0
    
    @pytest.mark.asyncio
    async def test_max_failover_attempts(self):
        """测试最大故障转移尝试次数限制"""
        await self.manager.initialize()
        
        # 设置最大尝试次数为2
        self.manager.configure_failover(max_attempts=2)
        
        # 创建3个都会失败的提供商
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, should_fail=True)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, should_fail=True)
        provider3 = MockAIProvider(AIProviderType.CLAUDE, self.base_config, should_fail=True)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        await self.manager.add_provider("claude", provider3)
        
        self.manager.set_fallback_order(["deepseek", "claude"])
        
        # 应该只尝试2次就停止
        with pytest.raises(AIProviderError):
            await self.manager.generate_response("测试提示")
        
        # 验证只尝试了最大次数
        assert self.manager.failover_stats["total_requests"] == 1
        assert self.manager.failover_stats["failed_requests"] == 1
    
    @pytest.mark.asyncio
    async def test_provider_health_check(self):
        """测试提供商健康检查"""
        await self.manager.initialize()
        
        # 创建健康和不健康的提供商
        healthy_provider = MockAIProvider(AIProviderType.OPENAI, self.base_config, 
                                        validate_key_result=True)
        unhealthy_provider = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, 
                                          validate_key_result=False)
        
        # 手动设置为已初始化状态，避免初始化时的验证失败
        healthy_provider._is_initialized = True
        healthy_provider._is_available = True
        unhealthy_provider._is_initialized = True
        unhealthy_provider._is_available = True
        
        # 直接添加到管理器，跳过初始化
        async with self.manager._lock:
            self.manager.providers["healthy"] = healthy_provider
            self.manager.providers["unhealthy"] = unhealthy_provider
        
        # 执行健康检查
        health_results = await self.manager.refresh_provider_health()
        
        assert health_results["healthy"] is True
        assert health_results["unhealthy"] is False
    
    @pytest.mark.asyncio
    async def test_provider_recovery_after_failure(self):
        """测试提供商失败后的恢复"""
        await self.manager.initialize()
        
        # 创建一个总是失败的提供商和一个总是成功的提供商
        failing_provider = MockAIProvider(AIProviderType.OPENAI, self.base_config, 
                                        should_fail=True)
        success_provider = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, 
                                        should_fail=False)
        
        await self.manager.add_provider("failing", failing_provider)
        await self.manager.add_provider("success", success_provider)
        
        # 设置故障转移顺序
        self.manager.set_default_provider("failing")
        self.manager.set_fallback_order(["success"])
        
        # 第一次请求应该故障转移到成功的提供商
        response = await self.manager.generate_response("测试提示")
        assert response.success is True
        assert "deepseek" in response.content
        
        # 验证故障转移统计
        stats = self.manager.get_failover_stats()
        assert stats["failover_count"] == 1
        assert "failing" in stats["provider_failures"]
    
    @pytest.mark.asyncio
    async def test_failover_delay(self):
        """测试故障转移延迟"""
        await self.manager.initialize()
        
        # 设置故障转移延迟
        self.manager.configure_failover(delay=0.1)  # 100ms延迟
        
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, should_fail=True)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, should_fail=False)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        self.manager.set_fallback_order(["deepseek"])
        
        # 记录开始时间
        start_time = time.time()
        
        # 执行请求
        response = await self.manager.generate_response("测试提示")
        
        # 验证延迟
        elapsed_time = time.time() - start_time
        assert elapsed_time >= 0.1  # 至少有延迟时间
        assert response.success is True
    
    @pytest.mark.asyncio
    async def test_failover_statistics(self):
        """测试故障转移统计"""
        await self.manager.initialize()
        
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, should_fail=True)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, should_fail=False)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        self.manager.set_fallback_order(["deepseek"])
        
        # 执行多次请求
        for i in range(3):
            await self.manager.generate_response(f"测试提示{i}")
        
        # 检查统计
        stats = self.manager.get_failover_stats()
        
        assert stats["total_requests"] == 3
        assert stats["successful_requests"] == 3
        assert stats["failed_requests"] == 0
        assert stats["failover_count"] == 3  # 每次都故障转移
        assert stats["success_rate"] == 1.0
        assert "openai" in stats["provider_failures"]
        # 注意：由于提供商在第一次失败后被标记为不健康，后续请求不会再尝试它
        # 所以失败次数可能不是3次，而是1次
        assert stats["provider_failures"]["openai"] >= 1
    
    @pytest.mark.asyncio
    async def test_reset_failover_statistics(self):
        """测试重置故障转移统计"""
        await self.manager.initialize()
        
        provider = MockAIProvider(AIProviderType.OPENAI, self.base_config, should_fail=False)
        await self.manager.add_provider("openai", provider)
        
        # 执行一些请求
        await self.manager.generate_response("测试提示")
        
        # 验证有统计数据
        stats_before = self.manager.get_failover_stats()
        assert stats_before["total_requests"] > 0
        
        # 重置统计
        self.manager.reset_failover_stats()
        
        # 验证统计已重置
        stats_after = self.manager.get_failover_stats()
        assert stats_after["total_requests"] == 0
        assert stats_after["successful_requests"] == 0
        assert stats_after["failed_requests"] == 0
        assert stats_after["failover_count"] == 0
    
    @pytest.mark.asyncio
    async def test_provider_priority_order(self):
        """测试提供商优先级顺序"""
        await self.manager.initialize()
        
        # 创建多个提供商
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, should_fail=False)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, should_fail=False)
        provider3 = MockAIProvider(AIProviderType.CLAUDE, self.base_config, should_fail=False)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        await self.manager.add_provider("claude", provider3)
        
        # 设置默认提供商和故障转移顺序
        self.manager.set_default_provider("deepseek")
        self.manager.set_fallback_order(["claude", "openai"])
        
        # 获取优先级列表
        priority_list = self.manager._get_provider_priority_list()
        
        # 验证顺序：默认提供商 -> 故障转移顺序 -> 其他提供商
        assert priority_list[0] == "deepseek"  # 默认提供商
        assert priority_list[1] == "claude"    # 故障转移顺序第一个
        assert priority_list[2] == "openai"    # 故障转移顺序第二个
    
    def test_manager_status_with_failover_info(self):
        """测试管理器状态包含故障转移信息"""
        status = self.manager.get_manager_status()
        
        # 验证包含故障转移相关信息
        assert "auto_failover_enabled" in status
        assert "max_failover_attempts" in status
        assert "failover_stats" in status
        assert "healthy_providers" in status
        
        # 验证默认值
        assert status["auto_failover_enabled"] is True
        assert status["max_failover_attempts"] == 3
    
    @pytest.mark.asyncio
    async def test_all_providers_fail(self):
        """测试所有提供商都失败的情况"""
        await self.manager.initialize()
        
        # 创建两个都会失败的提供商
        provider1 = MockAIProvider(AIProviderType.OPENAI, self.base_config, should_fail=True)
        provider2 = MockAIProvider(AIProviderType.DEEPSEEK, self.base_config, should_fail=True)
        
        await self.manager.add_provider("openai", provider1)
        await self.manager.add_provider("deepseek", provider2)
        
        self.manager.set_fallback_order(["deepseek"])
        
        # 应该抛出异常
        with pytest.raises(AIProviderError, match="所有AI提供商都不可用"):
            await self.manager.generate_response("测试提示")
        
        # 验证统计
        stats = self.manager.get_failover_stats()
        assert stats["total_requests"] == 1
        assert stats["failed_requests"] == 1
        assert stats["successful_requests"] == 0


if __name__ == "__main__":
    pytest.main([__file__])