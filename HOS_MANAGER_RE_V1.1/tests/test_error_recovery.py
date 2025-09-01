#!/usr/bin/env python3
"""
错误恢复系统测试
"""

import pytest
import asyncio
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.error_recovery import (
    ErrorRecoverySystem, RecoveryAction, ErrorPattern, RecoveryResult,
    get_recovery_system, initialize_error_recovery, handle_error_with_recovery
)
from core.logging_system import LoggingSystem, LogLevel
from core.exceptions import (
    CybersecurityPlatformError, NetworkError, ConfigurationError,
    AIProviderError, TimeoutError
)


class TestErrorRecoverySystem:
    """错误恢复系统测试类"""
    
    @pytest.fixture
    def logger(self):
        """创建测试日志系统"""
        return LoggingSystem(log_dir="test_logs", log_level=LogLevel.DEBUG)
    
    @pytest.fixture
    def recovery_system(self, logger):
        """创建测试恢复系统"""
        return ErrorRecoverySystem(logger)
    
    def test_initialization(self, recovery_system):
        """测试初始化"""
        assert recovery_system is not None
        assert len(recovery_system._error_patterns) > 0
        assert len(recovery_system._recovery_handlers) > 0
        assert recovery_system._recovery_stats["total_recoveries"] == 0
    
    def test_register_recovery_handler(self, recovery_system):
        """测试注册恢复处理器"""
        def test_handler(error, context):
            return True
        
        recovery_system.register_recovery_handler(RecoveryAction.CLEAR_CACHE, test_handler)
        assert RecoveryAction.CLEAR_CACHE in recovery_system._recovery_handlers
        assert recovery_system._recovery_handlers[RecoveryAction.CLEAR_CACHE] == test_handler
    
    @pytest.mark.asyncio
    async def test_handle_single_error(self, recovery_system):
        """测试处理单个错误"""
        error = NetworkError("连接失败")
        context = {"component": "test"}
        
        result = await recovery_system.handle_error(error, context)
        # 单个错误不应该触发恢复
        assert result is None
    
    @pytest.mark.asyncio
    async def test_handle_repeated_errors(self, recovery_system):
        """测试处理重复错误"""
        error = NetworkError("连接失败")
        context = {"component": "test"}
        
        # 触发多次相同错误
        for _ in range(4):
            result = await recovery_system.handle_error(error, context)
        
        # 应该触发恢复
        assert result is not None
        assert isinstance(result, RecoveryResult)
        assert result.action_taken in [RecoveryAction.RESET_CONNECTION, RecoveryAction.REDUCE_LOAD, RecoveryAction.GRACEFUL_DEGRADATION]
    
    @pytest.mark.asyncio
    async def test_api_key_error_recovery(self, recovery_system):
        """测试API密钥错误恢复"""
        error = AIProviderError("API key invalid")
        context = {"provider": "openai"}
        
        # 触发多次API密钥错误
        for _ in range(3):
            result = await recovery_system.handle_error(error, context)
        
        # 应该触发恢复
        assert result is not None
        assert result.action_taken in [RecoveryAction.RELOAD_CONFIG, RecoveryAction.SWITCH_PROVIDER, RecoveryAction.ESCALATE_TO_ADMIN]
    
    @pytest.mark.asyncio
    async def test_memory_error_recovery(self, recovery_system):
        """测试内存错误恢复"""
        error = MemoryError("内存不足")
        context = {"component": "scanner"}
        
        result = await recovery_system.handle_error(error, context)
        
        # 内存错误应该立即触发恢复
        assert result is not None
        assert result.action_taken in [RecoveryAction.CLEAR_CACHE, RecoveryAction.REDUCE_LOAD, RecoveryAction.RESTART_COMPONENT]
    
    @pytest.mark.asyncio
    async def test_custom_recovery_handler(self, recovery_system):
        """测试自定义恢复处理器"""
        custom_handler_called = False
        
        async def custom_handler(error, context):
            nonlocal custom_handler_called
            custom_handler_called = True
            return True
        
        # 注册自定义处理器
        recovery_system.register_recovery_handler(RecoveryAction.RESTART_COMPONENT, custom_handler)
        
        # 触发内存错误（会使用RESTART_COMPONENT）
        error = MemoryError("内存不足")
        result = await recovery_system.handle_error(error, {})
        
        assert result is not None
        assert custom_handler_called
        assert result.success
    
    def test_error_statistics(self, recovery_system):
        """测试错误统计"""
        # 添加一些错误历史
        error1 = NetworkError("连接失败")
        error2 = ConfigurationError("配置错误")
        
        # 模拟错误历史
        recovery_system._error_history["NetworkError:连接失败"] = [
            {"timestamp": recovery_system.logger._get_caller_component(), "context": {}, "error": error1}
        ]
        recovery_system._error_history["ConfigurationError:配置错误"] = [
            {"timestamp": recovery_system.logger._get_caller_component(), "context": {}, "error": error2}
        ]
        
        stats = recovery_system.get_error_statistics()
        
        assert stats["error_types"] == 2
        assert stats["total_errors"] == 2
        assert "NetworkError:连接失败" in stats["error_distribution"]
        assert "ConfigurationError:配置错误" in stats["error_distribution"]
    
    def test_recovery_recommendations(self, recovery_system):
        """测试恢复建议"""
        from datetime import datetime
        
        # 添加重复错误
        error_key = "NetworkError:连接失败"
        recovery_system._error_history[error_key] = [
            {"timestamp": datetime.now(), "context": {}, "error": NetworkError("连接失败")}
            for _ in range(3)
        ]
        
        recommendations = recovery_system.get_recovery_recommendations()
        
        assert len(recommendations) > 0
        assert any(rec["error_type"] == error_key for rec in recommendations)
    
    @pytest.mark.asyncio
    async def test_recovery_failure_handling(self, recovery_system):
        """测试恢复失败处理"""
        def failing_handler(error, context):
            raise Exception("恢复处理器失败")
        
        # 注册会失败的处理器
        recovery_system.register_recovery_handler(RecoveryAction.RESET_CONNECTION, failing_handler)
        
        # 触发网络错误
        error = NetworkError("连接失败")
        for _ in range(4):
            result = await recovery_system.handle_error(error, {})
        
        # 应该返回失败结果
        assert result is not None
        assert not result.success
        assert "失败" in result.message


class TestRetryIntegration:
    """重试集成测试"""
    
    @pytest.fixture
    def logger(self):
        """创建测试日志系统"""
        return LoggingSystem(log_dir="test_logs", log_level=LogLevel.DEBUG)
    
    @pytest.mark.asyncio
    async def test_retry_with_recovery(self, logger):
        """测试重试与恢复的集成"""
        from core.logging_system import RetryManager, RetryConfig, RetryStrategy
        
        retry_manager = RetryManager(logger)
        recovery_system = ErrorRecoverySystem(logger)
        
        call_count = 0
        
        async def failing_function():
            nonlocal call_count
            call_count += 1
            
            if call_count <= 2:
                error = NetworkError(f"网络失败 {call_count}")
                # 同时触发恢复
                await recovery_system.handle_error(error, {"function": "failing_function"})
                raise error
            
            return f"成功 (尝试 {call_count})"
        
        config = RetryConfig(
            max_attempts=5,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=0.1,
            retry_exceptions=(NetworkError,)
        )
        
        result = await retry_manager.retry_async(failing_function, config)
        
        assert "成功" in result
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_global_functions(self):
        """测试全局函数"""
        # 测试全局恢复系统
        recovery_system = get_recovery_system()
        assert recovery_system is not None
        
        # 测试初始化
        logger = LoggingSystem(log_dir="test_logs")
        new_recovery_system = initialize_error_recovery(logger)
        assert new_recovery_system is not None
        assert new_recovery_system.logger == logger
        
        # 测试便捷函数
        error = NetworkError("测试错误")
        result = await handle_error_with_recovery(error, {"test": True})
        # 单个错误不应该触发恢复
        assert result is None


class TestErrorPatterns:
    """错误模式测试"""
    
    def test_error_pattern_matching(self):
        """测试错误模式匹配"""
        pattern = ErrorPattern(
            error_type=NetworkError,
            error_message_pattern="连接",
            frequency_threshold=2,
            time_window_minutes=5,
            recovery_actions=[RecoveryAction.RESET_CONNECTION],
            severity_level=3
        )
        
        # 匹配的错误
        error1 = NetworkError("连接失败")
        assert isinstance(error1, pattern.error_type)
        assert pattern.error_message_pattern in str(error1)
        
        # 不匹配的错误
        error2 = ConfigurationError("配置错误")
        assert not isinstance(error2, pattern.error_type)
        
        error3 = NetworkError("超时")
        assert isinstance(error3, pattern.error_type)
        assert pattern.error_message_pattern not in str(error3)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])