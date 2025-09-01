#!/usr/bin/env python3
"""
日志系统测试
"""

import pytest
import asyncio
import sys
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.logging_system import (
    LoggingSystem, RetryManager, RetryConfig, RetryStrategy,
    LogLevel, LogEntry, get_logger, initialize_logging, retry
)
from core.interfaces import ThreatEvent, ThreatLevel
from core.exceptions import NetworkError, TimeoutError


class TestLoggingSystem:
    """日志系统测试类"""
    
    @pytest.fixture
    def temp_log_dir(self):
        """创建临时日志目录"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def logger(self, temp_log_dir):
        """创建测试日志系统"""
        logger = LoggingSystem(log_dir=temp_log_dir, log_level=LogLevel.DEBUG)
        yield logger
        # 确保测试结束后关闭日志系统
        logger.shutdown()
    
    def test_initialization(self, logger):
        """测试初始化"""
        assert logger is not None
        assert logger.log_level == LogLevel.DEBUG
        assert logger.log_dir.exists()
        assert logger.retry_manager is not None
    
    def test_log_levels(self, logger):
        """测试不同日志级别"""
        logger.log_debug("调试消息", {"test": True})
        logger.log_info("信息消息", {"test": True})
        logger.log_warning("警告消息", {"test": True})
        logger.log_error("错误消息", Exception("测试异常"), {"test": True})
        logger.log_critical("严重错误消息", {"test": True})
        
        # 检查缓存中的日志
        recent_logs = logger.get_recent_logs(count=5)
        assert len(recent_logs) == 5
        
        levels = [log.level for log in recent_logs]
        assert LogLevel.DEBUG in levels
        assert LogLevel.INFO in levels
        assert LogLevel.WARNING in levels
        assert LogLevel.ERROR in levels
        assert LogLevel.CRITICAL in levels
    
    def test_security_event_logging(self, logger):
        """测试安全事件日志"""
        threat_event = ThreatEvent(
            event_id="test_001",
            source_ip="192.168.1.100",
            target_ip="192.168.1.1",
            threat_type="port_scan",
            threat_level=ThreatLevel.HIGH,
            description="检测到端口扫描活动",
            timestamp=datetime.now().isoformat(),
            raw_data={"ports": [80, 443, 22]}
        )
        
        logger.log_security_event(threat_event)
        
        recent_logs = logger.get_recent_logs(count=1)
        assert len(recent_logs) == 1
        assert recent_logs[0].level == LogLevel.SECURITY
        assert "端口扫描" in recent_logs[0].message
    
    def test_log_search(self, logger):
        """测试日志搜索"""
        # 添加一些测试日志
        logger.log_info("用户登录", {"user": "admin", "ip": "192.168.1.10"})
        logger.log_warning("登录失败", {"user": "guest", "ip": "192.168.1.20"})
        logger.log_error("数据库连接失败", None, {"host": "localhost"})
        
        # 搜索包含"登录"的日志
        results = logger.search_logs("登录")
        assert len(results) == 2
        
        # 按级别过滤搜索
        error_results = logger.search_logs("连接", level_filter=LogLevel.ERROR)
        assert len(error_results) == 1
        assert error_results[0].level == LogLevel.ERROR
    
    def test_log_statistics(self, logger):
        """测试日志统计"""
        # 添加不同类型的日志
        logger.log_info("信息1")
        logger.log_info("信息2")
        logger.log_warning("警告1")
        logger.log_error("错误1", Exception("测试"))
        
        stats = logger.get_log_statistics()
        
        assert stats["total_logs"] == 4
        assert stats["level_distribution"]["INFO"] == 2
        assert stats["level_distribution"]["WARNING"] == 1
        assert stats["level_distribution"]["ERROR"] == 1
    
    def test_log_export(self, logger, temp_log_dir):
        """测试日志导出"""
        # 添加测试日志
        logger.log_info("导出测试1", {"test": True})
        logger.log_warning("导出测试2", {"test": True})
        
        # 导出为JSON
        json_file = Path(temp_log_dir) / "export_test.json"
        success = logger.export_logs(str(json_file), "json")
        
        assert success
        assert json_file.exists()
        
        # 验证JSON内容
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        assert len(data) == 2
        assert data[0]["message"] == "导出测试1"
        assert data[1]["message"] == "导出测试2"
        
        # 导出为文本
        text_file = Path(temp_log_dir) / "export_test.txt"
        success = logger.export_logs(str(text_file), "text")
        
        assert success
        assert text_file.exists()
        
        # 验证文本内容
        with open(text_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "导出测试1" in content
        assert "导出测试2" in content
    
    def test_cache_management(self, logger):
        """测试缓存管理"""
        # 填充缓存
        for i in range(10):
            logger.log_info(f"测试消息 {i}")
        
        assert len(logger.get_recent_logs(count=20)) == 10
        
        # 清空缓存
        logger.clear_cache()
        assert len(logger.get_recent_logs(count=20)) == 1  # 清空日志本身
    
    def test_shutdown(self, logger):
        """测试关闭"""
        logger.log_info("关闭前的日志")
        logger.shutdown()
        
        # 关闭后应该仍能记录日志（但可能不会写入文件）
        logger.log_info("关闭后的日志")


class TestRetryManager:
    """重试管理器测试类"""
    
    @pytest.fixture
    def logger(self):
        """创建测试日志系统"""
        return LoggingSystem(log_dir="test_logs", log_level=LogLevel.DEBUG)
    
    @pytest.fixture
    def retry_manager(self, logger):
        """创建重试管理器"""
        return RetryManager(logger)
    
    @pytest.mark.asyncio
    async def test_successful_retry_async(self, retry_manager):
        """测试异步成功重试"""
        call_count = 0
        
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            
            if call_count <= 2:
                raise NetworkError(f"失败 {call_count}")
            
            return f"成功 {call_count}"
        
        config = RetryConfig(
            max_attempts=5,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=0.01,  # 快速测试
            retry_exceptions=(NetworkError,)
        )
        
        result = await retry_manager.retry_async(flaky_function, config)
        
        assert "成功 3" == result
        assert call_count == 3
    
    def test_successful_retry_sync(self, retry_manager):
        """测试同步成功重试"""
        call_count = 0
        
        def flaky_function():
            nonlocal call_count
            call_count += 1
            
            if call_count <= 1:
                raise TimeoutError(f"超时 {call_count}")
            
            return f"成功 {call_count}"
        
        config = RetryConfig(
            max_attempts=3,
            strategy=RetryStrategy.FIXED_INTERVAL,
            base_delay=0.01,
            retry_exceptions=(TimeoutError,)
        )
        
        result = retry_manager.retry_sync(flaky_function, config)
        
        assert "成功 2" == result
        assert call_count == 2
    
    @pytest.mark.asyncio
    async def test_retry_exhaustion(self, retry_manager):
        """测试重试耗尽"""
        call_count = 0
        
        async def always_failing_function():
            nonlocal call_count
            call_count += 1
            raise NetworkError(f"总是失败 {call_count}")
        
        config = RetryConfig(
            max_attempts=3,
            strategy=RetryStrategy.IMMEDIATE,
            retry_exceptions=(NetworkError,)
        )
        
        with pytest.raises(NetworkError):
            await retry_manager.retry_async(always_failing_function, config)
        
        assert call_count == 3
    
    def test_non_retryable_exception(self, retry_manager):
        """测试不可重试异常"""
        call_count = 0
        
        def function_with_non_retryable_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("不可重试的错误")
        
        config = RetryConfig(
            max_attempts=3,
            retry_exceptions=(NetworkError,)  # 不包括ValueError
        )
        
        with pytest.raises(ValueError):
            retry_manager.retry_sync(function_with_non_retryable_error, config)
        
        assert call_count == 1  # 只调用一次
    
    def test_stop_on_exception(self, retry_manager):
        """测试停止异常"""
        call_count = 0
        
        def function_with_stop_exception():
            nonlocal call_count
            call_count += 1
            raise KeyboardInterrupt("用户中断")
        
        config = RetryConfig(
            max_attempts=3,
            retry_exceptions=(Exception,),
            stop_on_exceptions=(KeyboardInterrupt,)
        )
        
        with pytest.raises(KeyboardInterrupt):
            retry_manager.retry_sync(function_with_stop_exception, config)
        
        assert call_count == 1  # 只调用一次
    
    def test_retry_strategies(self, retry_manager):
        """测试不同重试策略"""
        # 测试指数退避
        config_exp = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=1.0,
            backoff_multiplier=2.0,
            max_delay=10.0
        )
        
        delay1 = retry_manager._calculate_delay(config_exp, 1)
        delay2 = retry_manager._calculate_delay(config_exp, 2)
        delay3 = retry_manager._calculate_delay(config_exp, 3)
        
        assert delay1 == 1.0
        assert delay2 == 2.0
        assert delay3 == 4.0
        
        # 测试线性退避
        config_linear = RetryConfig(
            strategy=RetryStrategy.LINEAR_BACKOFF,
            base_delay=1.0,
            max_delay=5.0
        )
        
        delay1 = retry_manager._calculate_delay(config_linear, 1)
        delay2 = retry_manager._calculate_delay(config_linear, 2)
        delay3 = retry_manager._calculate_delay(config_linear, 3)
        
        assert delay1 == 1.0
        assert delay2 == 2.0
        assert delay3 == 3.0
        
        # 测试固定间隔
        config_fixed = RetryConfig(
            strategy=RetryStrategy.FIXED_INTERVAL,
            base_delay=2.0
        )
        
        delay1 = retry_manager._calculate_delay(config_fixed, 1)
        delay2 = retry_manager._calculate_delay(config_fixed, 2)
        
        assert delay1 == 2.0
        assert delay2 == 2.0
        
        # 测试立即重试
        config_immediate = RetryConfig(
            strategy=RetryStrategy.IMMEDIATE
        )
        
        delay1 = retry_manager._calculate_delay(config_immediate, 1)
        assert delay1 == 0.0
    
    def test_retry_statistics(self, retry_manager):
        """测试重试统计"""
        def successful_function():
            return "成功"
        
        def failing_function():
            raise NetworkError("失败")
        
        config = RetryConfig(
            max_attempts=2,
            retry_exceptions=(NetworkError,)
        )
        
        # 成功的调用
        retry_manager.retry_sync(successful_function, config)
        
        # 失败的调用
        try:
            retry_manager.retry_sync(failing_function, config)
        except NetworkError:
            pass
        
        stats = retry_manager.get_retry_stats()
        
        assert len(stats) == 2
        
        # 检查成功函数的统计
        success_stats = None
        for op_id, stat in stats.items():
            if "successful_function" in op_id:
                success_stats = stat
                break
        
        assert success_stats is not None
        assert success_stats["successful_executions"] == 1
        assert success_stats["failed_executions"] == 0
        
        # 检查失败函数的统计
        fail_stats = None
        for op_id, stat in stats.items():
            if "failing_function" in op_id:
                fail_stats = stat
                break
        
        assert fail_stats is not None
        assert fail_stats["successful_executions"] == 0
        assert fail_stats["failed_executions"] == 1


class TestRetryDecorator:
    """重试装饰器测试"""
    
    @pytest.mark.asyncio
    async def test_async_retry_decorator(self):
        """测试异步重试装饰器"""
        call_count = 0
        
        @retry(RetryConfig(max_attempts=3, base_delay=0.01, retry_exceptions=(NetworkError,)))
        async def flaky_async_function():
            nonlocal call_count
            call_count += 1
            
            if call_count <= 1:
                raise NetworkError(f"异步失败 {call_count}")
            
            return f"异步成功 {call_count}"
        
        result = await flaky_async_function()
        
        assert "异步成功 2" == result
        assert call_count == 2
    
    def test_sync_retry_decorator(self):
        """测试同步重试装饰器"""
        call_count = 0
        
        @retry(RetryConfig(max_attempts=3, base_delay=0.01, retry_exceptions=(TimeoutError,)))
        def flaky_sync_function():
            nonlocal call_count
            call_count += 1
            
            if call_count <= 1:
                raise TimeoutError(f"同步失败 {call_count}")
            
            return f"同步成功 {call_count}"
        
        result = flaky_sync_function()
        
        assert "同步成功 2" == result
        assert call_count == 2


class TestGlobalFunctions:
    """全局函数测试"""
    
    def test_global_logger(self):
        """测试全局日志系统"""
        logger = get_logger()
        assert logger is not None
        
        # 测试初始化
        new_logger = initialize_logging(log_dir="test_logs", log_level=LogLevel.WARNING)
        assert new_logger is not None
        assert new_logger.log_level == LogLevel.WARNING
    
    def test_convenience_functions(self):
        """测试便捷函数"""
        from core.logging_system import log_info, log_warning, log_error, log_debug, log_critical
        
        # 这些函数应该不会抛出异常
        log_debug("调试消息")
        log_info("信息消息")
        log_warning("警告消息")
        log_error("错误消息", Exception("测试异常"))
        log_critical("严重错误消息")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])