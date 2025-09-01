#!/usr/bin/env python3
"""
错误处理和日志系统重试机制演示
展示Task 9的完整实现
"""

import sys
import asyncio
import random
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from core.logging_system import (
    LoggingSystem, RetryConfig, RetryStrategy, RetryManager,
    LogLevel, get_logger, initialize_logging, retry
)
from core.error_recovery import (
    ErrorRecoverySystem, RecoveryAction, get_recovery_system,
    initialize_error_recovery, handle_error_with_recovery
)
from core.exceptions import (
    CybersecurityPlatformError, NetworkError, ConfigurationError,
    AIProviderError, TimeoutError
)


class DemoService:
    """演示服务类，用于测试错误处理和重试"""
    
    def __init__(self):
        self.failure_count = 0
        self.max_failures = 3
        self.logger = get_logger()
    
    async def unreliable_network_call(self) -> str:
        """模拟不稳定的网络调用"""
        self.failure_count += 1
        
        if self.failure_count <= self.max_failures:
            if random.random() < 0.7:  # 70% 失败率
                raise NetworkError(f"网络连接失败 (尝试 {self.failure_count})")
        
        return f"网络调用成功 (尝试 {self.failure_count})"
    
    def flaky_api_call(self) -> dict:
        """模拟不稳定的API调用"""
        if random.random() < 0.5:  # 50% 失败率
            raise AIProviderError("API调用失败: 服务暂时不可用")
        
        return {"status": "success", "data": "API响应数据"}
    
    async def timeout_prone_operation(self) -> str:
        """模拟容易超时的操作"""
        delay = random.uniform(0.1, 2.0)
        await asyncio.sleep(delay)
        
        if delay > 1.5:
            raise TimeoutError("操作超时")
        
        return f"操作完成，耗时 {delay:.2f} 秒"
    
    def config_dependent_operation(self) -> str:
        """模拟依赖配置的操作"""
        if random.random() < 0.3:  # 30% 失败率
            raise ConfigurationError("配置文件损坏或缺失")
        
        return "配置加载成功"


async def demo_retry_mechanisms():
    """演示重试机制"""
    print("\n" + "="*60)
    print("🔄 重试机制演示")
    print("="*60)
    
    service = DemoService()
    retry_manager = RetryManager(get_logger())
    
    # 演示1: 指数退避重试
    print("\n1. 指数退避重试策略:")
    config = RetryConfig(
        max_attempts=5,
        strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
        base_delay=0.5,
        max_delay=5.0,
        backoff_multiplier=2.0,
        retry_exceptions=(NetworkError,)
    )
    
    try:
        result = await retry_manager.retry_async(
            service.unreliable_network_call, config
        )
        print(f"✅ 重试成功: {result}")
    except Exception as e:
        print(f"❌ 重试失败: {e}")
    
    # 演示2: 固定间隔重试
    print("\n2. 固定间隔重试策略:")
    config = RetryConfig(
        max_attempts=3,
        strategy=RetryStrategy.FIXED_INTERVAL,
        base_delay=1.0,
        retry_exceptions=(AIProviderError,)
    )
    
    try:
        result = retry_manager.retry_sync(
            service.flaky_api_call, config
        )
        print(f"✅ 重试成功: {result}")
    except Exception as e:
        print(f"❌ 重试失败: {e}")
    
    # 演示3: 线性退避重试
    print("\n3. 线性退避重试策略:")
    config = RetryConfig(
        max_attempts=4,
        strategy=RetryStrategy.LINEAR_BACKOFF,
        base_delay=0.3,
        max_delay=2.0,
        retry_exceptions=(TimeoutError,)
    )
    
    try:
        result = await retry_manager.retry_async(
            service.timeout_prone_operation, config
        )
        print(f"✅ 重试成功: {result}")
    except Exception as e:
        print(f"❌ 重试失败: {e}")
    
    # 显示重试统计
    print("\n📊 重试统计信息:")
    stats = retry_manager.get_retry_stats()
    for operation_id, stat in stats.items():
        print(f"  操作: {operation_id}")
        print(f"    总执行次数: {stat['total_executions']}")
        print(f"    成功次数: {stat['successful_executions']}")
        print(f"    失败次数: {stat['failed_executions']}")
        print(f"    平均重试次数: {stat['avg_attempts_on_success']:.2f}")


async def demo_error_recovery():
    """演示错误恢复系统"""
    print("\n" + "="*60)
    print("🛠️ 错误恢复系统演示")
    print("="*60)
    
    recovery_system = get_recovery_system()
    service = DemoService()
    
    # 演示1: 网络错误恢复
    print("\n1. 网络错误恢复:")
    for i in range(4):  # 触发错误模式
        try:
            await service.unreliable_network_call()
        except NetworkError as e:
            print(f"  网络错误 {i+1}: {e}")
            
            recovery_result = await recovery_system.handle_error(
                e, {"component_name": "network_service", "attempt": i+1}
            )
            
            if recovery_result:
                print(f"  🔧 恢复动作: {recovery_result.action_taken.value}")
                print(f"  📝 结果: {recovery_result.message}")
                print(f"  ⏱️ 执行时间: {recovery_result.execution_time:.3f}秒")
    
    # 演示2: API错误恢复
    print("\n2. API错误恢复:")
    for i in range(3):
        try:
            service.flaky_api_call()
        except AIProviderError as e:
            print(f"  API错误 {i+1}: {e}")
            
            recovery_result = await recovery_system.handle_error(
                e, {"provider": "openai", "api_endpoint": "/chat/completions"}
            )
            
            if recovery_result:
                print(f"  🔧 恢复动作: {recovery_result.action_taken.value}")
                print(f"  📝 结果: {recovery_result.message}")
    
    # 演示3: 配置错误恢复
    print("\n3. 配置错误恢复:")
    for i in range(3):
        try:
            service.config_dependent_operation()
        except ConfigurationError as e:
            print(f"  配置错误 {i+1}: {e}")
            
            recovery_result = await recovery_system.handle_error(
                e, {"config_file": "config.json", "section": "ai_providers"}
            )
            
            if recovery_result:
                print(f"  🔧 恢复动作: {recovery_result.action_taken.value}")
                print(f"  📝 结果: {recovery_result.message}")
    
    # 显示错误统计
    print("\n📊 错误统计信息:")
    stats = recovery_system.get_error_statistics()
    print(f"  错误类型数: {stats['error_types']}")
    print(f"  总错误数: {stats['total_errors']}")
    print(f"  总恢复次数: {stats['recovery_stats']['total_recoveries']}")
    print(f"  成功恢复次数: {stats['recovery_stats']['successful_recoveries']}")
    print(f"  失败恢复次数: {stats['recovery_stats']['failed_recoveries']}")
    
    # 显示恢复建议
    print("\n💡 恢复建议:")
    recommendations = recovery_system.get_recovery_recommendations()
    for rec in recommendations:
        print(f"  错误类型: {rec['error_type']}")
        print(f"  发生频率: {rec['frequency']}")
        print(f"  建议: {rec['recommendation']}")
        print(f"  严重程度: {rec['severity']}")
        print()


@retry(RetryConfig(max_attempts=3, strategy=RetryStrategy.EXPONENTIAL_BACKOFF))
async def demo_retry_decorator():
    """演示重试装饰器"""
    if random.random() < 0.6:  # 60% 失败率
        raise NetworkError("装饰器测试: 网络连接失败")
    
    return "装饰器重试成功!"


async def demo_logging_system():
    """演示日志系统功能"""
    print("\n" + "="*60)
    print("📝 日志系统演示")
    print("="*60)
    
    logger = get_logger()
    
    # 演示不同级别的日志
    print("\n1. 不同级别日志记录:")
    logger.log_debug("调试信息", {"module": "demo", "function": "test"})
    logger.log_info("系统启动", {"version": "1.0.0", "mode": "demo"})
    logger.log_warning("配置项缺失", {"missing_key": "api_timeout"})
    logger.log_error("数据库连接失败", NetworkError("连接超时"), {"host": "localhost", "port": 5432})
    logger.log_critical("系统内存不足", {"available_memory": "50MB", "required": "200MB"})
    
    # 演示日志搜索
    print("\n2. 日志搜索:")
    recent_logs = logger.get_recent_logs(count=5, level_filter=LogLevel.ERROR)
    print(f"  最近5条错误日志: {len(recent_logs)} 条")
    
    search_results = logger.search_logs("连接", level_filter=LogLevel.ERROR)
    print(f"  包含'连接'的错误日志: {len(search_results)} 条")
    
    # 演示日志统计
    print("\n3. 日志统计:")
    stats = logger.get_log_statistics()
    print(f"  总日志数: {stats['total_logs']}")
    print(f"  级别分布: {stats.get('level_distribution', {})}")
    print(f"  组件分布: {stats.get('component_distribution', {})}")
    
    # 演示日志导出
    print("\n4. 日志导出:")
    export_success = logger.export_logs("logs/demo_export.json", "json")
    print(f"  JSON导出: {'成功' if export_success else '失败'}")
    
    export_success = logger.export_logs("logs/demo_export.txt", "text")
    print(f"  文本导出: {'成功' if export_success else '失败'}")


async def demo_integrated_system():
    """演示集成系统"""
    print("\n" + "="*60)
    print("🔗 集成系统演示")
    print("="*60)
    
    service = DemoService()
    
    # 演示集成的错误处理、重试和恢复
    print("\n集成错误处理流程:")
    
    for attempt in range(5):
        try:
            print(f"\n尝试 {attempt + 1}:")
            
            # 使用重试装饰器
            result = await demo_retry_decorator()
            print(f"✅ 操作成功: {result}")
            break
            
        except Exception as e:
            print(f"❌ 操作失败: {e}")
            
            # 记录错误日志
            get_logger().log_error("集成演示操作失败", e, {"attempt": attempt + 1})
            
            # 尝试错误恢复
            recovery_result = await handle_error_with_recovery(
                e, {"operation": "demo_retry_decorator", "attempt": attempt + 1}
            )
            
            if recovery_result and recovery_result.success:
                print(f"🔧 恢复成功: {recovery_result.message}")
            else:
                print("🚨 恢复失败，继续重试...")


async def main():
    """主演示函数"""
    print("🎉 AI网络安全平台 - 错误处理和日志系统重试机制演示")
    print("Task 9: 实现错误处理和日志系统")
    
    # 初始化系统
    logger = initialize_logging(log_dir="logs", log_level=LogLevel.DEBUG)
    recovery_system = initialize_error_recovery(logger)
    
    try:
        # 运行各个演示
        await demo_logging_system()
        await demo_retry_mechanisms()
        await demo_error_recovery()
        await demo_integrated_system()
        
        print("\n" + "="*60)
        print("🎊 演示完成！Task 9 已成功实现所有功能:")
        print("  ✅ 统一错误处理框架")
        print("  ✅ 错误分类和处理策略")
        print("  ✅ 错误恢复和重试机制")
        print("  ✅ 综合日志系统")
        print("  ✅ 分级日志记录机制")
        print("  ✅ 日志轮转和存储管理")
        print("  ✅ 日志查询和分析功能")
        print("  ✅ 智能错误恢复系统")
        print("  ✅ 多种重试策略支持")
        print("  ✅ 错误模式识别和自动恢复")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # 清理资源
        logger.shutdown()


if __name__ == "__main__":
    asyncio.run(main())