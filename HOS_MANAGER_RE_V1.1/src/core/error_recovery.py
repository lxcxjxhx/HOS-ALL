"""
错误恢复系统 - 提供智能错误恢复和系统自愈能力
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Type
from dataclasses import dataclass
from enum import Enum
import threading
from collections import defaultdict

from .logging_system import LoggingSystem, RetryConfig, RetryStrategy, get_logger
from .exceptions import CybersecurityPlatformError, RetryExhaustionError


class RecoveryAction(Enum):
    """恢复动作类型"""
    RESTART_COMPONENT = "restart_component"
    RESET_CONNECTION = "reset_connection"
    CLEAR_CACHE = "clear_cache"
    RELOAD_CONFIG = "reload_config"
    SWITCH_PROVIDER = "switch_provider"
    REDUCE_LOAD = "reduce_load"
    ESCALATE_TO_ADMIN = "escalate_to_admin"
    GRACEFUL_DEGRADATION = "graceful_degradation"


@dataclass
class ErrorPattern:
    """错误模式定义"""
    error_type: Type[Exception]
    error_message_pattern: str
    frequency_threshold: int
    time_window_minutes: int
    recovery_actions: List[RecoveryAction]
    severity_level: int  # 1-5, 5最严重


@dataclass
class RecoveryResult:
    """恢复结果"""
    success: bool
    action_taken: RecoveryAction
    message: str
    execution_time: float
    additional_info: Optional[Dict[str, Any]] = None


class ErrorRecoverySystem:
    """错误恢复系统"""
    
    def __init__(self, logger: Optional[LoggingSystem] = None):
        self.logger = logger or get_logger()
        self._error_history = defaultdict(list)
        self._recovery_handlers = {}
        self._lock = threading.Lock()
        
        # 初始化错误模式
        self._error_patterns = self._initialize_error_patterns()
        
        # 恢复统计
        self._recovery_stats = {
            "total_recoveries": 0,
            "successful_recoveries": 0,
            "failed_recoveries": 0,
            "recovery_by_action": defaultdict(int),
            "recovery_by_error_type": defaultdict(int)
        }
        
        # 注册默认恢复处理器
        self._register_default_handlers()
    
    def register_recovery_handler(self, 
                                action: RecoveryAction, 
                                handler: Callable) -> None:
        """注册恢复处理器"""
        self._recovery_handlers[action] = handler
        self.logger.log_info(f"注册恢复处理器: {action.value}")
    
    async def handle_error(self, 
                          error: Exception, 
                          context: Dict[str, Any] = None) -> Optional[RecoveryResult]:
        """处理错误并尝试恢复"""
        error_key = f"{type(error).__name__}:{str(error)}"
        current_time = datetime.now()
        
        with self._lock:
            # 记录错误历史
            self._error_history[error_key].append({
                "timestamp": current_time,
                "context": context or {},
                "error": error
            })
            
            # 清理旧的错误记录
            self._cleanup_old_errors()
        
        # 分析错误模式
        pattern = self._analyze_error_pattern(error, error_key)
        
        if pattern:
            self.logger.log_warning(
                f"检测到错误模式: {pattern.error_message_pattern}",
                {
                    "error_type": type(error).__name__,
                    "frequency_threshold": pattern.frequency_threshold,
                    "recovery_actions": [action.value for action in pattern.recovery_actions]
                }
            )
            
            # 执行恢复动作
            return await self._execute_recovery_actions(pattern, error, context)
        
        return None
    
    def _analyze_error_pattern(self, 
                              error: Exception, 
                              error_key: str) -> Optional[ErrorPattern]:
        """分析错误模式"""
        with self._lock:
            error_history = self._error_history[error_key]
        
        # 检查每个错误模式
        for pattern in self._error_patterns:
            if not isinstance(error, pattern.error_type):
                continue
            
            if pattern.error_message_pattern and pattern.error_message_pattern not in str(error):
                continue
            
            # 检查频率阈值
            time_window = datetime.now() - timedelta(minutes=pattern.time_window_minutes)
            recent_errors = [
                e for e in error_history 
                if e["timestamp"] > time_window
            ]
            
            if len(recent_errors) >= pattern.frequency_threshold:
                return pattern
        
        return None
    
    async def _execute_recovery_actions(self, 
                                      pattern: ErrorPattern, 
                                      error: Exception, 
                                      context: Dict[str, Any]) -> RecoveryResult:
        """执行恢复动作"""
        self._recovery_stats["total_recoveries"] += 1
        
        for action in pattern.recovery_actions:
            try:
                start_time = time.time()
                
                self.logger.log_info(
                    f"执行恢复动作: {action.value}",
                    {"error_type": type(error).__name__, "context": context}
                )
                
                # 执行恢复处理器
                if action in self._recovery_handlers:
                    handler = self._recovery_handlers[action]
                    
                    if asyncio.iscoroutinefunction(handler):
                        result = await handler(error, context)
                    else:
                        result = handler(error, context)
                    
                    execution_time = time.time() - start_time
                    
                    if result:
                        # 恢复成功
                        self._recovery_stats["successful_recoveries"] += 1
                        self._recovery_stats["recovery_by_action"][action.value] += 1
                        self._recovery_stats["recovery_by_error_type"][type(error).__name__] += 1
                        
                        recovery_result = RecoveryResult(
                            success=True,
                            action_taken=action,
                            message=f"恢复动作 {action.value} 执行成功",
                            execution_time=execution_time,
                            additional_info=result if isinstance(result, dict) else None
                        )
                        
                        self.logger.log_info(
                            f"恢复成功: {action.value}",
                            {
                                "execution_time": execution_time,
                                "error_type": type(error).__name__
                            }
                        )
                        
                        return recovery_result
                
                else:
                    self.logger.log_warning(f"未找到恢复处理器: {action.value}")
            
            except Exception as recovery_error:
                self.logger.log_error(
                    f"恢复动作执行失败: {action.value}",
                    recovery_error,
                    {"original_error": str(error)}
                )
        
        # 所有恢复动作都失败
        self._recovery_stats["failed_recoveries"] += 1
        
        return RecoveryResult(
            success=False,
            action_taken=pattern.recovery_actions[0] if pattern.recovery_actions else RecoveryAction.ESCALATE_TO_ADMIN,
            message="所有恢复动作都失败",
            execution_time=0.0
        )
    
    def _cleanup_old_errors(self) -> None:
        """清理旧的错误记录"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for error_key in list(self._error_history.keys()):
            self._error_history[error_key] = [
                error for error in self._error_history[error_key]
                if error["timestamp"] > cutoff_time
            ]
            
            # 如果没有最近的错误，删除该键
            if not self._error_history[error_key]:
                del self._error_history[error_key]
    
    def _initialize_error_patterns(self) -> List[ErrorPattern]:
        """初始化错误模式"""
        return [
            # 网络连接错误
            ErrorPattern(
                error_type=ConnectionError,
                error_message_pattern="",
                frequency_threshold=3,
                time_window_minutes=5,
                recovery_actions=[
                    RecoveryAction.RESET_CONNECTION,
                    RecoveryAction.REDUCE_LOAD,
                    RecoveryAction.GRACEFUL_DEGRADATION
                ],
                severity_level=3
            ),
            
            # API密钥错误
            ErrorPattern(
                error_type=Exception,
                error_message_pattern="API key",
                frequency_threshold=2,
                time_window_minutes=10,
                recovery_actions=[
                    RecoveryAction.RELOAD_CONFIG,
                    RecoveryAction.SWITCH_PROVIDER,
                    RecoveryAction.ESCALATE_TO_ADMIN
                ],
                severity_level=4
            ),
            
            # 内存不足错误
            ErrorPattern(
                error_type=MemoryError,
                error_message_pattern="",
                frequency_threshold=1,
                time_window_minutes=1,
                recovery_actions=[
                    RecoveryAction.CLEAR_CACHE,
                    RecoveryAction.REDUCE_LOAD,
                    RecoveryAction.RESTART_COMPONENT
                ],
                severity_level=5
            ),
            
            # 配置错误
            ErrorPattern(
                error_type=CybersecurityPlatformError,
                error_message_pattern="配置",
                frequency_threshold=2,
                time_window_minutes=5,
                recovery_actions=[
                    RecoveryAction.RELOAD_CONFIG,
                    RecoveryAction.ESCALATE_TO_ADMIN
                ],
                severity_level=3
            ),
            
            # 超时错误
            ErrorPattern(
                error_type=TimeoutError,
                error_message_pattern="",
                frequency_threshold=5,
                time_window_minutes=10,
                recovery_actions=[
                    RecoveryAction.REDUCE_LOAD,
                    RecoveryAction.SWITCH_PROVIDER,
                    RecoveryAction.GRACEFUL_DEGRADATION
                ],
                severity_level=2
            )
        ]
    
    def _register_default_handlers(self) -> None:
        """注册默认恢复处理器"""
        
        async def restart_component_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """重启组件处理器"""
            component_name = context.get("component_name", "unknown")
            self.logger.log_info(f"尝试重启组件: {component_name}")
            
            # 模拟组件重启
            await asyncio.sleep(1)
            return True
        
        def reset_connection_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """重置连接处理器"""
            self.logger.log_info("重置网络连接")
            # 实际实现中会重置具体的连接
            return True
        
        def clear_cache_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """清理缓存处理器"""
            self.logger.log_info("清理系统缓存")
            # 实际实现中会清理具体的缓存
            return True
        
        def reload_config_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """重新加载配置处理器"""
            self.logger.log_info("重新加载系统配置")
            # 实际实现中会重新加载配置
            return True
        
        def switch_provider_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """切换提供商处理器"""
            current_provider = context.get("provider", "unknown")
            self.logger.log_info(f"切换AI提供商，当前: {current_provider}")
            # 实际实现中会切换到备用提供商
            return True
        
        def reduce_load_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """减少负载处理器"""
            self.logger.log_info("减少系统负载")
            # 实际实现中会降低并发数或延迟请求
            return True
        
        def escalate_to_admin_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """升级到管理员处理器"""
            self.logger.log_critical(
                "错误升级到管理员处理",
                {"error": str(error), "context": context}
            )
            # 实际实现中会发送通知给管理员
            return True
        
        def graceful_degradation_handler(error: Exception, context: Dict[str, Any]) -> bool:
            """优雅降级处理器"""
            self.logger.log_warning("启用优雅降级模式")
            # 实际实现中会禁用非关键功能
            return True
        
        # 注册处理器
        self.register_recovery_handler(RecoveryAction.RESTART_COMPONENT, restart_component_handler)
        self.register_recovery_handler(RecoveryAction.RESET_CONNECTION, reset_connection_handler)
        self.register_recovery_handler(RecoveryAction.CLEAR_CACHE, clear_cache_handler)
        self.register_recovery_handler(RecoveryAction.RELOAD_CONFIG, reload_config_handler)
        self.register_recovery_handler(RecoveryAction.SWITCH_PROVIDER, switch_provider_handler)
        self.register_recovery_handler(RecoveryAction.REDUCE_LOAD, reduce_load_handler)
        self.register_recovery_handler(RecoveryAction.ESCALATE_TO_ADMIN, escalate_to_admin_handler)
        self.register_recovery_handler(RecoveryAction.GRACEFUL_DEGRADATION, graceful_degradation_handler)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """获取错误统计信息"""
        with self._lock:
            error_counts = {
                error_key: len(errors)
                for error_key, errors in self._error_history.items()
            }
        
        return {
            "error_types": len(self._error_history),
            "total_errors": sum(error_counts.values()),
            "error_distribution": error_counts,
            "recovery_stats": dict(self._recovery_stats),
            "active_patterns": len(self._error_patterns)
        }
    
    def get_recovery_recommendations(self) -> List[Dict[str, Any]]:
        """获取恢复建议"""
        recommendations = []
        
        with self._lock:
            for error_key, errors in self._error_history.items():
                if len(errors) >= 2:  # 重复错误
                    recent_errors = errors[-5:]  # 最近5个错误
                    
                    recommendations.append({
                        "error_type": error_key,
                        "frequency": len(errors),
                        "recent_occurrences": len(recent_errors),
                        "recommendation": "考虑添加专门的错误处理逻辑",
                        "severity": "medium" if len(errors) < 5 else "high"
                    })
        
        return recommendations


# 全局错误恢复系统实例
_global_recovery_system: Optional[ErrorRecoverySystem] = None


def get_recovery_system() -> ErrorRecoverySystem:
    """获取全局错误恢复系统实例"""
    global _global_recovery_system
    if _global_recovery_system is None:
        _global_recovery_system = ErrorRecoverySystem()
    return _global_recovery_system


def initialize_error_recovery(logger: Optional[LoggingSystem] = None) -> ErrorRecoverySystem:
    """初始化全局错误恢复系统"""
    global _global_recovery_system
    _global_recovery_system = ErrorRecoverySystem(logger)
    return _global_recovery_system


# 便捷函数
async def handle_error_with_recovery(error: Exception, context: Dict[str, Any] = None) -> Optional[RecoveryResult]:
    """处理错误并尝试恢复"""
    return await get_recovery_system().handle_error(error, context)