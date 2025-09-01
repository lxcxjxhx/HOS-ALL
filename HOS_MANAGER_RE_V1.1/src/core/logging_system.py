"""
统一日志系统 - 提供分级日志记录、轮转和重试机制
"""

import os
import sys
import json
import asyncio
import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from pathlib import Path
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor

from .interfaces import ILogger, ThreatEvent
from .exceptions import CybersecurityPlatformError


class LogLevel(Enum):
    """日志级别枚举"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"


class RetryStrategy(Enum):
    """重试策略枚举"""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    FIXED_INTERVAL = "fixed_interval"
    LINEAR_BACKOFF = "linear_backoff"
    IMMEDIATE = "immediate"


@dataclass
class LogEntry:
    """日志条目数据模型"""
    timestamp: str
    level: LogLevel
    message: str
    component: str
    context: Optional[Dict[str, Any]] = None
    error_details: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None


@dataclass
class RetryConfig:
    """重试配置"""
    max_attempts: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    retry_exceptions: tuple = (Exception,)
    stop_on_exceptions: tuple = ()


class RetryManager:
    """重试管理器"""
    
    def __init__(self, logger: Optional['LoggingSystem'] = None):
        self.logger = logger
        self._retry_stats = {}
        self._lock = threading.Lock()
    
    async def retry_async(self, 
                         func: Callable,
                         config: RetryConfig,
                         *args, 
                         **kwargs) -> Any:
        """异步重试执行函数"""
        operation_id = f"{func.__name__}_{id(func)}"
        
        for attempt in range(1, config.max_attempts + 1):
            try:
                if self.logger:
                    self.logger.log_debug(
                        f"执行操作 {func.__name__} (尝试 {attempt}/{config.max_attempts})",
                        {"operation_id": operation_id, "attempt": attempt}
                    )
                
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # 成功执行，记录统计信息
                self._record_success(operation_id, attempt)
                
                if self.logger and attempt > 1:
                    self.logger.log_info(
                        f"操作 {func.__name__} 在第 {attempt} 次尝试后成功",
                        {"operation_id": operation_id, "attempts": attempt}
                    )
                
                return result
                
            except Exception as e:
                # 检查是否应该停止重试
                if any(isinstance(e, exc_type) for exc_type in config.stop_on_exceptions):
                    if self.logger:
                        self.logger.log_error(
                            f"操作 {func.__name__} 遇到不可重试异常",
                            e,
                            {"operation_id": operation_id, "attempt": attempt}
                        )
                    raise e
                
                # 检查是否应该重试
                if not any(isinstance(e, exc_type) for exc_type in config.retry_exceptions):
                    if self.logger:
                        self.logger.log_error(
                            f"操作 {func.__name__} 遇到不在重试范围内的异常",
                            e,
                            {"operation_id": operation_id, "attempt": attempt}
                        )
                    raise e
                
                # 如果是最后一次尝试，抛出异常
                if attempt == config.max_attempts:
                    self._record_failure(operation_id, attempt)
                    if self.logger:
                        self.logger.log_error(
                            f"操作 {func.__name__} 在 {attempt} 次尝试后最终失败",
                            e,
                            {"operation_id": operation_id, "total_attempts": attempt}
                        )
                    raise e
                
                # 计算延迟时间
                delay = self._calculate_delay(config, attempt)
                
                if self.logger:
                    self.logger.log_warning(
                        f"操作 {func.__name__} 第 {attempt} 次尝试失败，{delay:.2f}秒后重试",
                        {"operation_id": operation_id, "attempt": attempt, "delay": delay, "error": str(e)}
                    )
                
                # 等待后重试
                await asyncio.sleep(delay)
    
    def retry_sync(self, 
                   func: Callable,
                   config: RetryConfig,
                   *args, 
                   **kwargs) -> Any:
        """同步重试执行函数"""
        operation_id = f"{func.__name__}_{id(func)}"
        
        for attempt in range(1, config.max_attempts + 1):
            try:
                if self.logger:
                    self.logger.log_debug(
                        f"执行操作 {func.__name__} (尝试 {attempt}/{config.max_attempts})",
                        {"operation_id": operation_id, "attempt": attempt}
                    )
                
                result = func(*args, **kwargs)
                
                # 成功执行，记录统计信息
                self._record_success(operation_id, attempt)
                
                if self.logger and attempt > 1:
                    self.logger.log_info(
                        f"操作 {func.__name__} 在第 {attempt} 次尝试后成功",
                        {"operation_id": operation_id, "attempts": attempt}
                    )
                
                return result
                
            except Exception as e:
                # 检查是否应该停止重试
                if any(isinstance(e, exc_type) for exc_type in config.stop_on_exceptions):
                    if self.logger:
                        self.logger.log_error(
                            f"操作 {func.__name__} 遇到不可重试异常",
                            e,
                            {"operation_id": operation_id, "attempt": attempt}
                        )
                    raise e
                
                # 检查是否应该重试
                if not any(isinstance(e, exc_type) for exc_type in config.retry_exceptions):
                    if self.logger:
                        self.logger.log_error(
                            f"操作 {func.__name__} 遇到不在重试范围内的异常",
                            e,
                            {"operation_id": operation_id, "attempt": attempt}
                        )
                    raise e
                
                # 如果是最后一次尝试，抛出异常
                if attempt == config.max_attempts:
                    self._record_failure(operation_id, attempt)
                    if self.logger:
                        self.logger.log_error(
                            f"操作 {func.__name__} 在 {attempt} 次尝试后最终失败",
                            e,
                            {"operation_id": operation_id, "total_attempts": attempt}
                        )
                    raise e
                
                # 计算延迟时间
                delay = self._calculate_delay(config, attempt)
                
                if self.logger:
                    self.logger.log_warning(
                        f"操作 {func.__name__} 第 {attempt} 次尝试失败，{delay:.2f}秒后重试",
                        {"operation_id": operation_id, "attempt": attempt, "delay": delay, "error": str(e)}
                    )
                
                # 等待后重试
                import time
                time.sleep(delay)
    
    def _calculate_delay(self, config: RetryConfig, attempt: int) -> float:
        """计算重试延迟时间"""
        if config.strategy == RetryStrategy.IMMEDIATE:
            return 0.0
        elif config.strategy == RetryStrategy.FIXED_INTERVAL:
            return min(config.base_delay, config.max_delay)
        elif config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = config.base_delay * attempt
            return min(delay, config.max_delay)
        elif config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))
            return min(delay, config.max_delay)
        else:
            return config.base_delay
    
    def _record_success(self, operation_id: str, attempts: int) -> None:
        """记录成功统计"""
        with self._lock:
            if operation_id not in self._retry_stats:
                self._retry_stats[operation_id] = {
                    "total_executions": 0,
                    "successful_executions": 0,
                    "failed_executions": 0,
                    "total_attempts": 0,
                    "avg_attempts_on_success": 0.0
                }
            
            stats = self._retry_stats[operation_id]
            stats["total_executions"] += 1
            stats["successful_executions"] += 1
            stats["total_attempts"] += attempts
            stats["avg_attempts_on_success"] = (
                stats["total_attempts"] / stats["successful_executions"]
            )
    
    def _record_failure(self, operation_id: str, attempts: int) -> None:
        """记录失败统计"""
        with self._lock:
            if operation_id not in self._retry_stats:
                self._retry_stats[operation_id] = {
                    "total_executions": 0,
                    "successful_executions": 0,
                    "failed_executions": 0,
                    "total_attempts": 0,
                    "avg_attempts_on_success": 0.0
                }
            
            stats = self._retry_stats[operation_id]
            stats["total_executions"] += 1
            stats["failed_executions"] += 1
            stats["total_attempts"] += attempts
    
    def get_retry_stats(self) -> Dict[str, Dict[str, Any]]:
        """获取重试统计信息"""
        with self._lock:
            return dict(self._retry_stats)


class LoggingSystem(ILogger):
    """统一日志系统实现"""
    
    def __init__(self, 
                 log_dir: str = "logs",
                 max_file_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5,
                 log_level: LogLevel = LogLevel.INFO):
        """
        初始化日志系统
        
        Args:
            log_dir: 日志目录
            max_file_size: 单个日志文件最大大小
            backup_count: 备份文件数量
            log_level: 日志级别
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.log_level = log_level
        
        # 创建不同类型的日志记录器
        self._setup_loggers()
        
        # 内存中的日志缓存
        self._log_cache = []
        self._cache_lock = threading.Lock()
        self._max_cache_size = 1000
        
        # 重试管理器
        self.retry_manager = RetryManager(self)
        
        # 线程池用于异步日志写入
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="LogWriter")
        
        # 启动日志清理任务
        self._cleanup_task = None
        self._start_cleanup_task()
    
    def _setup_loggers(self) -> None:
        """设置日志记录器"""
        # 主日志记录器
        self.main_logger = logging.getLogger("cybersecurity_platform")
        self.main_logger.setLevel(getattr(logging, self.log_level.value))
        
        # 安全事件日志记录器
        self.security_logger = logging.getLogger("security_events")
        self.security_logger.setLevel(logging.INFO)
        
        # 错误日志记录器
        self.error_logger = logging.getLogger("errors")
        self.error_logger.setLevel(logging.ERROR)
        
        # 清除现有处理器
        for logger in [self.main_logger, self.security_logger, self.error_logger]:
            logger.handlers.clear()
        
        # 设置文件处理器
        self._setup_file_handlers()
        
        # 设置控制台处理器
        self._setup_console_handler()
    
    def _setup_file_handlers(self) -> None:
        """设置文件处理器"""
        # 主日志文件处理器
        main_handler = RotatingFileHandler(
            self.log_dir / "main.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        main_handler.setFormatter(self._get_formatter())
        self.main_logger.addHandler(main_handler)
        
        # 安全事件日志文件处理器
        security_handler = RotatingFileHandler(
            self.log_dir / "security.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        security_handler.setFormatter(self._get_formatter())
        self.security_logger.addHandler(security_handler)
        
        # 错误日志文件处理器
        error_handler = RotatingFileHandler(
            self.log_dir / "errors.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        error_handler.setFormatter(self._get_formatter())
        self.error_logger.addHandler(error_handler)
        
        # 按日期轮转的日志处理器
        daily_handler = TimedRotatingFileHandler(
            self.log_dir / "daily.log",
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        daily_handler.setFormatter(self._get_formatter())
        self.main_logger.addHandler(daily_handler)
    
    def _setup_console_handler(self) -> None:
        """设置控制台处理器"""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)  # 只在控制台显示警告及以上级别
        console_handler.setFormatter(self._get_console_formatter())
        
        self.main_logger.addHandler(console_handler)
        self.error_logger.addHandler(console_handler)
    
    def _get_formatter(self) -> logging.Formatter:
        """获取日志格式器"""
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _get_console_formatter(self) -> logging.Formatter:
        """获取控制台格式器"""
        return logging.Formatter(
            '%(levelname)s: %(message)s'
        )
    
    def _start_cleanup_task(self) -> None:
        """启动日志清理任务"""
        async def cleanup_loop():
            while True:
                try:
                    await asyncio.sleep(3600)  # 每小时清理一次
                    await self._cleanup_old_logs()
                except Exception as e:
                    self.log_error("日志清理任务异常", e)
        
        try:
            loop = asyncio.get_running_loop()
            self._cleanup_task = loop.create_task(cleanup_loop())
        except RuntimeError:
            # 如果没有运行的事件循环，跳过自动清理
            pass
    
    async def _cleanup_old_logs(self) -> None:
        """清理旧日志文件"""
        try:
            cutoff_date = datetime.now() - timedelta(days=30)
            
            for log_file in self.log_dir.glob("*.log*"):
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    log_file.unlink()
                    self.log_info(f"删除旧日志文件: {log_file.name}")
        
        except Exception as e:
            self.log_error("清理旧日志文件失败", e)   
 
    def log_info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """记录信息日志"""
        self._log_message(LogLevel.INFO, message, context)
    
    def log_warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """记录警告日志"""
        self._log_message(LogLevel.WARNING, message, context)
    
    def log_error(self, message: str, error: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None) -> None:
        """记录错误日志"""
        error_details = None
        if error:
            error_details = f"{type(error).__name__}: {str(error)}\n{traceback.format_exc()}"
        
        self._log_message(LogLevel.ERROR, message, context, error_details)
        
        # 同时记录到错误日志
        error_msg = f"{message}"
        if error:
            error_msg += f" - {str(error)}"
        
        self.error_logger.error(error_msg, extra={"context": context})
    
    def log_debug(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """记录调试日志"""
        self._log_message(LogLevel.DEBUG, message, context)
    
    def log_critical(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """记录严重错误日志"""
        self._log_message(LogLevel.CRITICAL, message, context)
    
    def log_security_event(self, event: ThreatEvent) -> None:
        """记录安全事件"""
        message = f"安全事件: {event.threat_type} - {event.description}"
        context = {
            "event_id": event.event_id,
            "source_ip": event.source_ip,
            "target_ip": event.target_ip,
            "threat_level": event.threat_level.value,
            "raw_data": event.raw_data
        }
        
        self._log_message(LogLevel.SECURITY, message, context)
        
        # 同时记录到安全日志
        security_msg = f"[{event.threat_level.value.upper()}] {event.threat_type}: {event.description}"
        self.security_logger.info(security_msg, extra={"event": asdict(event)})
    
    def _log_message(self, 
                    level: LogLevel, 
                    message: str, 
                    context: Optional[Dict[str, Any]] = None,
                    error_details: Optional[str] = None) -> None:
        """内部日志记录方法"""
        # 创建日志条目
        log_entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level,
            message=message,
            component=self._get_caller_component(),
            context=context,
            error_details=error_details
        )
        
        # 添加到缓存
        self._add_to_cache(log_entry)
        
        # 异步写入文件
        try:
            self._executor.submit(self._write_log_entry, log_entry)
        except RuntimeError:
            # 如果线程池已关闭，直接写入
            self._write_log_entry(log_entry)
    
    def _get_caller_component(self) -> str:
        """获取调用者组件名称"""
        import inspect
        
        # 获取调用栈
        stack = inspect.stack()
        
        # 跳过当前方法和_log_message方法
        for frame_info in stack[3:]:
            module_name = frame_info.filename
            if 'logging_system.py' not in module_name:
                # 提取模块名
                module_path = Path(module_name)
                return module_path.stem
        
        return "unknown"
    
    def _add_to_cache(self, log_entry: LogEntry) -> None:
        """添加日志条目到缓存"""
        with self._cache_lock:
            self._log_cache.append(log_entry)
            
            # 如果缓存超过最大大小，移除最旧的条目
            if len(self._log_cache) > self._max_cache_size:
                self._log_cache.pop(0)
    
    def _write_log_entry(self, log_entry: LogEntry) -> None:
        """写入日志条目到文件"""
        try:
            # 根据日志级别选择合适的记录器
            logger = self.main_logger
            
            # 处理自定义的SECURITY级别
            if log_entry.level == LogLevel.SECURITY:
                log_level = logging.INFO  # 使用INFO级别记录安全事件
            else:
                log_level = getattr(logging, log_entry.level.value)
            
            # 构建日志消息
            log_msg = log_entry.message
            
            # 添加上下文信息
            extra_data = {
                "component": log_entry.component,
                "context": log_entry.context or {}
            }
            
            if log_entry.session_id:
                extra_data["session_id"] = log_entry.session_id
            
            if log_entry.user_id:
                extra_data["user_id"] = log_entry.user_id
            
            # 记录日志
            logger.log(log_level, log_msg, extra=extra_data)
            
            # 如果有错误详情，单独记录
            if log_entry.error_details:
                logger.log(log_level, f"错误详情: {log_entry.error_details}", extra=extra_data)
        
        except Exception as e:
            # 日志记录失败，输出到标准错误
            print(f"日志记录失败: {e}", file=sys.stderr)
    
    def get_recent_logs(self, 
                       count: int = 100, 
                       level_filter: Optional[LogLevel] = None,
                       component_filter: Optional[str] = None) -> List[LogEntry]:
        """获取最近的日志条目"""
        with self._cache_lock:
            logs = list(self._log_cache)
        
        # 应用过滤器
        if level_filter:
            logs = [log for log in logs if log.level == level_filter]
        
        if component_filter:
            logs = [log for log in logs if log.component == component_filter]
        
        # 返回最近的条目
        return logs[-count:] if count < len(logs) else logs
    
    def search_logs(self, 
                   query: str,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   level_filter: Optional[LogLevel] = None) -> List[LogEntry]:
        """搜索日志条目"""
        with self._cache_lock:
            logs = list(self._log_cache)
        
        results = []
        
        for log in logs:
            # 时间过滤
            log_time = datetime.fromisoformat(log.timestamp)
            if start_time and log_time < start_time:
                continue
            if end_time and log_time > end_time:
                continue
            
            # 级别过滤
            if level_filter and log.level != level_filter:
                continue
            
            # 文本搜索
            if query.lower() in log.message.lower():
                results.append(log)
                continue
            
            # 在上下文中搜索
            if log.context:
                context_str = json.dumps(log.context, default=str).lower()
                if query.lower() in context_str:
                    results.append(log)
        
        return results
    
    def export_logs(self, 
                   output_file: str,
                   format_type: str = "json",
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None) -> bool:
        """导出日志到文件"""
        try:
            with self._cache_lock:
                logs = list(self._log_cache)
            
            # 时间过滤
            if start_time or end_time:
                filtered_logs = []
                for log in logs:
                    log_time = datetime.fromisoformat(log.timestamp)
                    if start_time and log_time < start_time:
                        continue
                    if end_time and log_time > end_time:
                        continue
                    filtered_logs.append(log)
                logs = filtered_logs
            
            # 导出到文件
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format_type.lower() == "json":
                with open(output_path, 'w', encoding='utf-8') as f:
                    # 转换LogLevel枚举为字符串
                    serializable_logs = []
                    for log in logs:
                        log_dict = asdict(log)
                        log_dict['level'] = log.level.value  # 转换枚举为字符串
                        serializable_logs.append(log_dict)
                    json.dump(serializable_logs, f, indent=2, ensure_ascii=False)
            
            elif format_type.lower() == "csv":
                import csv
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    if logs:
                        writer = csv.DictWriter(f, fieldnames=asdict(logs[0]).keys())
                        writer.writeheader()
                        for log in logs:
                            writer.writerow(asdict(log))
            
            else:
                # 纯文本格式
                with open(output_path, 'w', encoding='utf-8') as f:
                    for log in logs:
                        f.write(f"[{log.timestamp}] {log.level.value} - {log.component}: {log.message}\n")
                        if log.context:
                            f.write(f"  Context: {json.dumps(log.context, default=str)}\n")
                        if log.error_details:
                            f.write(f"  Error: {log.error_details}\n")
                        f.write("\n")
            
            self.log_info(f"日志导出成功: {output_file}", {"format": format_type, "count": len(logs)})
            return True
        
        except Exception as e:
            self.log_error("日志导出失败", e, {"output_file": output_file})
            return False
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """获取日志统计信息"""
        with self._cache_lock:
            logs = list(self._log_cache)
        
        if not logs:
            return {"total_logs": 0}
        
        # 统计各级别日志数量
        level_counts = {}
        component_counts = {}
        
        for log in logs:
            level_counts[log.level.value] = level_counts.get(log.level.value, 0) + 1
            component_counts[log.component] = component_counts.get(log.component, 0) + 1
        
        # 计算时间范围
        timestamps = [datetime.fromisoformat(log.timestamp) for log in logs]
        earliest = min(timestamps)
        latest = max(timestamps)
        
        return {
            "total_logs": len(logs),
            "level_distribution": level_counts,
            "component_distribution": component_counts,
            "time_range": {
                "earliest": earliest.isoformat(),
                "latest": latest.isoformat(),
                "duration_hours": (latest - earliest).total_seconds() / 3600
            },
            "cache_size": len(self._log_cache),
            "max_cache_size": self._max_cache_size
        }
    
    def clear_cache(self) -> None:
        """清空日志缓存"""
        with self._cache_lock:
            cleared_count = len(self._log_cache)
            self._log_cache.clear()
        
        self.log_info(f"清空日志缓存，共清除 {cleared_count} 条记录")
    
    def shutdown(self) -> None:
        """关闭日志系统"""
        try:
            # 取消清理任务
            if self._cleanup_task:
                self._cleanup_task.cancel()
            
            # 关闭线程池
            self._executor.shutdown(wait=True)
            
            # 关闭所有日志处理器并移除处理器
            for logger in [self.main_logger, self.security_logger, self.error_logger]:
                for handler in logger.handlers:
                    handler.close()
                    logger.removeHandler(handler)
            
            # 清除所有日志记录器
            self.main_logger.handlers.clear()
            self.security_logger.handlers.clear()
            self.error_logger.handlers.clear()
            
            self.log_info("日志系统已关闭")
        
        except Exception as e:
            print(f"关闭日志系统时出错: {e}", file=sys.stderr)


# 重试装饰器
def retry(config: RetryConfig = None):
    """重试装饰器"""
    if config is None:
        config = RetryConfig()
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            retry_manager = RetryManager()
            return retry_manager.retry_sync(func, config, *args, **kwargs)
        
        async def async_wrapper(*args, **kwargs):
            retry_manager = RetryManager()
            return await retry_manager.retry_async(func, config, *args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    
    return decorator


# 全局日志系统实例
_global_logger: Optional[LoggingSystem] = None


def get_logger() -> LoggingSystem:
    """获取全局日志系统实例"""
    global _global_logger
    if _global_logger is None:
        _global_logger = LoggingSystem()
    return _global_logger


def initialize_logging(log_dir: str = "logs", 
                      log_level: LogLevel = LogLevel.INFO) -> LoggingSystem:
    """初始化全局日志系统"""
    global _global_logger
    _global_logger = LoggingSystem(log_dir=log_dir, log_level=log_level)
    return _global_logger


# 便捷函数
def log_info(message: str, context: Optional[Dict[str, Any]] = None) -> None:
    """记录信息日志"""
    get_logger().log_info(message, context)


def log_warning(message: str, context: Optional[Dict[str, Any]] = None) -> None:
    """记录警告日志"""
    get_logger().log_warning(message, context)


def log_error(message: str, error: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None) -> None:
    """记录错误日志"""
    get_logger().log_error(message, error, context)


def log_debug(message: str, context: Optional[Dict[str, Any]] = None) -> None:
    """记录调试日志"""
    get_logger().log_debug(message, context)


def log_critical(message: str, context: Optional[Dict[str, Any]] = None) -> None:
    """记录严重错误日志"""
    get_logger().log_critical(message, context)


def log_security_event(event: ThreatEvent) -> None:
    """记录安全事件"""
    get_logger().log_security_event(event)