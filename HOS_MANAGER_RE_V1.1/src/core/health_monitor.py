"""
系统健康监控器 - 监控系统状态和性能
"""

import asyncio
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from .interfaces import ILogger
from .base import BaseComponent
from .exceptions import CybersecurityPlatformError


class HealthStatus(Enum):
    """健康状态枚举"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class SystemMetrics:
    """系统指标"""
    timestamp: datetime = field(default_factory=datetime.now)
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    network_io: Dict[str, int] = field(default_factory=dict)
    process_count: int = 0
    uptime: float = 0.0


@dataclass
class HealthCheck:
    """健康检查项"""
    name: str
    description: str
    check_function: Callable[[], bool]
    critical: bool = False
    timeout: float = 30.0
    last_check: Optional[datetime] = None
    last_result: Optional[bool] = None
    last_error: Optional[str] = None


class HealthMonitor(BaseComponent):
    """系统健康监控器"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.metrics_history: List[SystemMetrics] = []
        self.health_checks: Dict[str, HealthCheck] = {}
        self.alert_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        self.monitoring_interval = 60.0  # 监控间隔（秒）
        self.metrics_retention = 24 * 60 * 60  # 指标保留时间（秒）
        self._monitoring_task = None
        self._start_time = time.time()
        
        # 默认健康检查
        self._register_default_checks()
    
    async def _initialize_component(self) -> None:
        """初始化健康监控器"""
        if self.logger:
            self.logger.log_info("健康监控器初始化完成")
    
    async def _start_component(self) -> None:
        """启动健康监控"""
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        if self.logger:
            self.logger.log_info("健康监控已启动")
    
    async def _stop_component(self) -> None:
        """停止健康监控"""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        if self.logger:
            self.logger.log_info("健康监控已停止")
    
    def _register_default_checks(self) -> None:
        """注册默认健康检查"""
        self.register_health_check(
            "cpu_usage",
            "CPU使用率检查",
            self._check_cpu_usage,
            critical=False
        )
        
        self.register_health_check(
            "memory_usage",
            "内存使用率检查",
            self._check_memory_usage,
            critical=True
        )
        
        self.register_health_check(
            "disk_space",
            "磁盘空间检查",
            self._check_disk_space,
            critical=True
        )
        
        self.register_health_check(
            "process_health",
            "进程健康检查",
            self._check_process_health,
            critical=False
        )
    
    def register_health_check(self, name: str, description: str, 
                            check_function: Callable[[], bool], 
                            critical: bool = False, timeout: float = 30.0) -> None:
        """注册健康检查"""
        self.health_checks[name] = HealthCheck(
            name=name,
            description=description,
            check_function=check_function,
            critical=critical,
            timeout=timeout
        )
        
        if self.logger:
            self.logger.log_info(f"注册健康检查: {name}")
    
    def unregister_health_check(self, name: str) -> bool:
        """取消注册健康检查"""
        if name in self.health_checks:
            del self.health_checks[name]
            if self.logger:
                self.logger.log_info(f"取消注册健康检查: {name}")
            return True
        return False
    
    def add_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """添加告警回调"""
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """移除告警回调"""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    async def _monitoring_loop(self) -> None:
        """监控循环"""
        while True:
            try:
                # 收集系统指标
                metrics = await self._collect_system_metrics()
                self.metrics_history.append(metrics)
                
                # 清理过期指标
                self._cleanup_old_metrics()
                
                # 执行健康检查
                await self._run_health_checks()
                
                # 等待下次监控
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.logger:
                    self.logger.log_error("监控循环异常", e)
                await asyncio.sleep(self.monitoring_interval)
    
    async def _collect_system_metrics(self) -> SystemMetrics:
        """收集系统指标"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # 内存使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # 磁盘使用率
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # 网络IO
            network_io = psutil.net_io_counters()._asdict()
            
            # 进程数量
            process_count = len(psutil.pids())
            
            # 系统运行时间
            uptime = time.time() - self._start_time
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_percent=disk_percent,
                network_io=network_io,
                process_count=process_count,
                uptime=uptime
            )
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("收集系统指标失败", e)
            return SystemMetrics()
    
    def _cleanup_old_metrics(self) -> None:
        """清理过期指标"""
        cutoff_time = datetime.now() - timedelta(seconds=self.metrics_retention)
        self.metrics_history = [
            metrics for metrics in self.metrics_history
            if metrics.timestamp > cutoff_time
        ]
    
    async def _run_health_checks(self) -> None:
        """运行健康检查"""
        for check_name, check in self.health_checks.items():
            try:
                # 执行健康检查
                result = await asyncio.wait_for(
                    asyncio.to_thread(check.check_function),
                    timeout=check.timeout
                )
                
                check.last_check = datetime.now()
                check.last_result = result
                check.last_error = None
                
                # 如果检查失败且是关键检查，发送告警
                if not result and check.critical:
                    await self._send_alert(
                        f"关键健康检查失败: {check_name}",
                        {
                            "check_name": check_name,
                            "description": check.description,
                            "critical": check.critical,
                            "timestamp": check.last_check.isoformat()
                        }
                    )
                
            except asyncio.TimeoutError:
                check.last_check = datetime.now()
                check.last_result = False
                check.last_error = "检查超时"
                
                if self.logger:
                    self.logger.log_warning(f"健康检查超时: {check_name}")
                
            except Exception as e:
                check.last_check = datetime.now()
                check.last_result = False
                check.last_error = str(e)
                
                if self.logger:
                    self.logger.log_error(f"健康检查异常: {check_name}", e)
    
    async def _send_alert(self, message: str, context: Dict[str, Any]) -> None:
        """发送告警"""
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(message, context)
                else:
                    callback(message, context)
            except Exception as e:
                if self.logger:
                    self.logger.log_error("告警回调执行失败", e)
    
    # 默认健康检查方法
    def _check_cpu_usage(self) -> bool:
        """检查CPU使用率"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            return cpu_percent < 90.0  # CPU使用率低于90%
        except:
            return False
    
    def _check_memory_usage(self) -> bool:
        """检查内存使用率"""
        try:
            memory = psutil.virtual_memory()
            return memory.percent < 85.0  # 内存使用率低于85%
        except:
            return False
    
    def _check_disk_space(self) -> bool:
        """检查磁盘空间"""
        try:
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            return disk_percent < 90.0  # 磁盘使用率低于90%
        except:
            return False
    
    def _check_process_health(self) -> bool:
        """检查进程健康"""
        try:
            # 检查是否有僵尸进程
            for proc in psutil.process_iter(['pid', 'status']):
                if proc.info['status'] == psutil.STATUS_ZOMBIE:
                    return False
            return True
        except:
            return False
    
    # 公共接口方法
    def get_current_metrics(self) -> Optional[SystemMetrics]:
        """获取当前系统指标"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return None
    
    def get_metrics_history(self, hours: int = 1) -> List[SystemMetrics]:
        """获取指标历史"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            metrics for metrics in self.metrics_history
            if metrics.timestamp > cutoff_time
        ]
    
    def get_health_status(self) -> HealthStatus:
        """获取整体健康状态"""
        if not self.health_checks:
            return HealthStatus.UNKNOWN
        
        critical_failed = False
        warning_failed = False
        
        for check in self.health_checks.values():
            if check.last_result is False:
                if check.critical:
                    critical_failed = True
                else:
                    warning_failed = True
        
        if critical_failed:
            return HealthStatus.CRITICAL
        elif warning_failed:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    def get_health_report(self) -> Dict[str, Any]:
        """获取健康报告"""
        current_metrics = self.get_current_metrics()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": self.get_health_status().value,
            "system_metrics": {
                "cpu_percent": current_metrics.cpu_percent if current_metrics else 0,
                "memory_percent": current_metrics.memory_percent if current_metrics else 0,
                "disk_percent": current_metrics.disk_percent if current_metrics else 0,
                "process_count": current_metrics.process_count if current_metrics else 0,
                "uptime": current_metrics.uptime if current_metrics else 0
            },
            "health_checks": {}
        }
        
        for name, check in self.health_checks.items():
            report["health_checks"][name] = {
                "description": check.description,
                "critical": check.critical,
                "last_check": check.last_check.isoformat() if check.last_check else None,
                "last_result": check.last_result,
                "last_error": check.last_error
            }
        
        return report
    
    def set_monitoring_interval(self, interval: float) -> None:
        """设置监控间隔"""
        self.monitoring_interval = max(10.0, interval)  # 最小10秒
        if self.logger:
            self.logger.log_info(f"监控间隔设置为: {self.monitoring_interval}秒")
    
    def set_metrics_retention(self, hours: int) -> None:
        """设置指标保留时间"""
        self.metrics_retention = max(1, hours) * 3600  # 最少保留1小时
        if self.logger:
            self.logger.log_info(f"指标保留时间设置为: {hours}小时")