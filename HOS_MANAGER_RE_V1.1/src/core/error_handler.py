"""
核心错误处理器 - 提供统一的错误处理和异常管理
"""

import traceback
import sys
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from enum import Enum

from .interfaces import ILogger
from .exceptions import CybersecurityPlatformError


class ErrorSeverity(Enum):
    """错误严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """错误分类"""
    CONFIGURATION = "configuration"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    SYSTEM = "system"
    EXTERNAL_SERVICE = "external_service"
    USER_INPUT = "user_input"


class CoreErrorHandler:
    """核心错误处理器"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        self.logger = logger
        self.error_handlers: Dict[type, Callable] = {}
        self.error_statistics: Dict[str, int] = {}
        self.recent_errors: List[Dict[str, Any]] = []
        self.max_recent_errors = 100
        
        # 注册默认错误处理器
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """注册默认错误处理器"""
        self.register_handler(FileNotFoundError, self._handle_file_not_found)
        self.register_handler(PermissionError, self._handle_permission_error)
        self.register_handler(ConnectionError, self._handle_connection_error)
        self.register_handler(TimeoutError, self._handle_timeout_error)
        self.register_handler(ValueError, self._handle_value_error)
        self.register_handler(KeyError, self._handle_key_error)
        self.register_handler(CybersecurityPlatformError, self._handle_platform_error)
    
    def register_handler(self, error_type: type, handler: Callable) -> None:
        """注册错误处理器"""
        self.error_handlers[error_type] = handler
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理错误"""
        error_info = self._create_error_info(error, context)
        
        # 更新统计信息
        self._update_statistics(error_info)
        
        # 记录到最近错误列表
        self._add_to_recent_errors(error_info)
        
        # 查找并执行错误处理器
        handler = self._find_handler(type(error))
        if handler:
            try:
                handler_result = handler(error, context)
                error_info.update(handler_result)
            except Exception as handler_error:
                if self.logger:
                    self.logger.log_error("错误处理器执行失败", handler_error)
        
        # 记录日志
        if self.logger:
            self._log_error(error_info)
        
        return error_info
    
    def _create_error_info(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """创建错误信息"""
        return {
            "error_id": f"ERR_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
            "error_type": type(error).__name__,
            "error_message": str(error),
            "severity": self._determine_severity(error),
            "category": self._determine_category(error),
            "timestamp": datetime.now().isoformat(),
            "traceback": traceback.format_exc(),
            "context": context or {},
            "handled": False,
            "recovery_suggestions": []
        }
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """确定错误严重程度"""
        if isinstance(error, (SystemExit, KeyboardInterrupt, MemoryError)):
            return ErrorSeverity.CRITICAL
        elif isinstance(error, (ConnectionError, TimeoutError, PermissionError)):
            return ErrorSeverity.HIGH
        elif isinstance(error, (ValueError, KeyError, FileNotFoundError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _determine_category(self, error: Exception) -> ErrorCategory:
        """确定错误分类"""
        if isinstance(error, FileNotFoundError):
            return ErrorCategory.CONFIGURATION
        elif isinstance(error, (ConnectionError, TimeoutError)):
            return ErrorCategory.NETWORK
        elif isinstance(error, PermissionError):
            return ErrorCategory.AUTHORIZATION
        elif isinstance(error, (ValueError, KeyError)):
            return ErrorCategory.VALIDATION
        else:
            return ErrorCategory.SYSTEM
    
    def _find_handler(self, error_type: type) -> Optional[Callable]:
        """查找错误处理器"""
        # 直接匹配
        if error_type in self.error_handlers:
            return self.error_handlers[error_type]
        
        # 查找父类匹配
        for registered_type, handler in self.error_handlers.items():
            if issubclass(error_type, registered_type):
                return handler
        
        return None
    
    def _update_statistics(self, error_info: Dict[str, Any]) -> None:
        """更新错误统计"""
        error_type = error_info["error_type"]
        self.error_statistics[error_type] = self.error_statistics.get(error_type, 0) + 1
    
    def _add_to_recent_errors(self, error_info: Dict[str, Any]) -> None:
        """添加到最近错误列表"""
        self.recent_errors.append(error_info)
        if len(self.recent_errors) > self.max_recent_errors:
            self.recent_errors.pop(0)
    
    def _log_error(self, error_info: Dict[str, Any]) -> None:
        """记录错误日志"""
        severity = error_info["severity"]
        message = f"错误处理: {error_info['error_type']} - {error_info['error_message']}"
        
        if severity == ErrorSeverity.CRITICAL:
            self.logger.log_critical(message, error_info["context"])
        elif severity == ErrorSeverity.HIGH:
            self.logger.log_error(message, context=error_info["context"])
        elif severity == ErrorSeverity.MEDIUM:
            self.logger.log_warning(message, error_info["context"])
        else:
            self.logger.log_info(message, error_info["context"])
    
    # 默认错误处理器
    def _handle_file_not_found(self, error: FileNotFoundError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理文件未找到错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "检查文件路径是否正确",
                "确认文件是否存在",
                "检查文件权限",
                "尝试使用绝对路径"
            ],
            "user_message": f"文件未找到: {str(error)}",
            "technical_details": "文件系统访问错误"
        }
    
    def _handle_permission_error(self, error: PermissionError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理权限错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "检查文件或目录权限",
                "以管理员身份运行程序",
                "修改文件所有者",
                "检查防火墙设置"
            ],
            "user_message": f"权限不足: {str(error)}",
            "technical_details": "访问权限被拒绝"
        }
    
    def _handle_connection_error(self, error: ConnectionError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理连接错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "检查网络连接",
                "验证目标地址和端口",
                "检查防火墙设置",
                "尝试重新连接",
                "检查代理设置"
            ],
            "user_message": f"网络连接失败: {str(error)}",
            "technical_details": "网络通信错误"
        }
    
    def _handle_timeout_error(self, error: TimeoutError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理超时错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "增加超时时间",
                "检查网络延迟",
                "优化请求参数",
                "分批处理数据",
                "检查服务器负载"
            ],
            "user_message": f"操作超时: {str(error)}",
            "technical_details": "请求处理超时"
        }
    
    def _handle_value_error(self, error: ValueError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理值错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "检查输入参数格式",
                "验证数据类型",
                "确认参数范围",
                "查看参数文档"
            ],
            "user_message": f"参数值错误: {str(error)}",
            "technical_details": "输入参数验证失败"
        }
    
    def _handle_key_error(self, error: KeyError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理键错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "检查配置文件完整性",
                "验证必需的配置项",
                "查看配置文档",
                "使用配置模板"
            ],
            "user_message": f"配置项缺失: {str(error)}",
            "technical_details": "配置键不存在"
        }
    
    def _handle_platform_error(self, error: CybersecurityPlatformError, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """处理平台错误"""
        return {
            "handled": True,
            "recovery_suggestions": [
                "查看错误详细信息",
                "检查系统日志",
                "重试操作",
                "联系技术支持"
            ],
            "user_message": error.message,
            "technical_details": f"平台错误代码: {error.error_code}",
            "error_context": error.context
        }
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """获取错误统计信息"""
        total_errors = sum(self.error_statistics.values())
        
        return {
            "total_errors": total_errors,
            "error_types": dict(self.error_statistics),
            "recent_errors_count": len(self.recent_errors),
            "most_common_error": max(self.error_statistics.items(), key=lambda x: x[1])[0] if self.error_statistics else None
        }
    
    def get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取最近的错误"""
        return self.recent_errors[-limit:]
    
    def clear_statistics(self) -> None:
        """清空统计信息"""
        self.error_statistics.clear()
        self.recent_errors.clear()


# 全局错误处理器实例
_global_error_handler: Optional[CoreErrorHandler] = None


def get_error_handler() -> CoreErrorHandler:
    """获取全局错误处理器"""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = CoreErrorHandler()
    return _global_error_handler


def handle_error(error: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """处理错误的便捷函数"""
    return get_error_handler().handle_error(error, context)