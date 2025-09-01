"""
自定义异常类 - 定义系统中使用的各种异常类型
"""

from typing import Optional, Dict, Any


class CybersecurityPlatformError(Exception):
    """网络安全平台基础异常类"""
    
    def __init__(self, message: str, error_code: str = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
    
    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class ConfigurationError(CybersecurityPlatformError):
    """配置相关异常"""
    pass


class AuthenticationError(CybersecurityPlatformError):
    """认证相关异常"""
    pass


class AuthorizationError(CybersecurityPlatformError):
    """授权相关异常"""
    pass


class NetworkError(CybersecurityPlatformError):
    """网络相关异常"""
    pass


class AIProviderError(CybersecurityPlatformError):
    """AI提供商相关异常"""
    pass


class AttackSimulationError(CybersecurityPlatformError):
    """攻击模拟相关异常"""
    pass


class DefenseSystemError(CybersecurityPlatformError):
    """防御系统相关异常"""
    pass


class CTFSolverError(CybersecurityPlatformError):
    """CTF解题器相关异常"""
    pass


class ValidationError(CybersecurityPlatformError):
    """数据验证相关异常"""
    pass


class SecurityViolationError(CybersecurityPlatformError):
    """安全违规相关异常"""
    pass


class ResourceExhaustionError(CybersecurityPlatformError):
    """资源耗尽相关异常"""
    pass


class TimeoutError(CybersecurityPlatformError):
    """超时相关异常"""
    pass


class RetryExhaustionError(CybersecurityPlatformError):
    """重试次数耗尽异常"""
    pass


class SecurityError(CybersecurityPlatformError):
    """安全相关异常"""
    pass