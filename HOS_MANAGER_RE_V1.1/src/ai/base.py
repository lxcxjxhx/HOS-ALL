"""
AI提供商基础类 - 定义AI提供商的抽象接口和基础实现
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from datetime import datetime
import json

from core.interfaces import IAIProvider, AIResponse, AIProviderType, ILogger
from core.exceptions import AIProviderError
from core.base import BaseComponent


@dataclass
class AIRequest:
    """AI请求数据模型"""
    prompt: str
    context: Optional[Dict[str, Any]] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    system_message: Optional[str] = None
    conversation_history: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIUsageStats:
    """AI使用统计"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_tokens_used: int = 0
    total_response_time: float = 0.0
    average_response_time: float = 0.0
    last_request_time: Optional[datetime] = None
    
    def update_stats(self, tokens_used: int, response_time: float, success: bool):
        """更新统计信息"""
        self.total_requests += 1
        self.total_tokens_used += tokens_used
        self.total_response_time += response_time
        self.last_request_time = datetime.now()
        
        if success:
            self.successful_requests += 1
            self.average_response_time = self.total_response_time / self.successful_requests
        else:
            self.failed_requests += 1


class BaseAIProvider(BaseComponent, IAIProvider):
    """AI提供商基础类"""
    
    def __init__(self, provider_type: AIProviderType, config: Dict[str, Any], logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.provider_type = provider_type
        self.config = config.copy()
        self.api_key = config.get("api_key", "")
        self.base_url = config.get("base_url", "")
        self.model = config.get("model", "")
        self.default_max_tokens = config.get("max_tokens", 4000)
        self.default_temperature = config.get("temperature", 0.7)
        self.timeout = config.get("timeout", 30)
        
        # 使用统计
        self.usage_stats = AIUsageStats()
        
        # 请求限制
        self.max_requests_per_minute = config.get("max_requests_per_minute", 60)
        self.request_timestamps = []
        
        # 重试配置
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 1.0)
        
        # 状态管理
        self._is_available = False
        self._last_error = None
    
    async def _initialize_component(self) -> None:
        """初始化AI提供商"""
        if not self.api_key and self.provider_type != AIProviderType.OLLAMA:
            raise AIProviderError(f"{self.provider_type.value} 需要API密钥")
        
        if not self.base_url:
            raise AIProviderError(f"{self.provider_type.value} 需要base_url配置")
        
        if not self.model:
            raise AIProviderError(f"{self.provider_type.value} 需要model配置")
        
        # 验证API密钥
        try:
            is_valid = await self.validate_api_key()
            if not is_valid:
                raise AIProviderError(f"{self.provider_type.value} API密钥验证失败")
            
            self._is_available = True
            if self.logger:
                self.logger.log_info(f"AI提供商 {self.provider_type.value} 初始化成功")
                
        except Exception as e:
            self._last_error = str(e)
            if self.logger:
                self.logger.log_error(f"AI提供商 {self.provider_type.value} 初始化失败", e)
            raise AIProviderError(f"初始化失败: {str(e)}")
    
    async def generate_response(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """生成AI响应"""
        if not self._is_available:
            raise AIProviderError(f"AI提供商 {self.provider_type.value} 不可用")
        
        # 检查请求限制
        if not self._check_rate_limit():
            raise AIProviderError("请求频率超过限制")
        
        # 构建请求
        request = self._build_request(prompt, context)
        
        # 执行请求（带重试）
        start_time = time.time()
        response = None
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._make_api_request(request)
                break
            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    if self.logger:
                        self.logger.log_warning(f"AI请求失败，第{attempt + 1}次重试: {str(e)}")
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                else:
                    if self.logger:
                        self.logger.log_error(f"AI请求最终失败: {str(e)}", e)
        
        response_time = time.time() - start_time
        
        if response is None:
            # 更新统计
            self.usage_stats.update_stats(0, response_time, False)
            raise AIProviderError(f"请求失败: {str(last_error)}")
        
        # 更新统计
        self.usage_stats.update_stats(response.tokens_used, response_time, response.success)
        
        return response
    
    def get_provider_info(self) -> Dict[str, Any]:
        """获取提供商信息"""
        return {
            "provider_type": self.provider_type.value,
            "model": self.model,
            "base_url": self.base_url,
            "is_available": self._is_available,
            "last_error": self._last_error,
            "usage_stats": {
                "total_requests": self.usage_stats.total_requests,
                "successful_requests": self.usage_stats.successful_requests,
                "failed_requests": self.usage_stats.failed_requests,
                "total_tokens_used": self.usage_stats.total_tokens_used,
                "average_response_time": self.usage_stats.average_response_time,
                "last_request_time": self.usage_stats.last_request_time.isoformat() if self.usage_stats.last_request_time else None
            },
            "config": {
                "max_tokens": self.default_max_tokens,
                "temperature": self.default_temperature,
                "timeout": self.timeout,
                "max_requests_per_minute": self.max_requests_per_minute
            }
        }
    
    def get_usage_stats(self) -> AIUsageStats:
        """获取使用统计"""
        return self.usage_stats
    
    def reset_usage_stats(self) -> None:
        """重置使用统计"""
        self.usage_stats = AIUsageStats()
        if self.logger:
            self.logger.log_info(f"重置 {self.provider_type.value} 使用统计")
    
    def is_available(self) -> bool:
        """检查提供商是否可用"""
        return self._is_available
    
    def get_last_error(self) -> Optional[str]:
        """获取最后一次错误"""
        return self._last_error
    
    def _build_request(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIRequest:
        """构建AI请求"""
        context = context or {}
        
        return AIRequest(
            prompt=prompt,
            context=context,
            max_tokens=context.get("max_tokens", self.default_max_tokens),
            temperature=context.get("temperature", self.default_temperature),
            system_message=context.get("system_message"),
            conversation_history=context.get("conversation_history", []),
            metadata=context.get("metadata", {})
        )
    
    def _check_rate_limit(self) -> bool:
        """检查请求频率限制"""
        current_time = time.time()
        
        # 清理超过1分钟的请求记录
        self.request_timestamps = [
            timestamp for timestamp in self.request_timestamps
            if current_time - timestamp < 60
        ]
        
        # 检查是否超过限制
        if len(self.request_timestamps) >= self.max_requests_per_minute:
            return False
        
        # 记录当前请求时间
        self.request_timestamps.append(current_time)
        return True
    
    @abstractmethod
    async def _make_api_request(self, request: AIRequest) -> AIResponse:
        """执行API请求（子类实现）"""
        pass
    
    @abstractmethod
    async def validate_api_key(self) -> bool:
        """验证API密钥（子类实现）"""
        pass


class AIProviderManager(BaseComponent):
    """AI提供商管理器"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.providers: Dict[str, BaseAIProvider] = {}
        self.default_provider: Optional[str] = None
        self.fallback_order: List[str] = []
        self._lock = asyncio.Lock()
        
        # 故障转移配置
        self.enable_auto_failover = True
        self.max_failover_attempts = 3
        self.failover_delay = 1.0  # 秒
        
        # 提供商健康检查
        self.health_check_interval = 300  # 5分钟
        self.last_health_check = {}
        
        # 故障转移统计
        self.failover_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "failover_count": 0,
            "provider_failures": {}
        }
    
    async def _initialize_component(self) -> None:
        """初始化管理器"""
        if self.logger:
            self.logger.log_info("AI提供商管理器初始化完成")
    
    async def add_provider(self, name: str, provider: BaseAIProvider) -> bool:
        """添加AI提供商"""
        try:
            async with self._lock:
                await provider.initialize()
                await provider.start()
                
                self.providers[name] = provider
                
                if self.default_provider is None:
                    self.default_provider = name
                
                if self.logger:
                    self.logger.log_info(f"添加AI提供商: {name} ({provider.provider_type.value})")
                
                return True
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"添加AI提供商失败: {name}", e)
            return False
    
    async def remove_provider(self, name: str) -> bool:
        """移除AI提供商"""
        try:
            async with self._lock:
                if name in self.providers:
                    provider = self.providers[name]
                    await provider.stop()
                    del self.providers[name]
                    
                    if self.default_provider == name:
                        self.default_provider = next(iter(self.providers.keys()), None)
                    
                    if name in self.fallback_order:
                        self.fallback_order.remove(name)
                    
                    if self.logger:
                        self.logger.log_info(f"移除AI提供商: {name}")
                    
                    return True
                
                return False
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"移除AI提供商失败: {name}", e)
            return False
    
    def set_default_provider(self, name: str) -> bool:
        """设置默认提供商"""
        if name in self.providers:
            self.default_provider = name
            if self.logger:
                self.logger.log_info(f"设置默认AI提供商: {name}")
            return True
        return False
    
    def set_fallback_order(self, order: List[str]) -> None:
        """设置故障转移顺序"""
        valid_providers = [name for name in order if name in self.providers]
        self.fallback_order = valid_providers
        if self.logger:
            self.logger.log_info(f"设置故障转移顺序: {valid_providers}")
    
    async def generate_response(self, prompt: str, context: Optional[Dict[str, Any]] = None, provider_name: Optional[str] = None) -> AIResponse:
        """生成AI响应（支持智能故障转移）"""
        self.failover_stats["total_requests"] += 1
        
        # 确定使用的提供商列表
        if provider_name and provider_name in self.providers:
            providers_to_try = [provider_name]
            # 如果指定了提供商但失败，是否启用故障转移
            if self.enable_auto_failover:
                # 添加其他可用提供商作为备选
                for name in self._get_healthy_providers():
                    if name != provider_name and name not in providers_to_try:
                        providers_to_try.append(name)
        else:
            providers_to_try = self._get_provider_priority_list()
        
        last_error = None
        attempts = 0
        
        for current_provider_name in providers_to_try:
            if attempts >= self.max_failover_attempts:
                if self.logger:
                    self.logger.log_warning(f"达到最大故障转移尝试次数: {self.max_failover_attempts}")
                break
            
            if current_provider_name not in self.providers:
                continue
            
            provider = self.providers[current_provider_name]
            
            # 检查提供商健康状态
            if not await self._check_provider_health(current_provider_name):
                if self.logger:
                    self.logger.log_warning(f"跳过不健康的AI提供商: {current_provider_name}")
                continue
            
            try:
                attempts += 1
                
                # 如果不是第一次尝试，添加延迟并记录故障转移
                if attempts > 1:
                    await asyncio.sleep(self.failover_delay)
                    if self.logger:
                        self.logger.log_info(f"故障转移到AI提供商: {current_provider_name} (尝试 {attempts})")
                
                # 如果不是第一个提供商，记录为故障转移
                if current_provider_name != providers_to_try[0]:
                    self.failover_stats["failover_count"] += 1
                
                response = await provider.generate_response(prompt, context)
                
                # 成功响应
                self.failover_stats["successful_requests"] += 1
                if self.logger:
                    self.logger.log_info(f"使用AI提供商 {current_provider_name} 生成响应成功")
                
                return response
                
            except Exception as e:
                last_error = e
                
                # 记录提供商失败
                if current_provider_name not in self.failover_stats["provider_failures"]:
                    self.failover_stats["provider_failures"][current_provider_name] = 0
                self.failover_stats["provider_failures"][current_provider_name] += 1
                
                if self.logger:
                    self.logger.log_warning(f"AI提供商 {current_provider_name} 请求失败: {str(e)}")
                
                # 标记提供商为不健康
                await self._mark_provider_unhealthy(current_provider_name, str(e))
                
                continue
        
        # 所有提供商都失败
        self.failover_stats["failed_requests"] += 1
        error_msg = f"所有AI提供商都不可用，尝试了 {attempts} 次，最后错误: {str(last_error)}"
        if self.logger:
            self.logger.log_error(error_msg)
        raise AIProviderError(error_msg)
    
    def get_provider(self, name: str) -> Optional[BaseAIProvider]:
        """获取指定提供商"""
        return self.providers.get(name)
    
    def get_available_providers(self) -> List[str]:
        """获取可用提供商列表"""
        return [name for name, provider in self.providers.items() if provider.is_available()]
    
    def get_all_providers_info(self) -> Dict[str, Dict[str, Any]]:
        """获取所有提供商信息"""
        return {name: provider.get_provider_info() for name, provider in self.providers.items()}
    
    def get_manager_status(self) -> Dict[str, Any]:
        """获取管理器状态"""
        return {
            "total_providers": len(self.providers),
            "available_providers": len(self.get_available_providers()),
            "healthy_providers": len(self._get_healthy_providers()),
            "default_provider": self.default_provider,
            "fallback_order": self.fallback_order,
            "providers": list(self.providers.keys()),
            "auto_failover_enabled": self.enable_auto_failover,
            "max_failover_attempts": self.max_failover_attempts,
            "failover_stats": self.failover_stats.copy()
        }
    
    def _get_provider_priority_list(self) -> List[str]:
        """获取提供商优先级列表"""
        providers_to_try = []
        
        # 1. 默认提供商
        if self.default_provider and self.default_provider in self.providers:
            providers_to_try.append(self.default_provider)
        
        # 2. 故障转移顺序中的提供商
        for name in self.fallback_order:
            if name in self.providers and name not in providers_to_try:
                providers_to_try.append(name)
        
        # 3. 其他健康的提供商
        for name in self._get_healthy_providers():
            if name not in providers_to_try:
                providers_to_try.append(name)
        
        return providers_to_try
    
    def _get_healthy_providers(self) -> List[str]:
        """获取健康的提供商列表"""
        healthy_providers = []
        current_time = time.time()
        
        for name, provider in self.providers.items():
            # 检查基本可用性
            if not provider.is_available():
                continue
            
            # 检查最近的健康检查
            last_check = self.last_health_check.get(name, 0)
            if current_time - last_check < self.health_check_interval:
                healthy_providers.append(name)
            else:
                # 需要重新检查健康状态
                healthy_providers.append(name)  # 暂时认为健康，后续异步检查
        
        return healthy_providers
    
    async def _check_provider_health(self, provider_name: str) -> bool:
        """检查提供商健康状态"""
        if provider_name not in self.providers:
            return False
        
        provider = self.providers[provider_name]
        current_time = time.time()
        
        # 检查基本可用性
        if not provider.is_available():
            return False
        
        # 检查是否需要健康检查
        last_check = self.last_health_check.get(provider_name, 0)
        if current_time - last_check < self.health_check_interval:
            return True
        
        # 执行健康检查
        try:
            is_healthy = await provider.validate_api_key()
            self.last_health_check[provider_name] = current_time
            
            if not is_healthy:
                if self.logger:
                    self.logger.log_warning(f"提供商 {provider_name} 健康检查失败")
            
            return is_healthy
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"提供商 {provider_name} 健康检查异常", e)
            return False
    
    async def _mark_provider_unhealthy(self, provider_name: str, error_message: str) -> None:
        """标记提供商为不健康状态"""
        if provider_name in self.providers:
            provider = self.providers[provider_name]
            provider._is_available = False
            provider._last_error = error_message
            
            # 重置健康检查时间，强制下次重新检查
            self.last_health_check[provider_name] = 0
            
            if self.logger:
                self.logger.log_warning(f"标记提供商 {provider_name} 为不健康: {error_message}")
    
    async def refresh_provider_health(self) -> Dict[str, bool]:
        """刷新所有提供商的健康状态"""
        health_results = {}
        
        for provider_name in self.providers:
            try:
                # 强制重新检查健康状态
                self.last_health_check[provider_name] = 0
                is_healthy = await self._check_provider_health(provider_name)
                health_results[provider_name] = is_healthy
                
                if is_healthy:
                    # 恢复提供商可用性
                    self.providers[provider_name]._is_available = True
                    self.providers[provider_name]._last_error = None
                else:
                    # 标记为不可用
                    self.providers[provider_name]._is_available = False
                    
            except Exception as e:
                health_results[provider_name] = False
                self.providers[provider_name]._is_available = False
                if self.logger:
                    self.logger.log_error(f"刷新提供商 {provider_name} 健康状态失败", e)
        
        if self.logger:
            healthy_count = sum(health_results.values())
            self.logger.log_info(f"健康检查完成: {healthy_count}/{len(health_results)} 个提供商健康")
        
        return health_results
    
    def configure_failover(self, enable_auto_failover: bool = True, max_attempts: int = 3, delay: float = 1.0) -> None:
        """配置故障转移参数"""
        self.enable_auto_failover = enable_auto_failover
        self.max_failover_attempts = max_attempts
        self.failover_delay = delay
        
        if self.logger:
            self.logger.log_info(f"故障转移配置更新: 自动故障转移={'启用' if enable_auto_failover else '禁用'}, "
                               f"最大尝试次数={max_attempts}, 延迟={delay}秒")
    
    def reset_failover_stats(self) -> None:
        """重置故障转移统计"""
        self.failover_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "failover_count": 0,
            "provider_failures": {}
        }
        
        if self.logger:
            self.logger.log_info("故障转移统计已重置")
    
    def get_failover_stats(self) -> Dict[str, Any]:
        """获取故障转移统计"""
        stats = self.failover_stats.copy()
        
        # 计算成功率
        if stats["total_requests"] > 0:
            stats["success_rate"] = stats["successful_requests"] / stats["total_requests"]
            stats["failure_rate"] = stats["failed_requests"] / stats["total_requests"]
            stats["failover_rate"] = stats["failover_count"] / stats["total_requests"]
        else:
            stats["success_rate"] = 0.0
            stats["failure_rate"] = 0.0
            stats["failover_rate"] = 0.0
        
        return stats