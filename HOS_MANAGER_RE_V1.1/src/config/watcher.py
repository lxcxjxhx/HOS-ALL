"""
配置文件监控模块 - 实现配置文件的热重载功能
"""

import asyncio
import time
from pathlib import Path
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime
import threading

from src.core.interfaces import ILogger
from src.core.exceptions import ConfigurationError
from src.core.base import BaseComponent


class ConfigWatcher(BaseComponent):
    """配置文件监控器"""
    
    def __init__(self, config_file: str, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.config_file = Path(config_file)
        self.last_modified = None
        self.check_interval = 1.0  # 检查间隔（秒）
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._watch_task = None
        self._stop_event = asyncio.Event()
        self._lock = asyncio.Lock()
    
    async def _initialize_component(self) -> None:
        """初始化配置监控器"""
        if not self.config_file.exists():
            raise ConfigurationError(f"配置文件不存在: {self.config_file}")
        
        self.last_modified = self.config_file.stat().st_mtime
        
        if self.logger:
            self.logger.log_info(f"配置监控器初始化完成: {self.config_file}")
    
    async def _start_component(self) -> None:
        """启动配置监控"""
        self._stop_event.clear()
        self._watch_task = asyncio.create_task(self._watch_config_file())
        
        if self.logger:
            self.logger.log_info("配置文件监控已启动")
    
    async def _stop_component(self) -> None:
        """停止配置监控"""
        self._stop_event.set()
        
        if self._watch_task and not self._watch_task.done():
            try:
                await asyncio.wait_for(self._watch_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._watch_task.cancel()
                try:
                    await self._watch_task
                except asyncio.CancelledError:
                    pass
        
        if self.logger:
            self.logger.log_info("配置文件监控已停止")
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """添加配置变更回调函数"""
        if callback not in self.callbacks:
            self.callbacks.append(callback)
            if self.logger:
                self.logger.log_info(f"添加配置变更回调: {callback.__name__}")
    
    def remove_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """移除配置变更回调函数"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
            if self.logger:
                self.logger.log_info(f"移除配置变更回调: {callback.__name__}")
    
    def set_check_interval(self, interval: float) -> None:
        """设置检查间隔"""
        if interval > 0:
            self.check_interval = interval
            if self.logger:
                self.logger.log_info(f"配置检查间隔设置为: {interval}秒")
    
    async def force_reload(self) -> bool:
        """强制重新加载配置"""
        try:
            async with self._lock:
                if self.config_file.exists():
                    config_data = await self._load_config_async()
                    await self._notify_callbacks(config_data)
                    self.last_modified = self.config_file.stat().st_mtime
                    
                    if self.logger:
                        self.logger.log_info("强制重新加载配置成功")
                    return True
                else:
                    if self.logger:
                        self.logger.log_error("配置文件不存在，无法重新加载")
                    return False
                    
        except Exception as e:
            if self.logger:
                self.logger.log_error("强制重新加载配置失败", e)
            return False
    
    async def _watch_config_file(self) -> None:
        """监控配置文件变更"""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.check_interval)
                
                if not self.config_file.exists():
                    if self.logger:
                        self.logger.log_warning("配置文件已被删除")
                    continue
                
                current_modified = self.config_file.stat().st_mtime
                
                if current_modified != self.last_modified:
                    async with self._lock:
                        if self.logger:
                            self.logger.log_info("检测到配置文件变更")
                        
                        # 等待文件写入完成
                        await asyncio.sleep(0.1)
                        
                        try:
                            config_data = await self._load_config_async()
                            await self._notify_callbacks(config_data)
                            self.last_modified = current_modified
                            
                            if self.logger:
                                self.logger.log_info("配置文件重新加载成功")
                                
                        except Exception as e:
                            if self.logger:
                                self.logger.log_error("重新加载配置文件失败", e)
                            # 不更新last_modified，下次继续尝试
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.logger:
                    self.logger.log_error("配置文件监控过程中发生错误", e)
                await asyncio.sleep(self.check_interval)
    
    async def _load_config_async(self) -> Dict[str, Any]:
        """异步加载配置文件"""
        import json
        
        def load_config():
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # 在线程池中执行文件IO操作
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, load_config)
    
    async def _notify_callbacks(self, config_data: Dict[str, Any]) -> None:
        """通知所有回调函数"""
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(config_data)
                else:
                    callback(config_data)
            except Exception as e:
                if self.logger:
                    self.logger.log_error(f"配置变更回调执行失败: {callback.__name__}", e)


class ConfigValidator:
    """配置验证器"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        self.logger = logger
        self.validation_rules = {}
        self.error_messages = []
        self._setup_default_rules()
    
    def _setup_default_rules(self) -> None:
        """设置默认验证规则"""
        self.validation_rules = {
            "ai_providers": {
                "required": True,
                "type": dict,
                "validator": self._validate_ai_providers
            },
            "ai_providers.default": {
                "required": True,
                "type": str,
                "validator": self._validate_default_provider
            },
            "security": {
                "required": True,
                "type": dict,
                "validator": self._validate_security_config
            },
            "security.max_concurrent_sessions": {
                "required": True,
                "type": int,
                "min_value": 1,
                "max_value": 100
            },
            "security.session_timeout": {
                "required": True,
                "type": int,
                "min_value": 60,
                "max_value": 86400
            },
            "network": {
                "required": True,
                "type": dict,
                "validator": self._validate_network_config
            },
            "network.default_scan_timeout": {
                "required": True,
                "type": int,
                "min_value": 1,
                "max_value": 600
            },
            "network.max_scan_threads": {
                "required": True,
                "type": int,
                "min_value": 1,
                "max_value": 100
            },
            "logging": {
                "required": True,
                "type": dict,
                "validator": self._validate_logging_config
            },
            "logging.level": {
                "required": True,
                "type": str,
                "allowed_values": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            }
        }
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """验证配置"""
        self.error_messages.clear()
        
        try:
            for rule_path, rule in self.validation_rules.items():
                if not self._validate_field(config, rule_path, rule):
                    return False
            
            # 执行自定义验证
            if not self._validate_custom_rules(config):
                return False
            
            if self.logger:
                self.logger.log_info("配置验证通过")
            
            return True
            
        except Exception as e:
            self.error_messages.append(f"配置验证过程中发生错误: {str(e)}")
            if self.logger:
                self.logger.log_error("配置验证失败", e)
            return False
    
    def get_validation_errors(self) -> List[str]:
        """获取验证错误信息"""
        return self.error_messages.copy()
    
    def add_validation_rule(self, path: str, rule: Dict[str, Any]) -> None:
        """添加验证规则"""
        self.validation_rules[path] = rule
        if self.logger:
            self.logger.log_info(f"添加验证规则: {path}")
    
    def remove_validation_rule(self, path: str) -> None:
        """移除验证规则"""
        if path in self.validation_rules:
            del self.validation_rules[path]
            if self.logger:
                self.logger.log_info(f"移除验证规则: {path}")
    
    def _validate_field(self, config: Dict[str, Any], field_path: str, rule: Dict[str, Any]) -> bool:
        """验证单个字段"""
        try:
            value = self._get_nested_value(config, field_path)
            
            # 检查必需字段
            if rule.get("required", False) and value is None:
                self.error_messages.append(f"必需字段缺失: {field_path}")
                return False
            
            if value is None:
                return True  # 非必需字段可以为空
            
            # 检查类型
            expected_type = rule.get("type")
            if expected_type and not isinstance(value, expected_type):
                self.error_messages.append(f"字段类型错误: {field_path}, 期望 {expected_type.__name__}, 实际 {type(value).__name__}")
                return False
            
            # 检查数值范围
            if isinstance(value, (int, float)):
                min_value = rule.get("min_value")
                max_value = rule.get("max_value")
                
                if min_value is not None and value < min_value:
                    self.error_messages.append(f"字段值过小: {field_path}, 最小值 {min_value}, 实际值 {value}")
                    return False
                
                if max_value is not None and value > max_value:
                    self.error_messages.append(f"字段值过大: {field_path}, 最大值 {max_value}, 实际值 {value}")
                    return False
            
            # 检查允许的值
            allowed_values = rule.get("allowed_values")
            if allowed_values and value not in allowed_values:
                self.error_messages.append(f"字段值不在允许范围内: {field_path}, 允许值 {allowed_values}, 实际值 {value}")
                return False
            
            # 执行自定义验证器
            validator = rule.get("validator")
            if validator and callable(validator):
                if not validator(value, config):
                    return False
            
            return True
            
        except Exception as e:
            self.error_messages.append(f"验证字段 {field_path} 时发生错误: {str(e)}")
            return False
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """获取嵌套字典中的值"""
        keys = path.split('.')
        current = data
        
        try:
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            return current
        except (KeyError, TypeError):
            return None
    
    def _validate_ai_providers(self, value: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """验证AI提供商配置"""
        if "default" not in value:
            self.error_messages.append("AI提供商配置缺少默认提供商")
            return False
        
        default_provider = value["default"]
        if default_provider not in value:
            self.error_messages.append(f"默认AI提供商配置不存在: {default_provider}")
            return False
        
        return True
    
    def _validate_default_provider(self, value: str, config: Dict[str, Any]) -> bool:
        """验证默认AI提供商"""
        valid_providers = ["deepseek", "openai", "claude", "gemini", "ollama"]
        if value not in valid_providers:
            self.error_messages.append(f"不支持的默认AI提供商: {value}")
            return False
        return True
    
    def _validate_security_config(self, value: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """验证安全配置"""
        required_fields = ["max_concurrent_sessions", "session_timeout", "enable_audit_log"]
        for field in required_fields:
            if field not in value:
                self.error_messages.append(f"安全配置缺少字段: {field}")
                return False
        return True
    
    def _validate_network_config(self, value: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """验证网络配置"""
        required_fields = ["default_scan_timeout", "max_scan_threads"]
        for field in required_fields:
            if field not in value:
                self.error_messages.append(f"网络配置缺少字段: {field}")
                return False
        return True
    
    def _validate_logging_config(self, value: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """验证日志配置"""
        required_fields = ["level", "file"]
        for field in required_fields:
            if field not in value:
                self.error_messages.append(f"日志配置缺少字段: {field}")
                return False
        return True
    
    def _validate_custom_rules(self, config: Dict[str, Any]) -> bool:
        """执行自定义验证规则"""
        # 验证网络配置的逻辑一致性
        network_config = config.get("network", {})
        if "allowed_networks" in network_config and "blocked_networks" in network_config:
            allowed = set(network_config.get("allowed_networks", []))
            blocked = set(network_config.get("blocked_networks", []))
            
            # 检查是否有重叠
            overlap = allowed.intersection(blocked)
            if overlap:
                self.error_messages.append(f"网络配置冲突: 以下网络同时在允许和阻止列表中: {list(overlap)}")
                return False
        
        return True