"""
配置管理器 - 处理系统配置的加载、验证和保存
"""

import json
import os
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
import asyncio
from datetime import datetime

from src.core.interfaces import IConfigManager, ILogger
from src.core.exceptions import ConfigurationError, SecurityError
from src.core.base import BaseComponent
from .encryption import EncryptionManager, SecureConfigManager
from .watcher import ConfigWatcher, ConfigValidator


class ConfigManager(BaseComponent, IConfigManager):
    """配置管理器实现"""
    
    def __init__(self, config_dir: str = "config", logger: Optional[ILogger] = None, master_key: Optional[str] = None):
        super().__init__(logger)
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "config.json"
        self.template_file = self.config_dir / "config_template.json"
        self.backup_dir = self.config_dir / "backups"
        self._config_cache = {}
        self._config_schema = self._get_config_schema()
        
        # 初始化加密管理器
        try:
            self.encryption_manager = EncryptionManager(master_key)
            self.secure_config_manager = SecureConfigManager(self.encryption_manager)
        except Exception as e:
            if self.logger:
                self.logger.log_error("初始化加密管理器失败", e)
            raise ConfigurationError(f"初始化加密管理器失败: {str(e)}")
        
        # 初始化配置验证器和监控器
        self.config_validator = ConfigValidator(logger)
        self.config_watcher = None
        self._hot_reload_enabled = False
        self._reload_callbacks = []
    
    async def _initialize_component(self) -> None:
        """初始化配置管理器"""
        # 确保配置目录存在
        self.config_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        # 检查配置文件是否存在
        if not self.config_file.exists():
            if self.template_file.exists():
                if self.logger:
                    self.logger.log_info("配置文件不存在，从模板创建")
                self._create_config_from_template()
            else:
                raise ConfigurationError("配置文件和模板文件都不存在")
        
        # 加载配置到缓存
        encrypted_config = self.load_config(str(self.config_file))
        self._config_cache = self.secure_config_manager.decrypt_sensitive_config(encrypted_config)
        
        if self.logger:
            self.logger.log_info("配置管理器初始化完成")
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                raise ConfigurationError(f"配置文件不存在: {config_path}")
            
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 验证配置
            if not self.validate_config(config):
                raise ConfigurationError("配置文件验证失败")
            
            if self.logger:
                self.logger.log_info(f"成功加载配置文件: {config_path}")
            
            return config
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"配置文件JSON格式错误: {str(e)}")
        except Exception as e:
            raise ConfigurationError(f"加载配置文件失败: {str(e)}")
    
    def save_config(self, config: Dict[str, Any], config_path: str) -> bool:
        """保存配置文件"""
        try:
            # 验证配置
            if not self.validate_config(config):
                raise ConfigurationError("配置验证失败，无法保存")
            
            config_file = Path(config_path)
            
            # 备份现有配置
            if config_file.exists():
                self._backup_config(config_file)
            
            # 确保目录存在
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # 加密敏感数据后保存配置
            encrypted_config = self.secure_config_manager.encrypt_sensitive_config(config)
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_config, f, indent=2, ensure_ascii=False)
            
            # 更新缓存（保存解密后的配置）
            if config_path == str(self.config_file):
                self._config_cache = config.copy()
            
            if self.logger:
                self.logger.log_info(f"成功保存配置文件: {config_path}")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"保存配置文件失败: {config_path}", e)
            raise ConfigurationError(f"保存配置文件失败: {str(e)}")
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """验证配置文件"""
        return self.config_validator.validate_config(config)
    
    def get_validation_errors(self) -> List[str]:
        """获取配置验证错误信息"""
        return self.config_validator.get_validation_errors()
    
    def get_config(self, key: str = None, default: Any = None) -> Any:
        """获取配置值"""
        if key is None:
            return self._config_cache.copy()
        
        keys = key.split('.')
        value = self._config_cache
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_config(self, key: str, value: Any) -> bool:
        """设置配置值"""
        try:
            keys = key.split('.')
            config = self._config_cache.copy()
            current = config
            
            # 导航到目标位置
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            
            # 设置值
            current[keys[-1]] = value
            
            # 验证修改后的配置
            if not self.validate_config(config):
                if self.logger:
                    self.logger.log_error(f"设置配置值后验证失败: {key}")
                return False
            
            # 保存配置
            if self.save_config(config, str(self.config_file)):
                if self.logger:
                    self.logger.log_info(f"成功设置配置值: {key}")
                return True
            
            return False
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"设置配置值失败: {key}", e)
            return False
    
    def create_setup_wizard(self) -> Dict[str, Any]:
        """创建配置设置向导"""
        wizard_steps = {
            "step1": {
                "title": "AI提供商配置",
                "description": "配置AI服务提供商的API密钥和设置",
                "fields": [
                    {
                        "key": "ai_providers.default",
                        "label": "默认AI提供商",
                        "type": "select",
                        "options": ["deepseek", "openai", "claude", "gemini", "ollama"],
                        "required": True
                    },
                    {
                        "key": "ai_providers.deepseek.api_key",
                        "label": "DeepSeek API密钥",
                        "type": "password",
                        "required": False
                    },
                    {
                        "key": "ai_providers.openai.api_key",
                        "label": "OpenAI API密钥",
                        "type": "password",
                        "required": False
                    }
                ]
            },
            "step2": {
                "title": "安全设置",
                "description": "配置系统安全参数",
                "fields": [
                    {
                        "key": "security.max_concurrent_sessions",
                        "label": "最大并发会话数",
                        "type": "number",
                        "default": 5,
                        "min": 1,
                        "max": 20
                    },
                    {
                        "key": "security.session_timeout",
                        "label": "会话超时时间（秒）",
                        "type": "number",
                        "default": 3600,
                        "min": 300,
                        "max": 86400
                    }
                ]
            },
            "step3": {
                "title": "网络设置",
                "description": "配置网络扫描和监控参数",
                "fields": [
                    {
                        "key": "network.default_scan_timeout",
                        "label": "默认扫描超时时间（秒）",
                        "type": "number",
                        "default": 30,
                        "min": 5,
                        "max": 300
                    },
                    {
                        "key": "network.max_scan_threads",
                        "label": "最大扫描线程数",
                        "type": "number",
                        "default": 10,
                        "min": 1,
                        "max": 50
                    }
                ]
            }
        }
        
        return wizard_steps
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """加密敏感数据"""
        try:
            return self.encryption_manager.encrypt_data(data)
        except Exception as e:
            if self.logger:
                self.logger.log_error("加密敏感数据失败", e)
            raise SecurityError(f"加密敏感数据失败: {str(e)}")
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """解密敏感数据"""
        try:
            return self.encryption_manager.decrypt_data(encrypted_data)
        except Exception as e:
            if self.logger:
                self.logger.log_error("解密敏感数据失败", e)
            raise SecurityError(f"解密敏感数据失败: {str(e)}")
    
    def encrypt_api_key(self, api_key: str, provider: str) -> str:
        """加密API密钥"""
        try:
            return self.encryption_manager.encrypt_api_key(api_key, provider)
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"加密{provider} API密钥失败", e)
            raise SecurityError(f"加密API密钥失败: {str(e)}")
    
    def decrypt_api_key(self, encrypted_key: str, provider: str) -> str:
        """解密API密钥"""
        try:
            return self.encryption_manager.decrypt_api_key(encrypted_key, provider)
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"解密{provider} API密钥失败", e)
            raise SecurityError(f"解密API密钥失败: {str(e)}")
    
    def change_master_key(self, new_master_key: str) -> bool:
        """更改主密钥"""
        try:
            # 获取当前加密的配置
            current_config = self.load_config(str(self.config_file))
            
            # 提取所有敏感数据
            sensitive_data = self._extract_sensitive_data(current_config)
            
            # 更改主密钥并重新加密
            re_encrypted_data = self.encryption_manager.change_master_key(new_master_key, sensitive_data)
            
            # 更新配置中的敏感数据
            updated_config = self._update_sensitive_data(current_config, re_encrypted_data)
            
            # 保存更新后的配置
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(updated_config, f, indent=2, ensure_ascii=False)
            
            # 重新初始化加密管理器
            self.encryption_manager = EncryptionManager(new_master_key)
            self.secure_config_manager = SecureConfigManager(self.encryption_manager)
            
            # 重新加载配置缓存
            self._config_cache = self.secure_config_manager.decrypt_sensitive_config(updated_config)
            
            if self.logger:
                self.logger.log_info("主密钥更改成功")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("更改主密钥失败", e)
            raise SecurityError(f"更改主密钥失败: {str(e)}")
    
    def get_master_key_backup(self) -> str:
        """获取主密钥备份（仅用于安全备份）"""
        return self.encryption_manager.get_master_key()
    
    def validate_master_key(self, master_key: str) -> bool:
        """验证主密钥是否正确"""
        try:
            test_manager = EncryptionManager(master_key)
            # 尝试解密一个已知的加密值来验证密钥
            test_data = "test_validation"
            encrypted = self.encryption_manager.encrypt_data(test_data)
            decrypted = test_manager.decrypt_data(encrypted)
            return decrypted == test_data
        except Exception:
            return False
    
    def _create_config_from_template(self) -> None:
        """从模板创建配置文件"""
        try:
            shutil.copy2(self.template_file, self.config_file)
            if self.logger:
                self.logger.log_info("从模板创建配置文件成功")
        except Exception as e:
            raise ConfigurationError(f"从模板创建配置文件失败: {str(e)}")
    
    def _backup_config(self, config_file: Path) -> None:
        """备份配置文件"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"config_backup_{timestamp}.json"
            shutil.copy2(config_file, backup_file)
            
            # 只保留最近10个备份
            self._cleanup_old_backups()
            
            if self.logger:
                self.logger.log_info(f"配置文件备份成功: {backup_file}")
                
        except Exception as e:
            if self.logger:
                self.logger.log_warning(f"配置文件备份失败: {str(e)}")
    
    def _cleanup_old_backups(self, keep_count: int = 10) -> None:
        """清理旧的备份文件"""
        try:
            backup_files = list(self.backup_dir.glob("config_backup_*.json"))
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            for backup_file in backup_files[keep_count:]:
                backup_file.unlink()
                
        except Exception as e:
            if self.logger:
                self.logger.log_warning(f"清理备份文件失败: {str(e)}")
    
    def _validate_ai_providers(self, ai_config: Dict[str, Any]) -> bool:
        """验证AI提供商配置"""
        if "default" not in ai_config:
            if self.logger:
                self.logger.log_error("AI配置缺少默认提供商")
            return False
        
        default_provider = ai_config["default"]
        if default_provider not in ai_config:
            if self.logger:
                self.logger.log_error(f"默认AI提供商配置不存在: {default_provider}")
            return False
        
        # 验证每个提供商的配置
        valid_providers = ["deepseek", "openai", "claude", "gemini", "ollama"]
        for provider, config in ai_config.items():
            if provider == "default":
                continue
            
            if provider not in valid_providers:
                if self.logger:
                    self.logger.log_error(f"不支持的AI提供商: {provider}")
                return False
            
            if not isinstance(config, dict):
                if self.logger:
                    self.logger.log_error(f"AI提供商配置格式错误: {provider}")
                return False
        
        return True
    
    def _validate_security_config(self, security_config: Dict[str, Any]) -> bool:
        """验证安全配置"""
        required_fields = ["max_concurrent_sessions", "session_timeout", "enable_audit_log"]
        for field in required_fields:
            if field not in security_config:
                if self.logger:
                    self.logger.log_error(f"安全配置缺少字段: {field}")
                return False
        
        # 验证数值范围
        max_sessions = security_config.get("max_concurrent_sessions", 0)
        if not isinstance(max_sessions, int) or max_sessions < 1 or max_sessions > 100:
            if self.logger:
                self.logger.log_error("最大并发会话数配置无效")
            return False
        
        timeout = security_config.get("session_timeout", 0)
        if not isinstance(timeout, int) or timeout < 60 or timeout > 86400:
            if self.logger:
                self.logger.log_error("会话超时时间配置无效")
            return False
        
        return True
    
    def _validate_network_config(self, network_config: Dict[str, Any]) -> bool:
        """验证网络配置"""
        required_fields = ["default_scan_timeout", "max_scan_threads"]
        for field in required_fields:
            if field not in network_config:
                if self.logger:
                    self.logger.log_error(f"网络配置缺少字段: {field}")
                return False
        
        # 验证扫描超时
        timeout = network_config.get("default_scan_timeout", 0)
        if not isinstance(timeout, int) or timeout < 1 or timeout > 600:
            if self.logger:
                self.logger.log_error("扫描超时时间配置无效")
            return False
        
        # 验证线程数
        threads = network_config.get("max_scan_threads", 0)
        if not isinstance(threads, int) or threads < 1 or threads > 100:
            if self.logger:
                self.logger.log_error("最大扫描线程数配置无效")
            return False
        
        return True
    
    def _validate_logging_config(self, logging_config: Dict[str, Any]) -> bool:
        """验证日志配置"""
        required_fields = ["level", "file"]
        for field in required_fields:
            if field not in logging_config:
                if self.logger:
                    self.logger.log_error(f"日志配置缺少字段: {field}")
                return False
        
        # 验证日志级别
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        level = logging_config.get("level", "")
        if level not in valid_levels:
            if self.logger:
                self.logger.log_error(f"无效的日志级别: {level}")
            return False
        
        return True
    
    def _get_config_schema(self) -> Dict[str, Any]:
        """获取配置模式定义"""
        return {
            "type": "object",
            "required": ["ai_providers", "security", "network", "logging"],
            "properties": {
                "ai_providers": {
                    "type": "object",
                    "required": ["default"],
                    "properties": {
                        "default": {"type": "string"}
                    }
                },
                "security": {
                    "type": "object",
                    "required": ["max_concurrent_sessions", "session_timeout", "enable_audit_log"]
                },
                "network": {
                    "type": "object",
                    "required": ["default_scan_timeout", "max_scan_threads"]
                },
                "logging": {
                    "type": "object",
                    "required": ["level", "file"]
                }
            }
        }
    
    def _extract_sensitive_data(self, config: dict) -> dict:
        """提取配置中的敏感数据"""
        sensitive_data = {}
        self._extract_sensitive_recursive(config, "", sensitive_data)
        return sensitive_data
    
    def _extract_sensitive_recursive(self, data: dict, path_prefix: str, result: dict) -> None:
        """递归提取敏感数据"""
        for key, value in data.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key
            
            if isinstance(value, dict):
                self._extract_sensitive_recursive(value, current_path, result)
            elif isinstance(value, str) and value and self.secure_config_manager.is_sensitive_field(current_path):
                result[current_path] = value
    
    def _update_sensitive_data(self, config: dict, sensitive_data: dict) -> dict:
        """更新配置中的敏感数据"""
        updated_config = config.copy()
        for path, encrypted_value in sensitive_data.items():
            self._set_nested_value(updated_config, path, encrypted_value)
        return updated_config
    
    def _set_nested_value(self, data: dict, path: str, value: str) -> None:
        """设置嵌套字典中的值"""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    async def enable_hot_reload(self) -> bool:
        """启用配置热重载"""
        try:
            if self._hot_reload_enabled:
                if self.logger:
                    self.logger.log_info("配置热重载已经启用")
                return True
            
            # 创建配置监控器
            self.config_watcher = ConfigWatcher(str(self.config_file), self.logger)
            
            # 添加重载回调
            self.config_watcher.add_callback(self._on_config_changed)
            
            # 启动监控器
            await self.config_watcher.initialize()
            await self.config_watcher.start()
            
            self._hot_reload_enabled = True
            
            if self.logger:
                self.logger.log_info("配置热重载已启用")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("启用配置热重载失败", e)
            return False
    
    async def disable_hot_reload(self) -> bool:
        """禁用配置热重载"""
        try:
            if not self._hot_reload_enabled:
                return True
            
            if self.config_watcher:
                await self.config_watcher.stop()
                self.config_watcher = None
            
            self._hot_reload_enabled = False
            
            if self.logger:
                self.logger.log_info("配置热重载已禁用")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("禁用配置热重载失败", e)
            return False
    
    def add_reload_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """添加配置重载回调函数"""
        if callback not in self._reload_callbacks:
            self._reload_callbacks.append(callback)
            if self.logger:
                self.logger.log_info(f"添加配置重载回调: {callback.__name__}")
    
    def remove_reload_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """移除配置重载回调函数"""
        if callback in self._reload_callbacks:
            self._reload_callbacks.remove(callback)
            if self.logger:
                self.logger.log_info(f"移除配置重载回调: {callback.__name__}")
    
    async def reload_config(self) -> bool:
        """手动重新加载配置"""
        try:
            if self.logger:
                self.logger.log_info("开始手动重新加载配置")
            
            # 加载新配置
            encrypted_config = self.load_config(str(self.config_file))
            new_config = self.secure_config_manager.decrypt_sensitive_config(encrypted_config)
            
            # 更新缓存
            old_config = self._config_cache.copy()
            self._config_cache = new_config
            
            # 通知回调函数
            await self._notify_reload_callbacks(new_config, old_config)
            
            if self.logger:
                self.logger.log_info("手动重新加载配置成功")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("手动重新加载配置失败", e)
            return False
    
    def is_hot_reload_enabled(self) -> bool:
        """检查热重载是否启用"""
        return self._hot_reload_enabled
    
    def set_hot_reload_interval(self, interval: float) -> None:
        """设置热重载检查间隔"""
        if self.config_watcher:
            self.config_watcher.set_check_interval(interval)
            if self.logger:
                self.logger.log_info(f"热重载检查间隔设置为: {interval}秒")
    
    async def _on_config_changed(self, new_encrypted_config: Dict[str, Any]) -> None:
        """配置文件变更回调"""
        try:
            if self.logger:
                self.logger.log_info("检测到配置文件变更，开始重新加载")
            
            # 解密新配置
            new_config = self.secure_config_manager.decrypt_sensitive_config(new_encrypted_config)
            
            # 验证新配置
            if not self.validate_config(new_config):
                if self.logger:
                    errors = self.get_validation_errors()
                    self.logger.log_error(f"新配置验证失败，保持原配置: {errors}")
                return
            
            # 保存旧配置
            old_config = self._config_cache.copy()
            
            # 更新配置缓存
            self._config_cache = new_config
            
            # 通知所有回调函数
            await self._notify_reload_callbacks(new_config, old_config)
            
            if self.logger:
                self.logger.log_info("配置热重载成功")
                
        except Exception as e:
            if self.logger:
                self.logger.log_error("配置热重载失败", e)
    
    async def _notify_reload_callbacks(self, new_config: Dict[str, Any], old_config: Dict[str, Any]) -> None:
        """通知所有重载回调函数"""
        for callback in self._reload_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(new_config)
                else:
                    callback(new_config)
            except Exception as e:
                if self.logger:
                    self.logger.log_error(f"配置重载回调执行失败: {callback.__name__}", e)