"""
配置监控和验证器测试
"""

import pytest
import json
import tempfile
import shutil
import asyncio
from pathlib import Path
from unittest.mock import Mock

from src.config.watcher import ConfigWatcher, ConfigValidator
from src.core.exceptions import ConfigurationError


class TestConfigWatcher:
    """测试配置监控器"""
    
    def setup_method(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "test_config.json"
        
        # 创建测试配置文件
        self.test_config = {
            "ai_providers": {
                "default": "deepseek",
                "deepseek": {"api_key": "test_key"}
            },
            "security": {
                "max_concurrent_sessions": 5,
                "session_timeout": 3600,
                "enable_audit_log": True
            },
            "network": {
                "default_scan_timeout": 30,
                "max_scan_threads": 10
            },
            "logging": {
                "level": "INFO",
                "file": "test.log"
            }
        }
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.test_config, f, indent=2)
        
        self.logger = Mock()
        self.watcher = ConfigWatcher(str(self.config_file), self.logger)
    
    def teardown_method(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """测试初始化"""
        await self.watcher.initialize()
        assert self.watcher._is_initialized is True
        assert self.watcher.last_modified is not None
    
    @pytest.mark.asyncio
    async def test_initialization_nonexistent_file(self):
        """测试初始化不存在的文件"""
        nonexistent_file = Path(self.temp_dir) / "nonexistent.json"
        watcher = ConfigWatcher(str(nonexistent_file), self.logger)
        
        with pytest.raises(ConfigurationError):
            await watcher.initialize()
    
    @pytest.mark.asyncio
    async def test_callback_management(self):
        """测试回调函数管理"""
        await self.watcher.initialize()
        
        callback1 = Mock()
        callback2 = Mock()
        
        # 添加回调
        self.watcher.add_callback(callback1)
        self.watcher.add_callback(callback2)
        assert len(self.watcher.callbacks) == 2
        
        # 重复添加不会增加
        self.watcher.add_callback(callback1)
        assert len(self.watcher.callbacks) == 2
        
        # 移除回调
        self.watcher.remove_callback(callback1)
        assert len(self.watcher.callbacks) == 1
        assert callback2 in self.watcher.callbacks
    
    @pytest.mark.asyncio
    async def test_force_reload(self):
        """测试强制重新加载"""
        await self.watcher.initialize()
        
        callback = Mock()
        self.watcher.add_callback(callback)
        
        # 强制重新加载
        result = await self.watcher.force_reload()
        assert result is True
        
        # 验证回调被调用
        callback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_set_check_interval(self):
        """测试设置检查间隔"""
        await self.watcher.initialize()
        
        original_interval = self.watcher.check_interval
        new_interval = 2.0
        
        self.watcher.set_check_interval(new_interval)
        assert self.watcher.check_interval == new_interval
        
        # 无效间隔不会被设置
        self.watcher.set_check_interval(-1)
        assert self.watcher.check_interval == new_interval


class TestConfigValidator:
    """测试配置验证器"""
    
    def setup_method(self):
        """测试前准备"""
        self.logger = Mock()
        self.validator = ConfigValidator(self.logger)
        
        self.valid_config = {
            "ai_providers": {
                "default": "deepseek",
                "deepseek": {"api_key": "test_key"}
            },
            "security": {
                "max_concurrent_sessions": 5,
                "session_timeout": 3600,
                "enable_audit_log": True
            },
            "network": {
                "default_scan_timeout": 30,
                "max_scan_threads": 10
            },
            "logging": {
                "level": "INFO",
                "file": "test.log"
            }
        }
    
    def test_validate_valid_config(self):
        """测试验证有效配置"""
        result = self.validator.validate_config(self.valid_config)
        assert result is True
        assert len(self.validator.get_validation_errors()) == 0
    
    def test_validate_missing_required_field(self):
        """测试验证缺少必需字段的配置"""
        invalid_config = self.valid_config.copy()
        del invalid_config["ai_providers"]
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert len(errors) > 0
        assert any("ai_providers" in error for error in errors)
    
    def test_validate_invalid_type(self):
        """测试验证无效类型的配置"""
        invalid_config = self.valid_config.copy()
        invalid_config["security"]["max_concurrent_sessions"] = "invalid"  # 应该是int
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert any("类型错误" in error for error in errors)
    
    def test_validate_out_of_range_value(self):
        """测试验证超出范围的值"""
        invalid_config = self.valid_config.copy()
        invalid_config["security"]["max_concurrent_sessions"] = 0  # 小于最小值1
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert any("过小" in error for error in errors)
    
    def test_validate_invalid_allowed_value(self):
        """测试验证不在允许值范围内的配置"""
        invalid_config = self.valid_config.copy()
        invalid_config["logging"]["level"] = "INVALID_LEVEL"
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert any("不在允许范围内" in error for error in errors)
    
    def test_validate_invalid_default_provider(self):
        """测试验证无效的默认AI提供商"""
        invalid_config = self.valid_config.copy()
        invalid_config["ai_providers"]["default"] = "invalid_provider"
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert any("默认AI提供商配置不存在" in error for error in errors)
    
    def test_validate_missing_default_provider_config(self):
        """测试验证缺少默认提供商配置"""
        invalid_config = self.valid_config.copy()
        invalid_config["ai_providers"]["default"] = "openai"
        # 但没有openai的配置
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert any("默认AI提供商配置不存在" in error for error in errors)
    
    def test_add_remove_validation_rule(self):
        """测试添加和移除验证规则"""
        # 添加自定义规则
        custom_rule = {
            "required": True,
            "type": str,
            "allowed_values": ["test1", "test2"]
        }
        
        self.validator.add_validation_rule("custom.field", custom_rule)
        assert "custom.field" in self.validator.validation_rules
        
        # 移除规则
        self.validator.remove_validation_rule("custom.field")
        assert "custom.field" not in self.validator.validation_rules
    
    def test_validate_network_config_conflict(self):
        """测试验证网络配置冲突"""
        invalid_config = self.valid_config.copy()
        invalid_config["network"]["allowed_networks"] = ["192.168.1.0/24"]
        invalid_config["network"]["blocked_networks"] = ["192.168.1.0/24"]  # 冲突
        
        result = self.validator.validate_config(invalid_config)
        assert result is False
        
        errors = self.validator.get_validation_errors()
        assert any("网络配置冲突" in error for error in errors)


if __name__ == "__main__":
    pytest.main([__file__])