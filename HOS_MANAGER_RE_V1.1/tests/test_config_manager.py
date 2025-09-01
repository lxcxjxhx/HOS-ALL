"""
配置管理器测试
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock

from src.config.manager import ConfigManager
from src.core.exceptions import ConfigurationError


class TestConfigManager:
    """测试配置管理器"""
    
    def setup_method(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.config_dir.mkdir()
        
        # 创建测试配置模板
        self.template_config = {
            "ai_providers": {
                "default": "deepseek",
                "deepseek": {
                    "api_key": "",
                    "base_url": "https://api.deepseek.com",
                    "model": "deepseek-chat"
                }
            },
            "security": {
                "encryption_key": "",
                "max_concurrent_sessions": 5,
                "session_timeout": 3600,
                "enable_audit_log": True
            },
            "network": {
                "default_scan_timeout": 30,
                "max_scan_threads": 10,
                "allowed_networks": [],
                "blocked_networks": ["127.0.0.0/8"]
            },
            "logging": {
                "level": "INFO",
                "file": "logs/cybersecurity_platform.log",
                "max_size": "10MB",
                "backup_count": 5
            }
        }
        
        # 创建模板文件
        template_file = self.config_dir / "config_template.json"
        with open(template_file, 'w', encoding='utf-8') as f:
            json.dump(self.template_config, f, indent=2)
        
        self.logger = Mock()
        self.manager = ConfigManager(str(self.config_dir), self.logger)
    
    def teardown_method(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """测试初始化"""
        await self.manager.initialize()
        
        assert self.manager._is_initialized is True
        assert (self.config_dir / "config.json").exists()
        assert (self.config_dir / "backups").exists()
    
    def test_load_config(self):
        """测试加载配置"""
        # 创建配置文件
        config_file = self.config_dir / "test_config.json"
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.template_config, f)
        
        config = self.manager.load_config(str(config_file))
        assert config == self.template_config
    
    def test_load_nonexistent_config(self):
        """测试加载不存在的配置文件"""
        with pytest.raises(ConfigurationError):
            self.manager.load_config("nonexistent.json")
    
    def test_load_invalid_json(self):
        """测试加载无效JSON配置"""
        config_file = self.config_dir / "invalid.json"
        with open(config_file, 'w') as f:
            f.write("invalid json content")
        
        with pytest.raises(ConfigurationError):
            self.manager.load_config(str(config_file))
    
    def test_save_config(self):
        """测试保存配置"""
        config_file = self.config_dir / "test_save.json"
        
        result = self.manager.save_config(self.template_config, str(config_file))
        assert result is True
        assert config_file.exists()
        
        # 验证保存的内容
        with open(config_file, 'r', encoding='utf-8') as f:
            saved_config = json.load(f)
        assert saved_config == self.template_config
    
    def test_validate_config_valid(self):
        """测试验证有效配置"""
        result = self.manager.validate_config(self.template_config)
        assert result is True
    
    def test_validate_config_missing_key(self):
        """测试验证缺少必需键的配置"""
        invalid_config = self.template_config.copy()
        del invalid_config["ai_providers"]
        
        result = self.manager.validate_config(invalid_config)
        assert result is False
    
    def test_validate_ai_providers_invalid_default(self):
        """测试验证无效的默认AI提供商"""
        invalid_config = self.template_config.copy()
        invalid_config["ai_providers"]["default"] = "nonexistent"
        
        result = self.manager.validate_config(invalid_config)
        assert result is False
    
    def test_validate_security_config_invalid_sessions(self):
        """测试验证无效的会话配置"""
        invalid_config = self.template_config.copy()
        invalid_config["security"]["max_concurrent_sessions"] = 0
        
        result = self.manager.validate_config(invalid_config)
        assert result is False
    
    def test_validate_network_config_invalid_timeout(self):
        """测试验证无效的网络超时配置"""
        invalid_config = self.template_config.copy()
        invalid_config["network"]["default_scan_timeout"] = 0
        
        result = self.manager.validate_config(invalid_config)
        assert result is False
    
    def test_validate_logging_config_invalid_level(self):
        """测试验证无效的日志级别"""
        invalid_config = self.template_config.copy()
        invalid_config["logging"]["level"] = "INVALID"
        
        result = self.manager.validate_config(invalid_config)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_config(self):
        """测试获取配置值"""
        await self.manager.initialize()
        
        # 获取整个配置
        full_config = self.manager.get_config()
        assert isinstance(full_config, dict)
        
        # 获取特定键
        default_provider = self.manager.get_config("ai_providers.default")
        assert default_provider == "deepseek"
        
        # 获取不存在的键
        nonexistent = self.manager.get_config("nonexistent.key", "default_value")
        assert nonexistent == "default_value"
    
    @pytest.mark.asyncio
    async def test_set_config(self):
        """测试设置配置值"""
        await self.manager.initialize()
        
        # 设置配置值
        result = self.manager.set_config("ai_providers.default", "openai")
        assert result is True
        
        # 验证设置成功
        value = self.manager.get_config("ai_providers.default")
        assert value == "openai"
    
    def test_create_setup_wizard(self):
        """测试创建设置向导"""
        wizard = self.manager.create_setup_wizard()
        
        assert isinstance(wizard, dict)
        assert "step1" in wizard
        assert "step2" in wizard
        assert "step3" in wizard
        
        # 验证步骤结构
        step1 = wizard["step1"]
        assert "title" in step1
        assert "description" in step1
        assert "fields" in step1
        assert isinstance(step1["fields"], list)
    
    def test_encrypt_decrypt_placeholder(self):
        """测试加密解密占位符实现"""
        test_data = "sensitive_data"
        
        encrypted = self.manager.encrypt_sensitive_data(test_data)
        decrypted = self.manager.decrypt_sensitive_data(encrypted)
        
        # 当前是占位符实现，应该返回原始数据
        assert encrypted == test_data
        assert decrypted == test_data


if __name__ == "__main__":
    pytest.main([__file__])