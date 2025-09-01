"""
加密模块测试
"""

import pytest
import tempfile
import os
from unittest.mock import patch

from src.config.encryption import EncryptionManager, SecureConfigManager
from src.core.exceptions import SecurityError


class TestEncryptionManager:
    """测试加密管理器"""
    
    def setup_method(self):
        """测试前准备"""
        self.test_key = "test_master_key_12345"
        self.manager = EncryptionManager(self.test_key)
    
    def test_encrypt_decrypt_data(self):
        """测试数据加密解密"""
        test_data = "这是测试数据"
        
        encrypted = self.manager.encrypt_data(test_data)
        assert encrypted != test_data
        assert len(encrypted) > 0
        
        decrypted = self.manager.decrypt_data(encrypted)
        assert decrypted == test_data
    
    def test_encrypt_decrypt_bytes(self):
        """测试字节数据加密解密"""
        test_data = b"binary test data"
        
        encrypted = self.manager.encrypt_data(test_data)
        decrypted = self.manager.decrypt_data(encrypted)
        
        assert decrypted == test_data.decode('utf-8')
    
    def test_encrypt_api_key(self):
        """测试API密钥加密"""
        api_key = "sk-1234567890abcdef"
        provider = "openai"
        
        encrypted = self.manager.encrypt_api_key(api_key, provider)
        assert encrypted != api_key
        
        decrypted = self.manager.decrypt_api_key(encrypted, provider)
        assert decrypted == api_key
    
    def test_encrypt_empty_api_key(self):
        """测试空API密钥加密"""
        encrypted = self.manager.encrypt_api_key("", "openai")
        assert encrypted == ""
        
        decrypted = self.manager.decrypt_api_key("", "openai")
        assert decrypted == ""
    
    def test_decrypt_api_key_wrong_provider(self):
        """测试使用错误提供商解密API密钥"""
        api_key = "sk-1234567890abcdef"
        encrypted = self.manager.encrypt_api_key(api_key, "openai")
        
        with pytest.raises(SecurityError):
            self.manager.decrypt_api_key(encrypted, "deepseek")
    
    def test_validate_encrypted_data(self):
        """测试验证加密数据"""
        test_data = "test data"
        encrypted = self.manager.encrypt_data(test_data)
        
        assert self.manager.validate_encrypted_data(encrypted) is True
        assert self.manager.validate_encrypted_data("invalid_data") is False
        assert self.manager.validate_encrypted_data("") is True
    
    def test_change_master_key(self):
        """测试更改主密钥"""
        # 准备测试数据
        test_data = {
            "key1": self.manager.encrypt_data("value1"),
            "key2": self.manager.encrypt_data("value2"),
            "key3": ""  # 空值
        }
        
        new_key = "new_master_key_67890"
        re_encrypted = self.manager.change_master_key(new_key, test_data)
        
        # 验证数据可以用新密钥解密
        new_manager = EncryptionManager(new_key)
        assert new_manager.decrypt_data(re_encrypted["key1"]) == "value1"
        assert new_manager.decrypt_data(re_encrypted["key2"]) == "value2"
        assert re_encrypted["key3"] == ""
    
    def test_get_master_key(self):
        """测试获取主密钥"""
        key = self.manager.get_master_key()
        assert key == self.test_key
    
    def test_initialization_without_key(self):
        """测试无主密钥初始化"""
        with patch.dict(os.environ, {}, clear=True):
            manager = EncryptionManager()
            # 应该生成新的主密钥
            assert manager.get_master_key() is not None
            assert len(manager.get_master_key()) > 0
    
    def test_initialization_with_env_key(self):
        """测试从环境变量初始化"""
        env_key = "env_master_key_test"
        with patch.dict(os.environ, {'CYBERSEC_MASTER_KEY': env_key}):
            manager = EncryptionManager()
            assert manager.get_master_key() == env_key


class TestSecureConfigManager:
    """测试安全配置管理器"""
    
    def setup_method(self):
        """测试前准备"""
        self.encryption_manager = EncryptionManager("test_key")
        self.secure_manager = SecureConfigManager(self.encryption_manager)
    
    def test_is_sensitive_field(self):
        """测试敏感字段识别"""
        assert self.secure_manager.is_sensitive_field("ai_providers.openai.api_key") is True
        assert self.secure_manager.is_sensitive_field("security.encryption_key") is True
        assert self.secure_manager.is_sensitive_field("database.password") is True
        assert self.secure_manager.is_sensitive_field("normal.field") is False
    
    def test_encrypt_sensitive_config(self):
        """测试加密敏感配置"""
        config = {
            "ai_providers": {
                "openai": {
                    "api_key": "sk-test123",
                    "model": "gpt-4"
                }
            },
            "security": {
                "encryption_key": "secret123"
            },
            "normal_field": "normal_value"
        }
        
        encrypted_config = self.secure_manager.encrypt_sensitive_config(config)
        
        # 敏感字段应该被加密
        assert encrypted_config["ai_providers"]["openai"]["api_key"] != "sk-test123"
        assert encrypted_config["security"]["encryption_key"] != "secret123"
        
        # 普通字段应该保持不变
        assert encrypted_config["ai_providers"]["openai"]["model"] == "gpt-4"
        assert encrypted_config["normal_field"] == "normal_value"
    
    def test_decrypt_sensitive_config(self):
        """测试解密敏感配置"""
        config = {
            "ai_providers": {
                "openai": {
                    "api_key": "sk-test123",
                    "model": "gpt-4"
                }
            },
            "security": {
                "encryption_key": "secret123"
            }
        }
        
        # 先加密
        encrypted_config = self.secure_manager.encrypt_sensitive_config(config)
        
        # 再解密
        decrypted_config = self.secure_manager.decrypt_sensitive_config(encrypted_config)
        
        # 验证解密结果
        assert decrypted_config["ai_providers"]["openai"]["api_key"] == "sk-test123"
        assert decrypted_config["security"]["encryption_key"] == "secret123"
        assert decrypted_config["ai_providers"]["openai"]["model"] == "gpt-4"
    
    def test_add_remove_sensitive_pattern(self):
        """测试添加和移除敏感字段模式"""
        # 测试一个不会被现有模式匹配的字段
        test_field = "custom.unique_field"
        
        # 确认初始状态不是敏感字段
        assert self.secure_manager.is_sensitive_field(test_field) is False
        
        # 添加新模式
        self.secure_manager.add_sensitive_field_pattern(test_field)
        assert self.secure_manager.is_sensitive_field(test_field) is True
        
        # 移除模式
        self.secure_manager.remove_sensitive_field_pattern(test_field)
        assert self.secure_manager.is_sensitive_field(test_field) is False
    
    def test_encrypt_empty_values(self):
        """测试加密空值"""
        config = {
            "ai_providers": {
                "openai": {
                    "api_key": "",  # 空字符串
                    "model": "gpt-4"
                }
            }
        }
        
        encrypted_config = self.secure_manager.encrypt_sensitive_config(config)
        decrypted_config = self.secure_manager.decrypt_sensitive_config(encrypted_config)
        
        # 空值应该保持为空
        assert encrypted_config["ai_providers"]["openai"]["api_key"] == ""
        assert decrypted_config["ai_providers"]["openai"]["api_key"] == ""


if __name__ == "__main__":
    pytest.main([__file__])