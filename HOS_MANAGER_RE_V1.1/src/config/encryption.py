"""
加密模块 - 处理敏感数据的加密和解密
"""

import os
import base64
import hashlib
from typing import Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.core.exceptions import SecurityError


class EncryptionManager:
    """加密管理器"""
    
    def __init__(self, master_key: Optional[str] = None):
        self._master_key = master_key
        self._fernet = None
        self._salt = None
        self._initialize_encryption()
    
    def _initialize_encryption(self) -> None:
        """初始化加密系统"""
        try:
            if self._master_key is None:
                # 如果没有提供主密钥，尝试从环境变量获取
                self._master_key = os.environ.get('CYBERSEC_MASTER_KEY')
                
                if self._master_key is None:
                    # 生成新的主密钥
                    self._master_key = self._generate_master_key()
            
            # 生成或获取盐值
            self._salt = self._get_or_create_salt()
            
            # 创建Fernet实例
            self._fernet = self._create_fernet_instance()
            
        except Exception as e:
            raise SecurityError(f"初始化加密系统失败: {str(e)}")
    
    def encrypt_data(self, data: Union[str, bytes]) -> str:
        """加密数据"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            if self._fernet is None:
                raise SecurityError("加密系统未初始化")
            
            encrypted_data = self._fernet.encrypt(data)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            raise SecurityError(f"数据加密失败: {str(e)}")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """解密数据"""
        try:
            if self._fernet is None:
                raise SecurityError("加密系统未初始化")
            
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self._fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise SecurityError(f"数据解密失败: {str(e)}")
    
    def encrypt_api_key(self, api_key: str, provider: str) -> str:
        """加密API密钥"""
        if not api_key or not api_key.strip():
            return ""
        
        try:
            # 添加提供商标识以增强安全性
            prefixed_key = f"{provider}:{api_key}"
            return self.encrypt_data(prefixed_key)
            
        except Exception as e:
            raise SecurityError(f"API密钥加密失败: {str(e)}")
    
    def decrypt_api_key(self, encrypted_key: str, provider: str) -> str:
        """解密API密钥"""
        if not encrypted_key or not encrypted_key.strip():
            return ""
        
        try:
            decrypted_data = self.decrypt_data(encrypted_key)
            
            # 验证提供商标识
            if not decrypted_data.startswith(f"{provider}:"):
                raise SecurityError("API密钥提供商标识不匹配")
            
            return decrypted_data[len(f"{provider}:"):]
            
        except Exception as e:
            raise SecurityError(f"API密钥解密失败: {str(e)}")
    
    def validate_encrypted_data(self, encrypted_data: str) -> bool:
        """验证加密数据的有效性"""
        try:
            if not encrypted_data or not encrypted_data.strip():
                return True  # 空数据被认为是有效的
            
            # 尝试解密来验证
            self.decrypt_data(encrypted_data)
            return True
            
        except Exception:
            return False
    
    def change_master_key(self, new_master_key: str, old_encrypted_data: dict) -> dict:
        """更改主密钥并重新加密所有数据"""
        try:
            # 使用旧密钥解密所有数据
            decrypted_data = {}
            for key, encrypted_value in old_encrypted_data.items():
                if encrypted_value:
                    decrypted_data[key] = self.decrypt_data(encrypted_value)
                else:
                    decrypted_data[key] = ""
            
            # 更新主密钥
            self._master_key = new_master_key
            self._initialize_encryption()
            
            # 使用新密钥重新加密所有数据
            re_encrypted_data = {}
            for key, decrypted_value in decrypted_data.items():
                if decrypted_value:
                    re_encrypted_data[key] = self.encrypt_data(decrypted_value)
                else:
                    re_encrypted_data[key] = ""
            
            return re_encrypted_data
            
        except Exception as e:
            raise SecurityError(f"更改主密钥失败: {str(e)}")
    
    def get_master_key(self) -> str:
        """获取主密钥（用于备份）"""
        return self._master_key
    
    def _generate_master_key(self) -> str:
        """生成新的主密钥"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    
    def _get_or_create_salt(self) -> bytes:
        """获取或创建盐值"""
        salt_file = "config/.salt"
        
        try:
            # 尝试从文件读取盐值
            if os.path.exists(salt_file):
                with open(salt_file, 'rb') as f:
                    return f.read()
            else:
                # 生成新的盐值
                salt = os.urandom(16)
                os.makedirs(os.path.dirname(salt_file), exist_ok=True)
                with open(salt_file, 'wb') as f:
                    f.write(salt)
                return salt
                
        except Exception as e:
            # 如果文件操作失败，使用基于主密钥的固定盐值
            return hashlib.sha256(self._master_key.encode()).digest()[:16]
    
    def _create_fernet_instance(self) -> Fernet:
        """创建Fernet加密实例"""
        try:
            # 使用PBKDF2从主密钥派生加密密钥
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self._master_key.encode()))
            return Fernet(key)
            
        except Exception as e:
            raise SecurityError(f"创建加密实例失败: {str(e)}")


class SecureConfigManager:
    """安全配置管理器 - 处理敏感配置数据的加密存储"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
        self._sensitive_fields = {
            "ai_providers.*.api_key",
            "security.encryption_key",
            "database.password",
            "*.password",
            "*.secret",
            "*.token"
        }
    
    def encrypt_sensitive_config(self, config: dict) -> dict:
        """加密配置中的敏感字段"""
        encrypted_config = self._deep_copy_dict(config)
        self._encrypt_dict_recursive(encrypted_config, "")
        return encrypted_config
    
    def decrypt_sensitive_config(self, encrypted_config: dict) -> dict:
        """解密配置中的敏感字段"""
        decrypted_config = self._deep_copy_dict(encrypted_config)
        self._decrypt_dict_recursive(decrypted_config, "")
        return decrypted_config
    
    def is_sensitive_field(self, field_path: str) -> bool:
        """判断字段是否为敏感字段"""
        for pattern in self._sensitive_fields:
            if self._match_pattern(field_path, pattern):
                return True
        return False
    
    def add_sensitive_field_pattern(self, pattern: str) -> None:
        """添加敏感字段模式"""
        self._sensitive_fields.add(pattern)
    
    def remove_sensitive_field_pattern(self, pattern: str) -> None:
        """移除敏感字段模式"""
        self._sensitive_fields.discard(pattern)
    
    def _encrypt_dict_recursive(self, data: dict, path_prefix: str) -> None:
        """递归加密字典中的敏感字段"""
        for key, value in data.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key
            
            if isinstance(value, dict):
                self._encrypt_dict_recursive(value, current_path)
            elif isinstance(value, str) and value and self.is_sensitive_field(current_path):
                try:
                    # 特殊处理API密钥
                    if "api_key" in key.lower():
                        provider = self._extract_provider_from_path(current_path)
                        data[key] = self.encryption_manager.encrypt_api_key(value, provider)
                    else:
                        data[key] = self.encryption_manager.encrypt_data(value)
                except Exception:
                    # 如果加密失败，保持原值（可能已经是加密的）
                    pass
    
    def _decrypt_dict_recursive(self, data: dict, path_prefix: str) -> None:
        """递归解密字典中的敏感字段"""
        for key, value in data.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key
            
            if isinstance(value, dict):
                self._decrypt_dict_recursive(value, current_path)
            elif isinstance(value, str) and value and self.is_sensitive_field(current_path):
                try:
                    # 特殊处理API密钥
                    if "api_key" in key.lower():
                        provider = self._extract_provider_from_path(current_path)
                        data[key] = self.encryption_manager.decrypt_api_key(value, provider)
                    else:
                        data[key] = self.encryption_manager.decrypt_data(value)
                except Exception:
                    # 如果解密失败，保持原值（可能是明文）
                    pass
    
    def _match_pattern(self, field_path: str, pattern: str) -> bool:
        """匹配字段路径和模式"""
        # 简单的通配符匹配
        pattern_parts = pattern.split('.')
        path_parts = field_path.split('.')
        
        # 如果模式长度不同，检查是否有通配符
        if len(pattern_parts) != len(path_parts):
            # 检查是否有完全匹配的情况
            if pattern == field_path:
                return True
            return False
        
        for pattern_part, path_part in zip(pattern_parts, path_parts):
            if pattern_part != '*' and pattern_part != path_part:
                return False
        
        return True
    
    def _extract_provider_from_path(self, path: str) -> str:
        """从路径中提取AI提供商名称"""
        parts = path.split('.')
        if len(parts) >= 2 and parts[0] == "ai_providers":
            return parts[1]
        return "unknown"
    
    def _deep_copy_dict(self, data: dict) -> dict:
        """深拷贝字典"""
        import copy
        return copy.deepcopy(data)