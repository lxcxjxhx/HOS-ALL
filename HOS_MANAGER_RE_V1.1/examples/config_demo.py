"""
配置管理系统演示
"""

import asyncio
import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.config.manager import ConfigManager
from src.core.exceptions import ConfigurationError, SecurityError


class SimpleLogger:
    """简单的日志实现"""
    
    def log_info(self, message: str, context: dict = None):
        print(f"[INFO] {message}")
        if context:
            print(f"       Context: {context}")
    
    def log_warning(self, message: str, context: dict = None):
        print(f"[WARNING] {message}")
        if context:
            print(f"          Context: {context}")
    
    def log_error(self, message: str, error: Exception = None, context: dict = None):
        print(f"[ERROR] {message}")
        if error:
            print(f"        Error: {str(error)}")
        if context:
            print(f"        Context: {context}")
    
    def log_security_event(self, event):
        print(f"[SECURITY] {event}")


async def demo_basic_config_operations():
    """演示基本配置操作"""
    print("\n=== 基本配置操作演示 ===")
    
    logger = SimpleLogger()
    manager = ConfigManager(logger=logger)
    
    try:
        # 初始化配置管理器
        await manager.initialize()
        print("✅ 配置管理器初始化成功")
        
        # 获取配置
        print("\n📖 读取配置:")
        default_provider = manager.get_config("ai_providers.default")
        print(f"   默认AI提供商: {default_provider}")
        
        max_sessions = manager.get_config("security.max_concurrent_sessions")
        print(f"   最大并发会话数: {max_sessions}")
        
        # 设置配置
        print("\n✏️  修改配置:")
        success = manager.set_config("security.max_concurrent_sessions", 10)
        if success:
            new_value = manager.get_config("security.max_concurrent_sessions")
            print(f"   ✅ 最大并发会话数已更新为: {new_value}")
        else:
            print("   ❌ 配置更新失败")
        
        # 获取完整配置
        print("\n📋 完整配置结构:")
        full_config = manager.get_config()
        for key in full_config.keys():
            print(f"   - {key}")
        
    except Exception as e:
        print(f"❌ 演示失败: {str(e)}")


async def demo_encryption_features():
    """演示加密功能"""
    print("\n=== 加密功能演示 ===")
    
    logger = SimpleLogger()
    manager = ConfigManager(logger=logger)
    
    try:
        await manager.initialize()
        
        # 演示敏感数据加密
        print("\n🔐 敏感数据加密:")
        sensitive_data = "sk-1234567890abcdef"
        encrypted = manager.encrypt_sensitive_data(sensitive_data)
        print(f"   原始数据: {sensitive_data}")
        print(f"   加密后: {encrypted[:20]}...")
        
        decrypted = manager.decrypt_sensitive_data(encrypted)
        print(f"   解密后: {decrypted}")
        print(f"   ✅ 加密解密{'成功' if decrypted == sensitive_data else '失败'}")
        
        # 演示API密钥加密
        print("\n🔑 API密钥加密:")
        api_key = "sk-test-api-key-12345"
        provider = "openai"
        
        encrypted_key = manager.encrypt_api_key(api_key, provider)
        print(f"   原始API密钥: {api_key}")
        print(f"   加密后: {encrypted_key[:20]}...")
        
        decrypted_key = manager.decrypt_api_key(encrypted_key, provider)
        print(f"   解密后: {decrypted_key}")
        print(f"   ✅ API密钥加密解密{'成功' if decrypted_key == api_key else '失败'}")
        
    except Exception as e:
        print(f"❌ 加密演示失败: {str(e)}")


async def demo_validation():
    """演示配置验证"""
    print("\n=== 配置验证演示 ===")
    
    logger = SimpleLogger()
    manager = ConfigManager(logger=logger)
    
    try:
        await manager.initialize()
        
        # 测试有效配置
        print("\n✅ 有效配置验证:")
        valid_config = manager.get_config()
        is_valid = manager.validate_config(valid_config)
        print(f"   当前配置验证结果: {'通过' if is_valid else '失败'}")
        
        # 测试无效配置
        print("\n❌ 无效配置验证:")
        invalid_config = valid_config.copy()
        invalid_config["security"]["max_concurrent_sessions"] = -1  # 无效值
        
        is_valid = manager.validate_config(invalid_config)
        print(f"   无效配置验证结果: {'通过' if is_valid else '失败'}")
        
        if not is_valid:
            errors = manager.get_validation_errors()
            print("   验证错误:")
            for error in errors:
                print(f"     - {error}")
        
    except Exception as e:
        print(f"❌ 验证演示失败: {str(e)}")


async def demo_setup_wizard():
    """演示设置向导"""
    print("\n=== 设置向导演示 ===")
    
    logger = SimpleLogger()
    manager = ConfigManager(logger=logger)
    
    try:
        await manager.initialize()
        
        wizard = manager.create_setup_wizard()
        print("\n🧙 配置设置向导:")
        
        for step_id, step_info in wizard.items():
            print(f"\n   {step_info['title']}:")
            print(f"   {step_info['description']}")
            
            for field in step_info['fields']:
                field_type = field.get('type', 'text')
                required = '(必需)' if field.get('required', False) else '(可选)'
                print(f"     - {field['label']} [{field_type}] {required}")
                
                if 'options' in field:
                    print(f"       选项: {', '.join(field['options'])}")
                
                if 'default' in field:
                    print(f"       默认值: {field['default']}")
        
    except Exception as e:
        print(f"❌ 设置向导演示失败: {str(e)}")


async def main():
    """主演示函数"""
    print("🤖 AI网络安全平台 - 配置管理系统演示")
    print("=" * 50)
    
    try:
        await demo_basic_config_operations()
        await demo_encryption_features()
        await demo_validation()
        await demo_setup_wizard()
        
        print("\n" + "=" * 50)
        print("✅ 所有演示完成！配置管理系统功能正常")
        
    except Exception as e:
        print(f"\n❌ 演示过程中发生错误: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())