"""
AI网络安全平台主程序入口
"""

import asyncio
import sys
import os
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from core.interfaces import ILogger
from core.exceptions import CybersecurityPlatformError
from security.terms_service import TermsOfService
from security.security_warnings import SecurityWarnings


class SimpleLogger:
    """简单的日志实现（临时使用）"""
    
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


async def main():
    """主程序入口"""
    logger = SimpleLogger()
    
    try:
        logger.log_info("AI网络安全平台启动中...")
        
        # 初始化安全模块
        terms_service = TermsOfService()
        security_warnings = SecurityWarnings()
        
        # 检查并要求用户接受使用条款
        if not terms_service.prompt_acceptance():
            logger.log_info("用户拒绝使用条款，系统退出")
            return
        
        # 检查配置文件
        config_path = Path("config/config.json")
        if not config_path.exists():
            logger.log_warning("配置文件不存在，请复制config_template.json并重命名为config.json")
            return
        
        # 显示欢迎信息
        print("\n" + "="*60)
        print("🤖 AI网络安全平台 v1.0.0")
        print("="*60)
        print("⚠️  重要提醒：本工具仅用于授权的安全测试和教育目的")
        print("   请确保在合法合规的环境中使用")
        print("="*60)
        
        # 显示功能菜单
        print("\n可用功能模块：")
        print("1. 🤖 AI助手集成 - 多提供商AI服务")
        print("2. ⚔️  攻击模拟器 - 网络安全测试")
        print("3. 🛡️  防御系统 - 威胁监控检测")
        print("4. 🏆 CTF解题器 - 自动化解题")
        print("5. ⚙️  配置管理 - 系统设置")
        print("6. 📊 系统状态 - 运行监控")
        print("0. 退出系统")
        
        while True:
            try:
                choice = input("\n请选择功能模块 (0-6): ").strip()
                
                if choice == "0":
                    logger.log_info("用户选择退出系统")
                    break
                elif choice == "1":
                    print("🤖 AI助手集成模块 - 开发中...")
                elif choice == "2":
                    print("⚔️ 攻击模拟器模块 - 开发中...")
                elif choice == "3":
                    print("🛡️ 防御系统模块 - 开发中...")
                elif choice == "4":
                    print("🏆 CTF解题器模块 - 开发中...")
                elif choice == "5":
                    print("⚙️ 配置管理模块 - 开发中...")
                elif choice == "6":
                    print("📊 系统状态模块 - 开发中...")
                else:
                    print("❌ 无效选择，请输入0-6之间的数字")
                    
            except KeyboardInterrupt:
                logger.log_info("用户中断操作")
                break
            except Exception as e:
                logger.log_error("处理用户输入时发生错误", e)
        
        print("\n👋 感谢使用AI网络安全平台！")
        logger.log_info("AI网络安全平台正常退出")
        
    except CybersecurityPlatformError as e:
        logger.log_error(f"平台错误: {e.message}", e)
        sys.exit(1)
    except Exception as e:
        logger.log_error("未预期的错误", e)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())