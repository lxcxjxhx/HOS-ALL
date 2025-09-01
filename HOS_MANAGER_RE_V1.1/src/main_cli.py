"""
AI网络安全平台主程序入口 - 使用新的CLI框架
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
from ui.cli import CLIFramework
from ui.error_handler import ErrorHandler
from ui.progress import StatusDisplay


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


class CybersecurityPlatformCLI:
    """Main CLI application class."""
    
    def __init__(self):
        """Initialize the CLI application."""
        self.logger = SimpleLogger()
        self.error_handler = ErrorHandler()
        self.status_display = StatusDisplay()
        self.cli = CLIFramework(self.logger)
        
        # Initialize security components
        self.terms_service = TermsOfService()
        self.security_warnings = SecurityWarnings()
        
        # Register custom commands
        self._register_custom_commands()
    
    def _register_custom_commands(self):
        """Register custom commands with the CLI framework."""
        # Add custom commands here as modules are implemented
        pass
    
    async def initialize(self) -> bool:
        """
        Initialize the platform.
        
        Returns:
            True if initialization successful
        """
        try:
            self.logger.log_info("AI网络安全平台启动中...")
            
            # Check and require terms acceptance
            if not self.terms_service.prompt_acceptance():
                self.logger.log_info("用户拒绝使用条款，系统退出")
                return False
            
            # Check configuration file
            config_path = Path("config/config.json")
            if not config_path.exists():
                self.error_handler.display_error_message(
                    "CONFIG_NOT_FOUND", 
                    filename="config/config.json"
                )
                print("💡 请复制 config_template.json 并重命名为 config.json")
                return False
            
            self.logger.log_info("平台初始化完成")
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, "平台初始化")
            return False
    
    async def run(self):
        """Run the main application."""
        try:
            # Initialize platform
            if not await self.initialize():
                return
            
            # Start CLI interactive mode
            self.cli.run_interactive_mode()
            
        except KeyboardInterrupt:
            print("\n\n⚠️ 用户中断操作")
        except Exception as e:
            self.error_handler.handle_error(e, "主程序运行")
        finally:
            print("\n👋 感谢使用AI网络安全平台！")
            self.logger.log_info("AI网络安全平台正常退出")


async def main():
    """主程序入口"""
    try:
        app = CybersecurityPlatformCLI()
        await app.run()
    except CybersecurityPlatformError as e:
        print(f"❌ 平台错误: {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 未预期的错误: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())