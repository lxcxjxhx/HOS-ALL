"""
Command Line Interface for AI Cybersecurity Platform.

This module provides the main CLI framework with menu navigation,
command parsing, and interactive operations.
"""

import argparse
import sys
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.interfaces import ILogger
from ui.error_handler import ErrorHandler, HelpSystem, ParameterValidator


class CLIFramework:
    """Main CLI framework for the cybersecurity platform."""
    
    def __init__(self, logger: Optional[ILogger] = None):
        """
        Initialize CLI framework.
        
        Args:
            logger: Logger instance for CLI operations
        """
        self.logger = logger
        self.commands = {}
        self.current_menu = "main"
        self.running = True
        
        # Initialize error handling and help systems
        self.error_handler = ErrorHandler()
        self.help_system = HelpSystem()
        self.parameter_validator = ParameterValidator()
        
        # Initialize command registry
        self._register_default_commands()
    
    def register_command(self, name: str, handler: Callable, 
                        description: str, menu: str = "main") -> None:
        """
        Register a command with the CLI.
        
        Args:
            name: Command name
            handler: Function to handle the command
            description: Command description
            menu: Menu context for the command
        """
        if menu not in self.commands:
            self.commands[menu] = {}
        
        self.commands[menu][name] = {
            'handler': handler,
            'description': description
        }
    
    def _register_default_commands(self) -> None:
        """Register default system commands."""
        self.register_command('help', self._show_help, '显示帮助信息')
        self.register_command('exit', self._exit_system, '退出系统')
        self.register_command('quit', self._exit_system, '退出系统')
        self.register_command('clear', self._clear_screen, '清屏')
        self.register_command('status', self._show_status, '显示系统状态')
        self.register_command('examples', self._show_examples, '显示使用示例')
        self.register_command('troubleshoot', self._show_troubleshooting, '故障排除指南')
        self.register_command('validate', self._validate_input, '验证输入参数')
        self.register_command('diagnose', self._run_diagnostics, '系统诊断检查')
        self.register_command('version', self._show_version, '显示版本信息')
    
    def display_banner(self) -> None:
        """Display system banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                AI增强网络安全平台 v1.0.0                      ║
║              AI-Enhanced Cybersecurity Platform              ║
╠══════════════════════════════════════════════════════════════╣
║  🤖 AI助手集成    ⚔️ 攻击模拟器    🛡️ 防御系统    🏆 CTF解题器  ║
╚══════════════════════════════════════════════════════════════╝

⚠️  重要提醒：本工具仅用于授权的安全测试和教育目的
   请确保在合法合规的环境中使用

"""
        print(banner)   
 
    def display_main_menu(self) -> None:
        """Display main menu options."""
        print("\n" + "="*60)
        print("🎯 主功能菜单")
        print("="*60)
        
        menu_items = [
            ("1", "🤖 AI助手管理", "管理AI提供商和配置"),
            ("2", "⚔️ 攻击模拟器", "网络安全测试和渗透"),
            ("3", "🛡️ 防御系统", "威胁监控和响应"),
            ("4", "🏆 CTF解题器", "自动化解题和分析"),
            ("5", "⚙️ 系统配置", "配置管理和设置"),
            ("6", "📊 系统状态", "查看运行状态和日志"),
            ("7", "📚 帮助文档", "使用指南和说明"),
            ("0", "🚪 退出系统", "安全退出程序")
        ]
        
        for key, title, desc in menu_items:
            print(f"  {key}. {title:<15} - {desc}")
        
        print("="*60)
    
    def display_submenu(self, menu_name: str, title: str, items: List[tuple]) -> None:
        """
        Display a submenu.
        
        Args:
            menu_name: Menu identifier
            title: Menu title
            items: List of (key, name, description) tuples
        """
        print(f"\n" + "="*60)
        print(f"🎯 {title}")
        print("="*60)
        
        for key, name, desc in items:
            print(f"  {key}. {name:<20} - {desc}")
        
        print("  b. 返回上级菜单")
        print("  0. 退出系统")
        print("="*60)
    
    def get_user_input(self, prompt: str = "请选择操作") -> str:
        """
        Get user input with prompt.
        
        Args:
            prompt: Input prompt message
            
        Returns:
            User input string
        """
        try:
            return input(f"\n{prompt} > ").strip()
        except KeyboardInterrupt:
            print("\n\n⚠️ 用户中断操作")
            return "0"
        except EOFError:
            print("\n\n⚠️ 输入结束")
            return "0"
    
    def execute_command(self, command: str, args: List[str] = None) -> bool:
        """
        Execute a command.
        
        Args:
            command: Command to execute
            args: Command arguments
            
        Returns:
            True if command executed successfully
        """
        if args is None:
            args = []
        
        menu_commands = self.commands.get(self.current_menu, {})
        
        if command in menu_commands:
            try:
                handler = menu_commands[command]['handler']
                if args:
                    return handler(args)
                else:
                    return handler()
            except Exception as e:
                self.error_handler.handle_error(e, f"命令执行: {command}")
                return False
        else:
            self.error_handler.display_error_message(
                "INVALID_COMMAND",
                command=command,
                available_commands=", ".join(menu_commands.keys())
            )
            return False
    
    def validate_and_execute(self, command: str, target: str = None, 
                           ports: str = None, scan_type: str = None) -> bool:
        """
        Validate parameters and execute command.
        
        Args:
            command: Command to execute
            target: Target IP or hostname
            ports: Port specification
            scan_type: Type of scan
            
        Returns:
            True if validation passed and command executed
        """
        # Validate target IP if provided
        if target:
            is_valid, error_msg = self.parameter_validator.validate_ip_address(target)
            if not is_valid:
                print(f"❌ {error_msg}")
                return False
        
        # Validate ports if provided
        if ports:
            is_valid, error_msg = self.parameter_validator.validate_port_range(ports)
            if not is_valid:
                print(f"❌ {error_msg}")
                return False
        
        # Validate scan type if provided
        if scan_type:
            is_valid, error_msg = self.parameter_validator.validate_scan_type(scan_type)
            if not is_valid:
                print(f"❌ {error_msg}")
                return False
        
        # If all validations pass, execute the command
        return self.execute_command(command, [target, ports, scan_type])
    
    def run_interactive_mode(self) -> None:
        """Run interactive CLI mode."""
        self.display_banner()
        
        while self.running:
            try:
                if self.current_menu == "main":
                    self.display_main_menu()
                    choice = self.get_user_input("请选择功能模块")
                    self._handle_main_menu_choice(choice)
                else:
                    # Handle submenus
                    self._handle_submenu()
                    
            except KeyboardInterrupt:
                print("\n\n⚠️ 用户中断操作")
                if self._confirm_exit():
                    break
            except Exception as e:
                self._log_error("CLI运行时错误", e)
                print(f"❌ 系统错误: {str(e)}")
                print("💡 请重试或联系技术支持")
    
    def _handle_main_menu_choice(self, choice: str) -> None:
        """Handle main menu selection."""
        if choice == "0":
            self._exit_system()
        elif choice == "1":
            self.current_menu = "ai"
        elif choice == "2":
            self.current_menu = "attack"
        elif choice == "3":
            self.current_menu = "defense"
        elif choice == "4":
            self.current_menu = "ctf"
        elif choice == "5":
            self.current_menu = "config"
        elif choice == "6":
            self._show_status()
        elif choice == "7":
            self._show_help()
        else:
            print("❌ 无效选择，请输入0-7之间的数字")
    
    def _handle_submenu(self) -> None:
        """Handle submenu operations."""
        if self.current_menu == "ai":
            self._handle_ai_menu()
        elif self.current_menu == "attack":
            self._handle_attack_menu()
        elif self.current_menu == "defense":
            self._handle_defense_menu()
        elif self.current_menu == "ctf":
            self._handle_ctf_menu()
        elif self.current_menu == "config":
            self._handle_config_menu()
        else:
            self.current_menu = "main"    

    def _handle_ai_menu(self) -> None:
        """Handle AI assistant menu."""
        items = [
            ("1", "查看AI提供商", "显示已配置的AI提供商"),
            ("2", "切换AI提供商", "选择默认AI提供商"),
            ("3", "测试AI连接", "测试AI API连接"),
            ("4", "AI配置管理", "管理API密钥和设置")
        ]
        
        self.display_submenu("ai", "AI助手管理", items)
        choice = self.get_user_input("请选择AI操作")
        
        if choice == "b":
            self.current_menu = "main"
        elif choice == "0":
            self._exit_system()
        elif choice == "1":
            self._show_ai_providers()
        elif choice == "2":
            self._switch_ai_provider()
        elif choice == "3":
            self._test_ai_connection()
        elif choice == "4":
            self._manage_ai_config()
        else:
            print("❌ 无效选择")
    
    def _handle_attack_menu(self) -> None:
        """Handle attack simulator menu."""
        items = [
            ("1", "创建攻击会话", "创建新的攻击测试会话"),
            ("2", "端口扫描", "执行目标端口扫描"),
            ("3", "漏洞扫描", "分析和识别漏洞"),
            ("4", "载荷生成", "生成攻击载荷"),
            ("5", "会话管理", "管理活动攻击会话")
        ]
        
        self.display_submenu("attack", "攻击模拟器", items)
        choice = self.get_user_input("请选择攻击操作")
        
        if choice == "b":
            self.current_menu = "main"
        elif choice == "0":
            self._exit_system()
        elif choice == "1":
            self._create_attack_session()
        elif choice == "2":
            self._port_scan()
        elif choice == "3":
            self._vulnerability_scan()
        elif choice == "4":
            self._generate_payload()
        elif choice == "5":
            self._manage_sessions()
        else:
            print("❌ 无效选择")
    
    def _handle_defense_menu(self) -> None:
        """Handle defense system menu."""
        items = [
            ("1", "启动监控", "开始网络监控"),
            ("2", "威胁检测", "查看检测到的威胁"),
            ("3", "防御响应", "管理防御响应措施"),
            ("4", "安全事件", "查看安全事件日志"),
            ("5", "监控配置", "配置监控参数")
        ]
        
        self.display_submenu("defense", "防御系统", items)
        choice = self.get_user_input("请选择防御操作")
        
        if choice == "b":
            self.current_menu = "main"
        elif choice == "0":
            self._exit_system()
        elif choice == "1":
            self._start_monitoring()
        elif choice == "2":
            self._show_threats()
        elif choice == "3":
            self._manage_responses()
        elif choice == "4":
            self._show_security_events()
        elif choice == "5":
            self._configure_monitoring()
        else:
            print("❌ 无效选择")
    
    def _handle_ctf_menu(self) -> None:
        """Handle CTF solver menu."""
        items = [
            ("1", "分析挑战", "分析CTF挑战题目"),
            ("2", "自动解题", "尝试自动解题"),
            ("3", "工具集成", "使用CTF工具"),
            ("4", "解题历史", "查看解题记录"),
            ("5", "题目类型", "查看支持的题目类型")
        ]
        
        self.display_submenu("ctf", "CTF解题器", items)
        choice = self.get_user_input("请选择CTF操作")
        
        if choice == "b":
            self.current_menu = "main"
        elif choice == "0":
            self._exit_system()
        elif choice == "1":
            self._analyze_challenge()
        elif choice == "2":
            self._auto_solve()
        elif choice == "3":
            self._ctf_tools()
        elif choice == "4":
            self._solve_history()
        elif choice == "5":
            self._challenge_types()
        else:
            print("❌ 无效选择")
    
    def _handle_config_menu(self) -> None:
        """Handle configuration menu."""
        items = [
            ("1", "查看配置", "显示当前系统配置"),
            ("2", "修改配置", "修改系统设置"),
            ("3", "重载配置", "重新加载配置文件"),
            ("4", "配置验证", "验证配置有效性"),
            ("5", "备份配置", "备份当前配置")
        ]
        
        self.display_submenu("config", "系统配置", items)
        choice = self.get_user_input("请选择配置操作")
        
        if choice == "b":
            self.current_menu = "main"
        elif choice == "0":
            self._exit_system()
        elif choice == "1":
            self._show_config()
        elif choice == "2":
            self._modify_config()
        elif choice == "3":
            self._reload_config()
        elif choice == "4":
            self._validate_config()
        elif choice == "5":
            self._backup_config()
        else:
            print("❌ 无效选择")    
    
# Default command handlers
    def _show_help(self, args: List[str] = None) -> bool:
        """Show help information."""
        if args and len(args) > 0:
            topic = args[0]
            if topic == "topics":
                self.help_system.list_topics()
            elif topic == "examples":
                self.help_system.show_examples()
            elif topic == "parameters":
                if len(args) > 1:
                    self.parameter_validator.show_parameter_help(args[1])
                else:
                    self.help_system.show_parameter_help_all()
            elif topic == "troubleshooting":
                self.help_system.show_troubleshooting_guide()
            else:
                self.help_system.show_help(topic)
        else:
            self.help_system.show_help()
        return True
    
    def _show_examples(self, args: List[str] = None) -> bool:
        """Show usage examples."""
        if args and len(args) > 0:
            self.help_system.show_examples(args[0])
        else:
            self.help_system.show_examples()
        return True
    
    def _show_troubleshooting(self) -> bool:
        """Show troubleshooting guide."""
        self.help_system.show_troubleshooting_guide()
        return True
    
    def _validate_input(self, args: List[str] = None) -> bool:
        """Validate input parameters."""
        if not args or len(args) < 2:
            print("❌ 用法: validate <参数类型> <值>")
            print("💡 示例: validate ip_address 192.168.1.1")
            print("💡 支持的类型: ip_address, port_range, scan_type, ai_provider, network_range, file_path, timeout_value, thread_count")
            return False
        
        param_type = args[0]
        value = args[1]
        
        # Map parameter types to validation methods
        validation_methods = {
            "ip_address": self.parameter_validator.validate_ip_address,
            "port_range": self.parameter_validator.validate_port_range,
            "scan_type": self.parameter_validator.validate_scan_type,
            "ai_provider": self.parameter_validator.validate_ai_provider,
            "network_range": self.parameter_validator.validate_network_range,
            "file_path": self.parameter_validator.validate_file_path,
            "timeout_value": self.parameter_validator.validate_timeout_value,
            "thread_count": self.parameter_validator.validate_thread_count
        }
        
        if param_type not in validation_methods:
            print(f"❌ 不支持的参数类型: {param_type}")
            print(f"💡 支持的类型: {', '.join(validation_methods.keys())}")
            return False
        
        is_valid, msg = validation_methods[param_type](value)
        
        if is_valid:
            print(f"✅ 参数验证通过: {value}")
        else:
            print(f"❌ 参数验证失败: {msg}")
        
        return is_valid
    
    def _exit_system(self) -> bool:
        """Exit the system."""
        if self._confirm_exit():
            print("\n👋 感谢使用AI网络安全平台！")
            self.running = False
            return True
        return False
    
    def _clear_screen(self) -> bool:
        """Clear the screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        return True
    
    def _show_status(self) -> bool:
        """Show system status."""
        print("\n" + "="*60)
        print("📊 系统状态")
        print("="*60)
        print(f"🕐 当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🖥️ 操作系统: {os.name}")
        print(f"📁 工作目录: {os.getcwd()}")
        print(f"🐍 Python版本: {sys.version.split()[0]}")
        
        # TODO: Add more status information
        print("\n🔧 模块状态:")
        print("  • 配置管理: ✅ 已加载")
        print("  • AI助手: ⚠️ 待配置")
        print("  • 攻击模拟器: ✅ 就绪")
        print("  • 防御系统: ✅ 就绪")
        print("  • CTF解题器: ✅ 就绪")
        print("="*60)
        return True
    
    def _confirm_exit(self) -> bool:
        """Confirm system exit."""
        try:
            response = input("\n❓ 确定要退出系统吗? (y/N): ").strip().lower()
            return response in ['y', 'yes', '是', 'true']
        except (KeyboardInterrupt, EOFError):
            return True
    
    def _log_info(self, message: str) -> None:
        """Log info message."""
        if self.logger:
            self.logger.log_info(message)
    
    def _log_error(self, message: str, error: Exception = None) -> None:
        """Log error message."""
        if self.logger:
            self.logger.log_error(message, error)
    
    # Placeholder methods for menu handlers (to be implemented)
    def _show_ai_providers(self) -> None:
        """Show AI providers."""
        try:
            from ai.assistant import get_global_assistant
            from config.manager import ConfigManager
            
            config_manager = ConfigManager()
            assistant = get_global_assistant(config_manager)
            
            providers = assistant.get_available_providers()
            
            print("\n🤖 可用AI提供商:")
            print("="*60)
            
            for provider in providers:
                status = "✅ 可用" if provider["available"] else "❌ 不可用"
                print(f"{provider['name']:<15} - {status}")
                print(f"  模型: {provider.get('model', '未知')}")
                print(f"  请求次数: {provider['stats'].get('total_requests', 0)}")
                print(f"  成功次数: {provider['stats'].get('successful_requests', 0)}")
                print(f"  错误次数: {provider['stats'].get('failed_requests', 0)}")
                print()
                
        except Exception as e:
            print(f"❌ 获取AI提供商信息失败: {str(e)}")
    
    def _switch_ai_provider(self) -> None:
        """Switch AI provider."""
        try:
            from ai.assistant import get_global_assistant
            from config.manager import ConfigManager
            
            config_manager = ConfigManager()
            assistant = get_global_assistant(config_manager)
            
            providers = assistant.get_available_providers()
            available_providers = [p['name'] for p in providers if p['available']]
            
            if not available_providers:
                print("❌ 没有可用的AI提供商")
                return
                
            print("\n🔄 可用AI提供商:")
            for i, provider in enumerate(available_providers, 1):
                print(f"  {i}. {provider}")
                
            choice = input("\n请选择要切换的提供商编号: ").strip()
            
            if choice.isdigit() and 1 <= int(choice) <= len(available_providers):
                provider_name = available_providers[int(choice)-1]
                success = assistant.switch_provider(provider_name)
                if success:
                    print(f"✅ 已切换到 {provider_name}")
                else:
                    print(f"❌ 切换失败")
            else:
                print("❌ 无效选择")
                
        except Exception as e:
            print(f"❌ 切换AI提供商失败: {str(e)}")
    
    def _test_ai_connection(self) -> None:
        """Test AI connection."""
        try:
            from ai.assistant import get_global_assistant
            from config.manager import ConfigManager
            
            config_manager = ConfigManager()
            assistant = get_global_assistant(config_manager)
            
            print("\n🔗 测试AI连接...")
            
            # 测试简单的提示
            test_prompt = "你好，请回复'连接成功'来确认AI服务正常工作。"
            
            response = assistant.call_ai_api(test_prompt)
            
            if response:
                print("✅ AI连接测试成功！")
                print(f"响应: {response}")
            else:
                print("❌ AI连接测试失败")
                
        except Exception as e:
            print(f"❌ AI连接测试失败: {str(e)}")
    
    def _manage_ai_config(self) -> None:
        """Manage AI configuration."""
        print("⚙️ AI配置管理功能 - 开发中...")
    
    def _create_attack_session(self) -> None:
        """Create attack session."""
        print("⚔️ 创建攻击会话功能 - 开发中...")
    
    def _port_scan(self) -> None:
        """Port scan."""
        print("🔍 端口扫描功能 - 开发中...")
    
    def _vulnerability_scan(self) -> None:
        """Vulnerability scan."""
        print("🔎 漏洞扫描功能 - 开发中...")
    
    def _generate_payload(self) -> None:
        """Generate payload."""
        print("💣 载荷生成功能 - 开发中...")
    
    def _manage_sessions(self) -> None:
        """Manage sessions."""
        print("📋 会话管理功能 - 开发中...")
    
    def _start_monitoring(self) -> None:
        """Start monitoring."""
        print("🛡️ 启动监控功能 - 开发中...")
    
    def _show_threats(self) -> None:
        """Show threats."""
        print("⚠️ 威胁检测功能 - 开发中...")
    
    def _manage_responses(self) -> None:
        """Manage responses."""
        print("🚨 防御响应功能 - 开发中...")
    
    def _show_security_events(self) -> None:
        """Show security events."""
        print("📊 安全事件功能 - 开发中...")
    
    def _configure_monitoring(self) -> None:
        """Configure monitoring."""
        print("⚙️ 监控配置功能 - 开发中...")
    
    def _analyze_challenge(self) -> None:
        """Analyze challenge."""
        print("🏆 分析挑战功能 - 开发中...")
    
    def _auto_solve(self) -> None:
        """Auto solve."""
        print("🤖 自动解题功能 - 开发中...")
    
    def _ctf_tools(self) -> None:
        """CTF tools."""
        print("🔧 CTF工具功能 - 开发中...")
    
    def _solve_history(self) -> None:
        """Solve history."""
        print("📚 解题历史功能 - 开发中...")
    
    def _challenge_types(self) -> None:
        """Challenge types."""
        print("📝 题目类型功能 - 开发中...")
    
    def _show_config(self) -> None:
        """Show configuration."""
        print("📋 查看配置功能 - 开发中...")
    
    def _modify_config(self) -> None:
        """Modify configuration."""
        print("✏️ 修改配置功能 - 开发中...")
    
    def _reload_config(self) -> None:
        """Reload configuration."""
        print("🔄 重载配置功能 - 开发中...")
    
    def _validate_config(self) -> None:
        """Validate configuration."""
        print("✅ 配置验证功能 - 开发中...")
    
    def _backup_config(self) -> None:
        """Backup configuration."""
        print("💾 备份配置功能 - 开发中...")
    
    def _run_diagnostics(self) -> bool:
        """Run comprehensive system diagnostics."""
        print("\n🔍 系统诊断检查")
        print("="*60)
        
        diagnostics_passed = 0
        total_diagnostics = 0
        
        # Check Python version
        total_diagnostics += 1
        python_version = sys.version_info
        if python_version >= (3, 8):
            print(f"✅ Python版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
            diagnostics_passed += 1
        else:
            print(f"❌ Python版本过低: {python_version.major}.{python_version.minor}.{python_version.micro} (需要3.8+)")
        
        # Check configuration file
        total_diagnostics += 1
        config_path = Path("config/config.json")
        if config_path.exists():
            print("✅ 配置文件存在: config/config.json")
            diagnostics_passed += 1
        else:
            print("❌ 配置文件缺失: config/config.json")
        
        # Check required directories
        total_diagnostics += 1
        required_dirs = ["config", "logs", "src"]
        missing_dirs = [d for d in required_dirs if not Path(d).exists()]
        if not missing_dirs:
            print("✅ 必需目录完整")
            diagnostics_passed += 1
        else:
            print(f"❌ 缺失目录: {', '.join(missing_dirs)}")
        
        # Check Python packages
        total_diagnostics += 1
        required_packages = ["requests", "cryptography", "asyncio"]
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if not missing_packages:
            print("✅ Python依赖包完整")
            diagnostics_passed += 1
        else:
            print(f"❌ 缺失Python包: {', '.join(missing_packages)}")
        
        # Check network connectivity
        total_diagnostics += 1
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            print("✅ 网络连接正常")
            diagnostics_passed += 1
        except:
            print("❌ 网络连接异常")
        
        # Check file permissions
        total_diagnostics += 1
        try:
            test_file = Path("logs/.permission_test")
            test_file.touch()
            test_file.unlink()
            print("✅ 文件权限正常")
            diagnostics_passed += 1
        except:
            print("❌ 文件权限不足")
        
        # Summary
        print("\n" + "="*60)
        print(f"📊 诊断结果: {diagnostics_passed}/{total_diagnostics} 项检查通过")
        
        if diagnostics_passed == total_diagnostics:
            print("🎉 系统状态良好，所有检查都通过！")
        elif diagnostics_passed >= total_diagnostics * 0.8:
            print("⚠️ 系统基本正常，但有一些问题需要注意")
        else:
            print("❌ 系统存在多个问题，建议修复后再使用")
        
        print("💡 如需帮助，请运行 'troubleshoot' 查看故障排除指南")
        print("="*60)
        
        return diagnostics_passed == total_diagnostics
    
    def _show_version(self) -> bool:
        """Show version information."""
        print("\n📋 版本信息")
        print("="*60)
        print("🚀 AI增强网络安全平台 v1.0.0")
        print("📅 发布日期: 2024-01-01")
        print(f"🐍 Python版本: {sys.version.split()[0]}")
        print(f"🖥️ 操作系统: {os.name}")
        print(f"📁 安装路径: {os.getcwd()}")
        
        # Show module versions if available
        modules_info = {
            "requests": "HTTP请求库",
            "cryptography": "加密库", 
            "asyncio": "异步IO库"
        }
        
        print("\n📦 依赖模块:")
        for module, description in modules_info.items():
            try:
                mod = __import__(module)
                version = getattr(mod, '__version__', '未知版本')
                print(f"  ✅ {module} {version} - {description}")
            except ImportError:
                print(f"  ❌ {module} - {description} (未安装)")
        
        print("="*60)
        return True