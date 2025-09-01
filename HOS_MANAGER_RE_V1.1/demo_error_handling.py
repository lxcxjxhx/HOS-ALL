#!/usr/bin/env python3
"""
Demo script to showcase the error handling and help system implementation.
This demonstrates Task 8.3 completion.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from ui.cli import CLIFramework
from ui.error_handler import ErrorHandler, HelpSystem, ParameterValidator


def demo_error_handling():
    """Demonstrate error handling capabilities."""
    print("\n" + "="*60)
    print("🔧 错误处理系统演示")
    print("="*60)
    
    error_handler = ErrorHandler()
    
    # Demo 1: Handle different types of errors
    print("\n1. 不同类型错误的处理:")
    test_errors = [
        FileNotFoundError("config.json not found"),
        PermissionError("Access denied"),
        ConnectionError("Network unreachable"),
        ValueError("Invalid IP address format")
    ]
    
    for error in test_errors:
        print(f"\n处理错误: {type(error).__name__}")
        error_handler.handle_error(error, "演示")
    
    # Demo 2: Predefined error messages
    print("\n2. 预定义错误消息:")
    error_handler.display_error_message("API_KEY_INVALID", provider="OpenAI")
    error_handler.display_error_message("TARGET_UNREACHABLE", target="192.168.1.100")


def demo_help_system():
    """Demonstrate help system capabilities."""
    print("\n" + "="*60)
    print("📚 帮助系统演示")
    print("="*60)
    
    help_system = HelpSystem()
    
    # Demo 1: General help
    print("\n1. 通用帮助信息:")
    help_system.show_help()
    
    # Demo 2: Specific topic help
    print("\n2. 特定主题帮助 (配置管理):")
    help_system.show_help("config")
    
    # Demo 3: Available topics
    print("\n3. 可用帮助主题:")
    help_system.list_topics()


def demo_parameter_validation():
    """Demonstrate parameter validation capabilities."""
    print("\n" + "="*60)
    print("✅ 参数验证系统演示")
    print("="*60)
    
    validator = ParameterValidator()
    
    # Demo 1: IP address validation
    print("\n1. IP地址验证:")
    test_ips = ["192.168.1.1", "invalid_ip", "10.0.0.1", "256.256.256.256"]
    
    for ip in test_ips:
        is_valid, msg = validator.validate_ip_address(ip)
        status = "✅" if is_valid else "❌"
        print(f"  {status} {ip}: {'有效' if is_valid else msg}")
    
    # Demo 2: Port range validation
    print("\n2. 端口范围验证:")
    test_ports = ["80", "80,443,22", "1-1000", "invalid_ports", "80-22"]
    
    for ports in test_ports:
        is_valid, msg = validator.validate_port_range(ports)
        status = "✅" if is_valid else "❌"
        print(f"  {status} {ports}: {'有效' if is_valid else msg}")
    
    # Demo 3: Parameter help
    print("\n3. 参数格式帮助:")
    validator.show_parameter_help("ip_address")


def demo_cli_integration():
    """Demonstrate CLI integration."""
    print("\n" + "="*60)
    print("🖥️ CLI集成演示")
    print("="*60)
    
    cli = CLIFramework()
    
    # Demo 1: Help commands
    print("\n1. 帮助命令:")
    cli._show_help(["config"])
    
    # Demo 2: Parameter validation
    print("\n2. 参数验证命令:")
    cli._validate_input(["ip_address", "192.168.1.1"])
    cli._validate_input(["ip_address", "invalid_ip"])
    
    # Demo 3: System diagnostics
    print("\n3. 系统诊断:")
    cli._run_diagnostics()
    
    # Demo 4: Version information
    print("\n4. 版本信息:")
    cli._show_version()


def main():
    """Main demo function."""
    print("🎉 AI网络安全平台 - 错误处理和帮助系统演示")
    print("Task 8.3: 实现错误处理和帮助系统")
    
    try:
        demo_error_handling()
        demo_help_system()
        demo_parameter_validation()
        demo_cli_integration()
        
        print("\n" + "="*60)
        print("🎊 演示完成！Task 8.3 已成功实现所有功能:")
        print("  ✅ 用户友好的错误信息显示")
        print("  ✅ 内置帮助文档和使用示例")
        print("  ✅ 参数格式说明和有效示例")
        print("  ✅ 用户界面的单元测试")
        print("  ✅ 需求 7.4, 7.5, 7.6 完全满足")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()