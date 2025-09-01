"""
Comprehensive test for Task 8.3: 实现错误处理和帮助系统

This test verifies that all requirements for task 8.3 have been implemented:
- 实现用户友好的错误信息显示
- 创建内置帮助文档和使用示例  
- 添加参数格式说明和有效示例
- 编写用户界面的单元测试
- _需求: 7.4, 7.5, 7.6_
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ui.cli import CLIFramework
from ui.error_handler import ErrorHandler, HelpSystem, ParameterValidator
from main_cli import CybersecurityPlatformCLI


class TestTask8_3Complete(unittest.TestCase):
    """Comprehensive test for Task 8.3 completion."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.app = CybersecurityPlatformCLI()
        self.cli = self.app.cli
        self.error_handler = self.app.error_handler
        self.help_system = self.cli.help_system
        self.parameter_validator = self.cli.parameter_validator
    
    def test_user_friendly_error_display_complete(self):
        """Test requirement: 实现用户友好的错误信息显示"""
        
        # Test 1: Error severity icons and formatting
        test_errors = [
            (FileNotFoundError("config.json"), "❌", "文件未找到"),
            (PermissionError("access denied"), "❌", "权限不足"),
            (ConnectionError("network error"), "❌", "连接错误"),
            (ValueError("invalid input"), "❌", "无效值")
        ]
        
        for error, expected_icon, expected_msg in test_errors:
            with patch('builtins.print') as mock_print:
                self.error_handler.handle_error(error, "测试")
                
            call_args = str(mock_print.call_args_list)
            self.assertIn(expected_icon, call_args, f"Should show {expected_icon} for {type(error).__name__}")
            self.assertIn(expected_msg, call_args, f"Should show {expected_msg} for {type(error).__name__}")
            self.assertIn("💡 建议解决方案", call_args, "Should show solution suggestions")
        
        # Test 2: Predefined error messages with context
        predefined_errors = [
            ("CONFIG_NOT_FOUND", {"filename": "config.json"}),
            ("API_KEY_INVALID", {"provider": "OpenAI"}),
            ("TARGET_UNREACHABLE", {"target": "192.168.1.1"}),
            ("TOOL_NOT_FOUND", {"tool": "nmap"}),
            ("RATE_LIMIT_EXCEEDED", {"provider": "OpenAI"})
        ]
        
        for error_code, params in predefined_errors:
            with patch('builtins.print') as mock_print:
                self.error_handler.display_error_message(error_code, **params)
                
            call_args = str(mock_print.call_args_list)
            self.assertTrue(len(call_args) > 0, f"Should display error for {error_code}")
            self.assertIn("💡", call_args, f"Should show suggestions for {error_code}")
        
        print("✅ 用户友好的错误信息显示 - 测试通过")
    
    def test_built_in_help_documentation_complete(self):
        """Test requirement: 创建内置帮助文档和使用示例"""
        
        # Test 1: General help system
        with patch('builtins.print') as mock_print:
            self.help_system.show_help()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)
        self.assertIn("主要功能", call_args)
        self.assertIn("基本命令", call_args)
        self.assertIn("重要提醒", call_args)
        
        # Test 2: All help topics are available
        required_topics = [
            "config", "scan", "ai", "attack", 
            "defense", "ctf", "parameters", "troubleshooting"
        ]
        
        for topic in required_topics:
            self.assertIn(topic, self.help_system.help_topics)
            
            with patch('builtins.print') as mock_print:
                self.help_system.show_help(topic)
                
            call_args = str(mock_print.call_args_list)
            self.assertTrue(len(call_args) > 0, f"Should show help for topic: {topic}")
        
        # Test 3: Usage examples are comprehensive
        with patch('builtins.print') as mock_print:
            self.help_system.show_examples()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("使用示例", call_args)
        self.assertIn("基本操作", call_args)
        self.assertIn("AI助手", call_args)
        
        # Test 4: Troubleshooting guide is comprehensive
        with patch('builtins.print') as mock_print:
            self.help_system.show_troubleshooting_guide()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
        self.assertIn("常见错误", call_args)
        self.assertIn("性能问题", call_args)
        self.assertIn("配置问题", call_args)
        self.assertIn("网络问题", call_args)
        
        print("✅ 内置帮助文档和使用示例 - 测试通过")
    
    def test_parameter_format_guidance_complete(self):
        """Test requirement: 添加参数格式说明和有效示例"""
        
        # Test 1: All parameter types are supported
        expected_parameter_types = [
            "ip_address", "port_range", "scan_type", "ai_provider",
            "network_range", "file_path", "timeout_value", "thread_count"
        ]
        
        for param_type in expected_parameter_types:
            self.assertIn(param_type, self.parameter_validator.parameter_formats)
            
            format_info = self.parameter_validator.parameter_formats[param_type]
            self.assertIn('description', format_info)
            self.assertIn('format', format_info)
            self.assertIn('examples', format_info)
        
        # Test 2: Parameter validation with helpful error messages
        validation_tests = [
            ("ip_address", "192.168.1.1", True),
            ("ip_address", "invalid_ip", False),
            ("port_range", "80,443", True),
            ("port_range", "invalid_ports", False),
            ("network_range", "192.168.1.0/24", True),
            ("network_range", "invalid_network", False),
            ("timeout_value", "30", True),
            ("timeout_value", "-5", False),
            ("thread_count", "10", True),
            ("thread_count", "abc", False)
        ]
        
        for param_type, value, should_be_valid in validation_tests:
            validation_method = getattr(self.parameter_validator, f"validate_{param_type}")
            is_valid, msg = validation_method(value)
            
            self.assertEqual(is_valid, should_be_valid, 
                           f"Validation of {param_type}='{value}' should be {should_be_valid}")
            
            if not is_valid:
                self.assertIn("💡", msg, f"Invalid {param_type} should show helpful guidance")
        
        # Test 3: Parameter help display
        for param_type in expected_parameter_types:
            with patch('builtins.print') as mock_print:
                self.parameter_validator.show_parameter_help(param_type)
                
            call_args = str(mock_print.call_args_list)
            self.assertIn("参数格式说明", call_args)
            self.assertIn("💡 示例", call_args)
        
        print("✅ 参数格式说明和有效示例 - 测试通过")
    
    def test_cli_integration_complete(self):
        """Test CLI integration with error handling and help system."""
        
        # Test 1: CLI commands are properly registered
        expected_commands = [
            'help', 'exit', 'clear', 'status', 'examples', 
            'troubleshoot', 'validate', 'diagnose', 'version'
        ]
        
        main_commands = self.cli.commands.get('main', {})
        for command in expected_commands:
            self.assertIn(command, main_commands, f"Command '{command}' should be registered")
        
        # Test 2: Help command integration
        help_test_cases = [
            ([], "AI网络安全平台"),  # General help
            (["topics"], "可用帮助主题"),  # Topics list
            (["config"], "系统配置管理"),  # Specific topic
            (["parameters"], "参数格式说明"),  # Parameters help
            (["troubleshooting"], "故障排除指南")  # Troubleshooting
        ]
        
        for args, expected_content in help_test_cases:
            with patch('builtins.print') as mock_print:
                result = self.cli._show_help(args)
                
            self.assertTrue(result)
            call_args = str(mock_print.call_args_list)
            self.assertIn(expected_content, call_args)
        
        # Test 3: Validation command integration
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["ip_address", "192.168.1.1"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证通过", call_args)
        
        # Test 4: Diagnostics command
        with patch('builtins.print') as mock_print:
            result = self.cli._run_diagnostics()
            
        self.assertIsInstance(result, bool)
        call_args = str(mock_print.call_args_list)
        self.assertIn("系统诊断检查", call_args)
        
        # Test 5: Version command
        with patch('builtins.print') as mock_print:
            result = self.cli._show_version()
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("版本信息", call_args)
        
        print("✅ CLI集成功能 - 测试通过")
    
    def test_requirements_compliance_complete(self):
        """Test compliance with requirements 7.4, 7.5, 7.6."""
        
        # Requirement 7.4: User-friendly error messages and solutions
        error = ValueError("Invalid input format")
        with patch('builtins.print') as mock_print:
            self.error_handler.handle_error(error, "参数验证")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("❌", call_args)  # Error icon
        self.assertIn("无效值", call_args)  # User-friendly message
        self.assertIn("💡 建议解决方案", call_args)  # Solutions
        
        # Requirement 7.5: Built-in help and examples
        with patch('builtins.print') as mock_print:
            self.cli._show_help()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)  # Help content
        self.assertIn("基本命令", call_args)  # Usage examples
        
        # Requirement 7.6: Parameter format guidance for invalid input
        is_valid, error_msg = self.parameter_validator.validate_ip_address("invalid_ip")
        self.assertFalse(is_valid)
        self.assertIn("无效的IP地址格式", error_msg)  # Format explanation
        self.assertIn("192.168.1.1", error_msg)  # Valid example
        
        print("✅ 需求合规性 (7.4, 7.5, 7.6) - 测试通过")
    
    def test_comprehensive_error_recovery_workflow(self):
        """Test complete error recovery workflow."""
        
        # Simulate user making parameter error
        with patch('builtins.print') as mock_print:
            result = self.cli.validate_and_execute("test_command", target="invalid_ip")
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效的IP地址格式", call_args)  # Error message
        self.assertIn("192.168.1.1", call_args)  # Correct format example
        
        # User can then get parameter help
        with patch('builtins.print') as mock_print:
            self.parameter_validator.show_parameter_help("ip_address")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数格式说明", call_args)
        self.assertIn("IPv4地址格式", call_args)
        
        # User can get troubleshooting help
        with patch('builtins.print') as mock_print:
            self.help_system.show_troubleshooting_guide()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
        
        print("✅ 完整错误恢复工作流程 - 测试通过")
    
    def test_task_8_3_complete_summary(self):
        """Final verification that Task 8.3 is complete."""
        
        print("\n" + "="*60)
        print("📋 Task 8.3 完成情况验证")
        print("="*60)
        
        # Check all components exist and are properly integrated
        components_check = {
            "ErrorHandler": self.error_handler is not None,
            "HelpSystem": self.help_system is not None,
            "ParameterValidator": self.parameter_validator is not None,
            "CLI Integration": self.cli.error_handler is not None,
            "Main App Integration": self.app.error_handler is not None
        }
        
        for component, exists in components_check.items():
            status = "✅" if exists else "❌"
            print(f"  {status} {component}")
            self.assertTrue(exists, f"{component} should exist")
        
        # Check functionality implementation
        functionality_check = {
            "用户友好错误显示": len(self.error_handler.error_codes) > 10,
            "内置帮助文档": len(self.help_system.help_topics) >= 8,
            "参数格式说明": len(self.parameter_validator.parameter_formats) >= 8,
            "CLI命令集成": len(self.cli.commands.get('main', {})) >= 9,
            "故障排除指南": True,  # Verified in other tests
            "系统诊断功能": True,  # Verified in other tests
            "版本信息显示": True   # Verified in other tests
        }
        
        for functionality, implemented in functionality_check.items():
            status = "✅" if implemented else "❌"
            print(f"  {status} {functionality}")
            self.assertTrue(implemented, f"{functionality} should be implemented")
        
        print("\n🎉 Task 8.3 实现错误处理和帮助系统 - 完成！")
        print("="*60)


if __name__ == '__main__':
    unittest.main()