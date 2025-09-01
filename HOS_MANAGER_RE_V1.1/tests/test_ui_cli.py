"""
Unit tests for CLI Framework with Error Handling and Help System.

Tests the CLI framework integration with error handling, help system,
and parameter validation according to requirements 7.4, 7.5, and 7.6.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ui.cli import CLIFramework
from ui.error_handler import ErrorHandler, HelpSystem, ParameterValidator


class TestCLIFramework(unittest.TestCase):
    """Test cases for CLIFramework class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = MagicMock()
        self.cli = CLIFramework(self.mock_logger)
    
    def test_cli_initialization(self):
        """Test CLI framework initialization."""
        self.assertIsNotNone(self.cli.error_handler)
        self.assertIsNotNone(self.cli.help_system)
        self.assertIsNotNone(self.cli.parameter_validator)
        self.assertIsInstance(self.cli.error_handler, ErrorHandler)
        self.assertIsInstance(self.cli.help_system, HelpSystem)
        self.assertIsInstance(self.cli.parameter_validator, ParameterValidator)
    
    def test_command_registration(self):
        """Test command registration functionality."""
        def test_handler():
            return True
        
        self.cli.register_command(
            "test_cmd", 
            test_handler, 
            "Test command", 
            "test_menu"
        )
        
        self.assertIn("test_menu", self.cli.commands)
        self.assertIn("test_cmd", self.cli.commands["test_menu"])
        self.assertEqual(
            self.cli.commands["test_menu"]["test_cmd"]["handler"], 
            test_handler
        )
    
    def test_help_command_without_args(self):
        """Test help command without arguments."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help()
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)
    
    def test_help_command_with_topic(self):
        """Test help command with specific topic."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help(["config"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("系统配置管理", call_args)
    
    def test_help_command_topics_list(self):
        """Test help topics listing."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help(["topics"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("可用帮助主题", call_args)
    
    def test_help_command_examples(self):
        """Test help examples display."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help(["examples"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("使用示例", call_args)
    
    def test_help_command_parameters(self):
        """Test help parameters display."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help(["parameters"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数格式说明", call_args)
    
    def test_help_command_specific_parameter(self):
        """Test help for specific parameter type."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help(["parameters", "ip_address"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("IPv4地址格式", call_args)
    
    def test_help_command_troubleshooting(self):
        """Test troubleshooting help."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_help(["troubleshooting"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
    
    def test_examples_command(self):
        """Test examples command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_examples()
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("使用示例", call_args)
    
    def test_examples_command_with_category(self):
        """Test examples command with specific category."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_examples(["基本操作"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("基本操作", call_args)
    
    def test_troubleshooting_command(self):
        """Test troubleshooting command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_troubleshooting()
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
    
    def test_validate_command_success(self):
        """Test parameter validation command with valid input."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["ip_address", "192.168.1.1"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证通过", call_args)
    
    def test_validate_command_failure(self):
        """Test parameter validation command with invalid input."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["ip_address", "invalid_ip"])
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证失败", call_args)
    
    def test_validate_command_insufficient_args(self):
        """Test validation command with insufficient arguments."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["ip_address"])
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("用法: validate", call_args)
    
    def test_validate_command_unsupported_type(self):
        """Test validation command with unsupported parameter type."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["unsupported_type", "value"])
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("不支持的参数类型", call_args)
    
    def test_validate_command_network_range(self):
        """Test network range validation command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["network_range", "192.168.1.0/24"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证通过", call_args)
    
    def test_validate_command_timeout_value(self):
        """Test timeout value validation command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["timeout_value", "30"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证通过", call_args)
    
    def test_validate_command_thread_count(self):
        """Test thread count validation command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._validate_input(["thread_count", "10"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证通过", call_args)
    
    def test_diagnostics_command(self):
        """Test system diagnostics command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._run_diagnostics()
            
        # Should return a boolean
        self.assertIsInstance(result, bool)
        call_args = str(mock_print.call_args_list)
        self.assertIn("系统诊断检查", call_args)
        self.assertIn("诊断结果", call_args)
    
    def test_version_command(self):
        """Test version information command."""
        with patch('builtins.print') as mock_print:
            result = self.cli._show_version()
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("版本信息", call_args)
        self.assertIn("AI增强网络安全平台", call_args)
    
    def test_validate_and_execute_valid_parameters(self):
        """Test validate_and_execute with valid parameters."""
        # Mock a command handler
        mock_handler = MagicMock(return_value=True)
        self.cli.register_command("test_scan", mock_handler, "Test scan")
        
        result = self.cli.validate_and_execute(
            "test_scan", 
            target="192.168.1.1", 
            ports="80,443", 
            scan_type="tcp"
        )
        
        self.assertTrue(result)
    
    def test_validate_and_execute_invalid_ip(self):
        """Test validate_and_execute with invalid IP."""
        with patch('builtins.print') as mock_print:
            result = self.cli.validate_and_execute(
                "test_scan", 
                target="invalid_ip"
            )
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效的IP地址格式", call_args)
    
    def test_validate_and_execute_invalid_ports(self):
        """Test validate_and_execute with invalid ports."""
        with patch('builtins.print') as mock_print:
            result = self.cli.validate_and_execute(
                "test_scan", 
                target="192.168.1.1",
                ports="invalid_ports"
            )
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效的端口格式", call_args)
    
    def test_validate_and_execute_invalid_scan_type(self):
        """Test validate_and_execute with invalid scan type."""
        with patch('builtins.print') as mock_print:
            result = self.cli.validate_and_execute(
                "test_scan", 
                target="192.168.1.1",
                ports="80",
                scan_type="invalid_type"
            )
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效的扫描类型", call_args)
    
    def test_execute_command_unknown_command(self):
        """Test executing unknown command."""
        with patch.object(self.cli.error_handler, 'display_error_message') as mock_error:
            result = self.cli.execute_command("unknown_command")
            
        self.assertFalse(result)
        mock_error.assert_called_once()
    
    def test_execute_command_with_exception(self):
        """Test command execution with exception."""
        def failing_handler():
            raise ValueError("Test error")
        
        self.cli.register_command("failing_cmd", failing_handler, "Failing command")
        
        with patch.object(self.cli.error_handler, 'handle_error') as mock_error:
            result = self.cli.execute_command("failing_cmd")
            
        self.assertFalse(result)
        mock_error.assert_called_once()
    
    def test_banner_display(self):
        """Test banner display."""
        with patch('builtins.print') as mock_print:
            self.cli.display_banner()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI增强网络安全平台", call_args)
        self.assertIn("重要提醒", call_args)
    
    def test_main_menu_display(self):
        """Test main menu display."""
        with patch('builtins.print') as mock_print:
            self.cli.display_main_menu()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("主功能菜单", call_args)
        self.assertIn("AI助手管理", call_args)
        self.assertIn("攻击模拟器", call_args)
        self.assertIn("防御系统", call_args)
        self.assertIn("CTF解题器", call_args)
    
    def test_submenu_display(self):
        """Test submenu display."""
        items = [
            ("1", "选项1", "描述1"),
            ("2", "选项2", "描述2")
        ]
        
        with patch('builtins.print') as mock_print:
            self.cli.display_submenu("test_menu", "测试菜单", items)
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("测试菜单", call_args)
        self.assertIn("选项1", call_args)
        self.assertIn("选项2", call_args)
    
    def test_user_input_handling(self):
        """Test user input handling."""
        with patch('builtins.input', return_value="test_input"):
            result = self.cli.get_user_input("测试提示")
            
        self.assertEqual(result, "test_input")
    
    def test_user_input_keyboard_interrupt(self):
        """Test user input with keyboard interrupt."""
        with patch('builtins.input', side_effect=KeyboardInterrupt):
            result = self.cli.get_user_input("测试提示")
            
        self.assertEqual(result, "0")
    
    def test_user_input_eof_error(self):
        """Test user input with EOF error."""
        with patch('builtins.input', side_effect=EOFError):
            result = self.cli.get_user_input("测试提示")
            
        self.assertEqual(result, "0")


class TestCLIErrorIntegration(unittest.TestCase):
    """Test CLI integration with error handling system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cli = CLIFramework()
    
    def test_error_handler_integration(self):
        """Test that CLI properly integrates with error handler."""
        self.assertIsInstance(self.cli.error_handler, ErrorHandler)
        
        # Test that error handler is used for command errors
        def error_command():
            raise ValueError("Test error")
        
        self.cli.register_command("error_cmd", error_command, "Error command")
        
        with patch.object(self.cli.error_handler, 'handle_error') as mock_handle:
            self.cli.execute_command("error_cmd")
            
        mock_handle.assert_called_once()
    
    def test_help_system_integration(self):
        """Test that CLI properly integrates with help system."""
        self.assertIsInstance(self.cli.help_system, HelpSystem)
        
        # Test help command uses help system
        with patch.object(self.cli.help_system, 'show_help') as mock_help:
            self.cli._show_help()
            
        mock_help.assert_called_once()
    
    def test_parameter_validator_integration(self):
        """Test that CLI properly integrates with parameter validator."""
        self.assertIsInstance(self.cli.parameter_validator, ParameterValidator)
        
        # Test validation is used in validate_and_execute
        with patch.object(
            self.cli.parameter_validator, 
            'validate_ip_address', 
            return_value=(False, "Invalid IP")
        ) as mock_validate:
            with patch('builtins.print'):
                self.cli.validate_and_execute("test", target="invalid_ip")
            
        mock_validate.assert_called_once_with("invalid_ip")
    
    def test_comprehensive_error_workflow(self):
        """Test comprehensive error handling workflow."""
        # Test parameter validation error -> help suggestion
        with patch('builtins.print') as mock_print:
            self.cli.validate_and_execute("test", target="invalid_ip")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效的IP地址格式", call_args)
        self.assertIn("192.168.1.1", call_args)  # Should show correct format
    
    def test_help_command_error_recovery(self):
        """Test help command provides error recovery information."""
        with patch('builtins.print') as mock_print:
            self.cli._show_help(["troubleshooting"])
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
        self.assertIn("常见错误", call_args)
        self.assertIn("config validate", call_args)


if __name__ == '__main__':
    unittest.main()