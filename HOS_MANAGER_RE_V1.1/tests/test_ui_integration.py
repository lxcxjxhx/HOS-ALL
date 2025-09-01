"""
Integration tests for UI Error Handling and Help System.

Tests the complete integration of error handling, help system,
and parameter validation with the main CLI application.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from main_cli import CybersecurityPlatformCLI
from ui.cli import CLIFramework
from ui.error_handler import ErrorHandler, HelpSystem, ParameterValidator


class TestUIIntegration(unittest.TestCase):
    """Integration tests for UI components."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.app = CybersecurityPlatformCLI()
    
    def test_app_initialization_with_ui_components(self):
        """Test that main app properly initializes UI components."""
        self.assertIsInstance(self.app.cli, CLIFramework)
        self.assertIsInstance(self.app.error_handler, ErrorHandler)
        
        # Test CLI has error handling components
        self.assertIsInstance(self.app.cli.error_handler, ErrorHandler)
        self.assertIsInstance(self.app.cli.help_system, HelpSystem)
        self.assertIsInstance(self.app.cli.parameter_validator, ParameterValidator)
    
    def test_error_handling_integration(self):
        """Test error handling integration in main app."""
        # Test that app uses error handler for exceptions
        with patch.object(self.app.error_handler, 'handle_error') as mock_handle:
            with patch.object(self.app.terms_service, 'prompt_acceptance', return_value=False):
                # This should not raise an exception but handle it gracefully
                import asyncio
                result = asyncio.run(self.app.initialize())
                
        self.assertFalse(result)  # Should return False when terms not accepted
    
    def test_help_system_accessibility(self):
        """Test that help system is accessible through CLI."""
        with patch('builtins.print') as mock_print:
            result = self.app.cli._show_help()
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)
    
    def test_parameter_validation_integration(self):
        """Test parameter validation integration."""
        # Test IP validation
        is_valid, msg = self.app.cli.parameter_validator.validate_ip_address("192.168.1.1")
        self.assertTrue(is_valid)
        
        is_valid, msg = self.app.cli.parameter_validator.validate_ip_address("invalid")
        self.assertFalse(is_valid)
        self.assertIn("无效的IP地址格式", msg)
    
    def test_comprehensive_help_workflow(self):
        """Test comprehensive help workflow."""
        # Test general help
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help()
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)
        
        # Test specific topic help
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help(["config"])
        call_args = str(mock_print.call_args_list)
        self.assertIn("系统配置管理", call_args)
        
        # Test parameter help
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help(["parameters", "ip_address"])
        call_args = str(mock_print.call_args_list)
        self.assertIn("IPv4地址格式", call_args)
        
        # Test troubleshooting
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help(["troubleshooting"])
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
    
    def test_error_recovery_workflow(self):
        """Test error recovery workflow."""
        # Simulate parameter validation error
        with patch('builtins.print') as mock_print:
            result = self.app.cli.validate_and_execute("test", target="invalid_ip")
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效的IP地址格式", call_args)
        self.assertIn("192.168.1.1", call_args)  # Should show correct format example
    
    def test_command_error_handling(self):
        """Test command error handling."""
        # Test unknown command
        with patch.object(self.app.cli.error_handler, 'display_error_message') as mock_error:
            result = self.app.cli.execute_command("unknown_command")
            
        self.assertFalse(result)
        mock_error.assert_called_once()
    
    def test_examples_and_usage_guidance(self):
        """Test examples and usage guidance."""
        # Test examples command
        with patch('builtins.print') as mock_print:
            self.app.cli._show_examples()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("使用示例", call_args)
        self.assertIn("基本操作", call_args)
        
        # Test specific category examples
        with patch('builtins.print') as mock_print:
            self.app.cli._show_examples(["基本操作"])
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("help", call_args)
        self.assertIn("status", call_args)
    
    def test_parameter_validation_commands(self):
        """Test parameter validation commands."""
        # Test validate command with valid input
        with patch('builtins.print') as mock_print:
            result = self.app.cli._validate_input(["ip_address", "192.168.1.1"])
            
        self.assertTrue(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证通过", call_args)
        
        # Test validate command with invalid input
        with patch('builtins.print') as mock_print:
            result = self.app.cli._validate_input(["ip_address", "invalid"])
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证失败", call_args)
    
    def test_error_severity_handling(self):
        """Test different error severity levels."""
        # Test different error types
        test_errors = [
            (FileNotFoundError("test.txt"), "文件未找到"),
            (PermissionError("access denied"), "权限不足"),
            (ConnectionError("connection failed"), "连接错误"),
            (ValueError("invalid value"), "无效值")
        ]
        
        for error, expected_msg in test_errors:
            with patch('builtins.print') as mock_print:
                self.app.error_handler.handle_error(error, "测试")
                
            call_args = str(mock_print.call_args_list)
            self.assertIn(expected_msg, call_args)
    
    def test_help_topic_coverage(self):
        """Test that all major help topics are covered."""
        expected_topics = [
            "config", "scan", "ai", "attack", 
            "defense", "ctf", "parameters", "troubleshooting"
        ]
        
        for topic in expected_topics:
            self.assertIn(topic, self.app.cli.help_system.help_topics)
            
            # Test each topic can be displayed
            with patch('builtins.print') as mock_print:
                self.app.cli.help_system.show_help(topic)
                
            call_args = str(mock_print.call_args_list)
            self.assertTrue(len(call_args) > 0)  # Should produce output
    
    def test_parameter_format_coverage(self):
        """Test that all parameter formats are covered."""
        expected_formats = ["ip_address", "port_range", "scan_type", "ai_provider"]
        
        for param_type in expected_formats:
            self.assertIn(param_type, self.app.cli.parameter_validator.parameter_formats)
            
            # Test each format can be displayed
            with patch('builtins.print') as mock_print:
                self.app.cli.parameter_validator.show_parameter_help(param_type)
                
            call_args = str(mock_print.call_args_list)
            self.assertIn("参数格式说明", call_args)


class TestRequirementsCompliance(unittest.TestCase):
    """Test compliance with specific requirements 7.4, 7.5, 7.6."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.app = CybersecurityPlatformCLI()
    
    def test_requirement_7_4_user_friendly_errors(self):
        """
        Test requirement 7.4: 当发生错误时，系统应当提供用户友好的错误信息和解决方案
        """
        # Test that errors provide user-friendly messages
        error = FileNotFoundError("config.json not found")
        
        with patch('builtins.print') as mock_print:
            self.app.error_handler.handle_error(error, "配置加载")
            
        call_args = str(mock_print.call_args_list)
        
        # Should contain user-friendly message
        self.assertIn("文件未找到", call_args)
        
        # Should contain solution suggestions
        self.assertIn("💡 建议解决方案", call_args)
        self.assertIn("检查文件路径", call_args)
        
        # Should use appropriate icons
        self.assertIn("❌", call_args)
    
    def test_requirement_7_5_built_in_help(self):
        """
        Test requirement 7.5: 当用户需要帮助时，系统应当提供内置帮助文档和使用示例
        """
        # Test general help availability
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)
        self.assertIn("主要功能", call_args)
        
        # Test specific help topics
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help(["config"])
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("系统配置管理", call_args)
        self.assertIn("config show", call_args)  # Usage examples
        
        # Test examples are provided
        with patch('builtins.print') as mock_print:
            self.app.cli._show_examples()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("使用示例", call_args)
        self.assertIn("基本操作", call_args)
    
    def test_requirement_7_6_parameter_format_guidance(self):
        """
        Test requirement 7.6: 如果用户输入无效参数，系统应当提供参数格式说明和有效示例
        """
        # Test invalid IP address parameter
        is_valid, error_msg = self.app.cli.parameter_validator.validate_ip_address("invalid_ip")
        
        self.assertFalse(is_valid)
        self.assertIn("无效的IP地址格式", error_msg)
        self.assertIn("192.168.1.1", error_msg)  # Should show valid example
        
        # Test invalid port range parameter
        is_valid, error_msg = self.app.cli.parameter_validator.validate_port_range("invalid_ports")
        
        self.assertFalse(is_valid)
        self.assertIn("无效的端口格式", error_msg)
        self.assertIn("80", error_msg)  # Should show valid example
        
        # Test parameter help display
        with patch('builtins.print') as mock_print:
            self.app.cli.parameter_validator.show_parameter_help("ip_address")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数格式说明", call_args)
        self.assertIn("IPv4地址格式", call_args)
        self.assertIn("192.168.1.1", call_args)  # Valid examples
        self.assertIn("192.168.1.256", call_args)  # Invalid examples for learning
    
    def test_comprehensive_requirements_workflow(self):
        """Test complete workflow covering all three requirements."""
        # Simulate user making an error (7.4)
        with patch('builtins.print') as mock_print:
            result = self.app.cli.validate_and_execute("scan", target="invalid_ip")
            
        self.assertFalse(result)
        call_args = str(mock_print.call_args_list)
        
        # Should show user-friendly error (7.4)
        self.assertIn("无效的IP地址格式", call_args)
        
        # Should show parameter format guidance (7.6)
        self.assertIn("192.168.1.1", call_args)
        
        # User can then get help (7.5)
        with patch('builtins.print') as mock_print:
            self.app.cli._show_help(["parameters", "ip_address"])
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数格式说明", call_args)
        self.assertIn("IPv4地址格式", call_args)


if __name__ == '__main__':
    unittest.main()