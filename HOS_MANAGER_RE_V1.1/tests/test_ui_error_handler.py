"""
Unit tests for UI Error Handler and Help System.

Tests the error handling, help system, and parameter validation
functionality according to requirements 7.4, 7.5, and 7.6.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ui.error_handler import (
    ErrorHandler, HelpSystem, ParameterValidator,
    ErrorSeverity, ErrorInfo
)


class TestErrorHandler(unittest.TestCase):
    """Test cases for ErrorHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.error_handler = ErrorHandler()
    
    def test_handle_file_not_found_error(self):
        """Test handling of FileNotFoundError."""
        error = FileNotFoundError("config.json not found")
        
        with patch('builtins.print') as mock_print:
            self.error_handler.handle_error(error, "配置加载")
            
        # Verify error was displayed
        mock_print.assert_called()
        call_args = str(mock_print.call_args_list)
        self.assertIn("文件未找到", call_args)
        self.assertIn("❌", call_args)
    
    def test_handle_permission_error(self):
        """Test handling of PermissionError."""
        error = PermissionError("Permission denied")
        
        with patch('builtins.print') as mock_print:
            self.error_handler.handle_error(error, "网络扫描")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("权限不足", call_args)
        self.assertIn("以管理员权限运行", call_args)
    
    def test_handle_connection_error(self):
        """Test handling of ConnectionError."""
        error = ConnectionError("Connection failed")
        
        with patch('builtins.print') as mock_print:
            self.error_handler.handle_error(error, "AI API调用")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("连接错误", call_args)
        self.assertIn("检查网络连接", call_args)
    
    def test_handle_value_error(self):
        """Test handling of ValueError."""
        error = ValueError("Invalid IP address format")
        
        with patch('builtins.print') as mock_print:
            self.error_handler.handle_error(error, "参数验证")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("无效值", call_args)
        self.assertIn("检查输入参数格式", call_args)
    
    def test_display_predefined_error_message(self):
        """Test displaying predefined error messages."""
        with patch('builtins.print') as mock_print:
            self.error_handler.display_error_message(
                "API_KEY_INVALID", 
                provider="OpenAI"
            )
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("API密钥无效", call_args)
        self.assertIn("OpenAI", call_args)
    
    def test_enhanced_error_codes(self):
        """Test enhanced error codes."""
        enhanced_errors = [
            ("TOOL_NOT_FOUND", {"tool": "nmap"}),
            ("INSUFFICIENT_PRIVILEGES", {"operation": "网络扫描"}),
            ("RATE_LIMIT_EXCEEDED", {"provider": "OpenAI"}),
            ("DEPENDENCY_MISSING", {"package": "requests"})
        ]
        
        for error_code, params in enhanced_errors:
            with patch('builtins.print') as mock_print:
                self.error_handler.display_error_message(error_code, **params)
                
            call_args = str(mock_print.call_args_list)
            self.assertTrue(len(call_args) > 0)  # Should produce output
    
    def test_error_severity_display(self):
        """Test error severity icons and formatting."""
        test_cases = [
            (ErrorSeverity.INFO, "ℹ️"),
            (ErrorSeverity.WARNING, "⚠️"),
            (ErrorSeverity.ERROR, "❌"),
            (ErrorSeverity.CRITICAL, "🚨")
        ]
        
        for severity, expected_icon in test_cases:
            error_info = ErrorInfo(
                code="TEST_ERROR",
                severity=severity,
                message="Test message"
            )
            
            with patch('builtins.print') as mock_print:
                self.error_handler._display_error(error_info)
                
            call_args = str(mock_print.call_args_list)
            self.assertIn(expected_icon, call_args)
    
    def test_error_suggestions_display(self):
        """Test that error suggestions are properly displayed."""
        error_info = ErrorInfo(
            code="TEST_ERROR",
            severity=ErrorSeverity.ERROR,
            message="Test error",
            suggestions=["建议1", "建议2", "建议3"]
        )
        
        with patch('builtins.print') as mock_print:
            self.error_handler._display_error(error_info)
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("💡 建议解决方案", call_args)
        self.assertIn("建议1", call_args)
        self.assertIn("建议2", call_args)
        self.assertIn("建议3", call_args)
    
    def test_error_history_logging(self):
        """Test that errors are logged to history."""
        error = ValueError("Test error")
        initial_count = len(self.error_handler.error_history)
        
        with patch('builtins.print'):
            self.error_handler.handle_error(error, "测试")
        
        self.assertEqual(
            len(self.error_handler.error_history), 
            initial_count + 1
        )
        
        logged_error = self.error_handler.error_history[-1]
        self.assertEqual(logged_error['original_error'], error)
        self.assertIn('traceback', logged_error)


class TestParameterValidator(unittest.TestCase):
    """Test cases for ParameterValidator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = ParameterValidator()
    
    def test_validate_valid_ip_addresses(self):
        """Test validation of valid IP addresses."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
            "172.16.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]
        
        for ip in valid_ips:
            is_valid, msg = self.validator.validate_ip_address(ip)
            self.assertTrue(is_valid, f"IP {ip} should be valid")
            self.assertEqual(msg, "")
    
    def test_validate_invalid_ip_addresses(self):
        """Test validation of invalid IP addresses."""
        invalid_ips = [
            "192.168.1.256",  # Out of range
            "192.168.1",      # Incomplete
            "192.168.1.1.1",  # Too many parts
            "abc.def.ghi.jkl", # Non-numeric
            "192.168.-1.1",   # Negative number
            ""                # Empty string
        ]
        
        for ip in invalid_ips:
            is_valid, msg = self.validator.validate_ip_address(ip)
            self.assertFalse(is_valid, f"IP {ip} should be invalid")
            self.assertNotEqual(msg, "")
            self.assertIn("无效的IP地址格式", msg)
    
    def test_validate_valid_port_ranges(self):
        """Test validation of valid port ranges."""
        valid_ports = [
            "80",           # Single port
            "80,443,22",    # Port list
            "1-1000",       # Port range
            "80,443,1000-2000",  # Mixed format
            "1",            # Minimum port
            "65535"         # Maximum port
        ]
        
        for ports in valid_ports:
            is_valid, msg = self.validator.validate_port_range(ports)
            self.assertTrue(is_valid, f"Ports {ports} should be valid")
            self.assertEqual(msg, "")
    
    def test_validate_invalid_port_ranges(self):
        """Test validation of invalid port ranges."""
        invalid_ports = [
            "0",            # Port 0 invalid
            "65536",        # Port too high
            "80-22",        # Start > end
            "80,,443",      # Double comma
            "abc",          # Non-numeric
            "80-",          # Incomplete range
            "-80"           # Invalid format
        ]
        
        for ports in invalid_ports:
            is_valid, msg = self.validator.validate_port_range(ports)
            self.assertFalse(is_valid, f"Ports {ports} should be invalid")
            self.assertNotEqual(msg, "")
    
    def test_validate_scan_types(self):
        """Test validation of scan types."""
        valid_types = ['tcp', 'syn', 'udp', 'connect', 'stealth', 'version', 'TCP', 'SYN']  # Case insensitive
        invalid_types = ['invalid', 'unknown', '', 'xyz', 'abc']
        
        for scan_type in valid_types:
            is_valid, msg = self.validator.validate_scan_type(scan_type)
            self.assertTrue(is_valid, f"Scan type {scan_type} should be valid")
        
        for scan_type in invalid_types:
            is_valid, msg = self.validator.validate_scan_type(scan_type)
            self.assertFalse(is_valid, f"Scan type {scan_type} should be invalid")
    
    def test_validate_ai_providers(self):
        """Test validation of AI provider names."""
        valid_providers = ['deepseek', 'openai', 'claude', 'gemini', 'ollama', 'OpenAI', 'CLAUDE']  # Case insensitive
        invalid_providers = ['invalid', 'unknown', '', 'xyz', 'abc']
        
        for provider in valid_providers:
            is_valid, msg = self.validator.validate_ai_provider(provider)
            self.assertTrue(is_valid, f"Provider {provider} should be valid")
        
        for provider in invalid_providers:
            is_valid, msg = self.validator.validate_ai_provider(provider)
            self.assertFalse(is_valid, f"Provider {provider} should be invalid")
    
    def test_show_parameter_help(self):
        """Test parameter help display."""
        with patch('builtins.print') as mock_print:
            self.validator.show_parameter_help("ip_address")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数格式说明", call_args)
        self.assertIn("IPv4地址格式", call_args)
        self.assertIn("192.168.1.1", call_args)
    
    def test_parameter_format_initialization(self):
        """Test that parameter formats are properly initialized."""
        expected_types = [
            "ip_address", "port_range", "scan_type", "ai_provider", 
            "network_range", "file_path", "timeout_value", "thread_count"
        ]
        
        for param_type in expected_types:
            self.assertIn(param_type, self.validator.parameter_formats)
            format_info = self.validator.parameter_formats[param_type]
            self.assertIn('description', format_info)
            self.assertIn('format', format_info)
            self.assertIn('examples', format_info)
    
    def test_validate_network_range(self):
        """Test network range validation."""
        valid_ranges = [
            "192.168.1.0/24",
            "10.0.0.0/8", 
            "172.16.0.0/16",
            "127.0.0.0/8"
        ]
        
        invalid_ranges = [
            "192.168.1.0/33",  # Invalid prefix
            "192.168.1.256/24",  # Invalid IP
            "192.168.1.0",  # Missing prefix
            "invalid/24"  # Invalid format
        ]
        
        for network in valid_ranges:
            is_valid, msg = self.validator.validate_network_range(network)
            self.assertTrue(is_valid, f"Network {network} should be valid")
        
        for network in invalid_ranges:
            is_valid, msg = self.validator.validate_network_range(network)
            self.assertFalse(is_valid, f"Network {network} should be invalid")
    
    def test_validate_timeout_value(self):
        """Test timeout value validation."""
        valid_timeouts = ["30", "60.5", "120", "0.1"]
        invalid_timeouts = ["0", "-10", "abc", "3700"]  # 3700 > 3600 max
        
        for timeout in valid_timeouts:
            is_valid, msg = self.validator.validate_timeout_value(timeout)
            self.assertTrue(is_valid, f"Timeout {timeout} should be valid")
        
        for timeout in invalid_timeouts:
            is_valid, msg = self.validator.validate_timeout_value(timeout)
            self.assertFalse(is_valid, f"Timeout {timeout} should be invalid")
    
    def test_validate_thread_count(self):
        """Test thread count validation."""
        valid_counts = ["1", "10", "50", "100"]
        invalid_counts = ["0", "-5", "10.5", "abc", "1001"]  # 1001 > 1000 max
        
        for count in valid_counts:
            is_valid, msg = self.validator.validate_thread_count(count)
            self.assertTrue(is_valid, f"Thread count {count} should be valid")
        
        for count in invalid_counts:
            is_valid, msg = self.validator.validate_thread_count(count)
            self.assertFalse(is_valid, f"Thread count {count} should be invalid")


class TestHelpSystem(unittest.TestCase):
    """Test cases for HelpSystem class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.help_system = HelpSystem()
    
    def test_show_general_help(self):
        """Test general help display."""
        with patch('builtins.print') as mock_print:
            self.help_system.show_help()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("AI网络安全平台", call_args)
        self.assertIn("主要功能", call_args)
        self.assertIn("基本命令", call_args)
        self.assertIn("重要提醒", call_args)
    
    def test_show_specific_topic_help(self):
        """Test specific topic help display."""
        with patch('builtins.print') as mock_print:
            self.help_system.show_help("config")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("系统配置管理", call_args)
        self.assertIn("config show", call_args)
        self.assertIn("config edit", call_args)
    
    def test_show_nonexistent_topic(self):
        """Test handling of nonexistent help topics."""
        with patch('builtins.print') as mock_print:
            self.help_system.show_help("nonexistent")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("未找到帮助主题", call_args)
        self.assertIn("nonexistent", call_args)
    
    def test_list_topics(self):
        """Test listing all help topics."""
        with patch('builtins.print') as mock_print:
            self.help_system.list_topics()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("可用帮助主题", call_args)
        self.assertIn("config", call_args)
        self.assertIn("scan", call_args)
        self.assertIn("ai", call_args)
    
    def test_show_examples_all(self):
        """Test showing all examples."""
        with patch('builtins.print') as mock_print:
            self.help_system.show_examples()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("使用示例", call_args)
        self.assertIn("基本操作", call_args)
        self.assertIn("AI助手", call_args)
    
    def test_show_examples_category(self):
        """Test showing examples for specific category."""
        with patch('builtins.print') as mock_print:
            self.help_system.show_examples("基本操作")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("基本操作", call_args)
        self.assertIn("help", call_args)
        self.assertIn("status", call_args)
    
    def test_show_troubleshooting_guide(self):
        """Test troubleshooting guide display."""
        with patch('builtins.print') as mock_print:
            self.help_system.show_troubleshooting_guide()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
        self.assertIn("常见错误", call_args)
        self.assertIn("性能问题", call_args)
        self.assertIn("配置问题", call_args)
    
    def test_help_topics_initialization(self):
        """Test that help topics are properly initialized."""
        expected_topics = [
            "config", "scan", "ai", "attack", 
            "defense", "ctf", "parameters", "troubleshooting"
        ]
        
        for topic in expected_topics:
            self.assertIn(topic, self.help_system.help_topics)
            topic_info = self.help_system.help_topics[topic]
            self.assertIn('description', topic_info)
            self.assertIn('usage', topic_info)
            self.assertIn('examples', topic_info)
    
    def test_parameter_help_integration(self):
        """Test integration with parameter validator."""
        self.assertIsNotNone(self.help_system.parameter_validator)
        
        with patch('builtins.print') as mock_print:
            self.help_system.show_parameter_help_all()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数格式说明", call_args)


class TestErrorHandlerIntegration(unittest.TestCase):
    """Integration tests for error handling system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.error_handler = ErrorHandler()
        self.help_system = HelpSystem()
        self.validator = ParameterValidator()
    
    def test_error_with_parameter_help_suggestion(self):
        """Test that parameter errors suggest help resources."""
        with patch('builtins.print') as mock_print:
            self.error_handler.display_error_message(
                "PARAMETER_VALIDATION_FAILED",
                parameter="ip_address",
                value="invalid_ip"
            )
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("参数验证失败", call_args)
        self.assertIn("help parameters", call_args)
    
    def test_comprehensive_error_handling_workflow(self):
        """Test complete error handling workflow."""
        # Simulate a parameter validation error
        is_valid, error_msg = self.validator.validate_ip_address("invalid_ip")
        self.assertFalse(is_valid)
        
        # Show parameter help
        with patch('builtins.print') as mock_print:
            self.validator.show_parameter_help("ip_address")
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("IPv4地址格式", call_args)
        self.assertIn("192.168.1.1", call_args)
    
    def test_help_system_error_recovery(self):
        """Test help system assists in error recovery."""
        # Test that help system provides recovery information
        with patch('builtins.print') as mock_print:
            self.help_system.show_troubleshooting_guide()
            
        call_args = str(mock_print.call_args_list)
        self.assertIn("故障排除指南", call_args)
        self.assertIn("config validate", call_args)
        self.assertIn("logs show", call_args)


if __name__ == '__main__':
    unittest.main()