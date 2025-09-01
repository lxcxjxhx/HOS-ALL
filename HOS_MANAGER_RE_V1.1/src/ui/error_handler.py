"""
Error Handler and Help System Module.

This module provides user-friendly error handling, help documentation,
and usage examples for the cybersecurity platform.
"""

import sys
import traceback
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
from dataclasses import dataclass


class ErrorSeverity(Enum):
    """Error severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ErrorInfo:
    """Error information structure."""
    code: str
    severity: ErrorSeverity
    message: str
    details: Optional[str] = None
    suggestions: Optional[List[str]] = None
    timestamp: Optional[datetime] = None


class ErrorHandler:
    """Handle and display user-friendly error messages."""
    
    def __init__(self):
        """Initialize error handler."""
        self.error_codes = self._initialize_error_codes()
        self.error_history = []
    
    def handle_error(self, error: Exception, context: str = None) -> None:
        """
        Handle an error with user-friendly display.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
        """
        error_info = self._classify_error(error, context)
        self._display_error(error_info)
        self._log_error(error_info, error)
    
    def display_error_message(self, error_code: str, **kwargs) -> None:
        """
        Display a predefined error message.
        
        Args:
            error_code: Error code to display
            **kwargs: Format parameters for the message
        """
        if error_code in self.error_codes:
            error_template = self.error_codes[error_code]
            error_info = ErrorInfo(
                code=error_code,
                severity=error_template['severity'],
                message=error_template['message'].format(**kwargs),
                details=error_template.get('details', '').format(**kwargs) if error_template.get('details') else None,
                suggestions=error_template.get('suggestions', []),
                timestamp=datetime.now()
            )
            self._display_error(error_info)
        else:
            print(f"❌ 未知错误代码: {error_code}")
    
    def _classify_error(self, error: Exception, context: str = None) -> ErrorInfo:
        """Classify error and create error info."""
        error_type = type(error).__name__
        error_message = str(error)
        
        # Map common exceptions to user-friendly messages
        if isinstance(error, FileNotFoundError):
            return ErrorInfo(
                code="FILE_NOT_FOUND",
                severity=ErrorSeverity.ERROR,
                message=f"文件未找到: {error_message}",
                suggestions=[
                    "检查文件路径是否正确",
                    "确认文件是否存在",
                    "检查文件权限"
                ],
                timestamp=datetime.now()
            )
        elif isinstance(error, PermissionError):
            return ErrorInfo(
                code="PERMISSION_DENIED",
                severity=ErrorSeverity.ERROR,
                message=f"权限不足: {error_message}",
                suggestions=[
                    "以管理员权限运行程序",
                    "检查文件或目录权限",
                    "确认用户有足够的访问权限"
                ],
                timestamp=datetime.now()
            )
        elif isinstance(error, ConnectionError):
            return ErrorInfo(
                code="CONNECTION_ERROR",
                severity=ErrorSeverity.ERROR,
                message=f"连接错误: {error_message}",
                suggestions=[
                    "检查网络连接",
                    "验证目标地址是否正确",
                    "检查防火墙设置"
                ],
                timestamp=datetime.now()
            )
        elif isinstance(error, ValueError):
            return ErrorInfo(
                code="INVALID_VALUE",
                severity=ErrorSeverity.ERROR,
                message=f"无效值: {error_message}",
                suggestions=[
                    "检查输入参数格式",
                    "参考帮助文档中的示例",
                    "确认数据类型正确"
                ],
                timestamp=datetime.now()
            )
        else:
            return ErrorInfo(
                code="UNKNOWN_ERROR",
                severity=ErrorSeverity.ERROR,
                message=f"未知错误 ({error_type}): {error_message}",
                details=f"上下文: {context}" if context else None,
                suggestions=[
                    "重试操作",
                    "检查系统日志",
                    "联系技术支持"
                ],
                timestamp=datetime.now()
            )
    
    def _display_error(self, error_info: ErrorInfo) -> None:
        """Display error information."""
        # Choose icon based on severity
        icons = {
            ErrorSeverity.INFO: "ℹ️",
            ErrorSeverity.WARNING: "⚠️",
            ErrorSeverity.ERROR: "❌",
            ErrorSeverity.CRITICAL: "🚨"
        }
        
        icon = icons.get(error_info.severity, "❓")
        severity_text = error_info.severity.value.upper()
        
        print(f"\n{icon} [{severity_text}] {error_info.message}")
        
        if error_info.details:
            print(f"   详情: {error_info.details}")
        
        if error_info.suggestions:
            print("   💡 建议解决方案:")
            for suggestion in error_info.suggestions:
                print(f"      • {suggestion}")
        
        print()
    
    def _log_error(self, error_info: ErrorInfo, original_error: Exception) -> None:
        """Log error for debugging."""
        self.error_history.append({
            'error_info': error_info,
            'original_error': original_error,
            'traceback': traceback.format_exc()
        })
    
    def _initialize_error_codes(self) -> Dict[str, Dict]:
        """Initialize predefined error codes."""
        return {
            "CONFIG_NOT_FOUND": {
                "severity": ErrorSeverity.ERROR,
                "message": "配置文件未找到",
                "details": "系统无法找到配置文件 {filename}",
                "suggestions": [
                    "运行配置向导创建配置文件: python src/main_cli.py --setup",
                    "从模板复制配置文件: copy config_template.json config.json",
                    "检查配置文件路径是否正确",
                    "确认当前工作目录包含config文件夹"
                ]
            },
            "API_KEY_INVALID": {
                "severity": ErrorSeverity.ERROR,
                "message": "API密钥无效",
                "details": "AI提供商 {provider} 的API密钥验证失败",
                "suggestions": [
                    "检查API密钥是否正确",
                    "确认API密钥未过期",
                    "重新生成API密钥"
                ]
            },
            "TARGET_UNREACHABLE": {
                "severity": ErrorSeverity.WARNING,
                "message": "目标不可达",
                "details": "无法连接到目标 {target}",
                "suggestions": [
                    "检查目标地址是否正确",
                    "确认目标主机在线",
                    "检查网络连接"
                ]
            },
            "UNAUTHORIZED_TARGET": {
                "severity": ErrorSeverity.CRITICAL,
                "message": "未授权目标",
                "details": "尝试攻击未授权的目标 {target}",
                "suggestions": [
                    "确认拥有目标的测试授权",
                    "仅在授权环境中进行测试",
                    "查阅使用条款和法律要求"
                ]
            },
            "SCAN_BLOCKED": {
                "severity": ErrorSeverity.WARNING,
                "message": "扫描被阻止",
                "details": "目标 {target} 阻止了扫描请求",
                "suggestions": [
                    "使用更隐蔽的扫描技术",
                    "降低扫描速度",
                    "确认目标允许安全测试"
                ]
            },
            "INVALID_COMMAND": {
                "severity": ErrorSeverity.ERROR,
                "message": "无效命令",
                "details": "未知命令: {command}",
                "suggestions": [
                    "输入 'help' 查看可用命令",
                    "检查命令拼写是否正确",
                    "使用 'help topics' 查看所有主题"
                ]
            },
            "PARAMETER_VALIDATION_FAILED": {
                "severity": ErrorSeverity.ERROR,
                "message": "参数验证失败",
                "details": "参数 {parameter} 格式不正确: {value}",
                "suggestions": [
                    "使用 'help parameters' 查看参数格式",
                    "参考示例输入正确格式",
                    "使用 'validate' 命令检查参数"
                ]
            },
            "NETWORK_PERMISSION_DENIED": {
                "severity": ErrorSeverity.CRITICAL,
                "message": "网络权限不足",
                "details": "执行网络操作需要管理员权限",
                "suggestions": [
                    "以管理员身份运行程序",
                    "检查用户权限设置",
                    "确认具有网络访问权限"
                ]
            },
            "AI_SERVICE_UNAVAILABLE": {
                "severity": ErrorSeverity.WARNING,
                "message": "AI服务不可用",
                "details": "AI提供商 {provider} 服务暂时不可用",
                "suggestions": [
                    "检查网络连接",
                    "切换到其他AI提供商",
                    "稍后重试操作"
                ]
            },
            "CONFIGURATION_ERROR": {
                "severity": ErrorSeverity.ERROR,
                "message": "配置错误",
                "details": "配置项 {item} 设置不正确",
                "suggestions": [
                    "检查配置文件JSON格式是否正确",
                    "使用 'config validate' 验证配置",
                    "参考配置模板文件 config_template.json",
                    "确认所有必需字段都已填写"
                ]
            },
            "TOOL_NOT_FOUND": {
                "severity": ErrorSeverity.WARNING,
                "message": "工具未找到",
                "details": "系统工具 {tool} 未安装或不在PATH中",
                "suggestions": [
                    "安装缺失的工具: {tool}",
                    "检查工具是否在系统PATH中",
                    "使用 'which {tool}' 或 'where {tool}' 检查工具位置",
                    "参考安装文档获取工具安装指南"
                ]
            },
            "INSUFFICIENT_PRIVILEGES": {
                "severity": ErrorSeverity.CRITICAL,
                "message": "权限不足",
                "details": "执行操作 {operation} 需要更高权限",
                "suggestions": [
                    "以管理员身份重新运行程序",
                    "在Linux/Mac上使用 sudo 命令",
                    "在Windows上右键选择'以管理员身份运行'",
                    "检查用户组权限设置"
                ]
            },
            "RATE_LIMIT_EXCEEDED": {
                "severity": ErrorSeverity.WARNING,
                "message": "请求频率超限",
                "details": "AI提供商 {provider} API调用频率超过限制",
                "suggestions": [
                    "等待一段时间后重试",
                    "检查API配额和限制",
                    "考虑升级API计划",
                    "切换到其他AI提供商"
                ]
            },
            "DEPENDENCY_MISSING": {
                "severity": ErrorSeverity.ERROR,
                "message": "依赖缺失",
                "details": "Python包 {package} 未安装",
                "suggestions": [
                    "安装缺失的包: pip install {package}",
                    "运行 pip install -r requirements.txt 安装所有依赖",
                    "检查Python环境是否正确",
                    "确认使用正确的虚拟环境"
                ]
            }
        }


class ParameterValidator:
    """Validate user input parameters and provide format guidance."""
    
    def __init__(self):
        """Initialize parameter validator."""
        self.parameter_formats = self._initialize_parameter_formats()
    
    def validate_ip_address(self, ip: str) -> tuple[bool, str]:
        """
        Validate IP address format.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import re
        
        # IPv4 pattern
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if re.match(ipv4_pattern, ip):
            return True, ""
        
        return False, f"无效的IP地址格式: {ip}\n💡 正确格式: 192.168.1.1 或 10.0.0.1"
    
    def validate_port_range(self, ports: str) -> tuple[bool, str]:
        """
        Validate port range format.
        
        Args:
            ports: Port range string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import re
        
        # Single port: 80
        # Port list: 80,443,22
        # Port range: 1-1000
        # Mixed: 80,443,1000-2000
        
        port_pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
        
        if not re.match(port_pattern, ports):
            return False, f"无效的端口格式: {ports}\n💡 正确格式: 80 或 80,443 或 1-1000 或 80,443,1000-2000"
        
        # Validate port numbers are in valid range
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    return False, f"端口号必须在1-65535范围内: {part}"
                if int(start) > int(end):
                    return False, f"起始端口不能大于结束端口: {part}"
            else:
                if not (1 <= int(part) <= 65535):
                    return False, f"端口号必须在1-65535范围内: {part}"
        
        return True, ""
    
    def validate_scan_type(self, scan_type: str) -> tuple[bool, str]:
        """
        Validate scan type parameter.
        
        Args:
            scan_type: Scan type to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        valid_types = ['tcp', 'syn', 'udp', 'connect', 'stealth', 'version']
        
        if scan_type.lower() not in [t.lower() for t in valid_types]:
            return False, f"无效的扫描类型: {scan_type}\n💡 支持的类型: {', '.join(valid_types)}"
        
        return True, ""
    
    def validate_ai_provider(self, provider: str) -> tuple[bool, str]:
        """
        Validate AI provider name.
        
        Args:
            provider: AI provider name to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        valid_providers = ['deepseek', 'openai', 'claude', 'gemini', 'ollama']
        
        if provider.lower() not in [p.lower() for p in valid_providers]:
            return False, f"无效的AI提供商: {provider}\n💡 支持的提供商: {', '.join(valid_providers)}"
        
        return True, ""
    
    def validate_network_range(self, network: str) -> tuple[bool, str]:
        """
        Validate network range format (CIDR notation).
        
        Args:
            network: Network range to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import re
        
        # CIDR pattern: IP/prefix
        cidr_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$'
        
        if not re.match(cidr_pattern, network):
            return False, f"无效的网络范围格式: {network}\n💡 正确格式: 192.168.1.0/24 或 10.0.0.0/8"
        
        return True, ""
    
    def validate_file_path(self, file_path: str) -> tuple[bool, str]:
        """
        Validate file path format and existence.
        
        Args:
            file_path: File path to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import os
        
        if not file_path or file_path.strip() == "":
            return False, "文件路径不能为空\n💡 请提供有效的文件路径"
        
        # Check for invalid characters
        invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
        for char in invalid_chars:
            if char in file_path:
                return False, f"文件路径包含无效字符: {char}\n💡 请使用有效的文件路径字符"
        
        # Check if file exists
        if not os.path.exists(file_path):
            return False, f"文件不存在: {file_path}\n💡 请检查文件路径是否正确"
        
        return True, ""
    
    def validate_timeout_value(self, timeout: str) -> tuple[bool, str]:
        """
        Validate timeout value.
        
        Args:
            timeout: Timeout value to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            timeout_val = float(timeout)
            if timeout_val <= 0:
                return False, f"超时值必须大于0: {timeout}\n💡 正确格式: 30 或 30.5 (秒)"
            if timeout_val > 3600:  # 1 hour max
                return False, f"超时值过大: {timeout}\n💡 建议范围: 1-3600秒"
            return True, ""
        except ValueError:
            return False, f"无效的超时值格式: {timeout}\n💡 正确格式: 30 或 30.5 (秒)"
    
    def validate_thread_count(self, threads: str) -> tuple[bool, str]:
        """
        Validate thread count value.
        
        Args:
            threads: Thread count to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            thread_count = int(threads)
            if thread_count <= 0:
                return False, f"线程数必须大于0: {threads}\n💡 建议范围: 1-100"
            if thread_count > 1000:
                return False, f"线程数过大: {threads}\n💡 建议范围: 1-100"
            return True, ""
        except ValueError:
            return False, f"无效的线程数格式: {threads}\n💡 正确格式: 整数，如 10"
    
    def show_parameter_help(self, parameter_type: str) -> None:
        """
        Show help for specific parameter type.
        
        Args:
            parameter_type: Type of parameter to show help for
        """
        if parameter_type in self.parameter_formats:
            format_info = self.parameter_formats[parameter_type]
            
            print(f"\n📋 参数格式说明: {parameter_type}")
            print("="*50)
            print(f"📝 描述: {format_info['description']}")
            print(f"🔧 格式: {format_info['format']}")
            
            if 'examples' in format_info:
                print("💡 示例:")
                for example in format_info['examples']:
                    print(f"  ✅ {example}")
            
            if 'invalid_examples' in format_info:
                print("❌ 错误示例:")
                for example in format_info['invalid_examples']:
                    print(f"  ❌ {example}")
            
            print("="*50)
        else:
            print(f"❌ 未找到参数类型: {parameter_type}")
    
    def _initialize_parameter_formats(self) -> Dict[str, Dict]:
        """Initialize parameter format definitions."""
        return {
            "ip_address": {
                "description": "IPv4地址格式",
                "format": "xxx.xxx.xxx.xxx (每部分0-255)",
                "examples": [
                    "192.168.1.1",
                    "10.0.0.1", 
                    "127.0.0.1",
                    "172.16.0.1"
                ],
                "invalid_examples": [
                    "192.168.1.256 (超出范围)",
                    "192.168.1 (不完整)",
                    "192.168.1.1.1 (过多段)"
                ]
            },
            "port_range": {
                "description": "端口号或端口范围",
                "format": "单个端口、端口列表或端口范围",
                "examples": [
                    "80 (单个端口)",
                    "80,443,22 (端口列表)",
                    "1-1000 (端口范围)",
                    "80,443,1000-2000 (混合格式)"
                ],
                "invalid_examples": [
                    "80-22 (起始端口大于结束端口)",
                    "70000 (超出有效范围)",
                    "80,,443 (多余逗号)"
                ]
            },
            "scan_type": {
                "description": "网络扫描类型",
                "format": "预定义的扫描类型名称",
                "examples": [
                    "tcp (TCP连接扫描)",
                    "syn (SYN隐蔽扫描)",
                    "udp (UDP扫描)",
                    "stealth (隐蔽扫描)"
                ]
            },
            "ai_provider": {
                "description": "AI服务提供商名称",
                "format": "支持的AI提供商标识符",
                "examples": [
                    "openai (OpenAI GPT)",
                    "claude (Anthropic Claude)",
                    "deepseek (DeepSeek)",
                    "gemini (Google Gemini)",
                    "ollama (本地部署)"
                ]
            },
            "network_range": {
                "description": "网络范围 (CIDR格式)",
                "format": "IP地址/子网掩码位数",
                "examples": [
                    "192.168.1.0/24 (C类网络)",
                    "10.0.0.0/8 (A类网络)",
                    "172.16.0.0/16 (B类网络)",
                    "192.168.0.0/16 (大型局域网)"
                ],
                "invalid_examples": [
                    "192.168.1.0/33 (子网掩码位数超出范围)",
                    "192.168.1.256/24 (IP地址无效)",
                    "192.168.1.0 (缺少子网掩码)"
                ]
            },
            "file_path": {
                "description": "文件路径",
                "format": "相对或绝对文件路径",
                "examples": [
                    "config/config.json (相对路径)",
                    "/home/user/file.txt (绝对路径)",
                    "C:\\Users\\user\\file.txt (Windows路径)",
                    "./data/input.txt (当前目录相对路径)"
                ],
                "invalid_examples": [
                    "file<name>.txt (包含无效字符)",
                    "path|with|pipes.txt (包含管道符)",
                    "file?.txt (包含问号)"
                ]
            },
            "timeout_value": {
                "description": "超时时间 (秒)",
                "format": "正数，支持小数",
                "examples": [
                    "30 (30秒)",
                    "60.5 (60.5秒)",
                    "120 (2分钟)",
                    "300 (5分钟)"
                ],
                "invalid_examples": [
                    "0 (不能为0)",
                    "-10 (不能为负数)",
                    "abc (非数字格式)"
                ]
            },
            "thread_count": {
                "description": "线程数量",
                "format": "正整数",
                "examples": [
                    "1 (单线程)",
                    "10 (10个线程)",
                    "50 (50个线程)",
                    "100 (100个线程)"
                ],
                "invalid_examples": [
                    "0 (不能为0)",
                    "-5 (不能为负数)",
                    "10.5 (必须为整数)",
                    "abc (非数字格式)"
                ]
            }
        }


class HelpSystem:
    """Provide help documentation and usage examples."""
    
    def __init__(self):
        """Initialize help system."""
        self.help_topics = self._initialize_help_topics()
        self.parameter_validator = ParameterValidator()
    
    def show_help(self, topic: str = None) -> None:
        """
        Show help information.
        
        Args:
            topic: Specific help topic or None for general help
        """
        if topic is None:
            self._show_general_help()
        elif topic in self.help_topics:
            self._show_topic_help(topic)
        else:
            self._show_topic_not_found(topic)
    
    def list_topics(self) -> None:
        """List available help topics."""
        print("\n📚 可用帮助主题:")
        print("="*50)
        
        for topic, info in self.help_topics.items():
            print(f"  {topic:<20} - {info['description']}")
        
        print("\n💡 使用方法: help <主题名称>")
        print("="*50)
    
    def show_examples(self, category: str = None) -> None:
        """
        Show usage examples.
        
        Args:
            category: Example category or None for all
        """
        examples = self._get_examples()
        
        if category and category in examples:
            self._display_category_examples(category, examples[category])
        else:
            self._display_all_examples(examples)
    
    def _show_general_help(self) -> None:
        """Show general help information."""
        print("\n" + "="*60)
        print("📚 AI网络安全平台 - 帮助系统")
        print("="*60)
        
        print("🎯 主要功能:")
        print("  • AI助手集成 - 多提供商AI服务管理")
        print("  • 攻击模拟器 - 授权安全测试工具")
        print("  • 防御系统 - 威胁监控和响应")
        print("  • CTF解题器 - 自动化挑战解决")
        print("  • 系统配置 - 配置和设置管理")
        
        print("\n🔧 基本命令:")
        print("  • help [主题] - 显示帮助信息")
        print("  • status - 查看系统状态")
        print("  • config - 配置管理")
        print("  • exit - 退出系统")
        
        print("\n📖 获取更多帮助:")
        print("  • help topics - 查看所有帮助主题")
        print("  • help examples - 查看使用示例")
        print("  • help <主题名> - 查看特定主题帮助")
        
        print("\n⚠️ 重要提醒:")
        print("  • 仅在授权环境中使用攻击功能")
        print("  • 遵守相关法律法规")
        print("  • 定期备份重要数据")
        print("="*60)
    
    def _show_topic_help(self, topic: str) -> None:
        """Show help for specific topic."""
        help_info = self.help_topics[topic]
        
        print(f"\n📖 帮助主题: {topic}")
        print("="*60)
        print(f"📝 描述: {help_info['description']}")
        
        if 'usage' in help_info:
            print(f"\n🔧 用法:")
            for usage in help_info['usage']:
                print(f"  {usage}")
        
        if 'examples' in help_info:
            print(f"\n💡 示例:")
            for example in help_info['examples']:
                print(f"  {example}")
        
        if 'notes' in help_info:
            print(f"\n📋 注意事项:")
            for note in help_info['notes']:
                print(f"  • {note}")
        
        print("="*60)
    
    def _show_topic_not_found(self, topic: str) -> None:
        """Show message when topic not found."""
        print(f"\n❌ 未找到帮助主题: {topic}")
        print("\n💡 可用主题:")
        for available_topic in self.help_topics.keys():
            print(f"  • {available_topic}")
        print("\n使用 'help topics' 查看所有主题")
    
    def _display_all_examples(self, examples: Dict) -> None:
        """Display all examples."""
        print("\n📚 使用示例")
        print("="*60)
        
        for category, category_examples in examples.items():
            print(f"\n🔧 {category}:")
            for example in category_examples:
                print(f"  {example}")
        
        print("="*60)
    
    def _display_category_examples(self, category: str, examples: List[str]) -> None:
        """Display examples for specific category."""
        print(f"\n📚 {category} - 使用示例")
        print("="*60)
        
        for example in examples:
            print(f"  {example}")
        
        print("="*60)
    
    def _initialize_help_topics(self) -> Dict[str, Dict]:
        """Initialize help topics."""
        return {
            "config": {
                "description": "系统配置管理",
                "usage": [
                    "config show - 显示当前配置",
                    "config edit - 编辑配置文件",
                    "config validate - 验证配置",
                    "config backup - 备份配置文件",
                    "config restore - 恢复配置文件"
                ],
                "examples": [
                    "config show",
                    "config edit api_keys",
                    "config validate",
                    "config backup config_backup_20240101.json"
                ],
                "notes": [
                    "配置文件位于 config/ 目录",
                    "修改配置后会自动重载",
                    "敏感信息会自动加密存储",
                    "建议定期备份配置文件"
                ]
            },
            "scan": {
                "description": "端口扫描功能",
                "usage": [
                    "scan <目标> - 基本扫描",
                    "scan <目标> -p <端口> - 扫描指定端口",
                    "scan <目标> --type <类型> - 指定扫描类型",
                    "scan <目标> --timeout <秒> - 设置超时时间",
                    "scan <目标> --threads <数量> - 设置并发线程"
                ],
                "examples": [
                    "scan 192.168.1.1",
                    "scan localhost -p 80,443,22",
                    "scan 10.0.0.1 --type syn",
                    "scan 192.168.1.0/24 -p 1-1000",
                    "scan target.com --timeout 30 --threads 50"
                ],
                "notes": [
                    "仅扫描授权目标",
                    "大规模扫描可能被检测",
                    "使用隐蔽扫描避免被发现",
                    "注意扫描速度和目标负载"
                ]
            },
            "ai": {
                "description": "AI助手管理",
                "usage": [
                    "ai providers - 查看AI提供商",
                    "ai switch <提供商> - 切换AI提供商",
                    "ai test - 测试AI连接",
                    "ai config <提供商> - 配置AI提供商",
                    "ai analyze <数据> - AI分析功能"
                ],
                "examples": [
                    "ai providers",
                    "ai switch openai",
                    "ai test",
                    "ai config deepseek --api-key sk-xxx",
                    "ai analyze scan_results.json"
                ],
                "notes": [
                    "需要配置有效的API密钥",
                    "支持多个AI提供商",
                    "可以设置备用提供商",
                    "API调用可能产生费用"
                ]
            },
            "attack": {
                "description": "攻击模拟器功能",
                "usage": [
                    "attack create <会话名> <目标> - 创建攻击会话",
                    "attack list - 列出活动会话",
                    "attack status <会话ID> - 查看会话状态",
                    "attack stop <会话ID> - 停止攻击会话",
                    "attack payload <类型> - 生成攻击载荷"
                ],
                "examples": [
                    "attack create test_session 192.168.1.100",
                    "attack list",
                    "attack status session_001",
                    "attack payload sql_injection",
                    "attack stop session_001"
                ],
                "notes": [
                    "仅在授权环境中使用",
                    "记录所有攻击活动",
                    "遵守法律法规要求",
                    "定期清理会话数据"
                ]
            },
            "defense": {
                "description": "防御系统功能",
                "usage": [
                    "defense start <网络范围> - 启动监控",
                    "defense stop - 停止监控",
                    "defense status - 查看监控状态",
                    "defense events - 查看安全事件",
                    "defense response <事件ID> - 执行响应"
                ],
                "examples": [
                    "defense start 192.168.1.0/24",
                    "defense status",
                    "defense events --last 24h",
                    "defense response event_001",
                    "defense stop"
                ],
                "notes": [
                    "需要网络监控权限",
                    "实时检测威胁活动",
                    "自动生成响应建议",
                    "保存完整事件日志"
                ]
            },
            "ctf": {
                "description": "CTF解题器功能",
                "usage": [
                    "ctf analyze <题目文件> - 分析题目",
                    "ctf solve <题目ID> - 自动解题",
                    "ctf tools - 查看可用工具",
                    "ctf history - 查看解题历史",
                    "ctf types - 查看支持的题目类型"
                ],
                "examples": [
                    "ctf analyze challenge.txt",
                    "ctf solve web_001",
                    "ctf tools --category crypto",
                    "ctf history --date 2024-01-01",
                    "ctf types"
                ],
                "notes": [
                    "支持多种题目类型",
                    "集成常用CTF工具",
                    "提供解题思路分析",
                    "记录解题过程和结果"
                ]
            },
            "parameters": {
                "description": "参数格式说明",
                "usage": [
                    "help parameters - 查看所有参数格式",
                    "help parameters <类型> - 查看特定参数格式"
                ],
                "examples": [
                    "help parameters ip_address",
                    "help parameters port_range",
                    "help parameters scan_type"
                ],
                "notes": [
                    "严格按照格式输入参数",
                    "使用示例作为参考",
                    "检查参数有效性"
                ]
            },
            "troubleshooting": {
                "description": "故障排除指南",
                "usage": [
                    "help troubleshooting - 查看常见问题",
                    "logs show - 查看系统日志",
                    "status check - 检查系统状态"
                ],
                "examples": [
                    "help troubleshooting",
                    "logs show --level error",
                    "status check --verbose"
                ],
                "notes": [
                    "查看错误日志获取详细信息",
                    "检查网络连接和权限",
                    "确认配置文件正确性",
                    "联系技术支持获取帮助"
                ]
            }
        }
    
    def show_troubleshooting_guide(self) -> None:
        """Show comprehensive troubleshooting guide."""
        print("\n🔧 故障排除指南")
        print("="*60)
        
        troubleshooting_sections = {
            "常见错误": [
                "配置文件未找到 → 复制config_template.json并重命名为config.json",
                "API密钥无效 → 检查密钥格式、有效期和配额",
                "网络连接失败 → 检查网络设置、代理和防火墙",
                "权限不足 → 以管理员权限运行程序或使用sudo",
                "端口被占用 → 使用netstat -an检查端口使用情况",
                "依赖包缺失 → 运行pip install -r requirements.txt",
                "Python版本不兼容 → 确保使用Python 3.8+版本"
            ],
            "性能问题": [
                "扫描速度慢 → 调整并发线程数量 (--threads 参数)",
                "内存使用过高 → 减少并发会话数量或增加系统内存",
                "AI响应慢 → 检查网络连接、API配额和服务器负载",
                "日志文件过大 → 启用日志轮转功能或清理旧日志",
                "CPU使用率高 → 降低扫描频率或减少并发操作",
                "磁盘空间不足 → 清理临时文件和旧日志"
            ],
            "配置问题": [
                "配置验证失败 → 检查JSON格式、必需字段和数据类型",
                "加密密钥错误 → 删除.salt文件重新生成加密密钥",
                "路径不存在 → 检查文件和目录路径，使用绝对路径",
                "权限配置错误 → 检查文件访问权限 (chmod/chown)",
                "配置文件损坏 → 从备份恢复或重新创建配置",
                "环境变量未设置 → 检查必需的环境变量配置"
            ],
            "网络问题": [
                "目标不可达 → 检查目标IP、网络连通性和路由",
                "扫描被阻止 → 使用更隐蔽的扫描方式或调整扫描速度",
                "连接超时 → 增加超时时间设置 (--timeout 参数)",
                "DNS解析失败 → 检查DNS设置或使用IP地址",
                "防火墙阻止 → 检查本地和目标防火墙规则",
                "代理配置错误 → 检查HTTP/HTTPS代理设置"
            ],
            "工具和依赖": [
                "nmap未找到 → 安装nmap: apt-get install nmap 或下载安装包",
                "Python包导入失败 → 检查虚拟环境和包安装",
                "系统工具缺失 → 安装必需的系统工具和库",
                "版本不兼容 → 检查工具版本兼容性",
                "路径配置错误 → 将工具路径添加到系统PATH"
            ]
        }
        
        for section, items in troubleshooting_sections.items():
            print(f"\n📋 {section}:")
            for item in items:
                print(f"  • {item}")
        
        print("\n💡 获取更多帮助:")
        print("  • 查看系统日志: logs show --level error")
        print("  • 检查系统状态: status check --verbose")
        print("  • 验证配置: config validate")
        print("  • 重置配置: config reset")
        print("  • 测试网络连接: ping <目标IP>")
        print("  • 检查端口状态: netstat -an | grep <端口>")
        print("  • 查看进程状态: ps aux | grep python")
        
        print("\n🆘 紧急情况处理:")
        print("  • 程序无响应 → Ctrl+C 强制中断")
        print("  • 配置文件损坏 → 删除config.json重新配置")
        print("  • 系统资源耗尽 → 重启程序或系统")
        print("  • 数据丢失 → 检查备份文件夹")
        print("="*60)
    
    def show_parameter_help_all(self) -> None:
        """Show help for all parameter types."""
        print("\n📋 参数格式说明")
        print("="*60)
        
        for param_type in self.parameter_validator.parameter_formats.keys():
            self.parameter_validator.show_parameter_help(param_type)
            print()
    
    def _get_examples(self) -> Dict[str, List[str]]:
        """Get usage examples by category."""
        return {
            "基本操作": [
                "help - 显示帮助信息",
                "help <主题> - 查看特定主题帮助",
                "status - 查看系统状态",
                "config show - 显示当前配置",
                "clear - 清屏",
                "exit - 退出系统"
            ],
            "AI助手管理": [
                "ai providers - 查看所有AI提供商",
                "ai switch openai - 切换到OpenAI",
                "ai test - 测试当前AI连接",
                "ai config deepseek --api-key sk-xxx - 配置API密钥",
                "ai analyze scan_results.json - AI分析数据"
            ],
            "攻击模拟": [
                "scan localhost - 扫描本地主机",
                "scan 192.168.1.1 -p 80,443,22 - 扫描指定端口",
                "scan 10.0.0.0/24 --type syn - 网段SYN扫描",
                "attack create test_session 192.168.1.100 - 创建攻击会话",
                "attack payload sql_injection - 生成SQL注入载荷"
            ],
            "防御系统": [
                "defense start 192.168.1.0/24 - 启动网络监控",
                "defense status - 查看监控状态",
                "defense events --last 1h - 查看最近1小时事件",
                "defense response event_001 - 执行事件响应",
                "defense stop - 停止监控"
            ],
            "CTF解题": [
                "ctf analyze challenge.txt - 分析挑战题目",
                "ctf solve web_001 - 自动解Web题",
                "ctf tools --category crypto - 查看密码学工具",
                "ctf history --date 2024-01-01 - 查看解题历史",
                "ctf types - 查看支持的题目类型"
            ],
            "配置管理": [
                "config show - 显示完整配置",
                "config edit api_keys - 编辑API密钥",
                "config validate - 验证配置有效性",
                "config backup backup_20240101.json - 备份配置",
                "config restore backup_20240101.json - 恢复配置"
            ],
            "故障排除": [
                "logs show --level error - 查看错误日志",
                "status check --verbose - 详细状态检查",
                "help troubleshooting - 查看故障排除指南",
                "help parameters ip_address - 查看IP地址格式",
                "config reset - 重置配置到默认值"
            ]
        }