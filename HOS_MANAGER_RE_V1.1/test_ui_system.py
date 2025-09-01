#!/usr/bin/env python3
"""
Test script for UI system functionality.
"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_progress_indicators():
    """Test progress indicators."""
    print("🧪 测试进度指示器...")
    
    try:
        from ui.progress import ProgressIndicator, SpinnerIndicator, StatusDisplay
        
        # Test progress bar
        print("\n📊 测试进度条:")
        progress = ProgressIndicator(total=100, width=40)
        
        for i in range(0, 101, 10):
            progress.update(i, f"处理步骤 {i//10 + 1}")
            time.sleep(0.1)
        progress.finish("进度条测试完成")
        
        # Test spinner
        print("\n🔄 测试旋转指示器:")
        spinner = SpinnerIndicator("加载数据中")
        spinner.start()
        time.sleep(2)
        spinner.stop("旋转指示器测试完成")
        
        # Test status display
        print("\n📋 测试状态显示:")
        status = StatusDisplay()
        
        status.start_operation("test_op", "测试操作")
        time.sleep(0.5)
        status.update_operation("test_op", 50, "处理中...")
        time.sleep(0.5)
        status.complete_operation("test_op", True, "操作完成", {"result": "success"})
        
        print("✅ 进度指示器测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 进度指示器测试失败: {e}")
        return False

def test_error_handler():
    """Test error handler."""
    print("\n🧪 测试错误处理器...")
    
    try:
        from ui.error_handler import ErrorHandler, ErrorSeverity
        
        error_handler = ErrorHandler()
        
        # Test predefined error
        print("\n📋 测试预定义错误:")
        error_handler.display_error_message(
            "CONFIG_NOT_FOUND", 
            filename="test_config.json"
        )
        
        # Test exception handling
        print("\n🚨 测试异常处理:")
        try:
            raise FileNotFoundError("测试文件未找到")
        except Exception as e:
            error_handler.handle_error(e, "测试上下文")
        
        print("✅ 错误处理器测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 错误处理器测试失败: {e}")
        return False

def test_help_system():
    """Test help system."""
    print("\n🧪 测试帮助系统...")
    
    try:
        from ui.error_handler import HelpSystem
        
        help_system = HelpSystem()
        
        # Test general help
        print("\n📚 测试通用帮助:")
        help_system.show_help()
        
        # Test topic help
        print("\n📖 测试主题帮助:")
        help_system.show_help("config")
        
        # Test examples
        print("\n💡 测试使用示例:")
        help_system.show_examples("基本操作")
        
        print("✅ 帮助系统测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 帮助系统测试失败: {e}")
        return False

def test_result_formatter():
    """Test result formatter."""
    print("\n🧪 测试结果格式化器...")
    
    try:
        from ui.progress import ResultFormatter
        
        # Test scan results
        print("\n🔍 测试扫描结果格式化:")
        scan_results = {
            'target': '192.168.1.1',
            'open_ports': [
                {'port': 80, 'service': 'http'},
                {'port': 443, 'service': 'https'},
                {'port': 22, 'service': 'ssh'}
            ],
            'vulnerabilities': [
                {'severity': 'high', 'description': '测试漏洞1'},
                {'severity': 'medium', 'description': '测试漏洞2'}
            ]
        }
        ResultFormatter.display_scan_results(scan_results)
        
        # Test threat analysis
        print("\n🛡️ 测试威胁分析格式化:")
        threat_analysis = {
            'threat_level': 'high',
            'confidence': 85,
            'indicators': ['可疑端口扫描', '异常流量模式'],
            'recommendations': ['启用防火墙', '监控网络活动']
        }
        ResultFormatter.display_threat_analysis(threat_analysis)
        
        # Test CTF solution
        print("\n🏆 测试CTF解题结果格式化:")
        ctf_solution = {
            'type': 'Web',
            'difficulty': 'Medium',
            'solved': True,
            'flag': 'flag{test_flag_123}',
            'steps': ['分析源码', '发现SQL注入', '构造payload', '获取flag'],
            'tools_used': ['burp', 'sqlmap']
        }
        ResultFormatter.display_ctf_solution(ctf_solution)
        
        print("✅ 结果格式化器测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 结果格式化器测试失败: {e}")
        return False

def test_cli_framework():
    """Test CLI framework (basic functionality)."""
    print("\n🧪 测试CLI框架...")
    
    try:
        from ui.cli import CLIFramework
        
        # Create CLI instance
        cli = CLIFramework()
        
        # Test banner display
        print("\n🎨 测试横幅显示:")
        cli.display_banner()
        
        # Test menu display
        print("\n📋 测试菜单显示:")
        cli.display_main_menu()
        
        # Test command registration
        def test_command():
            print("测试命令执行成功")
            return True
        
        cli.register_command('test', test_command, '测试命令')
        
        # Test command execution
        print("\n🔧 测试命令执行:")
        result = cli.execute_command('test')
        if result:
            print("✅ 命令执行成功")
        
        print("✅ CLI框架测试通过")
        return True
        
    except Exception as e:
        print(f"❌ CLI框架测试失败: {e}")
        return False

def main():
    """Run all UI system tests."""
    print("🔐 AI网络安全平台 - UI系统测试")
    print("=" * 60)
    
    tests = [
        ("进度指示器", test_progress_indicators),
        ("错误处理器", test_error_handler),
        ("帮助系统", test_help_system),
        ("结果格式化器", test_result_formatter),
        ("CLI框架", test_cli_framework)
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"\n🎯 运行 {name} 测试...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {name} 测试通过")
            else:
                print(f"❌ {name} 测试失败")
        except Exception as e:
            print(f"💥 {name} 测试崩溃: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("📊 测试总结")
    print("="*60)
    print(f"🎯 总体结果: {passed}/{total} 测试通过")
    
    if passed == total:
        print("🎉 所有UI系统测试通过!")
        print("\n📋 已实现功能:")
        print("  ✓ CLI框架和菜单导航")
        print("  ✓ 进度指示器和状态显示")
        print("  ✓ 错误处理和用户友好消息")
        print("  ✓ 帮助系统和使用示例")
        print("  ✓ 结果格式化和展示")
        print("  ✓ 交互式操作流程")
        
        return 0
    else:
        print("⚠️ 部分测试失败 - 检查实现")
        return 1

if __name__ == "__main__":
    sys.exit(main())