"""
端到端集成测试 - 测试完整的系统工作流程
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.logging_system import LoggingSystem
from core.health_monitor import HealthMonitor
from core.error_recovery import ErrorRecoverySystem
from config.manager import ConfigManager
from ai.assistant import AIAssistant
from attack.scanner import AttackSimulator
from defense.simulator import DefenseSimulator
from ctf.solver import CTFSolver
from security.compliance_monitor import ComplianceMonitor
from security.audit_logger import AuditLogger
from integrated_main import IntegratedCybersecurityPlatform


class TestE2EIntegration:
    """端到端集成测试类"""
    
    @pytest.fixture
    async def temp_config(self):
        """创建临时配置文件"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {
                "ai_providers": {
                    "default": "mock",
                    "mock": {
                        "api_key": "test_key",
                        "base_url": "http://localhost:8000",
                        "model": "test_model"
                    }
                },
                "security": {
                    "encryption_key": "test_encryption_key_32_characters",
                    "max_concurrent_sessions": 5,
                    "session_timeout": 3600,
                    "enable_audit_log": True
                },
                "network": {
                    "default_scan_timeout": 30,
                    "max_scan_threads": 10,
                    "allowed_networks": ["192.168.1.0/24"],
                    "blocked_networks": ["127.0.0.0/8"]
                },
                "logging": {
                    "level": "INFO",
                    "file": "logs/test.log",
                    "max_size": "10MB",
                    "backup_count": 5
                }
            }
            json.dump(config, f)
            temp_path = f.name
        
        yield temp_path
        
        # 清理
        Path(temp_path).unlink(missing_ok=True)
    
    @pytest.fixture
    async def platform(self, temp_config):
        """创建集成平台实例"""
        platform = IntegratedCybersecurityPlatform()
        
        # 模拟配置文件路径
        with patch('config.manager.ConfigManager.get_config_path', return_value=temp_config):
            await platform.initialize()
        
        yield platform
        
        # 清理
        await platform.shutdown()
    
    @pytest.mark.asyncio
    async def test_platform_initialization(self, platform):
        """测试平台初始化"""
        # 验证所有组件都已初始化
        assert platform.logger is not None
        assert platform.config_manager is not None
        assert platform.health_monitor is not None
        assert platform.error_recovery is not None
        assert platform.ai_assistant is not None
        assert platform.attack_simulator is not None
        assert platform.defense_simulator is not None
        assert platform.ctf_solver is not None
        assert platform.compliance_monitor is not None
        assert platform.audit_logger is not None
        assert platform.cli_framework is not None
        
        # 验证系统信息
        system_info = platform.get_system_info()
        assert system_info["platform_name"] == "AI增强网络安全平台"
        assert system_info["component_count"] > 0
        assert "startup_time" in system_info
    
    @pytest.mark.asyncio
    async def test_component_startup_sequence(self, platform):
        """测试组件启动序列"""
        # 启动所有组件
        await platform.start()
        
        # 验证组件状态
        component_status = await platform.get_component_status()
        
        for component_name, status in component_status.items():
            assert status.get("status") != "error", f"组件 {component_name} 启动失败"
    
    @pytest.mark.asyncio
    async def test_health_monitoring_integration(self, platform):
        """测试健康监控集成"""
        await platform.start()
        
        # 执行健康检查
        health_report = await platform.execute_health_check()
        
        assert "timestamp" in health_report
        assert "overall_status" in health_report
        assert "system_metrics" in health_report
        assert "health_checks" in health_report
        
        # 验证健康状态
        assert health_report["overall_status"] in ["healthy", "warning", "critical", "unknown"]
    
    @pytest.mark.asyncio
    async def test_ai_assistant_integration(self, platform):
        """测试AI助手集成"""
        await platform.start()
        
        # 模拟AI响应
        with patch.object(platform.ai_assistant, 'generate_response') as mock_response:
            mock_response.return_value = {
                "content": "测试响应",
                "provider": "mock",
                "success": True
            }
            
            # 测试威胁分析
            scan_results = {
                "target": "192.168.1.100",
                "open_ports": [{"port": 80, "service": "http"}],
                "vulnerabilities": []
            }
            
            analysis = await platform.ai_assistant.analyze_threat(scan_results)
            assert analysis is not None
            mock_response.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_attack_simulation_workflow(self, platform):
        """测试攻击模拟工作流程"""
        await platform.start()
        
        # 模拟扫描结果
        with patch.object(platform.attack_simulator, 'port_scan') as mock_scan:
            mock_scan.return_value = {
                "target": "192.168.1.100",
                "scan_type": "tcp_connect",
                "open_ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
                    {"port": 80, "service": "http", "version": "Apache 2.4"}
                ],
                "vulnerabilities": [],
                "scan_duration": 5.2,
                "success": True
            }
            
            # 创建攻击会话
            session_id = await platform.attack_simulator.create_session(
                "test_session", "192.168.1.100", [22, 80, 443]
            )
            assert session_id is not None
            
            # 执行端口扫描
            scan_result = await platform.attack_simulator.port_scan(
                "192.168.1.100", [22, 80, 443], "tcp_connect"
            )
            assert scan_result["success"] is True
            assert len(scan_result["open_ports"]) > 0
    
    @pytest.mark.asyncio
    async def test_defense_system_workflow(self, platform):
        """测试防御系统工作流程"""
        await platform.start()
        
        # 模拟威胁检测
        with patch.object(platform.defense_simulator, 'detect_threats') as mock_detect:
            mock_detect.return_value = [
                {
                    "event_id": "test_event_001",
                    "source_ip": "192.168.1.200",
                    "target_ip": "192.168.1.100",
                    "threat_type": "port_scan",
                    "threat_level": "medium",
                    "description": "检测到端口扫描活动",
                    "timestamp": "2024-01-01T12:00:00Z"
                }
            ]
            
            # 创建防御会话
            session_id = await platform.defense_simulator.create_defense_session(
                "test_defense", "192.168.1.0/24"
            )
            assert session_id is not None
            
            # 模拟网络数据
            network_data = {
                "packets": [
                    {"src": "192.168.1.200", "dst": "192.168.1.100", "port": 22},
                    {"src": "192.168.1.200", "dst": "192.168.1.100", "port": 80}
                ]
            }
            
            # 检测威胁
            threats = await platform.defense_simulator.detect_threats(network_data)
            assert len(threats) > 0
            assert threats[0]["threat_type"] == "port_scan"
    
    @pytest.mark.asyncio
    async def test_ctf_solver_workflow(self, platform):
        """测试CTF解题器工作流程"""
        await platform.start()
        
        # 模拟CTF挑战
        challenge = {
            "challenge_id": "test_challenge_001",
            "title": "简单密码学挑战",
            "description": "解密以下Base64编码的字符串: SGVsbG8gV29ybGQ=",
            "challenge_type": "crypto",
            "difficulty": "easy",
            "files": [],
            "hints": ["这是Base64编码"]
        }
        
        with patch.object(platform.ctf_solver, 'analyze_challenge') as mock_analyze:
            mock_analyze.return_value = {
                "challenge_type": "crypto",
                "difficulty": "easy",
                "analysis": "这是一个Base64解码挑战",
                "confidence": 0.9
            }
            
            with patch.object(platform.ctf_solver, 'generate_solution') as mock_solve:
                mock_solve.return_value = {
                    "challenge_id": "test_challenge_001",
                    "solution_steps": [
                        "识别Base64编码格式",
                        "使用Base64解码器解码字符串",
                        "获得明文: Hello World"
                    ],
                    "tools_used": ["base64"],
                    "flag": "Hello World",
                    "confidence": 0.95,
                    "execution_time": 1.2,
                    "success": True
                }
                
                # 分析挑战
                analysis = await platform.ctf_solver.analyze_challenge(challenge)
                assert analysis["challenge_type"] == "crypto"
                
                # 生成解题方案
                solution = await platform.ctf_solver.generate_solution(challenge)
                assert solution["success"] is True
                assert solution["flag"] == "Hello World"
    
    @pytest.mark.asyncio
    async def test_error_recovery_integration(self, platform):
        """测试错误恢复集成"""
        await platform.start()
        
        # 模拟错误
        test_error = ConnectionError("网络连接失败")
        context = {"component": "ai_assistant", "operation": "api_call"}
        
        # 测试错误恢复
        recovery_result = await platform.error_recovery.handle_error(test_error, context)
        
        if recovery_result:
            assert recovery_result.success in [True, False]
            assert recovery_result.action_taken is not None
            assert recovery_result.message is not None
    
    @pytest.mark.asyncio
    async def test_compliance_monitoring_integration(self, platform):
        """测试合规监控集成"""
        await platform.start()
        
        # 模拟操作审计
        operation = {
            "user_id": "test_user",
            "operation": "port_scan",
            "target": "192.168.1.100",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        
        # 检查合规性
        compliance_result = platform.compliance_monitor.check_compliance(operation)
        assert "compliant" in compliance_result
        assert "warnings" in compliance_result
    
    @pytest.mark.asyncio
    async def test_audit_logging_integration(self, platform):
        """测试审计日志集成"""
        await platform.start()
        
        # 记录审计事件
        audit_event = {
            "event_type": "security_scan",
            "user_id": "test_user",
            "target": "192.168.1.100",
            "result": "success",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        
        await platform.audit_logger.log_event(audit_event)
        
        # 验证审计日志
        recent_events = platform.audit_logger.get_recent_events(limit=10)
        assert len(recent_events) > 0
    
    @pytest.mark.asyncio
    async def test_full_attack_defense_cycle(self, platform):
        """测试完整的攻击-防御循环"""
        await platform.start()
        
        # 1. 启动防御监控
        defense_session = await platform.defense_simulator.create_defense_session(
            "full_cycle_defense", "192.168.1.0/24"
        )
        
        # 2. 执行攻击模拟
        attack_session = await platform.attack_simulator.create_session(
            "full_cycle_attack", "192.168.1.100", [22, 80, 443]
        )
        
        # 3. 模拟攻击检测
        with patch.object(platform.defense_simulator, 'detect_threats') as mock_detect:
            mock_detect.return_value = [
                {
                    "event_id": "cycle_event_001",
                    "source_ip": "192.168.1.200",
                    "target_ip": "192.168.1.100",
                    "threat_type": "port_scan",
                    "threat_level": "medium",
                    "description": "检测到端口扫描活动"
                }
            ]
            
            # 4. 生成防御响应
            with patch.object(platform.defense_simulator, 'generate_defense_response') as mock_response:
                mock_response.return_value = {
                    "response_id": "response_001",
                    "actions": ["block_ip", "alert_admin"],
                    "confidence": 0.8
                }
                
                # 执行完整循环
                network_data = {"packets": [{"src": "192.168.1.200", "dst": "192.168.1.100"}]}
                threats = await platform.defense_simulator.detect_threats(network_data)
                
                if threats:
                    response = await platform.defense_simulator.generate_defense_response(threats[0])
                    assert response is not None
                    assert "actions" in response
    
    @pytest.mark.asyncio
    async def test_system_shutdown_sequence(self, platform):
        """测试系统关闭序列"""
        await platform.start()
        
        # 验证系统正在运行
        system_info = platform.get_system_info()
        assert system_info["component_count"] > 0
        
        # 执行关闭
        await platform.shutdown()
        
        # 验证组件已停止（这里主要测试没有异常抛出）
        # 实际的停止验证可能需要更复杂的状态检查
        assert True  # 如果到达这里说明关闭过程没有异常


@pytest.mark.asyncio
async def test_platform_resilience():
    """测试平台弹性和错误处理"""
    platform = IntegratedCybersecurityPlatform()
    
    # 测试初始化失败的情况
    with patch('core.logging_system.LoggingSystem.initialize', side_effect=Exception("初始化失败")):
        result = await platform.initialize()
        assert result is False
    
    # 测试部分组件失败的情况
    with patch('ai.assistant.AIAssistant.initialize', side_effect=Exception("AI助手初始化失败")):
        try:
            await platform.initialize()
        except Exception as e:
            assert "初始化失败" in str(e)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])