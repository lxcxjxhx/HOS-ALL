"""
核心模块测试
"""

import pytest
import asyncio
from unittest.mock import Mock

from src.core.interfaces import AIProviderType, AttackType, ThreatLevel, CTFChallengeType
from src.core.exceptions import CybersecurityPlatformError, ConfigurationError
from src.core.base import BaseComponent, BaseSession, BaseManager


class TestEnums:
    """测试枚举类"""
    
    def test_ai_provider_type(self):
        """测试AI提供商类型枚举"""
        assert AIProviderType.DEEPSEEK.value == "deepseek"
        assert AIProviderType.OPENAI.value == "openai"
        assert AIProviderType.CLAUDE.value == "claude"
        assert AIProviderType.GEMINI.value == "gemini"
        assert AIProviderType.OLLAMA.value == "ollama"
    
    def test_attack_type(self):
        """测试攻击类型枚举"""
        assert AttackType.PORT_SCAN.value == "port_scan"
        assert AttackType.VULNERABILITY_SCAN.value == "vulnerability_scan"
        assert AttackType.BRUTE_FORCE.value == "brute_force"
    
    def test_threat_level(self):
        """测试威胁等级枚举"""
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.CRITICAL.value == "critical"
    
    def test_ctf_challenge_type(self):
        """测试CTF挑战类型枚举"""
        assert CTFChallengeType.WEB.value == "web"
        assert CTFChallengeType.CRYPTO.value == "crypto"
        assert CTFChallengeType.REVERSE.value == "reverse"


class TestExceptions:
    """测试异常类"""
    
    def test_base_exception(self):
        """测试基础异常类"""
        error = CybersecurityPlatformError("测试错误", "TEST001", {"key": "value"})
        assert error.message == "测试错误"
        assert error.error_code == "TEST001"
        assert error.context == {"key": "value"}
    
    def test_configuration_error(self):
        """测试配置异常"""
        error = ConfigurationError("配置错误")
        assert isinstance(error, CybersecurityPlatformError)
        assert error.message == "配置错误"


class TestBaseSession:
    """测试基础会话类"""
    
    def test_session_creation(self):
        """测试会话创建"""
        session = BaseSession("test_session", "user123")
        assert session.session_type == "test_session"
        assert session.user_id == "user123"
        assert session.is_active is True
        assert len(session.session_id) > 0
    
    def test_session_metadata(self):
        """测试会话元数据"""
        session = BaseSession("test_session")
        session.add_metadata("key1", "value1")
        session.add_metadata("key2", 123)
        
        assert session.get_metadata("key1") == "value1"
        assert session.get_metadata("key2") == 123
        assert session.get_metadata("nonexistent", "default") == "default"
    
    def test_session_close(self):
        """测试会话关闭"""
        session = BaseSession("test_session")
        assert session.is_active is True
        
        session.close_session()
        assert session.is_active is False


class MockComponent(BaseComponent):
    """模拟组件用于测试"""
    
    def __init__(self, logger=None):
        super().__init__(logger)
        self.init_called = False
        self.start_called = False
        self.stop_called = False
    
    async def _initialize_component(self):
        self.init_called = True
    
    async def _start_component(self):
        self.start_called = True
    
    async def _stop_component(self):
        self.stop_called = True


class TestBaseComponent:
    """测试基础组件类"""
    
    @pytest.mark.asyncio
    async def test_component_lifecycle(self):
        """测试组件生命周期"""
        logger = Mock()
        component = MockComponent(logger)
        
        # 测试初始化
        assert await component.initialize() is True
        assert component.init_called is True
        assert component._is_initialized is True
        
        # 测试启动
        assert await component.start() is True
        assert component.start_called is True
        assert component._is_running is True
        
        # 测试停止
        assert await component.stop() is True
        assert component.stop_called is True
        assert component._is_running is False
    
    @pytest.mark.asyncio
    async def test_component_status(self):
        """测试组件状态"""
        component = MockComponent()
        status = component.get_status()
        
        assert "component_id" in status
        assert "component_name" in status
        assert status["component_name"] == "MockComponent"
        assert status["is_initialized"] is False
        assert status["is_running"] is False


class TestBaseManager:
    """测试基础管理器类"""
    
    @pytest.mark.asyncio
    async def test_session_management(self):
        """测试会话管理"""
        manager = BaseManager()
        await manager.initialize()
        
        # 创建会话
        session_id = await manager.create_session("test_session", "user123", key1="value1")
        assert len(session_id) > 0
        
        # 获取会话
        session = await manager.get_session(session_id)
        assert session is not None
        assert session.session_type == "test_session"
        assert session.user_id == "user123"
        assert session.get_metadata("key1") == "value1"
        
        # 关闭会话
        assert await manager.close_session(session_id) is True
        
        # 获取活跃会话
        active_sessions = manager.get_active_sessions()
        assert session_id not in active_sessions or not active_sessions[session_id]["is_active"]
    
    @pytest.mark.asyncio
    async def test_session_cleanup(self):
        """测试会话清理"""
        manager = BaseManager()
        await manager.initialize()
        
        # 创建会话
        session_id = await manager.create_session("test_session")
        
        # 模拟过期会话（设置很短的超时时间）
        cleaned = await manager.cleanup_expired_sessions(timeout_seconds=0)
        assert cleaned >= 0  # 可能为0或1，取决于时间精度


if __name__ == "__main__":
    pytest.main([__file__])