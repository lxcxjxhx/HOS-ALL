"""
基础抽象类 - 提供通用的基础功能实现
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from abc import ABC

from .interfaces import ILogger
from .exceptions import CybersecurityPlatformError


class BaseComponent(ABC):
    """基础组件抽象类"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        self.component_id = str(uuid.uuid4())
        self.created_at = datetime.now()
        self.logger = logger
        self._is_initialized = False
        self._is_running = False
    
    async def initialize(self) -> bool:
        """初始化组件"""
        try:
            await self._initialize_component()
            self._is_initialized = True
            if self.logger:
                self.logger.log_info(f"组件 {self.__class__.__name__} 初始化成功", 
                                   {"component_id": self.component_id})
            return True
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"组件 {self.__class__.__name__} 初始化失败", e,
                                    {"component_id": self.component_id})
            raise CybersecurityPlatformError(f"组件初始化失败: {str(e)}")
    
    async def start(self) -> bool:
        """启动组件"""
        if not self._is_initialized:
            await self.initialize()
        
        try:
            await self._start_component()
            self._is_running = True
            if self.logger:
                self.logger.log_info(f"组件 {self.__class__.__name__} 启动成功",
                                   {"component_id": self.component_id})
            return True
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"组件 {self.__class__.__name__} 启动失败", e,
                                    {"component_id": self.component_id})
            raise CybersecurityPlatformError(f"组件启动失败: {str(e)}")
    
    async def stop(self) -> bool:
        """停止组件"""
        try:
            await self._stop_component()
            self._is_running = False
            if self.logger:
                self.logger.log_info(f"组件 {self.__class__.__name__} 停止成功",
                                   {"component_id": self.component_id})
            return True
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"组件 {self.__class__.__name__} 停止失败", e,
                                    {"component_id": self.component_id})
            raise CybersecurityPlatformError(f"组件停止失败: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """获取组件状态"""
        return {
            "component_id": self.component_id,
            "component_name": self.__class__.__name__,
            "is_initialized": self._is_initialized,
            "is_running": self._is_running,
            "created_at": self.created_at.isoformat(),
            "uptime": (datetime.now() - self.created_at).total_seconds()
        }
    
    async def _initialize_component(self) -> None:
        """子类实现的初始化逻辑"""
        pass
    
    async def _start_component(self) -> None:
        """子类实现的启动逻辑"""
        pass
    
    async def _stop_component(self) -> None:
        """子类实现的停止逻辑"""
        pass


class BaseSession:
    """基础会话类"""
    
    def __init__(self, session_type: str, user_id: str = None):
        self.session_id = str(uuid.uuid4())
        self.session_type = session_type
        self.user_id = user_id or "anonymous"
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.is_active = True
        self.metadata = {}
    
    def update_activity(self) -> None:
        """更新会话活动时间"""
        self.last_activity = datetime.now()
    
    def add_metadata(self, key: str, value: Any) -> None:
        """添加会话元数据"""
        self.metadata[key] = value
        self.update_activity()
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """获取会话元数据"""
        return self.metadata.get(key, default)
    
    def close_session(self) -> None:
        """关闭会话"""
        self.is_active = False
        self.update_activity()
    
    def get_session_info(self) -> Dict[str, Any]:
        """获取会话信息"""
        return {
            "session_id": self.session_id,
            "session_type": self.session_type,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "is_active": self.is_active,
            "duration": (self.last_activity - self.created_at).total_seconds(),
            "metadata": self.metadata
        }


class BaseManager(BaseComponent):
    """基础管理器类"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self._sessions = {}
        self._lock = asyncio.Lock()
    
    async def create_session(self, session_type: str, user_id: str = None, **kwargs) -> str:
        """创建会话"""
        async with self._lock:
            session = BaseSession(session_type, user_id)
            for key, value in kwargs.items():
                session.add_metadata(key, value)
            
            self._sessions[session.session_id] = session
            
            if self.logger:
                self.logger.log_info(f"创建会话: {session_type}",
                                   {"session_id": session.session_id, "user_id": user_id})
            
            return session.session_id
    
    async def get_session(self, session_id: str) -> Optional[BaseSession]:
        """获取会话"""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session and session.is_active:
                session.update_activity()
                return session
            return None
    
    async def close_session(self, session_id: str) -> bool:
        """关闭会话"""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.close_session()
                if self.logger:
                    self.logger.log_info(f"关闭会话",
                                       {"session_id": session_id})
                return True
            return False
    
    async def cleanup_expired_sessions(self, timeout_seconds: int = 3600) -> int:
        """清理过期会话"""
        async with self._lock:
            current_time = datetime.now()
            expired_sessions = []
            
            for session_id, session in self._sessions.items():
                if (current_time - session.last_activity).total_seconds() > timeout_seconds:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self._sessions[session_id]
            
            if expired_sessions and self.logger:
                self.logger.log_info(f"清理了 {len(expired_sessions)} 个过期会话")
            
            return len(expired_sessions)
    
    def get_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """获取活跃会话列表"""
        return {
            session_id: session.get_session_info()
            for session_id, session in self._sessions.items()
            if session.is_active
        }