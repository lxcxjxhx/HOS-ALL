"""
会话管理器 - 管理攻击会话的生命周期和状态
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import threading
import time

from .models import AttackSession, AttackStatus, AttackType
from core.base import BaseComponent
from core.interfaces import ILogger
from core.exceptions import CybersecurityPlatformError


class SessionManagerError(CybersecurityPlatformError):
    """会话管理器异常"""
    pass


class SessionManager(BaseComponent):
    """攻击会话管理器"""
    
    def __init__(self, config_manager, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.config_manager = config_manager
        self.sessions: Dict[str, AttackSession] = {}
        self.session_storage_path = Path("data/sessions")
        self.max_sessions = 50
        self.session_timeout = timedelta(hours=24)
        self.cleanup_interval = 3600  # 1小时清理一次
        
        # 线程安全锁
        self._lock = threading.RLock()
        
        # 清理任务
        self._cleanup_task = None
        self._cleanup_running = False
    
    async def _initialize_component(self) -> None:
        """初始化会话管理器"""
        # 创建存储目录
        self.session_storage_path.mkdir(parents=True, exist_ok=True)
        
        # 加载已存在的会话
        await self._load_existing_sessions()
        
        # 启动清理任务
        await self._start_cleanup_task()
        
        if self.logger:
            self.logger.log_info(f"会话管理器初始化完成，加载了 {len(self.sessions)} 个会话")
    
    async def _cleanup_component(self) -> None:
        """清理会话管理器"""
        self._cleanup_running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # 保存所有活跃会话
        await self._save_all_sessions()
        
        if self.logger:
            self.logger.log_info("会话管理器已清理")
    
    async def create_session(self, session_name: str, target: str, 
                           ports: List[int] = None, 
                           attack_types: List[AttackType] = None,
                           user_id: str = "anonymous") -> str:
        """创建新的攻击会话"""
        with self._lock:
            # 检查会话数量限制
            if len(self.sessions) >= self.max_sessions:
                await self._cleanup_expired_sessions()
                if len(self.sessions) >= self.max_sessions:
                    raise SessionManagerError(f"会话数量已达上限 {self.max_sessions}")
            
            # 创建新会话
            session = AttackSession(
                session_name=session_name,
                target=target,
                ports=ports or [],
                attack_types=attack_types or [],
                user_id=user_id
            )
            
            # 添加到内存
            self.sessions[session.session_id] = session
            
            # 保存到磁盘
            await self._save_session(session)
            
            if self.logger:
                self.logger.log_info(f"创建攻击会话: {session.session_name} ({session.session_id})")
            
            return session.session_id
    
    def get_session(self, session_id: str) -> Optional[AttackSession]:
        """获取会话"""
        with self._lock:
            return self.sessions.get(session_id)
    
    def update_session_status(self, session_id: str, status: AttackStatus, message: str = "") -> bool:
        """更新会话状态"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            session.update_status(status, message)
            
            # 异步保存
            asyncio.create_task(self._save_session(session))
            
            if self.logger:
                self.logger.log_info(f"会话 {session_id} 状态更新为: {status.value}")
            
            return True
    
    def add_session_log(self, session_id: str, log_type: str, message: str, 
                       data: Optional[Dict[str, Any]] = None) -> bool:
        """添加会话日志"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            session.add_log(log_type, message, data)
            
            # 异步保存
            asyncio.create_task(self._save_session(session))
            
            return True
    
    def list_sessions(self, user_id: Optional[str] = None, 
                     status: Optional[AttackStatus] = None) -> List[Dict[str, Any]]:
        """列出会话"""
        with self._lock:
            sessions = []
            
            for session in self.sessions.values():
                # 过滤条件
                if user_id and session.user_id != user_id:
                    continue
                if status and session.status != status:
                    continue
                
                sessions.append(session.get_summary())
            
            # 按创建时间排序
            sessions.sort(key=lambda x: x['created_at'], reverse=True)
            
            return sessions
    
    def get_active_sessions(self) -> List[str]:
        """获取活跃会话ID列表"""
        with self._lock:
            active_statuses = {
                AttackStatus.SCANNING,
                AttackStatus.ANALYZING,
                AttackStatus.ATTACKING
            }
            
            return [
                session_id for session_id, session in self.sessions.items()
                if session.status in active_statuses
            ]
    
    async def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            # 如果会话正在运行，先停止
            if session.status in {AttackStatus.SCANNING, AttackStatus.ANALYZING, AttackStatus.ATTACKING}:
                session.update_status(AttackStatus.STOPPED, "会话被用户删除")
            
            # 从内存中移除
            del self.sessions[session_id]
            
            # 删除磁盘文件
            session_file = self.session_storage_path / f"{session_id}.json"
            if session_file.exists():
                session_file.unlink()
            
            if self.logger:
                self.logger.log_info(f"删除会话: {session_id}")
            
            return True
    
    async def stop_session(self, session_id: str) -> bool:
        """停止会话"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            if session.status in {AttackStatus.SCANNING, AttackStatus.ANALYZING, AttackStatus.ATTACKING}:
                session.update_status(AttackStatus.STOPPED, "会话被用户停止")
                
                # 异步保存
                asyncio.create_task(self._save_session(session))
                
                if self.logger:
                    self.logger.log_info(f"停止会话: {session_id}")
                
                return True
            
            return False
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """获取会话统计信息"""
        with self._lock:
            stats = {
                "total_sessions": len(self.sessions),
                "active_sessions": len(self.get_active_sessions()),
                "status_distribution": {},
                "user_distribution": {},
                "oldest_session": None,
                "newest_session": None
            }
            
            # 统计状态分布
            for session in self.sessions.values():
                status = session.status.value
                stats["status_distribution"][status] = stats["status_distribution"].get(status, 0) + 1
                
                # 统计用户分布
                user = session.user_id
                stats["user_distribution"][user] = stats["user_distribution"].get(user, 0) + 1
            
            # 找到最老和最新的会话
            if self.sessions:
                sessions_by_time = sorted(self.sessions.values(), key=lambda x: x.created_at)
                stats["oldest_session"] = sessions_by_time[0].created_at.isoformat()
                stats["newest_session"] = sessions_by_time[-1].created_at.isoformat()
            
            return stats
    
    async def cleanup_expired_sessions(self) -> int:
        """清理过期会话"""
        return await self._cleanup_expired_sessions()
    
    async def _cleanup_expired_sessions(self) -> int:
        """内部清理过期会话方法"""
        with self._lock:
            current_time = datetime.now()
            expired_sessions = []
            
            for session_id, session in self.sessions.items():
                # 检查是否过期
                if current_time - session.updated_at > self.session_timeout:
                    # 只清理非活跃状态的会话
                    if session.status not in {AttackStatus.SCANNING, AttackStatus.ANALYZING, AttackStatus.ATTACKING}:
                        expired_sessions.append(session_id)
            
            # 删除过期会话
            for session_id in expired_sessions:
                await self.delete_session(session_id)
            
            if expired_sessions and self.logger:
                self.logger.log_info(f"清理了 {len(expired_sessions)} 个过期会话")
            
            return len(expired_sessions)
    
    async def _load_existing_sessions(self) -> None:
        """加载已存在的会话"""
        if not self.session_storage_path.exists():
            return
        
        loaded_count = 0
        
        for session_file in self.session_storage_path.glob("*.json"):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                
                # 重建会话对象
                session = self._deserialize_session(session_data)
                
                # 检查会话是否过期
                if datetime.now() - session.updated_at > self.session_timeout:
                    session_file.unlink()  # 删除过期会话文件
                    continue
                
                # 重置运行中的会话状态
                if session.status in {AttackStatus.SCANNING, AttackStatus.ANALYZING, AttackStatus.ATTACKING}:
                    session.update_status(AttackStatus.STOPPED, "系统重启后自动停止")
                
                self.sessions[session.session_id] = session
                loaded_count += 1
                
            except Exception as e:
                if self.logger:
                    self.logger.log_error(f"加载会话文件失败: {session_file}", e)
                # 删除损坏的会话文件
                try:
                    session_file.unlink()
                except:
                    pass
        
        if loaded_count > 0 and self.logger:
            self.logger.log_info(f"加载了 {loaded_count} 个已存在的会话")
    
    async def _save_session(self, session: AttackSession) -> None:
        """保存会话到磁盘"""
        try:
            session_file = self.session_storage_path / f"{session.session_id}.json"
            session_data = self._serialize_session(session)
            
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"保存会话失败: {session.session_id}", e)
    
    async def _save_all_sessions(self) -> None:
        """保存所有会话"""
        for session in self.sessions.values():
            await self._save_session(session)
    
    def _serialize_session(self, session: AttackSession) -> Dict[str, Any]:
        """序列化会话对象"""
        return {
            "session_id": session.session_id,
            "session_name": session.session_name,
            "target": session.target,
            "ports": session.ports,
            "attack_types": [at.value for at in session.attack_types],
            "status": session.status.value,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "user_id": session.user_id,
            "scan_results": [self._serialize_scan_result(sr) for sr in session.scan_results],
            "vulnerabilities": [self._serialize_vulnerability(v) for v in session.vulnerabilities],
            "payloads": [self._serialize_payload(p) for p in session.payloads],
            "attack_results": [self._serialize_attack_result(ar) for ar in session.attack_results],
            "logs": session.logs,
            "metadata": session.metadata
        }
    
    def _deserialize_session(self, data: Dict[str, Any]) -> AttackSession:
        """反序列化会话对象"""
        session = AttackSession(
            session_id=data["session_id"],
            session_name=data["session_name"],
            target=data["target"],
            ports=data["ports"],
            attack_types=[AttackType(at) for at in data["attack_types"]],
            status=AttackStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            user_id=data["user_id"]
        )
        
        # 恢复其他数据
        session.logs = data.get("logs", [])
        session.metadata = data.get("metadata", {})
        
        # 恢复扫描结果、漏洞等（简化处理）
        # 在实际应用中可能需要更复杂的反序列化逻辑
        
        return session
    
    def _serialize_scan_result(self, scan_result) -> Dict[str, Any]:
        """序列化扫描结果"""
        # 简化实现，实际应用中需要完整的序列化逻辑
        return {"scan_id": scan_result.scan_id, "target": scan_result.target}
    
    def _serialize_vulnerability(self, vulnerability) -> Dict[str, Any]:
        """序列化漏洞信息"""
        # 简化实现
        return {"vuln_id": vulnerability.vuln_id, "name": vulnerability.name}
    
    def _serialize_payload(self, payload) -> Dict[str, Any]:
        """序列化攻击载荷"""
        # 简化实现
        return {"payload_id": payload.payload_id, "name": payload.name}
    
    def _serialize_attack_result(self, attack_result) -> Dict[str, Any]:
        """序列化攻击结果"""
        # 简化实现
        return {"attack_id": attack_result.attack_id, "success": attack_result.success}
    
    async def _start_cleanup_task(self) -> None:
        """启动清理任务"""
        self._cleanup_running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self) -> None:
        """清理循环任务"""
        while self._cleanup_running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                if self._cleanup_running:
                    await self._cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.logger:
                    self.logger.log_error("会话清理任务异常", e)
                await asyncio.sleep(60)  # 出错后等待1分钟再继续