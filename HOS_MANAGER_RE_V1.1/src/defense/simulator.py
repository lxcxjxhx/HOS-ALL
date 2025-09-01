"""
防御模拟器 - 实现网络防御监控和响应功能
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import ipaddress

from .models import (
    DefenseSession, DefenseStatus, ThreatEvent, ThreatType, 
    DefenseResponse, ResponseAction, MonitoringRule, NetworkStatistics
)
from .network_monitor import NetworkMonitor
from .threat_detector import ThreatDetector
from .response_engine import ResponseEngine
from core.base import BaseComponent
from core.interfaces import ILogger, ThreatLevel
from core.exceptions import CybersecurityPlatformError


class DefenseSimulatorError(CybersecurityPlatformError):
    """防御模拟器异常"""
    pass


class DefenseSimulator(BaseComponent):
    """防御模拟器主类"""
    
    def __init__(self, config_manager, ai_assistant, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.config_manager = config_manager
        self.ai_assistant = ai_assistant
        
        # 子组件
        self.network_monitor = NetworkMonitor(logger)
        self.threat_detector = ThreatDetector(logger)
        self.response_engine = ResponseEngine(logger)
        
        # 会话管理
        self.sessions: Dict[str, DefenseSession] = {}
        
        # 配置
        self.max_sessions = 10
        self.default_monitoring_rules = []
        
    async def _initialize_component(self) -> None:
        """初始化防御模拟器"""
        # 初始化子组件
        await self.network_monitor.initialize()
        await self.threat_detector.initialize()
        await self.response_engine.initialize()
        
        # 加载默认监控规则
        self._load_default_rules()
        
        if self.logger:
            self.logger.log_info("防御模拟器初始化完成")
    
    async def _cleanup_component(self) -> None:
        """清理防御模拟器"""
        # 停止所有会话
        for session_id in list(self.sessions.keys()):
            await self.stop_defense_session(session_id)
        
        # 清理子组件
        await self.network_monitor.cleanup()
        await self.threat_detector.cleanup()
        await self.response_engine.cleanup()
        
        if self.logger:
            self.logger.log_info("防御模拟器已清理")
    
    async def create_defense_session(self, session_name: str, network_range: str,
                                   interface: str = None, user_id: str = "anonymous") -> str:
        """创建防御会话"""
        # 检查会话数量限制
        if len(self.sessions) >= self.max_sessions:
            raise DefenseSimulatorError(f"防御会话数量已达上限 {self.max_sessions}")
        
        # 验证网络范围
        if not self._validate_network_range(network_range):
            raise DefenseSimulatorError(f"无效的网络范围: {network_range}")
        
        # 创建会话
        session = DefenseSession(
            session_name=session_name,
            network_range=network_range,
            interface=interface or "",
            user_id=user_id
        )
        
        # 添加默认监控规则
        session.monitoring_rules = self._create_default_rules()
        
        # 保存会话
        self.sessions[session.session_id] = session
        
        if self.logger:
            self.logger.log_info(f"创建防御会话: {session_name} ({session.session_id})")
        
        return session.session_id
    
    async def start_monitoring(self, session_id: str) -> bool:
        """开始监控"""
        session = self.sessions.get(session_id)
        if not session:
            raise DefenseSimulatorError(f"会话不存在: {session_id}")
        
        if session.status == DefenseStatus.MONITORING:
            return True
        
        try:
            # 更新会话状态
            session.update_status(DefenseStatus.MONITORING, "开始网络监控")
            
            # 启动网络监控
            await self.network_monitor.start_monitoring(
                session, 
                session.interface,
                self._build_packet_filter(session)
            )
            
            # 注册数据包处理器
            self.network_monitor.register_packet_handler(
                session_id,
                lambda packet: asyncio.create_task(self._process_packet(session_id, packet))
            )
            
            # 启动威胁检测
            await self.threat_detector.start_detection(session)
            
            if self.logger:
                self.logger.log_info(f"开始监控会话: {session_id}")
            
            return True
            
        except Exception as e:
            session.update_status(DefenseStatus.ERROR, f"启动监控失败: {str(e)}")
            if self.logger:
                self.logger.log_error(f"启动监控失败: {session_id}", e)
            raise DefenseSimulatorError(f"启动监控失败: {str(e)}")
    
    async def stop_monitoring(self, session_id: str) -> bool:
        """停止监控"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        try:
            # 停止网络监控
            await self.network_monitor.stop_monitoring(session_id)
            
            # 注销数据包处理器
            self.network_monitor.unregister_packet_handler(session_id)
            
            # 停止威胁检测
            await self.threat_detector.stop_detection(session_id)
            
            # 更新会话状态
            session.update_status(DefenseStatus.STOPPED, "监控已停止")
            
            if self.logger:
                self.logger.log_info(f"停止监控会话: {session_id}")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"停止监控失败: {session_id}", e)
            return False
    
    async def stop_defense_session(self, session_id: str) -> bool:
        """停止防御会话"""
        if session_id not in self.sessions:
            return False
        
        # 先停止监控
        await self.stop_monitoring(session_id)
        
        # 移除会话
        del self.sessions[session_id]
        
        if self.logger:
            self.logger.log_info(f"停止防御会话: {session_id}")
        
        return True
    
    def get_session(self, session_id: str) -> Optional[DefenseSession]:
        """获取会话"""
        return self.sessions.get(session_id)
    
    def list_sessions(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出会话"""
        sessions = []
        
        for session in self.sessions.values():
            if user_id and session.user_id != user_id:
                continue
            
            sessions.append(session.get_summary())
        
        # 按创建时间排序
        sessions.sort(key=lambda x: x['created_at'], reverse=True)
        
        return sessions
    
    async def add_monitoring_rule(self, session_id: str, rule: MonitoringRule) -> bool:
        """添加监控规则"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        session.monitoring_rules.append(rule)
        session.add_log("rule_added", f"添加监控规则: {rule.name}")
        
        # 如果正在监控，更新威胁检测器
        if session.status == DefenseStatus.MONITORING:
            await self.threat_detector.update_rules(session_id, session.monitoring_rules)
        
        return True
    
    async def remove_monitoring_rule(self, session_id: str, rule_id: str) -> bool:
        """移除监控规则"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        # 查找并移除规则
        for i, rule in enumerate(session.monitoring_rules):
            if rule.rule_id == rule_id:
                removed_rule = session.monitoring_rules.pop(i)
                session.add_log("rule_removed", f"移除监控规则: {removed_rule.name}")
                
                # 如果正在监控，更新威胁检测器
                if session.status == DefenseStatus.MONITORING:
                    await self.threat_detector.update_rules(session_id, session.monitoring_rules)
                
                return True
        
        return False
    
    async def execute_response(self, session_id: str, response: DefenseResponse) -> bool:
        """执行防御响应"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        try:
            # 执行响应
            success = await self.response_engine.execute_response(response)
            
            # 更新响应状态
            response.executed = True
            response.execution_time = datetime.now()
            response.success = success
            
            # 添加到会话
            session.add_defense_response(response)
            
            if self.logger:
                status = "成功" if success else "失败"
                self.logger.log_info(f"执行防御响应 {status}: {response.action.value}")
            
            return success
            
        except Exception as e:
            response.executed = True
            response.execution_time = datetime.now()
            response.success = False
            response.error_message = str(e)
            
            session.add_defense_response(response)
            
            if self.logger:
                self.logger.log_error(f"执行防御响应失败: {response.action.value}", e)
            
            return False
    
    async def get_threat_analysis(self, session_id: str, event: ThreatEvent) -> Dict[str, Any]:
        """获取威胁分析"""
        try:
            # 构建分析上下文
            context = {
                "threat_type": event.threat_type.value,
                "source_ip": event.source_ip,
                "target_ip": event.target_ip,
                "severity": event.severity.value,
                "evidence_count": len(event.evidence)
            }
            
            # 调用AI助手进行分析
            analysis = await self.ai_assistant.analyze_threat(
                {
                    "event": {
                        "type": event.threat_type.value,
                        "source": event.source_ip,
                        "target": event.target_ip,
                        "description": event.description
                    }
                },
                context
            )
            
            return analysis
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("威胁分析失败", e)
            return {"error": str(e)}
    
    async def get_defense_suggestions(self, session_id: str, event: ThreatEvent) -> List[DefenseResponse]:
        """获取防御建议"""
        try:
            # 构建威胁信息
            threat_info = {
                "type": event.threat_type.value,
                "source": event.source_ip,
                "targets": [event.target_ip] if event.target_ip else [],
                "severity": event.severity.value,
                "confidence": event.confidence_score
            }
            
            # 调用AI助手获取防御建议
            suggestions = await self.ai_assistant.suggest_defense_measures(threat_info)
            
            # 转换为DefenseResponse对象
            responses = []
            for suggestion in suggestions.get("defense_measures", []):
                response = DefenseResponse(
                    event_id=event.event_id,
                    action=self._parse_response_action(suggestion),
                    target=event.source_ip,
                    ai_generated=True
                )
                responses.append(response)
            
            return responses
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("获取防御建议失败", e)
            return []
    
    def get_session_statistics(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话统计信息"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # 获取网络统计
        network_stats = self.network_monitor.get_network_statistics(session_id)
        
        # 获取事件统计
        event_stats = session.get_event_statistics()
        
        # 获取监控状态
        monitoring_status = self.network_monitor.get_monitoring_status(session_id)
        
        return {
            "session_info": session.get_summary(),
            "network_statistics": network_stats.__dict__ if network_stats else {},
            "event_statistics": event_stats,
            "monitoring_status": monitoring_status
        }
    
    async def _process_packet(self, session_id: str, packet) -> None:
        """处理数据包"""
        session = self.sessions.get(session_id)
        if not session:
            return
        
        # 将数据包传递给威胁检测器
        threats = await self.threat_detector.analyze_packet(session_id, packet)
        
        # 处理检测到的威胁
        for threat in threats:
            session.add_threat_event(threat)
            
            # 如果启用了自动响应，生成并执行响应
            if session.auto_response_enabled:
                responses = await self.get_defense_suggestions(session_id, threat)
                for response in responses:
                    await self.execute_response(session_id, response)
    
    def _validate_network_range(self, network_range: str) -> bool:
        """验证网络范围"""
        try:
            ipaddress.ip_network(network_range, strict=False)
            return True
        except ValueError:
            return False
    
    def _build_packet_filter(self, session: DefenseSession) -> str:
        """构建数据包过滤器"""
        filters = []
        
        # 基于网络范围的过滤
        if session.network_range:
            filters.append(f"net {session.network_range}")
        
        # 基于监控规则的过滤（简化实现）
        # 在实际应用中，可以根据规则构建更复杂的过滤器
        
        return " and ".join(filters) if filters else ""
    
    def _load_default_rules(self) -> None:
        """加载默认监控规则"""
        # 这里可以从配置文件或数据库加载默认规则
        self.default_monitoring_rules = self._create_default_rules()
    
    def _create_default_rules(self) -> List[MonitoringRule]:
        """创建默认监控规则"""
        rules = []
        
        # 端口扫描检测规则
        port_scan_rule = MonitoringRule(
            name="端口扫描检测",
            description="检测来自单一源IP的大量端口连接尝试",
            threat_type=ThreatType.PORT_SCAN,
            conditions={
                "unique_ports_threshold": 10,
                "time_window": 60,
                "connection_attempts": 20
            },
            threshold=0.8,
            severity=ThreatLevel.MEDIUM,
            auto_response=False,
            response_actions=[ResponseAction.LOG_EVENT, ResponseAction.ALERT_ADMIN]
        )
        rules.append(port_scan_rule)
        
        # 暴力破解检测规则
        brute_force_rule = MonitoringRule(
            name="暴力破解检测",
            description="检测对特定端口的重复连接失败",
            threat_type=ThreatType.BRUTE_FORCE,
            conditions={
                "failed_attempts_threshold": 5,
                "time_window": 300,
                "target_ports": [22, 21, 23, 3389]
            },
            threshold=0.9,
            severity=ThreatLevel.HIGH,
            auto_response=True,
            response_actions=[ResponseAction.BLOCK_IP, ResponseAction.ALERT_ADMIN]
        )
        rules.append(brute_force_rule)
        
        return rules
    
    def _parse_response_action(self, suggestion: str) -> ResponseAction:
        """解析响应动作"""
        suggestion_lower = suggestion.lower()
        
        if "block" in suggestion_lower or "阻止" in suggestion_lower:
            return ResponseAction.BLOCK_IP
        elif "limit" in suggestion_lower or "限制" in suggestion_lower:
            return ResponseAction.RATE_LIMIT
        elif "alert" in suggestion_lower or "警告" in suggestion_lower:
            return ResponseAction.ALERT_ADMIN
        elif "quarantine" in suggestion_lower or "隔离" in suggestion_lower:
            return ResponseAction.QUARANTINE
        elif "monitor" in suggestion_lower or "监控" in suggestion_lower:
            return ResponseAction.MONITOR_CLOSELY
        else:
            return ResponseAction.LOG_EVENT
    
    def get_simulator_info(self) -> Dict[str, Any]:
        """获取模拟器信息"""
        return {
            "active_sessions": len(self.sessions),
            "max_sessions": self.max_sessions,
            "network_monitor": self.network_monitor.get_monitor_info(),
            "threat_detector": self.threat_detector.get_detector_info(),
            "response_engine": self.response_engine.get_engine_info()
        }