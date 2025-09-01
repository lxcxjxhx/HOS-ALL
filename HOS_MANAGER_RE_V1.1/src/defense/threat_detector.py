"""
威胁检测器 - 检测网络中的安全威胁
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
import re
import ipaddress

from .models import ThreatEvent, ThreatType, ThreatSeverity, DefenseSession
from core.base import BaseComponent
from core.interfaces import ILogger
from core.exceptions import CybersecurityPlatformError


class ThreatDetectorError(CybersecurityPlatformError):
    """威胁检测器异常"""
    pass


class ThreatDetector(BaseComponent):
    """威胁检测器主类"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        
        # 威胁检测规则
        self.threat_rules: List[Dict[str, Any]] = []
        
        # 会话管理
        self.active_sessions: Dict[str, DefenseSession] = {}
        self.detection_tasks: Dict[str, asyncio.Task] = {}
        
        # 威胁事件处理器
        self.threat_handlers: List[Callable[[ThreatEvent], None]] = []
        
        # 统计信息
        self.detected_threats: Dict[ThreatType, int] = {}
        self.false_positives: int = 0
        
    async def initialize(self) -> None:
        """初始化威胁检测器"""
        # 加载威胁检测规则
        self._load_threat_rules()
        
        # 初始化统计信息
        for threat_type in ThreatType:
            self.detected_threats[threat_type] = 0
        
        if self.logger:
            self.logger.log_info("威胁检测器初始化完成")
    
    async def cleanup(self) -> None:
        """清理威胁检测器"""
        # 停止所有检测任务
        for session_id in list(self.detection_tasks.keys()):
            await self.stop_detection(session_id)
        
        # 清空会话
        self.active_sessions.clear()
        
        if self.logger:
            self.logger.log_info("威胁检测器已清理")
    
    async def start_detection(self, session: DefenseSession) -> bool:
        """开始威胁检测"""
        session_id = session.session_id
        
        if session_id in self.active_sessions:
            return True
        
        try:
            # 保存会话
            self.active_sessions[session_id] = session
            
            # 创建检测任务
            detection_task = asyncio.create_task(
                self._detection_loop(session_id)
            )
            self.detection_tasks[session_id] = detection_task
            
            if self.logger:
                self.logger.log_info(f"开始威胁检测: {session_id}")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"启动威胁检测失败: {session_id}", e)
            raise ThreatDetectorError(f"启动威胁检测失败: {str(e)}")
    
    async def stop_detection(self, session_id: str) -> bool:
        """停止威胁检测"""
        if session_id not in self.detection_tasks:
            return False
        
        try:
            # 取消检测任务
            task = self.detection_tasks[session_id]
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            # 清理会话
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            del self.detection_tasks[session_id]
            
            if self.logger:
                self.logger.log_info(f"停止威胁检测: {session_id}")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"停止威胁检测失败: {session_id}", e)
            return False
    
    def register_threat_handler(self, handler: Callable[[ThreatEvent], None]) -> None:
        """注册威胁事件处理器"""
        self.threat_handlers.append(handler)
    
    def unregister_threat_handler(self, handler: Callable[[ThreatEvent], None]) -> None:
        """注销威胁事件处理器"""
        if handler in self.threat_handlers:
            self.threat_handlers.remove(handler)
    
    async def analyze_packet(self, packet_data: Dict[str, Any], 
                           session_id: str) -> Optional[ThreatEvent]:
        """分析数据包，检测威胁"""
        if session_id not in self.active_sessions:
            return None
        
        try:
            # 应用所有威胁检测规则
            for rule in self.threat_rules:
                threat_event = self._apply_rule(rule, packet_data, session_id)
                if threat_event:
                    return threat_event
            
            return None
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"数据包分析失败: {session_id}", e)
            return None
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """获取检测统计信息"""
        total_threats = sum(self.detected_threats.values())
        
        return {
            'total_detected_threats': total_threats,
            'threats_by_type': self.detected_threats,
            'false_positives': self.false_positives,
            'active_sessions': len(self.active_sessions),
            'detection_rules': len(self.threat_rules)
        }
    
    async def _detection_loop(self, session_id: str) -> None:
        """威胁检测循环"""
        try:
            while session_id in self.active_sessions:
                # 检查会话状态
                session = self.active_sessions[session_id]
                if not session.is_active():
                    break
                
                # 执行定期检测（这里可以添加定期检查逻辑）
                await asyncio.sleep(1.0)
                
        except asyncio.CancelledError:
            if self.logger:
                self.logger.log_info(f"威胁检测任务被取消: {session_id}")
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"威胁检测循环异常: {session_id}", e)
    
    def _load_threat_rules(self) -> None:
        """加载威胁检测规则"""
        self.threat_rules = [
            # 端口扫描检测
            {
                'name': 'port_scan_detection',
                'type': ThreatType.PORT_SCAN,
                'severity': ThreatSeverity.MEDIUM,
                'description': '检测端口扫描行为',
                'condition': lambda pkt: (
                    pkt.get('flags', {}).get('syn', False) and 
                    pkt.get('dst_port') is not None and
                    pkt.get('src_ip') is not None
                ),
                'evaluation': self._evaluate_port_scan
            },
            
            # SYN Flood攻击检测
            {
                'name': 'syn_flood_detection',
                'type': ThreatType.DDOS,
                'severity': ThreatSeverity.HIGH,
                'description': '检测SYN Flood攻击',
                'condition': lambda pkt: (
                    pkt.get('flags', {}).get('syn', False) and 
                    not pkt.get('flags', {}).get('ack', False)
                ),
                'evaluation': self._evaluate_syn_flood
            },
            
            # 恶意载荷检测
            {
                'name': 'malicious_payload_detection',
                'type': ThreatType.MALWARE,
                'severity': ThreatSeverity.CRITICAL,
                'description': '检测恶意载荷',
                'condition': lambda pkt: pkt.get('payload') is not None,
                'evaluation': self._evaluate_malicious_payload
            },
            
            # 异常连接检测
            {
                'name': 'suspicious_connection_detection',
                'type': ThreatType.SUSPICIOUS_ACTIVITY,
                'severity': ThreatSeverity.LOW,
                'description': '检测异常连接行为',
                'condition': lambda pkt: pkt.get('protocol') in ['tcp', 'udp'],
                'evaluation': self._evaluate_suspicious_connection
            }
        ]
    
    def _apply_rule(self, rule: Dict[str, Any], packet_data: Dict[str, Any], 
                  session_id: str) -> Optional[ThreatEvent]:
        """应用威胁检测规则"""
        try:
            # 检查条件
            condition_func = rule['condition']
            if not condition_func(packet_data):
                return None
            
            # 评估威胁
            evaluation_func = rule['evaluation']
            threat_level, confidence, details = evaluation_func(packet_data, session_id)
            
            if threat_level > 0:
                # 创建威胁事件
                threat_event = ThreatEvent(
                    event_type=rule['type'],
                    severity=rule['severity'],
                    description=rule['description'],
                    source_ip=packet_data.get('src_ip'),
                    destination_ip=packet_data.get('dst_ip'),
                    threat_level=threat_level,
                    confidence=confidence,
                    details=details,
                    timestamp=datetime.now()
                )
                
                # 更新统计信息
                self.detected_threats[rule['type']] += 1
                
                # 通知所有处理器
                for handler in self.threat_handlers:
                    try:
                        handler(threat_event)
                    except Exception as e:
                        if self.logger:
                            self.logger.log_error("威胁事件处理器异常", e)
                
                return threat_event
            
            return None
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"应用威胁检测规则失败: {rule['name']}", e)
            return None
    
    def _evaluate_port_scan(self, packet_data: Dict[str, Any], 
                           session_id: str) -> tuple:
        """评估端口扫描威胁"""
        # 这里实现端口扫描检测逻辑
        # 返回 (威胁等级, 置信度, 详细信息)
        return 0, 0.0, {}
    
    def _evaluate_syn_flood(self, packet_data: Dict[str, Any], 
                          session_id: str) -> tuple:
        """评估SYN Flood威胁"""
        # 这里实现SYN Flood检测逻辑
        return 0, 0.0, {}
    
    def _evaluate_malicious_payload(self, packet_data: Dict[str, Any], 
                                  session_id: str) -> tuple:
        """评估恶意载荷威胁"""
        payload = packet_data.get('payload', '')
        
        # 简单的恶意模式检测
        malicious_patterns = [
            r'rm\s+-rf\s+/',
            r'drop\s+table',
            r'delete\s+from',
            r'exec\s*\(',
            r'system\s*\(',
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return 8, 0.7, {'pattern': pattern, 'payload_sample': payload[:100]}
        
        return 0, 0.0, {}
    
    def _evaluate_suspicious_connection(self, packet_data: Dict[str, Any], 
                                      session_id: str) -> tuple:
        """评估异常连接威胁"""
        # 这里实现异常连接检测逻辑
        return 0, 0.0, {}
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        """检查是否为内部IP地址"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False