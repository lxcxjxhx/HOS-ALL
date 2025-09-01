"""
防御系统数据模型 - 定义防御会话、威胁事件等数据结构
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum
import uuid

from core.interfaces import ThreatLevel


class DefenseStatus(Enum):
    """防御系统状态枚举"""
    CREATED = "created"
    MONITORING = "monitoring"
    ANALYZING = "analyzing"
    RESPONDING = "responding"
    STOPPED = "stopped"
    ERROR = "error"


class ThreatType(Enum):
    """威胁类型枚举"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DOS_ATTACK = "dos_attack"
    MALWARE = "malware"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    UNKNOWN = "unknown"


class ThreatSeverity(Enum):
    """威胁严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseAction(Enum):
    """响应动作枚举"""
    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    ALERT_ADMIN = "alert_admin"
    LOG_EVENT = "log_event"
    QUARANTINE = "quarantine"
    MONITOR_CLOSELY = "monitor_closely"


class ResponseStatus(Enum):
    """响应状态枚举"""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class NetworkPacket:
    """网络数据包信息"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    flags: Optional[str] = None
    payload_preview: Optional[str] = None
    raw_data: Optional[bytes] = None


@dataclass
class ThreatEvent:
    """威胁事件"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    threat_type: ThreatType = ThreatType.UNKNOWN
    severity: ThreatLevel = ThreatLevel.LOW
    source_ip: str = ""
    target_ip: str = ""
    source_port: Optional[int] = None
    target_port: Optional[int] = None
    description: str = ""
    evidence: List[NetworkPacket] = field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseResponse:
    """防御响应"""
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    action: ResponseAction = ResponseAction.LOG_EVENT
    target: str = ""  # IP地址或其他目标
    parameters: Dict[str, Any] = field(default_factory=dict)
    executed: bool = False
    execution_time: Optional[datetime] = None
    success: bool = False
    error_message: Optional[str] = None
    ai_generated: bool = False


@dataclass
class MonitoringRule:
    """监控规则"""
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    enabled: bool = True
    threat_type: ThreatType = ThreatType.UNKNOWN
    conditions: Dict[str, Any] = field(default_factory=dict)
    threshold: float = 1.0
    time_window: int = 60  # 秒
    severity: ThreatLevel = ThreatLevel.MEDIUM
    auto_response: bool = False
    response_actions: List[ResponseAction] = field(default_factory=list)


@dataclass
class NetworkStatistics:
    """网络统计信息"""
    timestamp: datetime = field(default_factory=datetime.now)
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    top_src_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_dst_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_ports: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_activities: int = 0


@dataclass
class DefenseSession:
    """防御会话"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_name: str = ""
    network_range: str = ""
    interface: str = ""
    status: DefenseStatus = DefenseStatus.CREATED
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    user_id: str = "anonymous"
    
    # 监控配置
    monitoring_rules: List[MonitoringRule] = field(default_factory=list)
    auto_response_enabled: bool = False
    ai_analysis_enabled: bool = True
    
    # 事件和响应
    threat_events: List[ThreatEvent] = field(default_factory=list)
    defense_responses: List[DefenseResponse] = field(default_factory=list)
    
    # 统计信息
    statistics: List[NetworkStatistics] = field(default_factory=list)
    
    # 日志和元数据
    logs: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update_status(self, new_status: DefenseStatus, message: str = "") -> None:
        """更新会话状态"""
        self.status = new_status
        self.updated_at = datetime.now()
        self.add_log("status_change", f"状态变更为: {new_status.value}", {"message": message})
    
    def add_log(self, log_type: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        """添加日志"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": log_type,
            "message": message,
            "data": data or {}
        }
        self.logs.append(log_entry)
    
    def add_threat_event(self, threat_event: ThreatEvent) -> None:
        """添加威胁事件"""
        self.threat_events.append(threat_event)
        self.add_log("threat_detected", f"检测到威胁: {threat_event.threat_type.value}",
                    {"event_id": threat_event.event_id, "severity": threat_event.severity.value})
    
    def add_defense_response(self, response: DefenseResponse) -> None:
        """添加防御响应"""
        self.defense_responses.append(response)
        self.add_log("defense_response", f"执行防御响应: {response.action.value}",
                    {"response_id": response.response_id, "target": response.target})
    
    def add_statistics(self, stats: NetworkStatistics) -> None:
        """添加统计信息"""
        self.statistics.append(stats)
        # 只保留最近的统计信息（避免内存过度使用）
        if len(self.statistics) > 1000:
            self.statistics = self.statistics[-500:]
    
    def get_recent_events(self, hours: int = 24) -> List[ThreatEvent]:
        """获取最近的威胁事件"""
        cutoff_time = datetime.now() - datetime.timedelta(hours=hours)
        return [event for event in self.threat_events if event.timestamp >= cutoff_time]
    
    def get_event_statistics(self) -> Dict[str, Any]:
        """获取事件统计"""
        recent_events = self.get_recent_events()
        
        stats = {
            "total_events": len(self.threat_events),
            "recent_events": len(recent_events),
            "threat_type_distribution": {},
            "severity_distribution": {},
            "top_source_ips": {},
            "response_count": len(self.defense_responses)
        }
        
        # 统计威胁类型分布
        for event in recent_events:
            threat_type = event.threat_type.value
            stats["threat_type_distribution"][threat_type] = \
                stats["threat_type_distribution"].get(threat_type, 0) + 1
            
            # 统计严重程度分布
            severity = event.severity.value
            stats["severity_distribution"][severity] = \
                stats["severity_distribution"].get(severity, 0) + 1
            
            # 统计源IP
            if event.source_ip:
                stats["top_source_ips"][event.source_ip] = \
                    stats["top_source_ips"].get(event.source_ip, 0) + 1
        
        return stats
    
    def get_summary(self) -> Dict[str, Any]:
        """获取会话摘要"""
        return {
            "session_id": self.session_id,
            "session_name": self.session_name,
            "network_range": self.network_range,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "duration": (self.updated_at - self.created_at).total_seconds(),
            "threat_events_count": len(self.threat_events),
            "responses_count": len(self.defense_responses),
            "rules_count": len(self.monitoring_rules),
            "auto_response_enabled": self.auto_response_enabled,
            "ai_analysis_enabled": self.ai_analysis_enabled
        }