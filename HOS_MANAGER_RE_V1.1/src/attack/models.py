"""
攻击模拟数据模型 - 定义攻击会话、扫描结果等数据结构
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum
import uuid

from core.interfaces import AttackType, ThreatLevel


class ScanType(Enum):
    """扫描类型枚举"""
    TCP_CONNECT = "tcp_connect"
    SYN_STEALTH = "syn_stealth"
    UDP_SCAN = "udp_scan"
    VERSION_DETECTION = "version_detection"
    OS_FINGERPRINT = "os_fingerprint"


class AttackStatus(Enum):
    """攻击状态枚举"""
    CREATED = "created"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    ATTACKING = "attacking"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class PortInfo:
    """端口信息"""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    vuln_id: str
    name: str
    description: str
    severity: ThreatLevel
    cve_id: Optional[str] = None
    affected_service: Optional[str] = None
    affected_port: Optional[int] = None
    exploit_available: bool = False
    ai_analysis: Optional[Dict[str, Any]] = None


@dataclass
class AttackPayload:
    """攻击载荷"""
    payload_id: str
    name: str
    description: str
    payload_type: AttackType
    target_vulnerability: str
    payload_data: str
    execution_method: str
    expected_result: str
    safety_level: int = 1  # 1-5, 1最安全
    ai_generated: bool = False
    validation_passed: bool = False


@dataclass
class ScanResult:
    """扫描结果"""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    scan_type: ScanType = ScanType.TCP_CONNECT
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration: float = 0.0
    open_ports: List[PortInfo] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    os_info: Optional[Dict[str, Any]] = None
    success: bool = False
    error_message: Optional[str] = None
    raw_output: Optional[str] = None


@dataclass
class AttackResult:
    """攻击结果"""
    attack_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    payload_id: str = ""
    target: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration: float = 0.0
    success: bool = False
    result_data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class AttackSession:
    """攻击会话"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_name: str = ""
    target: str = ""
    ports: List[int] = field(default_factory=list)
    attack_types: List[AttackType] = field(default_factory=list)
    status: AttackStatus = AttackStatus.CREATED
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    user_id: str = "anonymous"
    
    # 扫描相关
    scan_results: List[ScanResult] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    
    # 攻击相关
    payloads: List[AttackPayload] = field(default_factory=list)
    attack_results: List[AttackResult] = field(default_factory=list)
    
    # 日志和元数据
    logs: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update_status(self, new_status: AttackStatus, message: str = "") -> None:
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
    
    def add_scan_result(self, scan_result: ScanResult) -> None:
        """添加扫描结果"""
        self.scan_results.append(scan_result)
        self.add_log("scan_completed", f"扫描完成: {scan_result.target}", 
                    {"scan_id": scan_result.scan_id, "open_ports": len(scan_result.open_ports)})
    
    def add_vulnerability(self, vulnerability: VulnerabilityInfo) -> None:
        """添加漏洞信息"""
        self.vulnerabilities.append(vulnerability)
        self.add_log("vulnerability_found", f"发现漏洞: {vulnerability.name}",
                    {"vuln_id": vulnerability.vuln_id, "severity": vulnerability.severity.value})
    
    def add_payload(self, payload: AttackPayload) -> None:
        """添加攻击载荷"""
        self.payloads.append(payload)
        self.add_log("payload_generated", f"生成载荷: {payload.name}",
                    {"payload_id": payload.payload_id, "type": payload.payload_type.value})
    
    def add_attack_result(self, attack_result: AttackResult) -> None:
        """添加攻击结果"""
        self.attack_results.append(attack_result)
        self.add_log("attack_executed", f"攻击执行完成",
                    {"attack_id": attack_result.attack_id, "success": attack_result.success})
    
    def get_summary(self) -> Dict[str, Any]:
        """获取会话摘要"""
        return {
            "session_id": self.session_id,
            "session_name": self.session_name,
            "target": self.target,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "duration": (self.updated_at - self.created_at).total_seconds(),
            "scan_count": len(self.scan_results),
            "vulnerability_count": len(self.vulnerabilities),
            "payload_count": len(self.payloads),
            "attack_count": len(self.attack_results),
            "log_count": len(self.logs)
        }