"""
合规监控器 - 检测和处理安全合规违规行为
"""

from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
import re
from dataclasses import dataclass

from core.base import BaseComponent
from core.interfaces import ILogger
from core.exceptions import CybersecurityPlatformError


class ComplianceError(CybersecurityPlatformError):
    """合规异常"""
    pass


@dataclass
class ComplianceViolation:
    """合规违规记录"""
    rule: str
    severity: str  # low, medium, high, critical
    description: str
    recommendation: str
    timestamp: datetime
    user_id: Optional[str] = None
    operation_type: Optional[str] = None
    target: Optional[str] = None


class ComplianceMonitor(BaseComponent):
    """合规监控器 - 检测和处理安全合规违规行为"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.violation_history: List[ComplianceViolation] = []
        self.user_operation_count: Dict[str, int] = {}
        self.operation_timestamps: Dict[str, List[datetime]] = {}
        
        # 合规规则配置
        self.rules = {
            'unauthorized_target': {
                'description': '扫描或攻击未授权的目标',
                'severity': 'high',
                'recommendation': '仅扫描已授权的目标网络'
            },
            'excessive_scanning': {
                'description': '过度扫描行为',
                'severity': 'medium',
                'recommendation': '限制扫描频率和范围'
            },
            'malicious_payload': {
                'description': '使用恶意载荷',
                'severity': 'critical',
                'recommendation': '仅使用授权的测试载荷'
            },
            'frequent_operations': {
                'description': '操作频率过高',
                'severity': 'low',
                'recommendation': '降低操作频率'
            }
        }
        
        # 授权目标网络
        self.authorized_networks = [
            '192.168.1.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12'
        ]
        
        # 恶意载荷模式
        self.malicious_patterns = [
            r'rm\s+-rf\s+/',
            r'drop\s+table',
            r'delete\s+from',
            r'exec\s*\(',
            r'system\s*\(',
            r'chmod\s+777',
            r'wget\s+http',
            r'curl\s+http'
        ]
    
    async def check_compliance_violation(self, operation_type: str, 
                                       operation_data: Dict[str, Any]) -> Tuple[bool, List[ComplianceViolation]]:
        """检查操作是否违反合规规则"""
        violations = []
        
        # 检查未授权目标
        if 'target' in operation_data:
            target = operation_data['target']
            if not self._is_target_authorized(target):
                violations.append(self._create_violation(
                    'unauthorized_target',
                    f"目标 {target} 未在授权网络中",
                    operation_type,
                    target
                ))
        
        # 检查过度扫描
        if operation_type == 'port_scan' and 'ports' in operation_data:
            ports = operation_data['ports']
            if len(ports) > 1000:  # 超过1000个端口视为过度扫描
                violations.append(self._create_violation(
                    'excessive_scanning',
                    f"扫描了 {len(ports)} 个端口，超过限制",
                    operation_type,
                    operation_data.get('target')
                ))
        
        # 检查恶意载荷
        if operation_type == 'attack_execution' and 'payload' in operation_data:
            payload = operation_data['payload']
            if self._contains_malicious_pattern(payload):
                violations.append(self._create_violation(
                    'malicious_payload',
                    "检测到可能的恶意载荷",
                    operation_type,
                    operation_data.get('target')
                ))
        
        # 检查操作频率
        user_id = operation_data.get('user_id', 'anonymous')
        if self._is_operation_too_frequent(user_id, operation_type):
            violations.append(self._create_violation(
                'frequent_operations',
                "操作频率过高",
                operation_type,
                operation_data.get('target'),
                user_id
            ))
        
        return len(violations) > 0, violations
    
    async def handle_compliance_violation(self, violations: List[ComplianceViolation], 
                                        user_id: Optional[str] = None) -> None:
        """处理合规违规"""
        for violation in violations:
            # 记录违规历史
            self.violation_history.append(violation)
            
            # 记录日志
            if self.logger:
                self.logger.log_warning(
                    f"合规违规: {violation.rule} - {violation.description}",
                    extra={
                        'severity': violation.severity,
                        'user_id': user_id,
                        'target': violation.target
                    }
                )
                
                # 记录合规事件到审计日志
                self.logger.log_compliance_event(
                    compliance_type=violation.rule,
                    status='fail',
                    details={
                        'description': violation.description,
                        'severity': violation.severity,
                        'user_id': user_id,
                        'target': violation.target,
                        'recommendation': violation.recommendation
                    }
                )
    
    async def generate_compliance_report(self, user_id: Optional[str] = None, 
                                      hours: int = 24) -> Dict[str, Any]:
        """生成合规报告"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # 过滤指定用户的违规记录
        if user_id:
            user_violations = [v for v in self.violation_history 
                             if v.user_id == user_id and v.timestamp >= cutoff_time]
        else:
            user_violations = [v for v in self.violation_history 
                             if v.timestamp >= cutoff_time]
        
        # 按规则分类统计
        violation_by_rule = {}
        for violation in user_violations:
            if violation.rule not in violation_by_rule:
                violation_by_rule[violation.rule] = 0
            violation_by_rule[violation.rule] += 1
        
        # 按严重程度统计
        violation_by_severity = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for violation in user_violations:
            violation_by_severity[violation.severity] += 1
        
        return {
            'report_generated': datetime.now().isoformat(),
            'time_period_hours': hours,
            'user_id': user_id,
            'total_violations': len(user_violations),
            'violation_by_rule': violation_by_rule,
            'violation_by_severity': violation_by_severity,
            'recent_violations': [
                {
                    'rule': v.rule,
                    'severity': v.severity,
                    'description': v.description,
                    'timestamp': v.timestamp.isoformat(),
                    'target': v.target
                } for v in user_violations[-10:]  # 最近10条记录
            ]
        }
    
    def _is_target_authorized(self, target: str) -> bool:
        """检查目标是否在授权网络中"""
        # 简单的IP地址检查（实际实现应该使用IP网络库）
        for network in self.authorized_networks:
            if network.startswith('192.168.1.') and target.startswith('192.168.1.'):
                return True
            if network.startswith('10.') and target.startswith('10.'):
                return True
            if network.startswith('172.16.') and target.startswith('172.16.'):
                return True
        return False
    
    def _contains_malicious_pattern(self, text: str) -> bool:
        """检查文本是否包含恶意模式"""
        text_lower = text.lower()
        for pattern in self.malicious_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _is_operation_too_frequent(self, user_id: str, operation_type: str) -> bool:
        """检查操作频率是否过高"""
        current_time = datetime.now()
        
        # 初始化用户操作记录
        if user_id not in self.operation_timestamps:
            self.operation_timestamps[user_id] = []
        
        # 清理过期的操作时间戳（最近5分钟）
        cutoff_time = current_time - timedelta(minutes=5)
        self.operation_timestamps[user_id] = [
            ts for ts in self.operation_timestamps[user_id] if ts > cutoff_time
        ]
        
        # 添加当前操作时间戳
        self.operation_timestamps[user_id].append(current_time)
        
        # 检查频率（5分钟内超过20次操作视为过高）
        return len(self.operation_timestamps[user_id]) > 20
    
    def _create_violation(self, rule: str, description: str, 
                         operation_type: str, target: Optional[str] = None,
                         user_id: Optional[str] = None) -> ComplianceViolation:
        """创建违规记录"""
        rule_config = self.rules.get(rule, {})
        
        return ComplianceViolation(
            rule=rule,
            severity=rule_config.get('severity', 'medium'),
            description=description,
            recommendation=rule_config.get('recommendation', '请检查操作合规性'),
            timestamp=datetime.now(),
            user_id=user_id,
            operation_type=operation_type,
            target=target
        )
    
    def get_compliance_stats(self) -> Dict[str, Any]:
        """获取合规统计信息"""
        return {
            'total_violations': len(self.violation_history),
            'active_users': len(self.operation_timestamps),
            'rules_configured': len(self.rules),
            'last_violation': self.violation_history[-1].timestamp.isoformat() if self.violation_history else None
        }