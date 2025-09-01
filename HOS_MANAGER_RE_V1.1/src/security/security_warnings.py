"""
Security Warnings and Authorization Module.

This module provides security warnings for potentially dangerous operations
and ensures users have proper authorization before executing attacks.
"""

import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import ipaddress


class SecurityWarnings:
    """Manages security warnings and authorization confirmations."""
    
    def __init__(self):
        """Initialize security warnings manager."""
        self.authorized_targets = set()
        self.warning_history = []
        
    def is_private_ip(self, ip: str) -> bool:
        """
        Check if IP address is in private range.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is private, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def is_localhost(self, target: str) -> bool:
        """
        Check if target is localhost.
        
        Args:
            target: Target hostname or IP
            
        Returns:
            True if target is localhost
        """
        localhost_patterns = [
            'localhost', '127.0.0.1', '::1', '0.0.0.0',
            '127.', 'local'
        ]
        target_lower = target.lower()
        return any(pattern in target_lower for pattern in localhost_patterns)
    
    def analyze_target_risk(self, target: str) -> Dict:
        """
        Analyze the risk level of a target.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            Dictionary with risk analysis
        """
        risk_info = {
            'target': target,
            'risk_level': 'low',
            'warnings': [],
            'requires_confirmation': False
        }
        
        # Check if target is localhost or private IP
        if self.is_localhost(target):
            risk_info['risk_level'] = 'low'
            risk_info['warnings'].append('目标是本地主机，风险较低')
        elif self.is_private_ip(target):
            risk_info['risk_level'] = 'medium'
            risk_info['warnings'].append('目标是内网IP，请确保您有权限测试此网络')
            risk_info['requires_confirmation'] = True
        else:
            risk_info['risk_level'] = 'high'
            risk_info['warnings'].extend([
                '目标是公网IP地址',
                '请确保您拥有该目标的合法授权',
                '未经授权的攻击可能违反法律法规'
            ])
            risk_info['requires_confirmation'] = True
            
        return risk_info
    
    def display_attack_warning(self, target: str, attack_type: str) -> None:
        """
        Display security warning for attack operations.
        
        Args:
            target: Target of the attack
            attack_type: Type of attack being performed
        """
        risk_info = self.analyze_target_risk(target)
        
        print("\n" + "="*60)
        print("🚨 安全警告 - SECURITY WARNING 🚨")
        print("="*60)
        print(f"目标: {target}")
        print(f"攻击类型: {attack_type}")
        print(f"风险级别: {risk_info['risk_level'].upper()}")
        print("\n警告信息:")
        for warning in risk_info['warnings']:
            print(f"  ⚠️  {warning}")
        
        print("\n重要提醒:")
        print("  • 仅对您拥有合法授权的目标进行测试")
        print("  • 未经授权的攻击可能触犯法律")
        print("  • 您需要对所有操作后果承担责任")
        print("  • 建议在隔离的测试环境中进行")
        print("="*60)
    
    def prompt_authorization(self, target: str, attack_type: str) -> bool:
        """
        Prompt user for authorization confirmation.
        
        Args:
            target: Target of the attack
            attack_type: Type of attack
            
        Returns:
            True if user confirms authorization, False otherwise
        """
        risk_info = self.analyze_target_risk(target)
        
        # Always show warning for attacks
        self.display_attack_warning(target, attack_type)
        
        # Record warning in history
        self.warning_history.append({
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'attack_type': attack_type,
            'risk_level': risk_info['risk_level']
        })
        
        if not risk_info['requires_confirmation']:
            return True
            
        print(f"\n请确认您对目标 {target} 的授权状态:")
        
        while True:
            response = input("您是否拥有对此目标的合法测试授权? (yes/no): ").strip().lower()
            
            if response in ['yes', 'y', '是', 'true', '1']:
                self.authorized_targets.add(target)
                print("✓ 授权确认完成，继续执行操作...")
                return True
            elif response in ['no', 'n', '否', 'false', '0']:
                print("✗ 未获得授权确认，操作已取消")
                return False
            else:
                print("请输入 'yes' 或 'no'")
    
    def check_target_authorization(self, target: str) -> bool:
        """
        Check if target has been previously authorized.
        
        Args:
            target: Target to check
            
        Returns:
            True if target is authorized
        """
        return target in self.authorized_targets
    
    def add_authorized_target(self, target: str) -> None:
        """
        Add target to authorized list.
        
        Args:
            target: Target to authorize
        """
        self.authorized_targets.add(target)
    
    def remove_authorized_target(self, target: str) -> None:
        """
        Remove target from authorized list.
        
        Args:
            target: Target to remove authorization
        """
        self.authorized_targets.discard(target)
    
    def get_authorized_targets(self) -> List[str]:
        """
        Get list of authorized targets.
        
        Returns:
            List of authorized target strings
        """
        return list(self.authorized_targets)
    
    def display_unauthorized_target_warning(self) -> None:
        """Display warning about attacking unauthorized targets."""
        print("\n" + "🚨"*20)
        print("严重警告 - CRITICAL WARNING")
        print("🚨"*20)
        print("检测到可能的未授权目标攻击尝试！")
        print("")
        print("提醒:")
        print("• 攻击未授权的目标是违法行为")
        print("• 可能面临法律后果和民事责任")
        print("• 请立即停止并确认目标授权状态")
        print("• 如有疑问请咨询法律专业人士")
        print("🚨"*20)
    
    def validate_scan_parameters(self, target: str, ports: List[int]) -> Tuple[bool, List[str]]:
        """
        Validate scan parameters for security concerns.
        
        Args:
            target: Target to scan
            ports: List of ports to scan
            
        Returns:
            Tuple of (is_valid, warnings)
        """
        warnings = []
        is_valid = True
        
        # Check for suspicious port ranges
        if len(ports) > 1000:
            warnings.append("扫描端口数量过多，可能被目标检测为恶意行为")
        
        # Check for common service ports that might be sensitive
        sensitive_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        scanned_sensitive = [p for p in ports if p in sensitive_ports]
        
        if scanned_sensitive:
            warnings.append(f"扫描包含敏感服务端口: {scanned_sensitive}")
        
        # Check target risk
        risk_info = self.analyze_target_risk(target)
        if risk_info['risk_level'] == 'high':
            warnings.extend(risk_info['warnings'])
        
        return is_valid, warnings
    
    def get_warning_history(self) -> List[Dict]:
        """
        Get history of security warnings.
        
        Returns:
            List of warning records
        """
        return self.warning_history.copy()
    
    def clear_warning_history(self) -> None:
        """Clear warning history."""
        self.warning_history.clear()