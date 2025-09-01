"""
Audit Logger Module.

This module provides comprehensive audit logging for security events,
user actions, and system operations with proper data sanitization.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from .data_protection import DataProtection


class AuditLogger:
    """Handles audit logging with security and compliance features."""
    
    def __init__(self, log_dir: str = "logs", data_protection: Optional[DataProtection] = None):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory to store log files
            data_protection: Data protection instance for sanitization
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.data_protection = data_protection or DataProtection()
        
        # Log file paths
        self.security_log = self.log_dir / "security_events.log"
        self.audit_log = self.log_dir / "audit_trail.log"
        self.compliance_log = self.log_dir / "compliance.log"
        self.error_log = self.log_dir / "errors.log"
        
    def log_security_event(self, event_type: str, severity: str, details: Dict) -> None:
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event
            severity: Event severity (low, medium, high, critical)
            details: Event details dictionary
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity.upper(),
            'details': self._sanitize_details(details)
        }
        
        self._write_log(self.security_log, log_entry)
        
        # Also log critical events to audit trail
        if severity.lower() == 'critical':
            self.log_audit_event('CRITICAL_SECURITY_EVENT', details)
    
    def log_audit_event(self, action: str, details: Dict, user_id: str = "system") -> None:
        """
        Log audit trail events.
        
        Args:
            action: Action performed
            details: Action details
            user_id: User who performed the action
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'action': action,
            'details': self._sanitize_details(details)
        }
        
        self._write_log(self.audit_log, log_entry)
    
    def log_compliance_event(self, compliance_type: str, status: str, details: Dict) -> None:
        """
        Log compliance-related events.
        
        Args:
            compliance_type: Type of compliance check
            status: Compliance status (pass, fail, warning)
            details: Compliance details
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'compliance_type': compliance_type,
            'status': status.upper(),
            'details': self._sanitize_details(details)
        }
        
        self._write_log(self.compliance_log, log_entry)
    
    def log_error_event(self, error_type: str, error_message: str, context: Dict) -> None:
        """
        Log error events.
        
        Args:
            error_type: Type of error
            error_message: Error message
            context: Error context
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'error_type': error_type,
            'error_message': self.data_protection.sanitize_log_data(error_message),
            'context': self._sanitize_details(context)
        }
        
        self._write_log(self.error_log, log_entry)
    
    def log_attack_attempt(self, target: str, attack_type: str, result: str, details: Dict) -> None:
        """
        Log attack attempt with security considerations.
        
        Args:
            target: Attack target
            attack_type: Type of attack
            result: Attack result
            details: Attack details
        """
        # Check if this should be logged (avoid logging unauthorized attacks)
        if not self._should_log_attack(target, details):
            self.log_security_event(
                'UNAUTHORIZED_ATTACK_BLOCKED',
                'high',
                {'target': target, 'attack_type': attack_type}
            )
            return
        
        self.log_security_event(
            'ATTACK_ATTEMPT',
            'medium',
            {
                'target': target,
                'attack_type': attack_type,
                'result': result,
                'details': details
            }
        )
    
    def log_defense_action(self, threat_type: str, action_taken: str, effectiveness: str, details: Dict) -> None:
        """
        Log defense system actions.
        
        Args:
            threat_type: Type of threat detected
            action_taken: Defense action taken
            effectiveness: Action effectiveness
            details: Action details
        """
        self.log_security_event(
            'DEFENSE_ACTION',
            'medium',
            {
                'threat_type': threat_type,
                'action_taken': action_taken,
                'effectiveness': effectiveness,
                'details': details
            }
        )
    
    def log_malicious_usage_detection(self, user_input: str, detected_patterns: List[str]) -> None:
        """
        Log detection of potentially malicious usage.
        
        Args:
            user_input: User input that triggered detection
            detected_patterns: List of detected malicious patterns
        """
        self.log_security_event(
            'MALICIOUS_USAGE_DETECTED',
            'high',
            {
                'sanitized_input': self.data_protection.sanitize_log_data(user_input),
                'detected_patterns': detected_patterns,
                'action': 'INPUT_BLOCKED'
            }
        )
    
    def log_terms_acceptance(self, user_id: str, accepted: bool) -> None:
        """
        Log terms of service acceptance.
        
        Args:
            user_id: User identifier
            accepted: Whether terms were accepted
        """
        self.log_compliance_event(
            'TERMS_OF_SERVICE',
            'pass' if accepted else 'fail',
            {
                'user_id': user_id,
                'accepted': accepted,
                'action': 'SYSTEM_ACCESS_GRANTED' if accepted else 'SYSTEM_ACCESS_DENIED'
            }
        )
    
    def get_security_events(self, hours: int = 24) -> List[Dict]:
        """
        Get recent security events.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of security events
        """
        return self._read_recent_logs(self.security_log, hours)
    
    def get_audit_trail(self, hours: int = 24) -> List[Dict]:
        """
        Get recent audit trail.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of audit events
        """
        return self._read_recent_logs(self.audit_log, hours)
    
    def generate_compliance_report(self, hours: int = 24) -> Dict:
        """
        Generate compliance report.
        
        Args:
            hours: Number of hours to include in report
            
        Returns:
            Compliance report dictionary
        """
        compliance_events = self._read_recent_logs(self.compliance_log, hours)
        security_events = self._read_recent_logs(self.security_log, hours)
        
        report = {
            'report_generated': datetime.now().isoformat(),
            'period_hours': hours,
            'compliance_summary': {
                'total_events': len(compliance_events),
                'passed': len([e for e in compliance_events if e.get('status') == 'PASS']),
                'failed': len([e for e in compliance_events if e.get('status') == 'FAIL']),
                'warnings': len([e for e in compliance_events if e.get('status') == 'WARNING'])
            },
            'security_summary': {
                'total_events': len(security_events),
                'critical': len([e for e in security_events if e.get('severity') == 'CRITICAL']),
                'high': len([e for e in security_events if e.get('severity') == 'HIGH']),
                'medium': len([e for e in security_events if e.get('severity') == 'MEDIUM']),
                'low': len([e for e in security_events if e.get('severity') == 'LOW'])
            },
            'compliance_events': compliance_events,
            'security_events': security_events
        }
        
        return report 
   
    def _sanitize_details(self, details: Dict) -> Dict:
        """
        Sanitize details dictionary for logging.
        
        Args:
            details: Details to sanitize
            
        Returns:
            Sanitized details dictionary
        """
        sanitized = {}
        for key, value in details.items():
            if isinstance(value, str):
                sanitized[key] = self.data_protection.sanitize_log_data(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.data_protection.sanitize_log_data(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _write_log(self, log_file: Path, log_entry: Dict) -> None:
        """
        Write log entry to file.
        
        Args:
            log_file: Path to log file
            log_entry: Log entry to write
        """
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        except Exception as e:
            # Fallback logging to stderr if file logging fails
            print(f"Failed to write log: {e}", file=sys.stderr)
    
    def _read_recent_logs(self, log_file: Path, hours: int) -> List[Dict]:
        """
        Read recent log entries.
        
        Args:
            log_file: Path to log file
            hours: Number of hours to look back
            
        Returns:
            List of log entries
        """
        if not log_file.exists():
            return []
        
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        recent_logs = []
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(log_entry['timestamp']).timestamp()
                        
                        if entry_time >= cutoff_time:
                            recent_logs.append(log_entry)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception:
            return []
        
        return recent_logs
    
    def _should_log_attack(self, target: str, details: Dict) -> bool:
        """
        Determine if attack should be logged based on authorization.
        
        Args:
            target: Attack target
            details: Attack details
            
        Returns:
            True if attack should be logged
        """
        # Check if target appears to be authorized
        # This is a simplified check - in practice, you'd want more sophisticated logic
        
        # Always log attacks on localhost/private IPs (assumed authorized)
        if any(pattern in target.lower() for pattern in ['localhost', '127.0.0.1', '192.168.', '10.']):
            return True
        
        # Check if authorization was confirmed in details
        if details.get('authorized', False):
            return True
        
        # For public IPs, require explicit authorization
        return False