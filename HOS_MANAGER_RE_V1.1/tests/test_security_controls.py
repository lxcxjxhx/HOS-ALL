"""
Unit tests for security controls and compliance features.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
import json
from datetime import datetime
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security.terms_service import TermsOfService
from security.security_warnings import SecurityWarnings
from security.data_protection import DataProtection
from security.compliance_monitor import ComplianceMonitor
from security.audit_logger import AuditLogger


class TestTermsOfService(unittest.TestCase):
    """Test cases for Terms of Service functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.terms_service = TermsOfService(self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_get_terms_text(self):
        """Test getting terms text."""
        terms = self.terms_service.get_terms_text()
        self.assertIn("使用条款", terms)
        self.assertIn("合法使用声明", terms)
        self.assertIn("用户责任", terms)
    
    def test_check_acceptance_no_file(self):
        """Test checking acceptance when no file exists."""
        self.assertFalse(self.terms_service.check_acceptance())
    
    def test_record_and_check_acceptance(self):
        """Test recording and checking acceptance."""
        self.terms_service.record_acceptance("test_user")
        self.assertTrue(self.terms_service.check_acceptance())
    
    def test_get_acceptance_info(self):
        """Test getting acceptance information."""
        self.terms_service.record_acceptance("test_user")
        info = self.terms_service.get_acceptance_info()
        
        self.assertIsNotNone(info)
        self.assertEqual(info['user_id'], "test_user")
        self.assertTrue(info['accepted'])
    
    def test_revoke_acceptance(self):
        """Test revoking acceptance."""
        self.terms_service.record_acceptance("test_user")
        self.assertTrue(self.terms_service.check_acceptance())
        
        self.terms_service.revoke_acceptance()
        self.assertFalse(self.terms_service.check_acceptance())


class TestSecurityWarnings(unittest.TestCase):
    """Test cases for Security Warnings functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.security_warnings = SecurityWarnings()
    
    def test_is_private_ip(self):
        """Test private IP detection."""
        self.assertTrue(self.security_warnings.is_private_ip("192.168.1.1"))
        self.assertTrue(self.security_warnings.is_private_ip("10.0.0.1"))
        self.assertTrue(self.security_warnings.is_private_ip("172.16.0.1"))
        self.assertFalse(self.security_warnings.is_private_ip("8.8.8.8"))
    
    def test_is_localhost(self):
        """Test localhost detection."""
        self.assertTrue(self.security_warnings.is_localhost("localhost"))
        self.assertTrue(self.security_warnings.is_localhost("127.0.0.1"))
        self.assertFalse(self.security_warnings.is_localhost("8.8.8.8"))
    
    def test_analyze_target_risk(self):
        """Test target risk analysis."""
        # Test localhost
        risk = self.security_warnings.analyze_target_risk("localhost")
        self.assertEqual(risk['risk_level'], 'low')
        self.assertFalse(risk['requires_confirmation'])
        
        # Test private IP
        risk = self.security_warnings.analyze_target_risk("192.168.1.1")
        self.assertEqual(risk['risk_level'], 'medium')
        self.assertTrue(risk['requires_confirmation'])
        
        # Test public IP
        risk = self.security_warnings.analyze_target_risk("8.8.8.8")
        self.assertEqual(risk['risk_level'], 'high')
        self.assertTrue(risk['requires_confirmation'])
    
    def test_validate_scan_parameters(self):
        """Test scan parameter validation."""
        # Test normal scan
        is_valid, warnings = self.security_warnings.validate_scan_parameters(
            "localhost", [80, 443, 22]
        )
        self.assertTrue(is_valid)
        
        # Test excessive ports
        is_valid, warnings = self.security_warnings.validate_scan_parameters(
            "localhost", list(range(1, 1002))
        )
        self.assertTrue(is_valid)
        self.assertTrue(any("扫描端口数量过多" in w for w in warnings))
    
    def test_authorized_targets(self):
        """Test authorized target management."""
        target = "192.168.1.100"
        
        self.assertFalse(self.security_warnings.check_target_authorization(target))
        
        self.security_warnings.add_authorized_target(target)
        self.assertTrue(self.security_warnings.check_target_authorization(target))
        
        self.security_warnings.remove_authorized_target(target)
        self.assertFalse(self.security_warnings.check_target_authorization(target))


class TestDataProtection(unittest.TestCase):
    """Test cases for Data Protection functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.data_protection = DataProtection()
    
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        original_data = "sensitive_password_123"
        
        encrypted = self.data_protection.encrypt_data(original_data)
        self.assertNotEqual(encrypted, original_data)
        
        decrypted = self.data_protection.decrypt_data(encrypted)
        self.assertEqual(decrypted, original_data)
    
    def test_sanitize_log_data(self):
        """Test log data sanitization."""
        log_data = "User login with password: secret123 and api_key: abc123"
        
        sanitized = self.data_protection.sanitize_log_data(log_data)
        
        self.assertNotIn("secret123", sanitized)
        self.assertNotIn("abc123", sanitized)
        self.assertIn("[MASKED]", sanitized)
    
    def test_detect_malicious_usage(self):
        """Test malicious usage detection."""
        # Test safe input
        is_malicious, patterns = self.data_protection.detect_malicious_usage("ls -la")
        self.assertFalse(is_malicious)
        
        # Test malicious input
        is_malicious, patterns = self.data_protection.detect_malicious_usage("rm -rf /")
        self.assertTrue(is_malicious)
        self.assertTrue(len(patterns) > 0)
    
    def test_validate_input_security(self):
        """Test input security validation."""
        # Test safe input
        result = self.data_protection.validate_input_security("normal input")
        self.assertTrue(result['is_safe'])
        
        # Test malicious input
        result = self.data_protection.validate_input_security("DROP TABLE users")
        self.assertFalse(result['is_safe'])
        self.assertTrue(len(result['blocked_patterns']) > 0)
    
    def test_encrypt_config_data(self):
        """Test configuration data encryption."""
        config = {
            "api_key": "secret_key_123",
            "password": "user_password",
            "normal_field": "normal_value"
        }
        
        encrypted_config = self.data_protection.encrypt_config_data(config)
        
        # Sensitive fields should be encrypted
        self.assertNotEqual(encrypted_config['api_key'], config['api_key'])
        self.assertNotEqual(encrypted_config['password'], config['password'])
        
        # Normal fields should remain unchanged
        self.assertEqual(encrypted_config['normal_field'], config['normal_field'])


class TestComplianceMonitor(unittest.IsolatedAsyncioTestCase):
    """Test cases for Compliance Monitor functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.audit_logger = Mock(spec=AuditLogger)
        self.audit_logger.log_warning = Mock()
        self.audit_logger.log_compliance_event = Mock()
        self.compliance_monitor = ComplianceMonitor(self.audit_logger)
    
    async def test_check_compliance_violation_unauthorized_target(self):
        """Test unauthorized target violation detection."""
        has_violations, violations = await self.compliance_monitor.check_compliance_violation(
            'port_scan', {'target': '8.8.8.8'}
        )
        
        self.assertTrue(has_violations)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, 'unauthorized_target')
    
    async def test_check_compliance_violation_excessive_scanning(self):
        """Test excessive scanning violation detection."""
        has_violations, violations = await self.compliance_monitor.check_compliance_violation(
            'port_scan', {'ports': list(range(1, 1002))}
        )
        
        self.assertTrue(has_violations)
        self.assertTrue(any(v.rule == 'excessive_scanning' for v in violations))
    
    async def test_check_compliance_violation_malicious_payload(self):
        """Test malicious payload violation detection."""
        has_violations, violations = await self.compliance_monitor.check_compliance_violation(
            'attack_execution', {'payload': 'rm -rf /'}
        )
        
        self.assertTrue(has_violations)
        self.assertTrue(any(v.rule == 'malicious_payload' for v in violations))
    
    async def test_handle_compliance_violation(self):
        """Test violation handling."""
        from src.security.compliance_monitor import ComplianceViolation
        violations = [ComplianceViolation(
            rule='unauthorized_target',
            severity='high',
            description='Test violation',
            recommendation='Test recommendation',
            timestamp=datetime.now()
        )]
        
        await self.compliance_monitor.handle_compliance_violation(violations, 'test_user')
        
        # Check that violation was recorded
        self.assertEqual(len(self.compliance_monitor.violation_history), 1)
        
        # Check that audit logger was called
        self.audit_logger.log_compliance_event.assert_called_once()
    
    async def test_generate_compliance_report(self):
        """Test compliance report generation."""
        # Add some test violations     
        from src.security.compliance_monitor import ComplianceViolation       
        violations = [ComplianceViolation(
            rule='unauthorized_target',            severity='high',
            description='Test violation',
            recommendation='Test recommendation',
            timestamp=datetime.now(),
            user_id='test_user'
        )]
        
        await self.compliance_monitor.handle_compliance_violation(violations, 'test_user')
        
        report = await self.compliance_monitor.generate_compliance_report('test_user', 1)
        
        self.assertEqual(report['total_violations'], 1)
        self.assertEqual(report['user_id'], 'test_user')
        self.assertIn('unauthorized_target', report['violation_by_rule'])


class TestAuditLogger(unittest.TestCase):
    """Test cases for Audit Logger functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_security_event(self):
        """Test security event logging."""
        self.audit_logger.log_security_event(
            'TEST_EVENT', 'high', {'test': 'data'}
        )
        
        # Check that log file was created
        self.assertTrue(self.audit_logger.security_log.exists())
    
    def test_log_audit_event(self):
        """Test audit event logging."""
        self.audit_logger.log_audit_event(
            'TEST_ACTION', {'test': 'data'}, 'test_user'
        )
        
        # Check that log file was created
        self.assertTrue(self.audit_logger.audit_log.exists())
    
    def test_log_compliance_event(self):
        """Test compliance event logging."""
        self.audit_logger.log_compliance_event(
            'TEST_COMPLIANCE', 'pass', {'test': 'data'}
        )
        
        # Check that log file was created
        self.assertTrue(self.audit_logger.compliance_log.exists())
    
    def test_generate_compliance_report(self):
        """Test compliance report generation."""
        # Log some events
        self.audit_logger.log_security_event('TEST_EVENT', 'high', {'test': 'data'})
        self.audit_logger.log_compliance_event('TEST_COMPLIANCE', 'pass', {'test': 'data'})
        
        report = self.audit_logger.generate_compliance_report(24)
        
        self.assertIn('report_generated', report)
        self.assertIn('compliance_summary', report)
        self.assertIn('security_summary', report)


if __name__ == '__main__':
    unittest.main()