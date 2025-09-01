"""
Data Protection and Security Module.

This module handles encryption of sensitive data, secure transmission,
log sanitization, and malicious usage detection.
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


class DataProtection:
    """Handles data protection, encryption, and security measures."""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        """
        Initialize data protection module.
        
        Args:
            encryption_key: Optional encryption key, generates new one if None
        """
        if encryption_key:
            self.fernet = Fernet(encryption_key)
        else:
            key = Fernet.generate_key()
            self.fernet = Fernet(key)
        
        # Patterns for sensitive data detection
        self.sensitive_patterns = {
            'password': [
                r'password["\s]*[:=]["\s]*([^"\s,}]+)',
                r'passwd["\s]*[:=]["\s]*([^"\s,}]+)',
                r'pwd["\s]*[:=]["\s]*([^"\s,}]+)',
            ],
            'api_key': [
                r'api[_-]?key["\s]*[:=]["\s]*([^"\s,}]+)',
                r'apikey["\s]*[:=]["\s]*([^"\s,}]+)',
                r'access[_-]?token["\s]*[:=]["\s]*([^"\s,}]+)',
            ],
            'secret': [
                r'secret["\s]*[:=]["\s]*([^"\s,}]+)',
                r'private[_-]?key["\s]*[:=]["\s]*([^"\s,}]+)',
            ],
            'credit_card': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            ],
            'email': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            'ip_address': [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            ]
        }
        
        # Malicious usage patterns
        self.malicious_patterns = [
            r'rm\s+-rf\s+/',  # Dangerous file deletion
            r'format\s+c:',   # Format system drive
            r'del\s+/[qsf]',  # Windows delete commands
            r'DROP\s+TABLE',  # SQL injection attempts
            r'UNION\s+SELECT', # SQL injection
            r'<script.*?>',   # XSS attempts
            r'javascript:',   # JavaScript injection
            r'eval\s*\(',     # Code evaluation
            r'exec\s*\(',     # Code execution
        ]
    
    def encrypt_data(self, data: str) -> str:
        """
        Encrypt sensitive data.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Base64 encoded encrypted data
        """
        try:
            encrypted = self.fernet.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise ValueError(f"加密失败: {str(e)}")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypt encrypted data.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            
        Returns:
            Decrypted data string
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"解密失败: {str(e)}")
    
    def sanitize_log_data(self, log_data: str) -> str:
        """
        Remove sensitive information from log data.
        
        Args:
            log_data: Raw log data
            
        Returns:
            Sanitized log data with sensitive info masked
        """
        sanitized = log_data
        
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                # Replace sensitive data with masked version
                if category == 'password':
                    sanitized = re.sub(pattern, f'{category}: [MASKED]', sanitized, flags=re.IGNORECASE)
                elif category == 'api_key':
                    sanitized = re.sub(pattern, f'{category}: [MASKED]', sanitized, flags=re.IGNORECASE)
                elif category == 'secret':
                    sanitized = re.sub(pattern, f'{category}: [MASKED]', sanitized, flags=re.IGNORECASE)
                elif category == 'credit_card':
                    sanitized = re.sub(pattern, 'XXXX-XXXX-XXXX-XXXX', sanitized)
                elif category == 'email':
                    sanitized = re.sub(pattern, '[EMAIL_MASKED]', sanitized)
                elif category == 'ip_address':
                    # Only mask if it's not localhost/private IP
                    def mask_ip(match):
                        ip = match.group(0)
                        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
                            return ip  # Keep private IPs
                        return 'XXX.XXX.XXX.XXX'
                    sanitized = re.sub(pattern, mask_ip, sanitized)
        
        return sanitized
    
    def detect_malicious_usage(self, input_data: str) -> Tuple[bool, List[str]]:
        """
        Detect potentially malicious usage patterns.
        
        Args:
            input_data: User input or command to analyze
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected_patterns = []
        
        for pattern in self.malicious_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        # Additional checks for suspicious behavior
        suspicious_keywords = [
            'backdoor', 'rootkit', 'keylogger', 'trojan',
            'ransomware', 'botnet', 'ddos', 'dos attack'
        ]
        
        for keyword in suspicious_keywords:
            if keyword.lower() in input_data.lower():
                detected_patterns.append(f"suspicious_keyword: {keyword}")
        
        return len(detected_patterns) > 0, detected_patterns
    
    def secure_hash(self, data: str, salt: Optional[str] = None) -> str:
        """
        Generate secure hash of data.
        
        Args:
            data: Data to hash
            salt: Optional salt for hashing
            
        Returns:
            Hexadecimal hash string
        """
        if salt is None:
            salt = os.urandom(32)
        elif isinstance(salt, str):
            salt = salt.encode()
        
        # Use PBKDF2 for secure hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(data.encode())
        return key.hex()
    
    def validate_input_security(self, user_input: str) -> Dict:
        """
        Validate user input for security concerns.
        
        Args:
            user_input: User input to validate
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'is_safe': True,
            'warnings': [],
            'blocked_patterns': [],
            'sanitized_input': user_input
        }
        
        # Check for malicious patterns
        is_malicious, patterns = self.detect_malicious_usage(user_input)
        if is_malicious:
            result['is_safe'] = False
            result['blocked_patterns'] = patterns
            result['warnings'].append("检测到潜在恶意输入模式")
        
        # Check input length
        if len(user_input) > 10000:
            result['warnings'].append("输入长度过长，可能存在安全风险")
        
        # Check for excessive special characters
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', user_input)) / len(user_input) if user_input else 0
        if special_char_ratio > 0.5:
            result['warnings'].append("输入包含过多特殊字符")
        
        # Sanitize the input
        result['sanitized_input'] = self.sanitize_log_data(user_input)
        
        return result
    
    def encrypt_config_data(self, config_data: Dict) -> Dict:
        """
        Encrypt sensitive fields in configuration data.
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            Configuration with encrypted sensitive fields
        """
        encrypted_config = config_data.copy()
        
        # Fields that should be encrypted
        sensitive_fields = [
            'api_key', 'password', 'secret', 'token',
            'private_key', 'access_token', 'refresh_token'
        ]
        
        def encrypt_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if any(field in key.lower() for field in sensitive_fields):
                        if isinstance(value, str) and value:
                            obj[key] = self.encrypt_data(value)
                    elif isinstance(value, (dict, list)):
                        encrypt_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        encrypt_recursive(item, f"{path}[{i}]")
        
        encrypt_recursive(encrypted_config)
        return encrypted_config
    
    def decrypt_config_data(self, encrypted_config: Dict) -> Dict:
        """
        Decrypt sensitive fields in configuration data.
        
        Args:
            encrypted_config: Configuration with encrypted fields
            
        Returns:
            Configuration with decrypted sensitive fields
        """
        decrypted_config = encrypted_config.copy()
        
        # Fields that should be decrypted
        sensitive_fields = [
            'api_key', 'password', 'secret', 'token',
            'private_key', 'access_token', 'refresh_token'
        ]
        
        def decrypt_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if any(field in key.lower() for field in sensitive_fields):
                        if isinstance(value, str) and value:
                            try:
                                obj[key] = self.decrypt_data(value)
                            except ValueError:
                                # If decryption fails, assume it's not encrypted
                                pass
                    elif isinstance(value, (dict, list)):
                        decrypt_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        decrypt_recursive(item, f"{path}[{i}]")
        
        decrypt_recursive(decrypted_config)
        return decrypted_config
    
    def create_secure_session(self, user_id: str, session_data: Dict) -> str:
        """
        Create a secure session token.
        
        Args:
            user_id: User identifier
            session_data: Session data to include
            
        Returns:
            Encrypted session token
        """
        session_info = {
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'data': session_data
        }
        
        session_json = json.dumps(session_info)
        return self.encrypt_data(session_json)
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """
        Validate and decode session token.
        
        Args:
            session_token: Encrypted session token
            
        Returns:
            Session data if valid, None otherwise
        """
        try:
            session_json = self.decrypt_data(session_token)
            session_info = json.loads(session_json)
            
            # Check if session is not too old (24 hours)
            created_at = datetime.fromisoformat(session_info['created_at'])
            age = datetime.now() - created_at
            
            if age.total_seconds() > 86400:  # 24 hours
                return None
                
            return session_info
        except (ValueError, json.JSONDecodeError, KeyError):
            return None
    
    def log_security_event(self, event_type: str, details: Dict) -> Dict:
        """
        Log security event with sanitized data.
        
        Args:
            event_type: Type of security event
            details: Event details
            
        Returns:
            Sanitized log entry
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details.copy()
        }
        
        # Sanitize the details
        sanitized_details = {}
        for key, value in details.items():
            if isinstance(value, str):
                sanitized_details[key] = self.sanitize_log_data(value)
            else:
                sanitized_details[key] = value
        
        log_entry['details'] = sanitized_details
        return log_entry
    
    def generate_encryption_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Generate encryption key from password.
        
        Args:
            password: Password to derive key from
            salt: Optional salt bytes
            
        Returns:
            Derived encryption key
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)
    
    def check_data_integrity(self, data: str, expected_hash: str) -> bool:
        """
        Check data integrity using hash comparison.
        
        Args:
            data: Data to check
            expected_hash: Expected hash value
            
        Returns:
            True if data integrity is valid
        """
        actual_hash = hashlib.sha256(data.encode()).hexdigest()
        return actual_hash == expected_hash