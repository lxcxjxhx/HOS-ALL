"""
Terms of Service and Legal Compliance Module.

This module handles the display and acceptance of terms of service,
legal disclaimers, and usage agreements for the cybersecurity platform.
"""

import json
import os
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path


class TermsOfService:
    """Manages terms of service display and acceptance tracking."""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize Terms of Service manager.
        
        Args:
            config_dir: Directory to store acceptance records
        """
        self.config_dir = Path(config_dir)
        self.acceptance_file = self.config_dir / "terms_acceptance.json"
        self.config_dir.mkdir(exist_ok=True)
        
    def get_terms_text(self) -> str:
        """
        Get the current terms of service text.
        
        Returns:
            Terms of service text in Chinese
        """
        return """
=================================================================
AI增强网络安全系统 - 使用条款和法律声明
=================================================================

重要提示：请仔细阅读以下条款。使用本系统即表示您同意遵守所有条款。

1. 合法使用声明
   本系统仅供教育、研究和授权的安全测试使用。严禁用于：
   - 未经授权的网络攻击或渗透测试
   - 恶意破坏他人计算机系统或网络
   - 非法获取他人敏感信息
   - 任何违反当地法律法规的活动

2. 用户责任
   用户必须：
   - 确保拥有目标系统的合法授权
   - 遵守所有适用的法律法规
   - 对使用本系统的后果承担全部责任
   - 不得将系统用于商业攻击或恶意目的

3. 免责声明
   - 本系统开发者不对用户的违法使用承担任何责任
   - 用户使用本系统造成的任何损失由用户自行承担
   - 系统提供的功能仅用于安全研究和教育目的

4. 数据安全
   - 系统会记录操作日志用于安全审计
   - 敏感信息将被加密存储和传输
   - 用户有责任保护自己的API密钥和配置信息

5. 合规监控
   - 系统会监控可疑的恶意使用行为
   - 违规使用可能导致功能限制或访问禁止
   - 严重违规行为将被记录并可能上报相关部门

通过输入 'accept' 或 'agree'，您确认已阅读、理解并同意遵守上述条款。
输入 'decline' 或 'reject' 将退出系统。

=================================================================
"""

    def display_terms(self) -> None:
        """Display the terms of service to the user."""
        print(self.get_terms_text())
        
    def check_acceptance(self) -> bool:
        """
        Check if user has previously accepted terms.
        
        Returns:
            True if terms have been accepted, False otherwise
        """
        if not self.acceptance_file.exists():
            return False
            
        try:
            with open(self.acceptance_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('accepted', False)
        except (json.JSONDecodeError, FileNotFoundError):
            return False
    
    def record_acceptance(self, user_id: str = "default") -> None:
        """
        Record user acceptance of terms.
        
        Args:
            user_id: Identifier for the user accepting terms
        """
        acceptance_data = {
            'accepted': True,
            'user_id': user_id,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        with open(self.acceptance_file, 'w', encoding='utf-8') as f:
            json.dump(acceptance_data, f, indent=2, ensure_ascii=False)
    
    def prompt_acceptance(self) -> bool:
        """
        Prompt user to accept terms and record response.
        
        Returns:
            True if user accepts, False if declined
        """
        if self.check_acceptance():
            return True
            
        self.display_terms()
        
        while True:
            response = input("\n请输入您的选择 (accept/agree 同意, decline/reject 拒绝): ").strip().lower()
            
            if response in ['accept', 'agree', '同意', 'y', 'yes']:
                self.record_acceptance()
                print("\n✓ 感谢您接受使用条款。系统将继续启动...")
                return True
            elif response in ['decline', 'reject', '拒绝', 'n', 'no']:
                print("\n✗ 您已拒绝使用条款。系统将退出...")
                return False
            else:
                print("无效输入，请输入 'accept'/'agree' 同意或 'decline'/'reject' 拒绝")
    
    def get_acceptance_info(self) -> Optional[Dict]:
        """
        Get information about terms acceptance.
        
        Returns:
            Dictionary with acceptance information or None if not accepted
        """
        if not self.acceptance_file.exists():
            return None
            
        try:
            with open(self.acceptance_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return None
    
    def revoke_acceptance(self) -> None:
        """Revoke terms acceptance (for testing or user request)."""
        if self.acceptance_file.exists():
            self.acceptance_file.unlink()