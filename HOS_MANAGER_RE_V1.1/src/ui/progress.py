"""
Progress Display and Status Feedback Module.

This module provides progress indicators, status updates, and result display
for long-running operations in the cybersecurity platform.
"""

import time
import sys
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum


class OperationStatus(Enum):
    """Operation status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class OperationResult:
    """Operation result data structure."""
    operation_id: str
    status: OperationStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    progress: float = 0.0
    message: str = ""
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ProgressIndicator:
    """Progress indicator for long-running operations."""
    
    def __init__(self, total: int = 100, width: int = 50, 
                 show_percentage: bool = True, show_eta: bool = True):
        """
        Initialize progress indicator.
        
        Args:
            total: Total number of steps
            width: Progress bar width in characters
            show_percentage: Whether to show percentage
            show_eta: Whether to show estimated time
        """
        self.total = total
        self.width = width
        self.show_percentage = show_percentage
        self.show_eta = show_eta
        self.current = 0
        self.start_time = datetime.now()
        self.last_update = self.start_time
        
    def update(self, current: int, message: str = "") -> None:
        """
        Update progress.
        
        Args:
            current: Current progress value
            message: Status message
        """
        self.current = min(current, self.total)
        self.last_update = datetime.now()
        self._display_progress(message)
    
    def increment(self, step: int = 1, message: str = "") -> None:
        """
        Increment progress by step.
        
        Args:
            step: Step size to increment
            message: Status message
        """
        self.update(self.current + step, message)
    
    def finish(self, message: str = "完成") -> None:
        """
        Finish progress indicator.
        
        Args:
            message: Completion message
        """
        self.update(self.total, message)
        print()  # New line after completion
    
    def _display_progress(self, message: str) -> None:
        """Display progress bar."""
        percentage = (self.current / self.total) * 100
        filled_width = int(self.width * self.current / self.total)
        
        # Create progress bar
        bar = "█" * filled_width + "░" * (self.width - filled_width)
        
        # Build display string
        display_parts = [f"[{bar}]"]
        
        if self.show_percentage:
            display_parts.append(f"{percentage:6.1f}%")
        
        display_parts.append(f"({self.current}/{self.total})")
        
        if self.show_eta and self.current > 0:
            elapsed = datetime.now() - self.start_time
            rate = self.current / elapsed.total_seconds()
            if rate > 0:
                remaining_seconds = (self.total - self.current) / rate
                eta = timedelta(seconds=int(remaining_seconds))
                display_parts.append(f"ETA: {eta}")
        
        if message:
            display_parts.append(f"- {message}")
        
        # Print with carriage return to overwrite
        print(f"\r{' '.join(display_parts)}", end="", flush=True)


class SpinnerIndicator:
    """Spinner indicator for indeterminate operations."""
    
    def __init__(self, message: str = "处理中", 
                 spinner_chars: str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
        """
        Initialize spinner indicator.
        
        Args:
            message: Display message
            spinner_chars: Characters for spinner animation
        """
        self.message = message
        self.spinner_chars = spinner_chars
        self.running = False
        self.thread = None
        self.current_char = 0
    
    def start(self) -> None:
        """Start spinner animation."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._animate)
            self.thread.daemon = True
            self.thread.start()
    
    def stop(self, final_message: str = "完成") -> None:
        """
        Stop spinner animation.
        
        Args:
            final_message: Final message to display
        """
        if self.running:
            self.running = False
            if self.thread:
                self.thread.join()
            print(f"\r{final_message}" + " " * 20)  # Clear line
    
    def _animate(self) -> None:
        """Animate spinner."""
        while self.running:
            char = self.spinner_chars[self.current_char]
            print(f"\r{char} {self.message}", end="", flush=True)
            self.current_char = (self.current_char + 1) % len(self.spinner_chars)
            time.sleep(0.1)


class StatusDisplay:
    """Status display for operation feedback."""
    
    def __init__(self):
        """Initialize status display."""
        self.operations = {}
        self.display_width = 80
    
    def start_operation(self, operation_id: str, description: str) -> None:
        """
        Start tracking an operation.
        
        Args:
            operation_id: Unique operation identifier
            description: Operation description
        """
        result = OperationResult(
            operation_id=operation_id,
            status=OperationStatus.RUNNING,
            start_time=datetime.now(),
            message=description
        )
        self.operations[operation_id] = result
        self._display_operation_start(result)
    
    def update_operation(self, operation_id: str, progress: float = None, 
                        message: str = None) -> None:
        """
        Update operation status.
        
        Args:
            operation_id: Operation identifier
            progress: Progress percentage (0-100)
            message: Status message
        """
        if operation_id in self.operations:
            operation = self.operations[operation_id]
            if progress is not None:
                operation.progress = progress
            if message is not None:
                operation.message = message
            self._display_operation_update(operation)
    
    def complete_operation(self, operation_id: str, success: bool = True, 
                          message: str = None, data: Dict[str, Any] = None,
                          error: str = None) -> None:
        """
        Complete an operation.
        
        Args:
            operation_id: Operation identifier
            success: Whether operation succeeded
            message: Completion message
            data: Result data
            error: Error message if failed
        """
        if operation_id in self.operations:
            operation = self.operations[operation_id]
            operation.status = OperationStatus.SUCCESS if success else OperationStatus.ERROR
            operation.end_time = datetime.now()
            operation.progress = 100.0
            if message:
                operation.message = message
            if data:
                operation.data = data
            if error:
                operation.error = error
            
            self._display_operation_complete(operation)
    
    def _display_operation_start(self, operation: OperationResult) -> None:
        """Display operation start."""
        timestamp = operation.start_time.strftime("%H:%M:%S")
        print(f"[{timestamp}] 🚀 开始: {operation.message}")
    
    def _display_operation_update(self, operation: OperationResult) -> None:
        """Display operation update."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if operation.progress > 0:
            print(f"[{timestamp}] ⏳ 进度 {operation.progress:.1f}%: {operation.message}")
        else:
            print(f"[{timestamp}] ⏳ {operation.message}")
    
    def _display_operation_complete(self, operation: OperationResult) -> None:
        """Display operation completion."""
        timestamp = operation.end_time.strftime("%H:%M:%S")
        duration = operation.end_time - operation.start_time
        
        if operation.status == OperationStatus.SUCCESS:
            icon = "✅"
            status_text = "完成"
        else:
            icon = "❌"
            status_text = "失败"
        
        print(f"[{timestamp}] {icon} {status_text}: {operation.message} "
              f"(耗时: {duration.total_seconds():.1f}s)")
        
        if operation.error:
            print(f"    错误: {operation.error}")


class ResultFormatter:
    """Format and display operation results."""
    
    @staticmethod
    def display_scan_results(results: Dict[str, Any]) -> None:
        """
        Display scan results.
        
        Args:
            results: Scan results dictionary
        """
        print("\n" + "="*60)
        print("🔍 扫描结果")
        print("="*60)
        
        target = results.get('target', 'Unknown')
        print(f"📍 目标: {target}")
        
        ports = results.get('open_ports', [])
        if ports:
            print(f"🔓 开放端口 ({len(ports)}个):")
            for port_info in ports[:10]:  # Show first 10
                port = port_info.get('port', 'Unknown')
                service = port_info.get('service', 'Unknown')
                print(f"  • {port}/tcp - {service}")
            
            if len(ports) > 10:
                print(f"  ... 还有 {len(ports) - 10} 个端口")
        else:
            print("🔒 未发现开放端口")
        
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n⚠️ 发现漏洞 ({len(vulnerabilities)}个):")
            for vuln in vulnerabilities[:5]:  # Show first 5
                severity = vuln.get('severity', 'Unknown')
                description = vuln.get('description', 'Unknown')
                print(f"  • [{severity}] {description}")
        
        print("="*60)
    
    @staticmethod
    def display_threat_analysis(analysis: Dict[str, Any]) -> None:
        """
        Display threat analysis results.
        
        Args:
            analysis: Threat analysis dictionary
        """
        print("\n" + "="*60)
        print("🛡️ 威胁分析")
        print("="*60)
        
        threat_level = analysis.get('threat_level', 'Unknown')
        confidence = analysis.get('confidence', 0)
        
        level_icons = {
            'low': '🟢',
            'medium': '🟡', 
            'high': '🟠',
            'critical': '🔴'
        }
        
        icon = level_icons.get(threat_level.lower(), '⚪')
        print(f"{icon} 威胁级别: {threat_level.upper()} (置信度: {confidence}%)")
        
        indicators = analysis.get('indicators', [])
        if indicators:
            print(f"\n📊 威胁指标:")
            for indicator in indicators:
                print(f"  • {indicator}")
        
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            print(f"\n💡 建议措施:")
            for rec in recommendations:
                print(f"  • {rec}")
        
        print("="*60)
    
    @staticmethod
    def display_ctf_solution(solution: Dict[str, Any]) -> None:
        """
        Display CTF solution results.
        
        Args:
            solution: CTF solution dictionary
        """
        print("\n" + "="*60)
        print("🏆 CTF解题结果")
        print("="*60)
        
        challenge_type = solution.get('type', 'Unknown')
        difficulty = solution.get('difficulty', 'Unknown')
        
        print(f"📝 题目类型: {challenge_type}")
        print(f"⭐ 难度: {difficulty}")
        
        if solution.get('solved', False):
            print("✅ 解题状态: 已解决")
            flag = solution.get('flag', '')
            if flag:
                print(f"🚩 Flag: {flag}")
        else:
            print("❌ 解题状态: 未解决")
        
        steps = solution.get('steps', [])
        if steps:
            print(f"\n🔧 解题步骤:")
            for i, step in enumerate(steps, 1):
                print(f"  {i}. {step}")
        
        tools_used = solution.get('tools_used', [])
        if tools_used:
            print(f"\n🛠️ 使用工具: {', '.join(tools_used)}")
        
        print("="*60)