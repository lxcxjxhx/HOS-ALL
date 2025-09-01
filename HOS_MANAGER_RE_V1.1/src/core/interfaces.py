"""
核心接口定义 - 定义系统中各个组件的抽象接口
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import asyncio


class AIProviderType(Enum):
    """AI提供商类型枚举"""
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    CLAUDE = "claude"
    GEMINI = "gemini"
    OLLAMA = "ollama"


class AttackType(Enum):
    """攻击类型枚举"""
    PORT_SCAN = "port_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CUSTOM = "custom"


class ThreatLevel(Enum):
    """威胁等级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CTFChallengeType(Enum):
    """CTF挑战类型枚举"""
    WEB = "web"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    PWN = "pwn"
    FORENSICS = "forensics"
    MISC = "misc"


@dataclass
class AIResponse:
    """AI响应数据模型"""
    content: str
    provider: AIProviderType
    model: str
    tokens_used: int
    response_time: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class ScanResult:
    """扫描结果数据模型"""
    target: str
    scan_type: str
    open_ports: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    scan_duration: float
    timestamp: str
    success: bool
    error_message: Optional[str] = None


@dataclass
class ThreatEvent:
    """威胁事件数据模型"""
    event_id: str
    source_ip: str
    target_ip: str
    threat_type: str
    threat_level: ThreatLevel
    description: str
    timestamp: str
    raw_data: Dict[str, Any]


@dataclass
class CTFChallenge:
    """CTF挑战数据模型"""
    challenge_id: str
    title: str
    description: str
    challenge_type: CTFChallengeType
    difficulty: str
    files: List[str]
    hints: List[str]
    flag_format: Optional[str] = None


@dataclass
class CTFSolution:
    """CTF解题方案数据模型"""
    challenge_id: str
    solution_steps: List[str]
    tools_used: List[str]
    flag: Optional[str]
    confidence: float
    execution_time: float
    success: bool


class IAIProvider(ABC):
    """AI提供商接口"""
    
    @abstractmethod
    async def generate_response(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """生成AI响应"""
        pass
    
    @abstractmethod
    async def validate_api_key(self) -> bool:
        """验证API密钥"""
        pass
    
    @abstractmethod
    def get_provider_info(self) -> Dict[str, Any]:
        """获取提供商信息"""
        pass


class IAttackSimulator(ABC):
    """攻击模拟器接口"""
    
    @abstractmethod
    async def start_session(self, target: str, attack_types: List[AttackType]) -> str:
        """开始攻击会话"""
        pass
    
    @abstractmethod
    async def execute_attack(self, session_id: str, attack_config: Dict[str, Any]) -> ScanResult:
        """执行攻击"""
        pass
    
    @abstractmethod
    async def stop_session(self, session_id: str) -> bool:
        """停止攻击会话"""
        pass
    
    @abstractmethod
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """获取会话状态"""
        pass


class IDefenseSystem(ABC):
    """防御系统接口"""
    
    @abstractmethod
    async def start_monitoring(self, network_range: str) -> bool:
        """开始网络监控"""
        pass
    
    @abstractmethod
    async def stop_monitoring(self) -> bool:
        """停止网络监控"""
        pass
    
    @abstractmethod
    async def detect_threats(self, network_data: Dict[str, Any]) -> List[ThreatEvent]:
        """检测威胁"""
        pass
    
    @abstractmethod
    async def generate_defense_response(self, threat: ThreatEvent) -> Dict[str, Any]:
        """生成防御响应"""
        pass


class ICTFSolver(ABC):
    """CTF解题器接口"""
    
    @abstractmethod
    async def analyze_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析挑战"""
        pass
    
    @abstractmethod
    async def generate_solution(self, challenge: CTFChallenge) -> CTFSolution:
        """生成解题方案"""
        pass
    
    @abstractmethod
    async def execute_solution(self, solution: CTFSolution) -> Dict[str, Any]:
        """执行解题方案"""
        pass


class IConfigManager(ABC):
    """配置管理器接口"""
    
    @abstractmethod
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """加载配置"""
        pass
    
    @abstractmethod
    def save_config(self, config: Dict[str, Any], config_path: str) -> bool:
        """保存配置"""
        pass
    
    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """验证配置"""
        pass
    
    @abstractmethod
    def encrypt_sensitive_data(self, data: str) -> str:
        """加密敏感数据"""
        pass
    
    @abstractmethod
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """解密敏感数据"""
        pass


class ILogger(ABC):
    """日志记录器接口"""
    
    @abstractmethod
    def log_info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """记录信息日志"""
        pass
    
    @abstractmethod
    def log_warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """记录警告日志"""
        pass
    
    @abstractmethod
    def log_error(self, message: str, error: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None) -> None:
        """记录错误日志"""
        pass
    
    @abstractmethod
    def log_security_event(self, event: ThreatEvent) -> None:
        """记录安全事件"""
        pass


class IUserInterface(ABC):
    """用户界面接口"""
    
    @abstractmethod
    async def display_menu(self) -> str:
        """显示主菜单"""
        pass
    
    @abstractmethod
    async def get_user_input(self, prompt: str, input_type: str = "text") -> Any:
        """获取用户输入"""
        pass
    
    @abstractmethod
    async def display_results(self, results: Dict[str, Any]) -> None:
        """显示结果"""
        pass
    
    @abstractmethod
    async def display_progress(self, current: int, total: int, message: str) -> None:
        """显示进度"""
        pass
    
    @abstractmethod
    async def display_error(self, error_message: str) -> None:
        """显示错误信息"""
        pass