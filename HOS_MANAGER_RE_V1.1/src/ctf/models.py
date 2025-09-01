"""
CTF数据模型 - 定义CTF相关的数据结构
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from src.core.interfaces import CTFChallengeType


class CTFDifficulty(Enum):
    """CTF难度等级"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class SolutionStatus(Enum):
    """解题状态"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SOLVED = "solved"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class CTFFile:
    """CTF挑战文件"""
    filename: str
    filepath: str
    file_type: str
    file_size: int
    checksum: Optional[str] = None
    description: Optional[str] = None


@dataclass
class CTFHint:
    """CTF提示"""
    hint_id: str
    content: str
    cost: int = 0
    unlocked: bool = False
    unlock_time: Optional[datetime] = None


@dataclass
class CTFChallenge:
    """CTF挑战完整模型"""
    challenge_id: str
    title: str
    description: str
    challenge_type: CTFChallengeType
    difficulty: CTFDifficulty
    points: int
    files: List[CTFFile] = field(default_factory=list)
    hints: List[CTFHint] = field(default_factory=list)
    flag_format: Optional[str] = None
    author: Optional[str] = None
    created_time: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CTFSolutionStep:
    """解题步骤"""
    step_id: str
    description: str
    command: Optional[str] = None
    expected_output: Optional[str] = None
    actual_output: Optional[str] = None
    tools_used: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    success: bool = False
    error_message: Optional[str] = None


@dataclass
class CTFSolution:
    """CTF解题方案完整模型"""
    solution_id: str
    challenge_id: str
    solution_steps: List[CTFSolutionStep]
    tools_used: List[str]
    flag: Optional[str] = None
    confidence: float = 0.0
    execution_time: float = 0.0
    success: bool = False
    status: SolutionStatus = SolutionStatus.PENDING
    created_time: Optional[datetime] = None
    completed_time: Optional[datetime] = None
    error_messages: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CTFSession:
    """CTF解题会话"""
    session_id: str
    challenge: CTFChallenge
    solution: Optional[CTFSolution] = None
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: SolutionStatus = SolutionStatus.PENDING
    current_step: int = 0
    notes: List[str] = field(default_factory=list)
    ai_interactions: List[Dict[str, Any]] = field(default_factory=list)
    user_id: Optional[str] = None


@dataclass
class CTFTool:
    """CTF工具信息"""
    tool_name: str
    tool_type: str
    version: Optional[str] = None
    command_template: Optional[str] = None
    description: Optional[str] = None
    installation_guide: Optional[str] = None
    is_available: bool = False
    supported_challenges: List[CTFChallengeType] = field(default_factory=list)


@dataclass
class CTFAnalysisResult:
    """CTF分析结果"""
    analysis_id: str
    challenge_id: str
    analysis_time: datetime
    identified_type: CTFChallengeType
    confidence: float
    analysis_steps: List[str]
    recommended_tools: List[str]
    potential_solutions: List[str]
    ai_analysis: Dict[str, Any]
    vulnerability_assessment: Optional[Dict[str, Any]] = None
    complexity_score: float = 0.0
    estimated_solve_time: float = 0.0


@dataclass
class CTFStatistics:
    """CTF统计信息"""
    total_challenges: int = 0
    solved_challenges: int = 0
    failed_challenges: int = 0
    success_rate: float = 0.0
    average_solve_time: float = 0.0
    challenges_by_type: Dict[str, int] = field(default_factory=dict)
    challenges_by_difficulty: Dict[str, int] = field(default_factory=dict)
    most_used_tools: List[str] = field(default_factory=list)
    fastest_solves: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class CTFCompetition:
    """CTF竞赛信息"""
    competition_id: str
    name: str
    description: str
    start_time: datetime
    end_time: datetime
    challenges: List[CTFChallenge] = field(default_factory=list)
    teams: List[str] = field(default_factory=list)
    scoreboard: Dict[str, int] = field(default_factory=dict)
    rules: Dict[str, Any] = field(default_factory=dict)
    status: str = "upcoming"  # upcoming, active, finished


@dataclass
class CTFTeam:
    """CTF团队信息"""
    team_id: str
    team_name: str
    members: List[str]
    total_score: int = 0
    solved_challenges: List[str] = field(default_factory=list)
    submission_history: List[Dict[str, Any]] = field(default_factory=list)
    ranking: int = 0
    last_submission: Optional[datetime] = None


@dataclass
class CTFSubmission:
    """CTF提交记录"""
    submission_id: str
    challenge_id: str
    team_id: str
    user_id: str
    submitted_flag: str
    is_correct: bool
    submission_time: datetime
    points_awarded: int = 0
    attempt_number: int = 1
    response_message: Optional[str] = None


# 工具配置模型
@dataclass
class CTFToolConfig:
    """CTF工具配置"""
    tool_name: str
    enabled: bool = True
    path: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    timeout: int = 300  # 5分钟默认超时
    max_memory: int = 1024  # MB
    working_directory: Optional[str] = None


@dataclass
class CTFEnvironment:
    """CTF环境配置"""
    environment_id: str
    name: str
    description: str
    docker_image: Optional[str] = None
    network_config: Dict[str, Any] = field(default_factory=dict)
    volume_mounts: List[str] = field(default_factory=list)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    tools: List[CTFToolConfig] = field(default_factory=list)


# 辅助函数
def create_challenge_from_dict(data: Dict[str, Any]) -> CTFChallenge:
    """从字典创建CTF挑战对象"""
    files = [
        CTFFile(
            filename=f.get("filename", ""),
            filepath=f.get("filepath", ""),
            file_type=f.get("file_type", "unknown"),
            file_size=f.get("file_size", 0),
            checksum=f.get("checksum"),
            description=f.get("description")
        )
        for f in data.get("files", [])
    ]
    
    hints = [
        CTFHint(
            hint_id=h.get("hint_id", ""),
            content=h.get("content", ""),
            cost=h.get("cost", 0),
            unlocked=h.get("unlocked", False)
        )
        for h in data.get("hints", [])
    ]
    
    return CTFChallenge(
        challenge_id=data["challenge_id"],
        title=data["title"],
        description=data["description"],
        challenge_type=CTFChallengeType(data["challenge_type"]),
        difficulty=CTFDifficulty(data.get("difficulty", "medium")),
        points=data.get("points", 100),
        files=files,
        hints=hints,
        flag_format=data.get("flag_format"),
        author=data.get("author"),
        tags=data.get("tags", []),
        metadata=data.get("metadata", {})
    )


def create_solution_from_dict(data: Dict[str, Any]) -> CTFSolution:
    """从字典创建CTF解题方案对象"""
    steps = [
        CTFSolutionStep(
            step_id=s.get("step_id", ""),
            description=s.get("description", ""),
            command=s.get("command"),
            expected_output=s.get("expected_output"),
            tools_used=s.get("tools_used", []),
            success=s.get("success", False)
        )
        for s in data.get("solution_steps", [])
    ]
    
    return CTFSolution(
        solution_id=data["solution_id"],
        challenge_id=data["challenge_id"],
        solution_steps=steps,
        tools_used=data.get("tools_used", []),
        flag=data.get("flag"),
        confidence=data.get("confidence", 0.0),
        success=data.get("success", False),
        status=SolutionStatus(data.get("status", "pending")),
        metadata=data.get("metadata", {})
    )


def challenge_to_dict(challenge: CTFChallenge) -> Dict[str, Any]:
    """将CTF挑战对象转换为字典"""
    return {
        "challenge_id": challenge.challenge_id,
        "title": challenge.title,
        "description": challenge.description,
        "challenge_type": challenge.challenge_type.value,
        "difficulty": challenge.difficulty.value,
        "points": challenge.points,
        "files": [
            {
                "filename": f.filename,
                "filepath": f.filepath,
                "file_type": f.file_type,
                "file_size": f.file_size,
                "checksum": f.checksum,
                "description": f.description
            }
            for f in challenge.files
        ],
        "hints": [
            {
                "hint_id": h.hint_id,
                "content": h.content,
                "cost": h.cost,
                "unlocked": h.unlocked
            }
            for h in challenge.hints
        ],
        "flag_format": challenge.flag_format,
        "author": challenge.author,
        "created_time": challenge.created_time.isoformat() if challenge.created_time else None,
        "tags": challenge.tags,
        "metadata": challenge.metadata
    }


def solution_to_dict(solution: CTFSolution) -> Dict[str, Any]:
    """将CTF解题方案对象转换为字典"""
    return {
        "solution_id": solution.solution_id,
        "challenge_id": solution.challenge_id,
        "solution_steps": [
            {
                "step_id": s.step_id,
                "description": s.description,
                "command": s.command,
                "expected_output": s.expected_output,
                "actual_output": s.actual_output,
                "tools_used": s.tools_used,
                "execution_time": s.execution_time,
                "success": s.success,
                "error_message": s.error_message
            }
            for s in solution.solution_steps
        ],
        "tools_used": solution.tools_used,
        "flag": solution.flag,
        "confidence": solution.confidence,
        "execution_time": solution.execution_time,
        "success": solution.success,
        "status": solution.status.value,
        "created_time": solution.created_time.isoformat() if solution.created_time else None,
        "completed_time": solution.completed_time.isoformat() if solution.completed_time else None,
        "error_messages": solution.error_messages,
        "metadata": solution.metadata
    }