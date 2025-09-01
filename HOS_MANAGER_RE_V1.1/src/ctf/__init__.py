"""
CTF模块 - CTF挑战分析和解题功能
"""

from .solver import CTFSolver, CTFToolType
from .models import (
    CTFChallenge, CTFSolution, CTFSession, CTFTool, CTFAnalysisResult,
    CTFDifficulty, SolutionStatus, CTFFile, CTFHint, CTFSolutionStep,
    CTFStatistics, CTFCompetition, CTFTeam, CTFSubmission,
    CTFToolConfig, CTFEnvironment,
    create_challenge_from_dict, create_solution_from_dict,
    challenge_to_dict, solution_to_dict
)
from .tools import (
    CTFToolManager, CTFScriptExecutor, CTFToolInterface,
    BaseCTFTool, WebTool, CryptoTool, ReverseTool, PwnTool,
    ForensicsTool, MiscTool
)

__all__ = [
    # 主要类
    "CTFSolver",
    "CTFToolManager", 
    "CTFScriptExecutor",
    
    # 数据模型
    "CTFChallenge",
    "CTFSolution", 
    "CTFSession",
    "CTFTool",
    "CTFAnalysisResult",
    "CTFFile",
    "CTFHint",
    "CTFSolutionStep",
    "CTFStatistics",
    "CTFCompetition",
    "CTFTeam", 
    "CTFSubmission",
    "CTFToolConfig",
    "CTFEnvironment",
    
    # 枚举
    "CTFToolType",
    "CTFDifficulty",
    "SolutionStatus",
    
    # 工具接口
    "CTFToolInterface",
    "BaseCTFTool",
    "WebTool",
    "CryptoTool", 
    "ReverseTool",
    "PwnTool",
    "ForensicsTool",
    "MiscTool",
    
    # 辅助函数
    "create_challenge_from_dict",
    "create_solution_from_dict", 
    "challenge_to_dict",
    "solution_to_dict"
]

# 版本信息
__version__ = "1.0.0"
__author__ = "AI Cybersecurity Platform Team"
__description__ = "CTF挑战分析和解题模块"