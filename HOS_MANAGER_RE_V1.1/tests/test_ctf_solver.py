"""
CTF解题器测试
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from src.ctf.solver import CTFSolver, CTFToolType
from src.ctf.models import CTFChallenge, CTFSolution, CTFDifficulty
from src.core.interfaces import CTFChallengeType
from src.core.exceptions import CybersecurityPlatformError


class TestCTFSolver:
    """CTF解题器测试类"""
    
    @pytest.fixture
    def mock_ai_assistant(self):
        """模拟AI助手"""
        assistant = Mock()
        assistant.analyze_ctf_challenge = AsyncMock(return_value={
            "analysis": "这是一个Web安全挑战",
            "solution_steps": ["步骤1", "步骤2"],
            "tools": ["curl", "sqlmap"],
            "confidence": 0.8
        })
        return assistant
    
    @pytest.fixture
    def mock_config_manager(self):
        """模拟配置管理器"""
        config_manager = Mock()
        config_manager.get_config = Mock(return_value={})
        return config_manager
    
    @pytest.fixture
    def mock_logger(self):
        """模拟日志记录器"""
        logger = Mock()
        logger.log_info = Mock()
        logger.log_error = Mock()
        return logger
    
    @pytest.fixture
    def ctf_solver(self, mock_ai_assistant, mock_config_manager, mock_logger):
        """创建CTF解题器实例"""
        return CTFSolver(mock_ai_assistant, mock_config_manager, mock_logger)
    
    @pytest.fixture
    def sample_web_challenge(self):
        """示例Web挑战"""
        return CTFChallenge(
            challenge_id="web_001",
            title="SQL注入挑战",
            description="这是一个包含SQL注入漏洞的Web应用程序，请找到flag",
            challenge_type=CTFChallengeType.WEB,
            difficulty=CTFDifficulty.MEDIUM,
            points=200,
            files=[],
            hints=[],
            flag_format="flag{.*}"
        )
    
    @pytest.fixture
    def sample_crypto_challenge(self):
        """示例密码学挑战"""
        return CTFChallenge(
            challenge_id="crypto_001", 
            title="Caesar密码",
            description="使用Caesar密码加密的文本: Wklv lv d vhfuhw phvvdjh",
            challenge_type=CTFChallengeType.CRYPTO,
            difficulty=CTFDifficulty.EASY,
            points=100,
            files=[],
            hints=[],
            flag_format="flag{.*}"
        )
    
    def test_challenge_type_identification(self, ctf_solver):
        """测试挑战类型识别"""
        # Web挑战识别
        web_text = "这是一个Web应用程序，包含SQL注入漏洞"
        assert ctf_solver.identify_challenge_type(web_text) == CTFChallengeType.WEB
        
        # 密码学挑战识别
        crypto_text = "这段文本使用了RSA加密算法"
        assert ctf_solver.identify_challenge_type(crypto_text) == CTFChallengeType.CRYPTO
        
        # 逆向工程挑战识别
        reverse_text = "请分析这个二进制文件并找到flag"
        assert ctf_solver.identify_challenge_type(reverse_text) == CTFChallengeType.REVERSE
        
        # 未知类型默认为MISC
        unknown_text = "这是一个未知类型的挑战"
        assert ctf_solver.identify_challenge_type(unknown_text) == CTFChallengeType.MISC
    
    @pytest.mark.asyncio
    async def test_solver_initialization(self, ctf_solver):
        """测试解题器初始化"""
        await ctf_solver.initialize()
        assert ctf_solver._is_initialized
    
    @pytest.mark.asyncio
    async def test_analyze_web_challenge(self, ctf_solver, sample_web_challenge):
        """测试Web挑战分析"""
        await ctf_solver.initialize()
        
        result = await ctf_solver.analyze_challenge(sample_web_challenge)
        
        assert result["challenge_id"] == "web_001"
        assert result["identified_type"] == "web"
        assert "ai_analysis" in result
        assert "recommended_tools" in result
        assert "analysis_steps" in result
    
    @pytest.mark.asyncio
    async def test_analyze_crypto_challenge(self, ctf_solver, sample_crypto_challenge):
        """测试密码学挑战分析"""
        await ctf_solver.initialize()
        
        result = await ctf_solver.analyze_challenge(sample_crypto_challenge)
        
        assert result["challenge_id"] == "crypto_001"
        assert result["identified_type"] == "crypto"
        assert "recommended_tools" in result
        assert "potential_methods" in result
    
    @pytest.mark.asyncio
    async def test_generate_web_solution(self, ctf_solver, sample_web_challenge):
        """测试Web解题方案生成"""
        await ctf_solver.initialize()
        
        solution = await ctf_solver.generate_solution(sample_web_challenge)
        
        assert isinstance(solution, CTFSolution)
        assert solution.challenge_id == "web_001"
        assert len(solution.solution_steps) > 0
        assert len(solution.tools_used) > 0
        assert solution.confidence > 0
    
    @pytest.mark.asyncio
    async def test_generate_crypto_solution(self, ctf_solver, sample_crypto_challenge):
        """测试密码学解题方案生成"""
        await ctf_solver.initialize()
        
        solution = await ctf_solver.generate_solution(sample_crypto_challenge)
        
        assert isinstance(solution, CTFSolution)
        assert solution.challenge_id == "crypto_001"
        assert len(solution.solution_steps) > 0
        assert "openssl" in solution.tools_used or "python" in solution.tools_used
    
    @pytest.mark.asyncio
    async def test_execute_solution(self, ctf_solver, sample_web_challenge):
        """测试解题方案执行"""
        await ctf_solver.initialize()
        
        solution = await ctf_solver.generate_solution(sample_web_challenge)
        result = await ctf_solver.execute_solution(solution)
        
        assert "solution_id" in result
        assert "execution_time" in result
        assert "steps_executed" in result
        assert isinstance(result["steps_executed"], list)
    
    def test_flag_extraction(self, ctf_solver):
        """测试flag提取"""
        # 测试标准flag格式
        output1 = "恭喜！你找到了flag{this_is_the_flag}"
        flag1 = ctf_solver._extract_flag_from_output(output1)
        assert flag1 == "flag{this_is_the_flag}"
        
        # 测试大写FLAG格式
        output2 = "FLAG{ANOTHER_FLAG_HERE}"
        flag2 = ctf_solver._extract_flag_from_output(output2)
        assert flag2 == "FLAG{ANOTHER_FLAG_HERE}"
        
        # 测试CTF格式
        output3 = "ctf{yet_another_flag}"
        flag3 = ctf_solver._extract_flag_from_output(output3)
        assert flag3 == "ctf{yet_another_flag}"
        
        # 测试无flag情况
        output4 = "没有找到任何flag"
        flag4 = ctf_solver._extract_flag_from_output(output4)
        assert flag4 is None
    
    def test_base64_detection(self, ctf_solver):
        """测试Base64检测"""
        # 有效的Base64
        valid_base64 = "SGVsbG8gV29ybGQ="
        assert ctf_solver._looks_like_base64(valid_base64)
        
        # 无效的Base64
        invalid_base64 = "这不是Base64"
        assert not ctf_solver._looks_like_base64(invalid_base64)
    
    def test_hex_detection(self, ctf_solver):
        """测试十六进制检测"""
        # 有效的十六进制
        valid_hex = "48656c6c6f20576f726c64"
        assert ctf_solver._looks_like_hex(valid_hex)
        
        # 无效的十六进制
        invalid_hex = "这不是十六进制"
        assert not ctf_solver._looks_like_hex(invalid_hex)
    
    def test_session_management(self, ctf_solver):
        """测试会话管理"""
        # 初始状态
        sessions = ctf_solver.get_solving_sessions()
        assert len(sessions) == 0
        
        # 添加会话后会在analyze_challenge中自动创建
        # 这里测试统计功能
        stats = ctf_solver.get_solver_statistics()
        assert stats["total_sessions"] == 0
        assert stats["solved_challenges"] == 0
        assert stats["success_rate"] == 0
    
    def test_solved_challenges_tracking(self, ctf_solver):
        """测试已解决挑战跟踪"""
        solved = ctf_solver.get_solved_challenges()
        assert len(solved) == 0
        
        # 模拟添加已解决的挑战
        ctf_solver.solved_challenges["test_001"] = {
            "solved_time": datetime.now(),
            "flag": "flag{test}",
            "solution": Mock()
        }
        
        solved = ctf_solver.get_solved_challenges()
        assert len(solved) == 1
        assert "test_001" in solved
    
    def test_statistics_calculation(self, ctf_solver):
        """测试统计信息计算"""
        stats = ctf_solver.get_solver_statistics()
        
        assert "total_sessions" in stats
        assert "solved_challenges" in stats
        assert "success_rate" in stats
        assert "type_statistics" in stats
        assert "available_tools" in stats
    
    def test_export_solutions(self, ctf_solver):
        """测试解题方案导出"""
        # 空导出
        export_data = ctf_solver.export_solutions()
        assert "export_time" in export_data
        assert "solutions" in export_data
        assert len(export_data["solutions"]) == 0
        
        # 添加解题方案后导出
        mock_solution = Mock()
        mock_solution.solution_steps = ["步骤1", "步骤2"]
        mock_solution.tools_used = ["tool1", "tool2"]
        mock_solution.confidence = 0.8
        
        ctf_solver.solved_challenges["test_001"] = {
            "solved_time": datetime.now(),
            "flag": "flag{test}",
            "solution": mock_solution
        }
        
        export_data = ctf_solver.export_solutions(["test_001"])
        assert len(export_data["solutions"]) == 1
        assert "test_001" in export_data["solutions"]
    
    @pytest.mark.asyncio
    async def test_error_handling(self, mock_ai_assistant, mock_config_manager, mock_logger):
        """测试错误处理"""
        # 模拟AI助手错误
        mock_ai_assistant.analyze_ctf_challenge = AsyncMock(side_effect=Exception("AI服务错误"))
        
        solver = CTFSolver(mock_ai_assistant, mock_config_manager, mock_logger)
        await solver.initialize()
        
        challenge = CTFChallenge(
            challenge_id="error_test",
            title="错误测试",
            description="测试错误处理",
            challenge_type=CTFChallengeType.WEB,
            difficulty=CTFDifficulty.EASY,
            points=100
        )
        
        with pytest.raises(CybersecurityPlatformError):
            await solver.analyze_challenge(challenge)
    
    def test_clear_session_history(self, ctf_solver):
        """测试清空会话历史"""
        # 添加一些模拟会话
        ctf_solver.solving_sessions["test_session"] = {
            "challenge": Mock(),
            "start_time": datetime.now(),
            "status": "completed",
            "steps": []
        }
        
        assert len(ctf_solver.solving_sessions) == 1
        
        ctf_solver.clear_session_history()
        assert len(ctf_solver.solving_sessions) == 0


if __name__ == "__main__":
    pytest.main([__file__])