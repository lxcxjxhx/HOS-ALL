"""
CTF解题器演示脚本
"""

import asyncio
import sys
import os
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.ctf.solver import CTFSolver
from src.ctf.models import CTFChallenge, CTFDifficulty
from src.ctf.tools import CTFToolManager
from src.core.interfaces import CTFChallengeType
from src.ai.assistant import AIAssistant
from src.config.manager import ConfigManager


class MockLogger:
    """简单的日志记录器"""
    
    def log_info(self, message, context=None):
        print(f"[INFO] {message}")
        if context:
            print(f"       Context: {context}")
    
    def log_error(self, message, error=None, context=None):
        print(f"[ERROR] {message}")
        if error:
            print(f"        Error: {error}")
        if context:
            print(f"        Context: {context}")
    
    def log_warning(self, message, context=None):
        print(f"[WARN] {message}")
        if context:
            print(f"       Context: {context}")


async def demo_web_challenge():
    """演示Web挑战解题"""
    print("=== Web挑战解题演示 ===")
    
    # 创建示例Web挑战
    web_challenge = CTFChallenge(
        challenge_id="demo_web_001",
        title="简单的SQL注入",
        description="""
        这是一个包含SQL注入漏洞的登录页面。
        URL: http://example.com/login.php
        
        提示：尝试在用户名字段中注入SQL代码来绕过认证。
        """,
        challenge_type=CTFChallengeType.WEB,
        difficulty=CTFDifficulty.EASY,
        points=150,
        flag_format="flag{.*}"
    )
    
    # 创建模拟的AI助手和配置管理器
    logger = MockLogger()
    config_manager = ConfigManager(logger)
    
    # 创建简单的AI助手模拟
    class MockAIAssistant:
        async def analyze_ctf_challenge(self, challenge):
            return {
                "analysis": f"这是一个{challenge.challenge_type.value}类型的挑战，难度为{challenge.difficulty.value}",
                "solution_steps": [
                    "分析登录页面的源代码",
                    "测试用户名字段的SQL注入",
                    "尝试使用' OR '1'='1绕过认证",
                    "查找flag在页面中的位置"
                ],
                "tools": ["curl", "sqlmap", "burp"],
                "confidence": 0.8
            }
    
    ai_assistant = MockAIAssistant()
    
    # 创建CTF解题器
    solver = CTFSolver(ai_assistant, config_manager, logger)
    await solver.initialize()
    
    print(f"挑战标题: {web_challenge.title}")
    print(f"挑战类型: {web_challenge.challenge_type.value}")
    print(f"难度: {web_challenge.difficulty.value}")
    print(f"分数: {web_challenge.points}")
    print(f"描述: {web_challenge.description.strip()}")
    print()
    
    # 分析挑战
    print("正在分析挑战...")
    analysis_result = await solver.analyze_challenge(web_challenge)
    
    print("分析结果:")
    print(f"- 识别类型: {analysis_result['identified_type']}")
    print(f"- 推荐工具: {analysis_result.get('recommended_tools', [])}")
    print(f"- 分析步骤: {analysis_result.get('analysis_steps', [])}")
    print()
    
    # 生成解题方案
    print("正在生成解题方案...")
    solution = await solver.generate_solution(web_challenge)
    
    print("解题方案:")
    print(f"- 置信度: {solution.confidence}")
    print(f"- 使用工具: {solution.tools_used}")
    print("- 解题步骤:")
    for i, step in enumerate(solution.solution_steps, 1):
        print(f"  {i}. {step}")
    print()
    
    # 执行解题方案
    print("正在执行解题方案...")
    execution_result = await solver.execute_solution(solution)
    
    print("执行结果:")
    print(f"- 成功: {execution_result['success']}")
    print(f"- 执行步骤数: {len(execution_result['steps_executed'])}")
    if execution_result.get('flag_found'):
        print(f"- 找到Flag: {execution_result['flag_found']}")
    if execution_result.get('error_messages'):
        print(f"- 错误信息: {execution_result['error_messages']}")
    print()


async def demo_crypto_challenge():
    """演示密码学挑战解题"""
    print("=== 密码学挑战解题演示 ===")
    
    # 创建示例密码学挑战
    crypto_challenge = CTFChallenge(
        challenge_id="demo_crypto_001",
        title="Caesar密码解密",
        description="""
        以下文本使用了Caesar密码加密：
        
        Wklv lv d vhfuhw phvvdjh. Wkh iodj lv: iodj{fdhvdu_flskhu_lv_hdvb}
        
        请解密这段文本并找到flag。
        """,
        challenge_type=CTFChallengeType.CRYPTO,
        difficulty=CTFDifficulty.EASY,
        points=100,
        flag_format="flag{.*}"
    )
    
    logger = MockLogger()
    config_manager = ConfigManager(logger)
    
    class MockAIAssistant:
        async def analyze_ctf_challenge(self, challenge):
            return {
                "analysis": f"这是一个{challenge.challenge_type.value}类型的挑战，看起来是Caesar密码",
                "solution_steps": [
                    "识别加密类型为Caesar密码",
                    "尝试不同的偏移量进行解密",
                    "查找解密后文本中的flag",
                    "验证flag格式"
                ],
                "tools": ["python", "openssl"],
                "confidence": 0.9
            }
    
    ai_assistant = MockAIAssistant()
    solver = CTFSolver(ai_assistant, config_manager, logger)
    await solver.initialize()
    
    print(f"挑战标题: {crypto_challenge.title}")
    print(f"挑战类型: {crypto_challenge.challenge_type.value}")
    print(f"描述: {crypto_challenge.description.strip()}")
    print()
    
    # 分析挑战
    analysis_result = await solver.analyze_challenge(crypto_challenge)
    print("分析结果:")
    print(f"- 推荐工具: {analysis_result.get('recommended_tools', [])}")
    print(f"- 潜在方法: {analysis_result.get('potential_methods', [])}")
    print()
    
    # 生成解题方案
    solution = await solver.generate_solution(crypto_challenge)
    print("解题方案:")
    print(f"- 置信度: {solution.confidence}")
    for i, step in enumerate(solution.solution_steps, 1):
        print(f"  {i}. {step}")
    print()
    
    # 模拟找到flag
    print("模拟解密过程...")
    print("尝试偏移量3...")
    decrypted = "This is a secret message. The flag is: flag{caesar_cipher_is_easy}"
    print(f"解密结果: {decrypted}")
    
    # 提取flag
    flag = solver._extract_flag_from_output(decrypted)
    if flag:
        print(f"找到Flag: {flag}")
    print()


async def demo_tool_management():
    """演示工具管理"""
    print("=== CTF工具管理演示 ===")
    
    logger = MockLogger()
    tool_manager = CTFToolManager(logger)
    await tool_manager.initialize()
    
    # 获取可用工具
    all_tools = tool_manager.get_available_tools()
    print(f"可用工具总数: {len(all_tools)}")
    print(f"可用工具: {', '.join(all_tools[:10])}{'...' if len(all_tools) > 10 else ''}")
    print()
    
    # 按挑战类型获取工具
    for challenge_type in CTFChallengeType:
        tools = tool_manager.get_available_tools(challenge_type)
        print(f"{challenge_type.value}类型可用工具: {tools}")
    print()
    
    # 获取工具统计
    stats = tool_manager.get_tool_statistics()
    print("工具统计:")
    print(f"- 总工具数: {stats['total_tools']}")
    print(f"- 可用工具数: {stats['available_tools']}")
    print(f"- 可用率: {stats['availability_rate']:.2%}")
    print()
    
    # 测试工具执行（如果工具可用）
    if "file" in all_tools:
        print("测试file工具...")
        try:
            result = await tool_manager.execute_tool("file", [__file__])
            print(f"执行结果: {result['success']}")
            if result['success']:
                print(f"输出: {result['stdout'][:100]}...")
        except Exception as e:
            print(f"执行失败: {e}")
    print()


async def demo_solver_statistics():
    """演示解题器统计"""
    print("=== 解题器统计演示 ===")
    
    logger = MockLogger()
    config_manager = ConfigManager(logger)
    
    class MockAIAssistant:
        async def analyze_ctf_challenge(self, challenge):
            return {"analysis": "模拟分析", "confidence": 0.7}
    
    ai_assistant = MockAIAssistant()
    solver = CTFSolver(ai_assistant, config_manager, logger)
    await solver.initialize()
    
    # 获取初始统计
    stats = solver.get_solver_statistics()
    print("初始统计:")
    print(f"- 总会话数: {stats['total_sessions']}")
    print(f"- 已解决挑战: {stats['solved_challenges']}")
    print(f"- 成功率: {stats['success_rate']:.2%}")
    print(f"- 可用工具数: {stats['available_tools']}")
    print()
    
    # 模拟一些解题活动
    challenges = [
        CTFChallenge("web_001", "Web挑战1", "描述1", CTFChallengeType.WEB, CTFDifficulty.EASY, 100),
        CTFChallenge("crypto_001", "密码挑战1", "描述2", CTFChallengeType.CRYPTO, CTFDifficulty.MEDIUM, 200),
        CTFChallenge("reverse_001", "逆向挑战1", "描述3", CTFChallengeType.REVERSE, CTFDifficulty.HARD, 300)
    ]
    
    for challenge in challenges:
        await solver.analyze_challenge(challenge)
    
    # 模拟解决一个挑战
    solver.solved_challenges["web_001"] = {
        "solved_time": datetime.now(),
        "flag": "flag{demo_flag}",
        "solution": type('MockSolution', (), {
            'solution_steps': ["步骤1", "步骤2"],
            'tools_used': ["curl", "sqlmap"],
            'confidence': 0.8
        })()
    }
    
    # 获取更新后的统计
    updated_stats = solver.get_solver_statistics()
    print("更新后统计:")
    print(f"- 总会话数: {updated_stats['total_sessions']}")
    print(f"- 已解决挑战: {updated_stats['solved_challenges']}")
    print(f"- 成功率: {updated_stats['success_rate']:.2%}")
    print(f"- 类型统计: {updated_stats['type_statistics']}")
    print()
    
    # 导出解题方案
    export_data = solver.export_solutions()
    print("导出数据:")
    print(f"- 导出时间: {export_data['export_time']}")
    print(f"- 解题方案数: {len(export_data['solutions'])}")
    print()


async def main():
    """主演示函数"""
    print("CTF解题器演示程序")
    print("=" * 50)
    print()
    
    try:
        await demo_web_challenge()
        await demo_crypto_challenge()
        await demo_tool_management()
        await demo_solver_statistics()
        
        print("演示完成！")
        
    except Exception as e:
        print(f"演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())