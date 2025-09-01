"""
CTF解题器 - 分析和解决各类CTF挑战
"""

import asyncio
import re
import base64
import hashlib
import json
import subprocess
import tempfile
import os
from typing import Dict, Any, Optional, List, Union, Tuple
from datetime import datetime
from enum import Enum

from src.core.interfaces import ICTFSolver, CTFChallenge, CTFSolution, CTFChallengeType
from src.core.base import BaseComponent
from src.core.exceptions import CybersecurityPlatformError


class CTFToolType(Enum):
    """CTF工具类型"""
    WEB_SCANNER = "web_scanner"
    CRYPTO_ANALYZER = "crypto_analyzer"
    BINARY_ANALYZER = "binary_analyzer"
    FORENSICS_TOOL = "forensics_tool"
    NETWORK_ANALYZER = "network_analyzer"
    STEGANOGRAPHY = "steganography"


class CTFSolver(BaseComponent, ICTFSolver):
    """CTF解题器主类"""
    
    def __init__(self, ai_assistant, config_manager, logger=None):
        super().__init__(logger)
        self.ai_assistant = ai_assistant
        self.config_manager = config_manager
        
        # 解题统计
        self.solved_challenges = {}
        self.solving_sessions = {}
        
        # 工具配置
        self.available_tools = {
            CTFToolType.WEB_SCANNER: ["curl", "wget", "sqlmap", "dirb"],
            CTFToolType.CRYPTO_ANALYZER: ["hashcat", "john", "openssl"],
            CTFToolType.BINARY_ANALYZER: ["objdump", "strings", "gdb", "radare2"],
            CTFToolType.FORENSICS_TOOL: ["binwalk", "foremost", "volatility"],
            CTFToolType.NETWORK_ANALYZER: ["wireshark", "tcpdump", "nmap"],
            CTFToolType.STEGANOGRAPHY: ["steghide", "stegsolve", "zsteg"]
        }
        
        # 挑战类型识别模式
        self.challenge_patterns = {
            CTFChallengeType.WEB: [
                r"(?i)(web|http|url|website|server|php|javascript|sql|xss|csrf)",
                r"(?i)(login|authentication|session|cookie|injection)"
            ],
            CTFChallengeType.CRYPTO: [
                r"(?i)(crypto|cipher|encrypt|decrypt|hash|rsa|aes|des)",
                r"(?i)(key|password|secret|encode|decode|base64)"
            ],
            CTFChallengeType.REVERSE: [
                r"(?i)(reverse|binary|executable|disassemble|decompile)",
                r"(?i)(assembly|machine code|debugger|ida|ghidra)"
            ],
            CTFChallengeType.PWN: [
                r"(?i)(pwn|exploit|buffer overflow|rop|shellcode)",
                r"(?i)(vulnerability|memory|stack|heap|format string)"
            ],
            CTFChallengeType.FORENSICS: [
                r"(?i)(forensics|memory dump|disk image|network capture)",
                r"(?i)(pcap|volatility|autopsy|sleuthkit|deleted)"
            ],
            CTFChallengeType.MISC: [
                r"(?i)(misc|miscellaneous|puzzle|logic|programming)",
                r"(?i)(algorithm|math|calculation|script|automation)"
            ]
        }
    
    async def _initialize_component(self) -> None:
        """初始化CTF解题器"""
        # 检查可用工具
        await self._check_available_tools()
        
        if self.logger:
            self.logger.log_info("CTF解题器初始化完成")
    
    async def _check_available_tools(self) -> None:
        """检查可用的CTF工具"""
        available_count = 0
        total_count = 0
        
        for tool_type, tools in self.available_tools.items():
            for tool in tools:
                total_count += 1
                if await self._is_tool_available(tool):
                    available_count += 1
        
        if self.logger:
            self.logger.log_info(f"CTF工具检查完成: {available_count}/{total_count} 个工具可用")
    
    async def _is_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        try:
            process = await asyncio.create_subprocess_exec(
                "which", tool_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except:
            return False
    
    def identify_challenge_type(self, challenge_text: str) -> CTFChallengeType:
        """识别挑战类型"""
        scores = {}
        
        for challenge_type, patterns in self.challenge_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, challenge_text))
                score += matches
            scores[challenge_type] = score
        
        # 返回得分最高的类型
        if scores:
            best_type = max(scores, key=scores.get)
            if scores[best_type] > 0:
                return best_type
        
        # 默认返回MISC类型
        return CTFChallengeType.MISC
    
    async def analyze_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析挑战"""
        try:
            session_id = f"ctf_analysis_{challenge.challenge_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # 记录分析会话
            self.solving_sessions[session_id] = {
                "challenge": challenge,
                "start_time": datetime.now(),
                "status": "analyzing",
                "steps": []
            }
            
            analysis_result = {
                "session_id": session_id,
                "challenge_id": challenge.challenge_id,
                "identified_type": challenge.challenge_type.value,
                "analysis_time": datetime.now().isoformat(),
                "confidence": 0.0,
                "analysis_steps": [],
                "recommended_tools": [],
                "potential_solutions": []
            }
            
            # 使用AI分析挑战
            ai_analysis = await self.ai_assistant.analyze_ctf_challenge(challenge)
            analysis_result["ai_analysis"] = ai_analysis
            
            # 基于挑战类型进行专门分析
            if challenge.challenge_type == CTFChallengeType.WEB:
                web_analysis = await self._analyze_web_challenge(challenge)
                analysis_result.update(web_analysis)
            elif challenge.challenge_type == CTFChallengeType.CRYPTO:
                crypto_analysis = await self._analyze_crypto_challenge(challenge)
                analysis_result.update(crypto_analysis)
            elif challenge.challenge_type == CTFChallengeType.REVERSE:
                reverse_analysis = await self._analyze_reverse_challenge(challenge)
                analysis_result.update(reverse_analysis)
            elif challenge.challenge_type == CTFChallengeType.PWN:
                pwn_analysis = await self._analyze_pwn_challenge(challenge)
                analysis_result.update(pwn_analysis)
            elif challenge.challenge_type == CTFChallengeType.FORENSICS:
                forensics_analysis = await self._analyze_forensics_challenge(challenge)
                analysis_result.update(forensics_analysis)
            else:
                misc_analysis = await self._analyze_misc_challenge(challenge)
                analysis_result.update(misc_analysis)
            
            # 更新会话状态
            self.solving_sessions[session_id]["status"] = "analyzed"
            self.solving_sessions[session_id]["analysis_result"] = analysis_result
            
            if self.logger:
                self.logger.log_info(f"CTF挑战分析完成: {challenge.challenge_id}")
            
            return analysis_result
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"CTF挑战分析失败: {challenge.challenge_id}", e)
            raise CybersecurityPlatformError(f"CTF挑战分析失败: {str(e)}")
    
    async def generate_solution(self, challenge: CTFChallenge) -> CTFSolution:
        """生成解题方案"""
        try:
            start_time = datetime.now()
            
            # 先分析挑战
            analysis = await self.analyze_challenge(challenge)
            
            solution = CTFSolution(
                challenge_id=challenge.challenge_id,
                solution_steps=[],
                tools_used=[],
                flag=None,
                confidence=0.0,
                execution_time=0.0,
                success=False
            )
            
            # 基于挑战类型生成解题方案
            if challenge.challenge_type == CTFChallengeType.WEB:
                solution = await self._generate_web_solution(challenge, analysis)
            elif challenge.challenge_type == CTFChallengeType.CRYPTO:
                solution = await self._generate_crypto_solution(challenge, analysis)
            elif challenge.challenge_type == CTFChallengeType.REVERSE:
                solution = await self._generate_reverse_solution(challenge, analysis)
            elif challenge.challenge_type == CTFChallengeType.PWN:
                solution = await self._generate_pwn_solution(challenge, analysis)
            elif challenge.challenge_type == CTFChallengeType.FORENSICS:
                solution = await self._generate_forensics_solution(challenge, analysis)
            else:
                solution = await self._generate_misc_solution(challenge, analysis)
            
            # 计算执行时间
            solution.execution_time = (datetime.now() - start_time).total_seconds()
            
            if self.logger:
                self.logger.log_info(f"CTF解题方案生成完成: {challenge.challenge_id}")
            
            return solution
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"CTF解题方案生成失败: {challenge.challenge_id}", e)
            raise CybersecurityPlatformError(f"解题方案生成失败: {str(e)}")
    
    async def execute_solution(self, solution: CTFSolution) -> Dict[str, Any]:
        """执行解题方案"""
        try:
            execution_result = {
                "solution_id": solution.challenge_id,
                "execution_time": datetime.now().isoformat(),
                "steps_executed": [],
                "tools_output": {},
                "flag_found": None,
                "success": False,
                "error_messages": []
            }
            
            # 执行解题步骤
            for i, step in enumerate(solution.solution_steps):
                try:
                    step_result = await self._execute_solution_step(step, solution.tools_used)
                    execution_result["steps_executed"].append({
                        "step_number": i + 1,
                        "description": step,
                        "result": step_result,
                        "success": True
                    })
                    
                    # 检查是否找到flag
                    if step_result and "flag" in str(step_result).lower():
                        potential_flag = self._extract_flag_from_output(str(step_result))
                        if potential_flag:
                            execution_result["flag_found"] = potential_flag
                            execution_result["success"] = True
                            break
                            
                except Exception as step_error:
                    execution_result["steps_executed"].append({
                        "step_number": i + 1,
                        "description": step,
                        "error": str(step_error),
                        "success": False
                    })
                    execution_result["error_messages"].append(f"步骤 {i+1} 执行失败: {str(step_error)}")
            
            # 记录解题结果
            if execution_result["success"]:
                self.solved_challenges[solution.challenge_id] = {
                    "solved_time": datetime.now(),
                    "flag": execution_result["flag_found"],
                    "solution": solution
                }
            
            if self.logger:
                status = "成功" if execution_result["success"] else "失败"
                self.logger.log_info(f"CTF解题执行{status}: {solution.challenge_id}")
            
            return execution_result
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"CTF解题执行失败: {solution.challenge_id}", e)
            raise CybersecurityPlatformError(f"解题执行失败: {str(e)}")    

    async def _execute_solution_step(self, step: str, tools: List[str]) -> Any:
        """执行单个解题步骤"""
        # 这里实现具体的步骤执行逻辑
        # 可以根据步骤内容调用相应的工具
        return f"执行步骤: {step}"
    
    def _extract_flag_from_output(self, output: str) -> Optional[str]:
        """从输出中提取flag"""
        # 常见的flag格式模式
        flag_patterns = [
            r"flag\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"ctf\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"\w+\{[^}]+\}"
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                return matches[0]
        
        return None
    
    # 各类型挑战的专门分析方法
    async def _analyze_web_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析Web挑战"""
        analysis = {
            "challenge_type": "web",
            "recommended_tools": ["curl", "burp", "sqlmap", "dirb"],
            "analysis_steps": [
                "检查网站结构和技术栈",
                "查找隐藏页面和目录",
                "测试常见Web漏洞",
                "分析源代码和JavaScript"
            ],
            "potential_vulnerabilities": [
                "SQL注入",
                "XSS跨站脚本",
                "CSRF跨站请求伪造",
                "文件包含漏洞",
                "认证绕过"
            ]
        }
        
        # 检查描述中的关键词
        description = challenge.description.lower()
        if "sql" in description or "database" in description:
            analysis["likely_vulnerability"] = "SQL注入"
        elif "xss" in description or "script" in description:
            analysis["likely_vulnerability"] = "XSS跨站脚本"
        elif "upload" in description or "file" in description:
            analysis["likely_vulnerability"] = "文件上传漏洞"
        
        return analysis
    
    async def _analyze_crypto_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析密码学挑战"""
        analysis = {
            "challenge_type": "crypto",
            "recommended_tools": ["openssl", "hashcat", "john", "sage"],
            "analysis_steps": [
                "识别加密算法类型",
                "分析密钥长度和格式",
                "检查是否为经典密码",
                "尝试频率分析",
                "查找已知漏洞"
            ],
            "potential_methods": [
                "暴力破解",
                "字典攻击",
                "频率分析",
                "数学攻击",
                "侧信道攻击"
            ]
        }
        
        # 检查是否包含编码数据
        if challenge.files:
            for file_path in challenge.files:
                if self._looks_like_base64(file_path):
                    analysis["encoding_detected"] = "Base64"
                elif self._looks_like_hex(file_path):
                    analysis["encoding_detected"] = "Hexadecimal"
        
        return analysis
    
    async def _analyze_reverse_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析逆向工程挑战"""
        analysis = {
            "challenge_type": "reverse",
            "recommended_tools": ["objdump", "strings", "gdb", "radare2", "ghidra"],
            "analysis_steps": [
                "确定文件类型和架构",
                "提取字符串信息",
                "分析程序流程",
                "识别关键函数",
                "动态调试分析"
            ],
            "analysis_techniques": [
                "静态分析",
                "动态调试",
                "符号执行",
                "反汇编分析",
                "控制流分析"
            ]
        }
        
        return analysis
    
    async def _analyze_pwn_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析二进制利用挑战"""
        analysis = {
            "challenge_type": "pwn",
            "recommended_tools": ["gdb", "pwntools", "checksec", "ropper"],
            "analysis_steps": [
                "检查二进制保护机制",
                "分析程序漏洞点",
                "构造利用载荷",
                "绕过保护机制",
                "获取shell或flag"
            ],
            "exploit_techniques": [
                "栈溢出",
                "堆溢出",
                "格式化字符串",
                "ROP链构造",
                "Return-to-libc"
            ]
        }
        
        return analysis
    
    async def _analyze_forensics_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析取证挑战"""
        analysis = {
            "challenge_type": "forensics",
            "recommended_tools": ["binwalk", "foremost", "volatility", "autopsy"],
            "analysis_steps": [
                "确定文件类型和格式",
                "提取隐藏或删除的数据",
                "分析文件系统结构",
                "恢复损坏的文件",
                "查找隐写术痕迹"
            ],
            "analysis_areas": [
                "文件恢复",
                "内存分析",
                "网络流量分析",
                "隐写术检测",
                "时间线分析"
            ]
        }
        
        return analysis
    
    async def _analyze_misc_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """分析杂项挑战"""
        analysis = {
            "challenge_type": "misc",
            "recommended_tools": ["python", "bash", "custom_scripts"],
            "analysis_steps": [
                "理解题目要求",
                "识别问题类型",
                "设计解决方案",
                "编写自动化脚本",
                "验证结果"
            ],
            "potential_types": [
                "编程题",
                "数学题",
                "逻辑推理",
                "协议分析",
                "数据处理"
            ]
        }
        
        return analysis
    
    # 各类型挑战的解题方案生成方法
    async def _generate_web_solution(self, challenge: CTFChallenge, analysis: Dict[str, Any]) -> CTFSolution:
        """生成Web挑战解题方案"""
        solution = CTFSolution(
            challenge_id=challenge.challenge_id,
            solution_steps=[
                "使用curl或浏览器访问目标网站",
                "查看页面源代码，寻找隐藏信息",
                "使用dirb或gobuster扫描隐藏目录",
                "测试常见Web漏洞（SQL注入、XSS等）",
                "分析HTTP请求和响应",
                "尝试绕过认证或访问控制"
            ],
            tools_used=["curl", "dirb", "sqlmap", "burp"],
            flag=None,
            confidence=0.7,
            execution_time=0.0,
            success=False
        )
        
        return solution
    
    async def _generate_crypto_solution(self, challenge: CTFChallenge, analysis: Dict[str, Any]) -> CTFSolution:
        """生成密码学挑战解题方案"""
        solution = CTFSolution(
            challenge_id=challenge.challenge_id,
            solution_steps=[
                "分析加密文本或数据格式",
                "识别可能的加密算法",
                "尝试常见的解码方法（Base64、Hex等）",
                "进行频率分析（如果是替换密码）",
                "使用工具进行暴力破解或字典攻击",
                "验证解密结果"
            ],
            tools_used=["openssl", "hashcat", "python"],
            flag=None,
            confidence=0.6,
            execution_time=0.0,
            success=False
        )
        
        return solution
    
    async def _generate_reverse_solution(self, challenge: CTFChallenge, analysis: Dict[str, Any]) -> CTFSolution:
        """生成逆向工程挑战解题方案"""
        solution = CTFSolution(
            challenge_id=challenge.challenge_id,
            solution_steps=[
                "使用file命令确定文件类型",
                "使用strings提取可读字符串",
                "使用objdump或radare2进行反汇编",
                "分析程序逻辑和控制流",
                "识别关键函数和算法",
                "动态调试验证分析结果"
            ],
            tools_used=["file", "strings", "objdump", "gdb", "radare2"],
            flag=None,
            confidence=0.5,
            execution_time=0.0,
            success=False
        )
        
        return solution
    
    async def _generate_pwn_solution(self, challenge: CTFChallenge, analysis: Dict[str, Any]) -> CTFSolution:
        """生成二进制利用挑战解题方案"""
        solution = CTFSolution(
            challenge_id=challenge.challenge_id,
            solution_steps=[
                "使用checksec检查二进制保护",
                "分析程序找到漏洞点",
                "计算溢出偏移量",
                "构造ROP链或shellcode",
                "编写exploit脚本",
                "获取shell或读取flag"
            ],
            tools_used=["checksec", "gdb", "pwntools", "ropper"],
            flag=None,
            confidence=0.4,
            execution_time=0.0,
            success=False
        )
        
        return solution
    
    async def _generate_forensics_solution(self, challenge: CTFChallenge, analysis: Dict[str, Any]) -> CTFSolution:
        """生成取证挑战解题方案"""
        solution = CTFSolution(
            challenge_id=challenge.challenge_id,
            solution_steps=[
                "使用file命令分析文件类型",
                "使用binwalk提取隐藏文件",
                "使用foremost恢复删除文件",
                "分析文件系统或内存转储",
                "查找隐写术或隐藏数据",
                "重构完整信息获取flag"
            ],
            tools_used=["file", "binwalk", "foremost", "volatility"],
            flag=None,
            confidence=0.6,
            execution_time=0.0,
            success=False
        )
        
        return solution
    
    async def _generate_misc_solution(self, challenge: CTFChallenge, analysis: Dict[str, Any]) -> CTFSolution:
        """生成杂项挑战解题方案"""
        solution = CTFSolution(
            challenge_id=challenge.challenge_id,
            solution_steps=[
                "仔细阅读题目描述",
                "分析提供的文件或数据",
                "识别问题的本质",
                "设计解决算法或方法",
                "编写脚本自动化处理",
                "验证结果并提取flag"
            ],
            tools_used=["python", "bash", "custom_tools"],
            flag=None,
            confidence=0.5,
            execution_time=0.0,
            success=False
        )
        
        return solution
    
    # 辅助方法
    def _looks_like_base64(self, text: str) -> bool:
        """检查文本是否像Base64编码"""
        try:
            if len(text) % 4 == 0:
                base64.b64decode(text, validate=True)
                return True
        except:
            pass
        return False
    
    def _looks_like_hex(self, text: str) -> bool:
        """检查文本是否像十六进制编码"""
        try:
            bytes.fromhex(text.replace(' ', '').replace('\n', ''))
            return True
        except:
            return False
    
    # 管理方法
    def get_solving_sessions(self) -> Dict[str, Dict[str, Any]]:
        """获取解题会话列表"""
        return {
            session_id: {
                "challenge_id": session["challenge"].challenge_id,
                "challenge_type": session["challenge"].challenge_type.value,
                "start_time": session["start_time"].isoformat(),
                "status": session["status"],
                "steps_count": len(session["steps"])
            }
            for session_id, session in self.solving_sessions.items()
        }
    
    def get_solved_challenges(self) -> Dict[str, Dict[str, Any]]:
        """获取已解决的挑战"""
        return {
            challenge_id: {
                "solved_time": info["solved_time"].isoformat(),
                "flag": info["flag"],
                "solution_steps": len(info["solution"].solution_steps)
            }
            for challenge_id, info in self.solved_challenges.items()
        }
    
    def get_solver_statistics(self) -> Dict[str, Any]:
        """获取解题器统计信息"""
        total_sessions = len(self.solving_sessions)
        solved_count = len(self.solved_challenges)
        
        # 按类型统计
        type_stats = {}
        for session in self.solving_sessions.values():
            challenge_type = session["challenge"].challenge_type.value
            if challenge_type not in type_stats:
                type_stats[challenge_type] = {"total": 0, "solved": 0}
            type_stats[challenge_type]["total"] += 1
            
            if session["challenge"].challenge_id in self.solved_challenges:
                type_stats[challenge_type]["solved"] += 1
        
        return {
            "total_sessions": total_sessions,
            "solved_challenges": solved_count,
            "success_rate": solved_count / total_sessions if total_sessions > 0 else 0,
            "type_statistics": type_stats,
            "available_tools": sum(len(tools) for tools in self.available_tools.values())
        }
    
    def clear_session_history(self) -> None:
        """清空会话历史"""
        self.solving_sessions.clear()
        if self.logger:
            self.logger.log_info("已清空CTF解题会话历史")
    
    def export_solutions(self, challenge_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """导出解题方案"""
        if challenge_ids is None:
            challenge_ids = list(self.solved_challenges.keys())
        
        export_data = {
            "export_time": datetime.now().isoformat(),
            "solutions": {}
        }
        
        for challenge_id in challenge_ids:
            if challenge_id in self.solved_challenges:
                solution_info = self.solved_challenges[challenge_id]
                export_data["solutions"][challenge_id] = {
                    "solved_time": solution_info["solved_time"].isoformat(),
                    "flag": solution_info["flag"],
                    "solution_steps": solution_info["solution"].solution_steps,
                    "tools_used": solution_info["solution"].tools_used,
                    "confidence": solution_info["solution"].confidence
                }
        
        return export_data