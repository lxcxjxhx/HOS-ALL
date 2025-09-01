"""
CTF工具集成 - 集成和管理各种CTF工具
"""

import asyncio
import subprocess
import tempfile
import os
import json
import shutil
from typing import Dict, List, Any, Optional, Tuple
from abc import ABC, abstractmethod
from datetime import datetime

from src.ctf.models import CTFTool, CTFToolConfig, CTFChallengeType
from src.core.base import BaseComponent
from src.core.exceptions import CybersecurityPlatformError


class CTFToolInterface(ABC):
    """CTF工具接口"""
    
    @abstractmethod
    async def execute(self, command: str, args: List[str], **kwargs) -> Dict[str, Any]:
        """执行工具命令"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """检查工具是否可用"""
        pass
    
    @abstractmethod
    def get_tool_info(self) -> CTFTool:
        """获取工具信息"""
        pass


class BaseCTFTool(CTFToolInterface):
    """基础CTF工具类"""
    
    def __init__(self, tool_name: str, tool_type: str, config: CTFToolConfig = None):
        self.tool_name = tool_name
        self.tool_type = tool_type
        self.config = config or CTFToolConfig(tool_name=tool_name)
        self._is_available = None
    
    async def execute(self, command: str, args: List[str], **kwargs) -> Dict[str, Any]:
        """执行工具命令"""
        try:
            # 构建完整命令
            full_command = [command] + args
            
            # 设置执行环境
            env = os.environ.copy()
            env.update(self.config.environment_vars)
            
            # 执行命令
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=self.config.working_directory
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise CybersecurityPlatformError(f"工具执行超时: {self.tool_name}")
            
            return {
                "command": " ".join(full_command),
                "return_code": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "success": process.returncode == 0,
                "execution_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "command": " ".join([command] + args),
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
                "execution_time": datetime.now().isoformat()
            }
    
    def is_available(self) -> bool:
        """检查工具是否可用"""
        if self._is_available is None:
            self._is_available = shutil.which(self.tool_name) is not None
        return self._is_available
    
    def get_tool_info(self) -> CTFTool:
        """获取工具信息"""
        return CTFTool(
            tool_name=self.tool_name,
            tool_type=self.tool_type,
            is_available=self.is_available(),
            supported_challenges=self._get_supported_challenges()
        )
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        """获取支持的挑战类型"""
        return []


class WebTool(BaseCTFTool):
    """Web安全工具"""
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        return [CTFChallengeType.WEB]


class CryptoTool(BaseCTFTool):
    """密码学工具"""
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        return [CTFChallengeType.CRYPTO]


class ReverseTool(BaseCTFTool):
    """逆向工程工具"""
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        return [CTFChallengeType.REVERSE]


class PwnTool(BaseCTFTool):
    """二进制利用工具"""
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        return [CTFChallengeType.PWN]


class ForensicsTool(BaseCTFTool):
    """取证工具"""
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        return [CTFChallengeType.FORENSICS]


class MiscTool(BaseCTFTool):
    """杂项工具"""
    
    def _get_supported_challenges(self) -> List[CTFChallengeType]:
        return [CTFChallengeType.MISC]


class CTFToolManager(BaseComponent):
    """CTF工具管理器"""
    
    def __init__(self, logger=None):
        super().__init__(logger)
        self.tools = {}
        self.tool_configs = {}
        self._initialize_default_tools()
    
    def _initialize_default_tools(self):
        """初始化默认工具"""
        # Web工具
        self.tools["curl"] = WebTool("curl", "web_client")
        self.tools["wget"] = WebTool("wget", "web_client")
        self.tools["sqlmap"] = WebTool("sqlmap", "sql_injection")
        self.tools["dirb"] = WebTool("dirb", "directory_scanner")
        self.tools["gobuster"] = WebTool("gobuster", "directory_scanner")
        
        # 密码学工具
        self.tools["openssl"] = CryptoTool("openssl", "crypto_library")
        self.tools["hashcat"] = CryptoTool("hashcat", "password_cracker")
        self.tools["john"] = CryptoTool("john", "password_cracker")
        
        # 逆向工程工具
        self.tools["objdump"] = ReverseTool("objdump", "disassembler")
        self.tools["strings"] = ReverseTool("strings", "string_extractor")
        self.tools["gdb"] = ReverseTool("gdb", "debugger")
        self.tools["radare2"] = ReverseTool("radare2", "reverse_framework")
        
        # 二进制利用工具
        self.tools["checksec"] = PwnTool("checksec", "security_checker")
        self.tools["ropper"] = PwnTool("ropper", "rop_gadget_finder")
        
        # 取证工具
        self.tools["binwalk"] = ForensicsTool("binwalk", "firmware_analyzer")
        self.tools["foremost"] = ForensicsTool("foremost", "file_carver")
        self.tools["volatility"] = ForensicsTool("volatility", "memory_analyzer")
        
        # 杂项工具
        self.tools["file"] = MiscTool("file", "file_identifier")
        self.tools["xxd"] = MiscTool("xxd", "hex_dump")
        self.tools["base64"] = MiscTool("base64", "encoder_decoder")
    
    async def _initialize_component(self) -> None:
        """初始化工具管理器"""
        # 检查所有工具的可用性
        available_count = 0
        for tool_name, tool in self.tools.items():
            if tool.is_available():
                available_count += 1
        
        if self.logger:
            self.logger.log_info(f"CTF工具管理器初始化完成，{available_count}/{len(self.tools)} 个工具可用")
    
    async def execute_tool(self, tool_name: str, args: List[str], **kwargs) -> Dict[str, Any]:
        """执行指定工具"""
        if tool_name not in self.tools:
            raise CybersecurityPlatformError(f"未知工具: {tool_name}")
        
        tool = self.tools[tool_name]
        if not tool.is_available():
            raise CybersecurityPlatformError(f"工具不可用: {tool_name}")
        
        result = await tool.execute(tool_name, args, **kwargs)
        
        if self.logger:
            status = "成功" if result["success"] else "失败"
            self.logger.log_info(f"工具执行{status}: {tool_name}")
        
        return result
    
    def get_available_tools(self, challenge_type: Optional[CTFChallengeType] = None) -> List[str]:
        """获取可用工具列表"""
        available_tools = []
        
        for tool_name, tool in self.tools.items():
            if not tool.is_available():
                continue
            
            if challenge_type is None:
                available_tools.append(tool_name)
            else:
                tool_info = tool.get_tool_info()
                if challenge_type in tool_info.supported_challenges:
                    available_tools.append(tool_name)
        
        return available_tools
    
    def get_tool_info(self, tool_name: str) -> Optional[CTFTool]:
        """获取工具信息"""
        if tool_name in self.tools:
            return self.tools[tool_name].get_tool_info()
        return None
    
    def get_all_tools_info(self) -> Dict[str, CTFTool]:
        """获取所有工具信息"""
        return {
            tool_name: tool.get_tool_info()
            for tool_name, tool in self.tools.items()
        }
    
    def add_custom_tool(self, tool_name: str, tool: CTFToolInterface) -> bool:
        """添加自定义工具"""
        try:
            self.tools[tool_name] = tool
            if self.logger:
                self.logger.log_info(f"添加自定义工具: {tool_name}")
            return True
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"添加自定义工具失败: {tool_name}", e)
            return False
    
    def remove_tool(self, tool_name: str) -> bool:
        """移除工具"""
        if tool_name in self.tools:
            del self.tools[tool_name]
            if self.logger:
                self.logger.log_info(f"移除工具: {tool_name}")
            return True
        return False
    
    def configure_tool(self, tool_name: str, config: CTFToolConfig) -> bool:
        """配置工具"""
        if tool_name in self.tools:
            self.tool_configs[tool_name] = config
            # 更新工具配置
            if hasattr(self.tools[tool_name], 'config'):
                self.tools[tool_name].config = config
            if self.logger:
                self.logger.log_info(f"配置工具: {tool_name}")
            return True
        return False
    
    def get_tool_statistics(self) -> Dict[str, Any]:
        """获取工具统计信息"""
        total_tools = len(self.tools)
        available_tools = sum(1 for tool in self.tools.values() if tool.is_available())
        
        # 按类型统计
        type_stats = {}
        for tool in self.tools.values():
            tool_type = tool.tool_type
            if tool_type not in type_stats:
                type_stats[tool_type] = {"total": 0, "available": 0}
            type_stats[tool_type]["total"] += 1
            if tool.is_available():
                type_stats[tool_type]["available"] += 1
        
        # 按挑战类型统计
        challenge_stats = {}
        for challenge_type in CTFChallengeType:
            challenge_stats[challenge_type.value] = len(self.get_available_tools(challenge_type))
        
        return {
            "total_tools": total_tools,
            "available_tools": available_tools,
            "availability_rate": available_tools / total_tools if total_tools > 0 else 0,
            "type_statistics": type_stats,
            "challenge_support": challenge_stats
        }


class CTFScriptExecutor:
    """CTF脚本执行器"""
    
    def __init__(self, tool_manager: CTFToolManager, logger=None):
        self.tool_manager = tool_manager
        self.logger = logger
    
    async def execute_python_script(self, script_content: str, args: List[str] = None) -> Dict[str, Any]:
        """执行Python脚本"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                script_path = f.name
            
            try:
                command_args = ["python3", script_path]
                if args:
                    command_args.extend(args)
                
                process = await asyncio.create_subprocess_exec(
                    *command_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                return {
                    "script_path": script_path,
                    "return_code": process.returncode,
                    "stdout": stdout.decode('utf-8', errors='ignore'),
                    "stderr": stderr.decode('utf-8', errors='ignore'),
                    "success": process.returncode == 0
                }
                
            finally:
                os.unlink(script_path)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error("Python脚本执行失败", e)
            return {
                "script_path": "",
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
    
    async def execute_bash_script(self, script_content: str, args: List[str] = None) -> Dict[str, Any]:
        """执行Bash脚本"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
                f.write(script_content)
                script_path = f.name
            
            # 设置执行权限
            os.chmod(script_path, 0o755)
            
            try:
                command_args = ["/bin/bash", script_path]
                if args:
                    command_args.extend(args)
                
                process = await asyncio.create_subprocess_exec(
                    *command_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                return {
                    "script_path": script_path,
                    "return_code": process.returncode,
                    "stdout": stdout.decode('utf-8', errors='ignore'),
                    "stderr": stderr.decode('utf-8', errors='ignore'),
                    "success": process.returncode == 0
                }
                
            finally:
                os.unlink(script_path)
                
        except Exception as e:
            if self.logger:
                self.logger.log_error("Bash脚本执行失败", e)
            return {
                "script_path": "",
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
    
    async def execute_tool_chain(self, tool_chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """执行工具链"""
        results = []
        
        for i, tool_config in enumerate(tool_chain):
            tool_name = tool_config.get("tool")
            args = tool_config.get("args", [])
            
            try:
                result = await self.tool_manager.execute_tool(tool_name, args)
                result["chain_step"] = i + 1
                result["tool_config"] = tool_config
                results.append(result)
                
                # 如果某个步骤失败且配置为停止，则中断执行
                if not result["success"] and tool_config.get("stop_on_failure", False):
                    break
                    
            except Exception as e:
                error_result = {
                    "chain_step": i + 1,
                    "tool_config": tool_config,
                    "success": False,
                    "error": str(e)
                }
                results.append(error_result)
                
                if tool_config.get("stop_on_failure", False):
                    break
        
        return results