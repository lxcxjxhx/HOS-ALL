"""
AI工具类 - 提供AI相关的工具函数和辅助类
"""

import re
import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import hashlib

from ..core.interfaces import AIResponse, AIProviderType


class AIResponseProcessor:
    """AI响应处理器"""
    
    @staticmethod
    def extract_code_blocks(content: str) -> List[Dict[str, str]]:
        """提取代码块"""
        code_blocks = []
        pattern = r'```(\w+)?\n(.*?)\n```'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for language, code in matches:
            code_blocks.append({
                "language": language or "text",
                "code": code.strip()
            })
        
        return code_blocks
    
    @staticmethod
    def extract_json_objects(content: str) -> List[Dict[str, Any]]:
        """提取JSON对象"""
        json_objects = []
        
        # 查找JSON代码块
        json_pattern = r'```json\n(.*?)\n```'
        json_matches = re.findall(json_pattern, content, re.DOTALL)
        
        for json_str in json_matches:
            try:
                json_obj = json.loads(json_str.strip())
                json_objects.append(json_obj)
            except json.JSONDecodeError:
                continue
        
        # 查找裸露的JSON对象
        brace_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        brace_matches = re.findall(brace_pattern, content)
        
        for json_str in brace_matches:
            try:
                json_obj = json.loads(json_str)
                if json_obj not in json_objects:
                    json_objects.append(json_obj)
            except json.JSONDecodeError:
                continue
        
        return json_objects
    
    @staticmethod
    def extract_commands(content: str) -> List[str]:
        """提取命令"""
        commands = []
        
        # 查找命令代码块
        cmd_patterns = [
            r'```(?:bash|sh|cmd|powershell)\n(.*?)\n```',
            r'`([^`]+)`'
        ]
        
        for pattern in cmd_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                command = match.strip()
                if command and command not in commands:
                    commands.append(command)
        
        return commands
    
    @staticmethod
    def clean_response(content: str) -> str:
        """清理响应内容"""
        # 移除多余的空行
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
        
        # 移除首尾空白
        content = content.strip()
        
        return content
    
    @staticmethod
    def extract_key_points(content: str) -> List[str]:
        """提取关键点"""
        key_points = []
        
        # 查找列表项
        list_patterns = [
            r'^[-*+]\s+(.+)',  # 无序列表
            r'^\d+\.\s+(.+)',  # 有序列表
        ]
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            for pattern in list_patterns:
                match = re.match(pattern, line)
                if match:
                    key_points.append(match.group(1))
                    break
        
        return key_points


class PromptTemplate:
    """提示词模板"""
    
    def __init__(self, template: str, variables: Optional[List[str]] = None):
        self.template = template
        self.variables = variables or self._extract_variables()
    
    def _extract_variables(self) -> List[str]:
        """提取模板变量"""
        pattern = r'\{(\w+)\}'
        return list(set(re.findall(pattern, self.template)))
    
    def render(self, **kwargs) -> str:
        """渲染模板"""
        missing_vars = set(self.variables) - set(kwargs.keys())
        if missing_vars:
            raise ValueError(f"缺少模板变量: {missing_vars}")
        
        return self.template.format(**kwargs)
    
    def get_variables(self) -> List[str]:
        """获取模板变量"""
        return self.variables.copy()


class PromptLibrary:
    """提示词库"""
    
    def __init__(self):
        self.templates: Dict[str, PromptTemplate] = {}
        self._load_default_templates()
    
    def _load_default_templates(self):
        """加载默认模板"""
        # 网络安全分析模板
        self.add_template("security_analysis", """
你是一个网络安全专家。请分析以下信息并提供专业建议：

目标信息：
{target_info}

扫描结果：
{scan_results}

请提供：
1. 安全风险评估
2. 潜在漏洞分析
3. 攻击向量识别
4. 防护建议

请以JSON格式返回分析结果。
""")
        
        # 攻击载荷生成模板
        self.add_template("payload_generation", """
作为网络安全测试专家，请为以下漏洞生成测试载荷：

漏洞类型：{vulnerability_type}
目标系统：{target_system}
端口信息：{port_info}

要求：
1. 生成安全的测试载荷（仅用于授权测试）
2. 提供多种测试方法
3. 包含验证步骤
4. 注明风险等级

请确保所有载荷仅用于合法的安全测试目的。
""")
        
        # 防御策略生成模板
        self.add_template("defense_strategy", """
基于以下威胁信息，请制定防御策略：

威胁类型：{threat_type}
攻击来源：{attack_source}
目标资产：{target_assets}
当前防护：{current_defenses}

请提供：
1. 即时响应措施
2. 长期防护策略
3. 监控建议
4. 应急预案

以结构化格式返回建议。
""")
        
        # CTF解题分析模板
        self.add_template("ctf_analysis", """
请分析以下CTF挑战：

挑战类型：{challenge_type}
题目描述：{description}
提供文件：{files}
提示信息：{hints}

请提供：
1. 问题分析
2. 解题思路
3. 所需工具
4. 详细步骤
5. 预期答案格式

如果可能，请提供自动化解题脚本。
""")
    
    def add_template(self, name: str, template: str) -> None:
        """添加模板"""
        self.templates[name] = PromptTemplate(template)
    
    def get_template(self, name: str) -> Optional[PromptTemplate]:
        """获取模板"""
        return self.templates.get(name)
    
    def render_template(self, name: str, **kwargs) -> str:
        """渲染模板"""
        template = self.get_template(name)
        if not template:
            raise ValueError(f"模板不存在: {name}")
        
        return template.render(**kwargs)
    
    def list_templates(self) -> List[str]:
        """列出所有模板"""
        return list(self.templates.keys())
    
    def remove_template(self, name: str) -> bool:
        """移除模板"""
        if name in self.templates:
            del self.templates[name]
            return True
        return False


class ConversationManager:
    """对话管理器"""
    
    def __init__(self, max_history: int = 10):
        self.max_history = max_history
        self.conversations: Dict[str, List[Dict[str, str]]] = {}
    
    def create_conversation(self, conversation_id: str) -> None:
        """创建对话"""
        self.conversations[conversation_id] = []
    
    def add_message(self, conversation_id: str, role: str, content: str) -> None:
        """添加消息"""
        if conversation_id not in self.conversations:
            self.create_conversation(conversation_id)
        
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        }
        
        self.conversations[conversation_id].append(message)
        
        # 限制历史记录长度
        if len(self.conversations[conversation_id]) > self.max_history:
            self.conversations[conversation_id] = self.conversations[conversation_id][-self.max_history:]
    
    def get_conversation(self, conversation_id: str) -> List[Dict[str, str]]:
        """获取对话历史"""
        return self.conversations.get(conversation_id, [])
    
    def clear_conversation(self, conversation_id: str) -> None:
        """清空对话"""
        if conversation_id in self.conversations:
            self.conversations[conversation_id] = []
    
    def delete_conversation(self, conversation_id: str) -> None:
        """删除对话"""
        if conversation_id in self.conversations:
            del self.conversations[conversation_id]
    
    def get_conversation_summary(self, conversation_id: str) -> Dict[str, Any]:
        """获取对话摘要"""
        history = self.get_conversation(conversation_id)
        
        if not history:
            return {"message_count": 0, "participants": [], "duration": 0}
        
        participants = list(set(msg["role"] for msg in history))
        
        start_time = datetime.fromisoformat(history[0]["timestamp"])
        end_time = datetime.fromisoformat(history[-1]["timestamp"])
        duration = (end_time - start_time).total_seconds()
        
        return {
            "message_count": len(history),
            "participants": participants,
            "duration": duration,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }


class AIRequestCache:
    """AI请求缓存"""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Dict[str, Any]] = {}
    
    def _generate_key(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """生成缓存键"""
        content = prompt
        if context:
            content += json.dumps(context, sort_keys=True)
        
        return hashlib.md5(content.encode()).hexdigest()
    
    def get(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Optional[AIResponse]:
        """获取缓存的响应"""
        key = self._generate_key(prompt, context)
        
        if key in self.cache:
            cached_item = self.cache[key]
            
            # 检查是否过期
            if datetime.now().timestamp() - cached_item["timestamp"] < self.ttl_seconds:
                return cached_item["response"]
            else:
                # 删除过期项
                del self.cache[key]
        
        return None
    
    def put(self, prompt: str, response: AIResponse, context: Optional[Dict[str, Any]] = None) -> None:
        """缓存响应"""
        key = self._generate_key(prompt, context)
        
        # 如果缓存已满，删除最旧的项
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["timestamp"])
            del self.cache[oldest_key]
        
        self.cache[key] = {
            "response": response,
            "timestamp": datetime.now().timestamp()
        }
    
    def clear(self) -> None:
        """清空缓存"""
        self.cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        current_time = datetime.now().timestamp()
        valid_items = sum(1 for item in self.cache.values() 
                         if current_time - item["timestamp"] < self.ttl_seconds)
        
        return {
            "total_items": len(self.cache),
            "valid_items": valid_items,
            "expired_items": len(self.cache) - valid_items,
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds
        }
    
    def cleanup_expired(self) -> int:
        """清理过期项"""
        current_time = datetime.now().timestamp()
        expired_keys = [
            key for key, item in self.cache.items()
            if current_time - item["timestamp"] >= self.ttl_seconds
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        return len(expired_keys)