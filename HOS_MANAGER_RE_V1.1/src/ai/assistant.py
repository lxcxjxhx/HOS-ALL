"""
AI助手主类 - 集成多个AI提供商，提供统一的智能分析接口
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import logging

from .base import BaseAIProvider, AIRequest, AIUsageStats
from .providers import DeepSeekProvider, OpenAIProvider, ClaudeProvider, GeminiProvider, OllamaProvider
from core.interfaces import IAIProvider, AIResponse, AIProviderType, ThreatLevel, CTFChallengeType
from core.exceptions import AIProviderError
from core.base import BaseComponent
from config.manager import ConfigManager


class AIAssistantMode(Enum):
    """AI助手工作模式"""
    THREAT_ANALYSIS = "threat_analysis"
    ATTACK_GENERATION = "attack_generation"
    DEFENSE_SUGGESTION = "defense_suggestion"
    CTF_ANALYSIS = "ctf_analysis"
    GENERAL = "general"


@dataclass
class AIAssistantConfig:
    """AI助手配置"""
    default_provider: AIProviderType = AIProviderType.DEEPSEEK
    fallback_providers: List[AIProviderType] = field(default_factory=lambda: [
        AIProviderType.OPENAI, 
        AIProviderType.CLAUDE, 
        AIProviderType.GEMINI
    ])
    max_retries: int = 3
    timeout: int = 30
    enable_cache: bool = True
    cache_ttl: int = 300  # 5 minutes


class AIAssistant(BaseComponent):
    """AI助手主类 - 统一管理多个AI提供商"""
    
    """AI助手主类 - 统一管理多个AI提供商"""

    def __init__(self, config_manager: ConfigManager, logger=None):
        super().__init__(logger)
        self.config_manager = config_manager
        self.providers: Dict[AIProviderType, BaseAIProvider] = {}
        self.assistant_config = AIAssistantConfig()
        self._is_initialized = False
        self._response_cache: Dict[str, Tuple[AIResponse, float]] = {}
        
    async def _initialize_component(self) -> None:
        """初始化AI助手"""
        if self._is_initialized:
            return
            
        try:
            # 加载AI配置
            ai_config = self.config_manager.get_ai_config()
            
            # 初始化所有配置的AI提供商
            for provider_type_str, provider_config in ai_config.items():
                try:
                    provider_type = AIProviderType(provider_type_str)
                    provider = self._create_provider(provider_type, provider_config)
                    await provider.initialize()
                    self.providers[provider_type] = provider
                    
                    if self.logger:
                        self.logger.log_info(f"AI提供商 {provider_type.value} 初始化成功")
                        
                except Exception as e:
                    if self.logger:
                        self.logger.log_error(f"AI提供商 {provider_type_str} 初始化失败", e)
            
            # 设置默认提供商
            default_provider_name = self.config_manager.get_config().get("default_ai_provider", "deepseek")
            self.assistant_config.default_provider = AIProviderType(default_provider_name)
            
            self._is_initialized = True
            
            if self.logger:
                self.logger.log_info("AI助手初始化完成")
                
        except Exception as e:
            if self.logger:
                self.logger.log_error("AI助手初始化失败", e)
            raise AIProviderError(f"AI助手初始化失败: {str(e)}")
    
    def _create_provider(self, provider_type: AIProviderType, config: Dict[str, Any]) -> BaseAIProvider:
        """创建AI提供商实例"""
        provider_map = {
            AIProviderType.DEEPSEEK: DeepSeekProvider,
            AIProviderType.OPENAI: OpenAIProvider,
            AIProviderType.CLAUDE: ClaudeProvider,
            AIProviderType.GEMINI: GeminiProvider,
            AIProviderType.OLLAMA: OllamaProvider
        }
        
        if provider_type not in provider_map:
            raise AIProviderError(f"不支持的AI提供商类型: {provider_type}")
        
        return provider_map[provider_type](config, self.logger)
    
    async def analyze_threat(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """分析威胁级别和潜在风险"""
        prompt = self._build_threat_analysis_prompt(scan_results)
        context = {"scan_results": scan_results, "mode": "threat_analysis"}
        
        response = await self._call_ai_with_fallback(prompt, context)
        
        return self._parse_threat_analysis_response(response.content, scan_results)

    async def generate_attack_payload(self, vulnerability: Dict[str, Any]) -> str:
        """生成攻击载荷"""
        prompt = self._build_attack_generation_prompt(vulnerability)
        context = {"vulnerability": vulnerability, "mode": "attack_generation"}
        
        response = await self._call_ai_with_fallback(prompt, context)
        
        return self._parse_attack_payload_response(response.content, vulnerability)
    
    async def suggest_defense_measures(self, threat_info: Dict[str, Any]) -> List[str]:
        """建议防御措施"""
        prompt = self._build_defense_suggestion_prompt(threat_info)
        context = {"threat_info": threat_info, "mode": "defense_suggestion"}
        
        response = await self._call_ai_with_fallback(prompt, context)
        
        return self._parse_defense_suggestions_response(response.content, threat_info)
    

    
    def _parse_defense_suggestions_response(self, response_content: str, threat_info: Dict[str, Any]) -> List[str]:
        """解析防御建议响应"""
        try:
            # 尝试解析JSON格式响应
            suggestions = json.loads(response_content)
            if isinstance(suggestions, list):
                return suggestions
        except json.JSONDecodeError:
            pass
        
        # 如果无法解析为JSON，按行分割并清理
        lines = response_content.strip().split('\n')
        suggestions = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith(('1.', '2.', '3.', '4.', '-', '*')):
                suggestions.append(line)
        
        return suggestions if suggestions else ["建议加强安全监控和定期进行安全评估"]

    async def analyze_ctf_challenge(self, challenge_text: str, challenge_type: str) -> Dict[str, Any]:
        """分析CTF挑战"""
        prompt = self._build_ctf_analysis_prompt(challenge_text, challenge_type)
        context = {
            "challenge_text": challenge_text, 
            "challenge_type": challenge_type, 
            "mode": "ctf_analysis"
        }
        
        response = await self._call_ai_with_fallback(prompt, context)
        
        return self._parse_ctf_analysis_response(response.content, challenge_text, challenge_type)

    async def switch_provider(self, provider_name: str) -> bool:
        """切换默认AI提供商"""
        try:
            provider_type = AIProviderType(provider_name)
            if provider_type not in self.providers:
                raise AIProviderError(f"提供商 {provider_name} 未配置或不可用")
            
            self.assistant_config.default_provider = provider_type
            
            # 更新配置
            config = self.config_manager.get_config()
            config["default_ai_provider"] = provider_name
            self.config_manager.save_config(config)
            
            if self.logger:
                self.logger.log_info(f"切换到AI提供商: {provider_name}")
            
            return True
            
        except ValueError:
            raise AIProviderError(f"无效的AI提供商名称: {provider_name}")

    async def call_ai_api(self, prompt: str, provider: str = None, 
                        context: Optional[Dict[str, Any]] = None) -> str:
        """直接调用AI API"""
        provider_type = None
        if provider:
            provider_type = AIProviderType(provider)
        
        response = await self._call_ai_with_fallback(prompt, context, provider_type)
        return response.content
    
    async def _call_ai_with_fallback(self, prompt: str, context: Optional[Dict[str, Any]] = None,
                                    preferred_provider: Optional[AIProviderType] = None) -> AIResponse:
        """调用AI服务，支持故障转移"""
        if not self._is_initialized:
            await self.initialize()
        
        # 确定要使用的提供商顺序
        providers_to_try = self._get_provider_priority(preferred_provider)
        
        last_error = None
        
        for provider_type in providers_to_try:
            if provider_type not in self.providers:
                continue
                
            provider = self.providers[provider_type]
            
            if not provider.is_available():
                if self.logger:
                    self.logger.log_warning(f"AI提供商 {provider_type.value} 不可用")
                continue
            
            try:
                # 检查缓存
                cache_key = self._generate_cache_key(prompt, context, provider_type)
                if self.assistant_config.enable_cache and cache_key in self._response_cache:
                    cached_response, timestamp = self._response_cache[cache_key]
                    if time.time() - timestamp < self.assistant_config.cache_ttl:
                        if self.logger:
                            self.logger.log_info(f"使用缓存响应 from {provider_type.value}")
                        return cached_response
                
                # 调用AI提供商
                response = await provider.generate_response(prompt, context)
                
                # 缓存响应
                if self.assistant_config.enable_cache and response.success:
                    self._response_cache[cache_key] = (response, time.time())
                
                return response
                
            except Exception as e:
                last_error = e
                if self.logger:
                    self.logger.log_error(f"AI提供商 {provider_type.value} 调用失败", e)

    def _get_provider_priority(self, preferred_provider: Optional[AIProviderType] = None) -> List[AIProviderType]:
        """获取提供商优先级列表"""
        providers = []
        
        # 首选提供商
        if preferred_provider:
            providers.append(preferred_provider)
        
        # 默认提供商
        if self.assistant_config.default_provider not in providers:
            providers.append(self.assistant_config.default_provider)
        
        # 备用提供商
        for provider_type in self.assistant_config.fallback_providers:
            if provider_type not in providers:
                providers.append(provider_type)
        
        # 其他可用提供商
        for provider_type in self.providers.keys():
            if provider_type not in providers:
                providers.append(provider_type)
        
        return providers

    def _generate_cache_key(self, prompt: str, context: Optional[Dict[str, Any]], 
                           provider_type: AIProviderType) -> str:
        """生成缓存键"""
        import hashlib
        
        key_data = {
            "prompt": prompt,
            "provider": provider_type.value
        }
        
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _build_threat_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """构建威胁分析提示"""
        return f"""
作为网络安全专家，请分析以下扫描结果并评估威胁级别：

扫描目标: {scan_results.get('target', '未知')}
扫描类型: {scan_results.get('scan_type', '未知')}
开放端口: {len(scan_results.get('open_ports', []))}
漏洞数量: {len(scan_results.get('vulnerabilities', []))}

详细结果:
{json.dumps(scan_results, indent=2, ensure_ascii=False)}

请提供：
1. 威胁级别评估（低/中/高/严重）
2. 主要风险点分析
3. 建议的应对措施
4. 潜在的攻击向量
"""
    
    def _build_attack_generation_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """构建攻击生成提示"""
        return f"""
作为渗透测试专家，请为以下漏洞生成攻击载荷：

漏洞类型: {vulnerability.get('type', '未知')}
 严重程度: {vulnerability.get('severity', '未知')}
目标信息: {vulnerability.get('target', '未知')}

漏洞详情:
{json.dumps(vulnerability, indent=2, ensure_ascii=False)}

请生成:
1. 有效的攻击载荷代码
2. 使用说明
3. 预期的攻击效果
4. 注意事项
 4. 注意事项
"""

    def _build_defense_suggestion_prompt(self, threat_info: Dict[str, Any]) -> str:
        """构建防御建议提示"""
        return f"""
作为安全防御专家，请为以下威胁提供防御建议：

威胁类型: {threat_info.get('threat_type', threat_info.get('type', '未知'))}
威胁级别: {threat_info.get('threat_level', threat_info.get('severity', '未知'))}
来源IP: {threat_info.get('source_ip', '未知')}
目标IP: {threat_info.get('target_ip', threat_info.get('target', '未知'))}

威胁详情:
{json.dumps(threat_info, indent=2, ensure_ascii=False)}

请提供：
1. 立即执行的防御措施
2. 长期防护建议
3. 监控和检测方案
4. 事件响应流程
"""

    def _build_ctf_analysis_prompt(self, challenge_text: str, challenge_type: str) -> str:
        """构建CTF分析提示"""
        return f"""
作为CTF竞赛专家，请分析以下挑战：

挑战类型: {challenge_type}
挑战描述:
{challenge_text}

请提供：
1. 挑战类型确认
2. 解题思路分析
3. 所需工具和技术
4. 逐步解题方案
5. 可能的flag格式
"""
    
    def _parse_threat_analysis_response(self, response: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """解析威胁分析响应"""
        # 这里可以添加更复杂的解析逻辑
        return {
            "raw_response": response,
            "scan_results": scan_results,
            "parsed_at": time.time()
        }
    
    def _parse_attack_payload_response(self, response: str, vulnerability: Dict[str, Any]) -> str:
        """解析攻击载荷响应"""
        # 提取代码块或直接返回
        return response
    
    def _parse_defense_suggestions_response(self, response: str, threat_info: Dict[str, Any]) -> List[str]:
        """解析防御建议响应"""
        # 提取建议列表
        return [s.strip() for s in response.split('\n') if s.strip()]
    
    def _parse_ctf_analysis_response(self, response: str, challenge_text: str, challenge_type: str) -> Dict[str, Any]:
        """解析CTF分析响应"""
        return {
            "raw_response": response,
            "challenge_text": challenge_text,
            "challenge_type": challenge_type,
            "parsed_at": time.time()
        }
    
    def get_available_providers(self) -> List[Dict[str, Any]]:
        """获取可用提供商列表"""
        providers_info = []
        
        for provider_type, provider in self.providers.items():
            providers_info.append({
                "name": provider_type.value,
                "available": provider.is_available(),
                "model": provider.model,
                "stats": provider.get_usage_stats().__dict__
            })
        
        return providers_info
    
    def clear_cache(self) -> None:
        """清空响应缓存"""
        self._response_cache.clear()
        if self.logger:
            self.logger.log_info("AI响应缓存已清空")


# 单例实例
_global_assistant: Optional[AIAssistant] = None


def get_global_assistant(config_manager: ConfigManager, logger=None) -> AIAssistant:
    """获取全局AI助手实例"""
    global _global_assistant
    
    if _global_assistant is None:
        _global_assistant = AIAssistant(config_manager, logger)
    
    return _global_assistant


def set_global_assistant(assistant: AIAssistant) -> None:
    """设置全局AI助手实例"""
    global _global_assistant
    _global_assistant = assistant