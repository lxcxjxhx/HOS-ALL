"""
防御响应引擎 - 自动生成和执行防御响应措施
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum

from .models import ThreatEvent, DefenseResponse, ResponseAction, ResponseStatus
from core.base import BaseComponent
from core.interfaces import ILogger, ThreatLevel
from core.exceptions import CybersecurityPlatformError


class ResponsePriority(Enum):
    """响应优先级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseEngine(BaseComponent):
    """防御响应引擎"""
    
    def __init__(self, ai_assistant=None, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.ai_assistant = ai_assistant
        
        # 响应规则库
        self.response_rules = self._load_response_rules()
        
        # 活跃响应
        self.active_responses: Dict[str, DefenseResponse] = {}
        
        # 响应历史
        self.response_history: List[DefenseResponse] = []
        
        # 配置
        self.max_concurrent_responses = 10
        self.response_timeout = 300  # 5分钟
    
    async def _initialize_component(self) -> None:
        """初始化响应引擎"""
        if self.logger:
            self.logger.log_info("防御响应引擎初始化完成")
    
    def _load_response_rules(self) -> Dict[str, Dict[str, Any]]:
        """加载响应规则"""
        return {
            "port_scan": {
                "priority": ResponsePriority.MEDIUM,
                "actions": [
                    ResponseAction.LOG_EVENT,
                    ResponseAction.RATE_LIMIT,
                    ResponseAction.ALERT_ADMIN
                ],
                "conditions": {
                    "min_ports": 5,
                    "time_window": 60
                }
            },
            "brute_force": {
                "priority": ResponsePriority.HIGH,
                "actions": [
                    ResponseAction.BLOCK_IP,
                    ResponseAction.LOG_EVENT,
                    ResponseAction.ALERT_ADMIN,
                    ResponseAction.INCREASE_MONITORING
                ],
                "conditions": {
                    "failed_attempts": 5,
                    "time_window": 300
                }
            },
            "malware_detected": {
                "priority": ResponsePriority.CRITICAL,
                "actions": [
                    ResponseAction.ISOLATE_HOST,
                    ResponseAction.BLOCK_IP,
                    ResponseAction.LOG_EVENT,
                    ResponseAction.ALERT_ADMIN,
                    ResponseAction.BACKUP_EVIDENCE
                ],
                "conditions": {}
            },
            "suspicious_traffic": {
                "priority": ResponsePriority.MEDIUM,
                "actions": [
                    ResponseAction.LOG_EVENT,
                    ResponseAction.DEEP_PACKET_INSPECTION,
                    ResponseAction.RATE_LIMIT
                ],
                "conditions": {
                    "traffic_threshold": 1000,
                    "anomaly_score": 0.8
                }
            }
        }
    
    async def generate_response(self, threat_event: ThreatEvent) -> DefenseResponse:
        """生成防御响应"""
        try:
            # 分析威胁类型
            threat_type = threat_event.threat_type
            threat_level = threat_event.threat_level
            
            # 获取基础响应规则
            base_response = self._get_base_response(threat_type, threat_level)
            
            # 使用AI增强响应策略
            if self.ai_assistant:
                ai_response = await self._generate_ai_response(threat_event, base_response)
                enhanced_response = self._merge_responses(base_response, ai_response)
            else:
                enhanced_response = base_response
            
            # 创建响应对象
            response = DefenseResponse(
                response_id=f"RESP_{threat_event.event_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                threat_event_id=threat_event.event_id,
                actions=enhanced_response["actions"],
                priority=enhanced_response["priority"],
                status=ResponseStatus.PENDING,
                created_at=datetime.now(),
                metadata=enhanced_response.get("metadata", {})
            )
            
            if self.logger:
                self.logger.log_info(f"生成防御响应: {response.response_id}")
            
            return response
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("生成防御响应失败", e)
            raise CybersecurityPlatformError(f"生成防御响应失败: {str(e)}")
    
    def _get_base_response(self, threat_type: str, threat_level: ThreatLevel) -> Dict[str, Any]:
        """获取基础响应规则"""
        # 获取威胁类型对应的规则
        rule = self.response_rules.get(threat_type, {})
        
        if not rule:
            # 默认响应
            return {
                "priority": ResponsePriority.MEDIUM,
                "actions": [ResponseAction.LOG_EVENT, ResponseAction.ALERT_ADMIN],
                "metadata": {"rule_type": "default"}
            }
        
        # 根据威胁级别调整优先级
        priority = rule["priority"]
        if threat_level == ThreatLevel.CRITICAL:
            priority = ResponsePriority.CRITICAL
        elif threat_level == ThreatLevel.HIGH and priority.value in ["low", "medium"]:
            priority = ResponsePriority.HIGH
        
        return {
            "priority": priority,
            "actions": rule["actions"].copy(),
            "conditions": rule.get("conditions", {}),
            "metadata": {"rule_type": "predefined", "threat_type": threat_type}
        }
    
    async def _generate_ai_response(self, threat_event: ThreatEvent, base_response: Dict[str, Any]) -> Dict[str, Any]:
        """使用AI生成增强响应"""
        try:
            threat_info = {
                "type": threat_event.threat_type,
                "level": threat_event.threat_level.value,
                "source": threat_event.source_ip,
                "target": threat_event.target_ip,
                "description": threat_event.description,
                "raw_data": threat_event.raw_data
            }
            
            ai_suggestions = await self.ai_assistant.suggest_defense_measures(threat_info)
            
            return {
                "priority": ResponsePriority(ai_suggestions.get("priority", "medium")),
                "actions": [ResponseAction(action) for action in ai_suggestions.get("actions", [])],
                "metadata": {
                    "ai_confidence": ai_suggestions.get("confidence", 0.5),
                    "ai_reasoning": ai_suggestions.get("reasoning", ""),
                    "additional_measures": ai_suggestions.get("additional_measures", [])
                }
            }
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("AI响应生成失败", e)
            return {"priority": ResponsePriority.MEDIUM, "actions": [], "metadata": {}}
    
    def _merge_responses(self, base_response: Dict[str, Any], ai_response: Dict[str, Any]) -> Dict[str, Any]:
        """合并基础响应和AI响应"""
        # 使用更高的优先级
        priority = base_response["priority"]
        if ai_response.get("priority") and ai_response["priority"].value == "critical":
            priority = ai_response["priority"]
        elif ai_response.get("priority") and ai_response["priority"].value == "high" and priority.value in ["low", "medium"]:
            priority = ai_response["priority"]
        
        # 合并动作列表
        actions = list(set(base_response["actions"] + ai_response.get("actions", [])))
        
        # 合并元数据
        metadata = base_response.get("metadata", {})
        metadata.update(ai_response.get("metadata", {}))
        
        return {
            "priority": priority,
            "actions": actions,
            "metadata": metadata
        }
    
    async def execute_response(self, response: DefenseResponse) -> bool:
        """执行防御响应"""
        try:
            if len(self.active_responses) >= self.max_concurrent_responses:
                if self.logger:
                    self.logger.log_warning("达到最大并发响应数量限制")
                return False
            
            # 更新响应状态
            response.status = ResponseStatus.EXECUTING
            response.started_at = datetime.now()
            self.active_responses[response.response_id] = response
            
            if self.logger:
                self.logger.log_info(f"开始执行防御响应: {response.response_id}")
            
            # 执行各个动作
            execution_results = []
            for action in response.actions:
                try:
                    result = await self._execute_action(action, response)
                    execution_results.append({
                        "action": action.value,
                        "success": result,
                        "timestamp": datetime.now().isoformat()
                    })
                except Exception as e:
                    execution_results.append({
                        "action": action.value,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
            
            # 更新响应状态
            success_count = sum(1 for result in execution_results if result["success"])
            if success_count == len(response.actions):
                response.status = ResponseStatus.COMPLETED
            elif success_count > 0:
                response.status = ResponseStatus.PARTIAL_SUCCESS
            else:
                response.status = ResponseStatus.FAILED
            
            response.completed_at = datetime.now()
            response.execution_results = execution_results
            
            # 移动到历史记录
            self.response_history.append(response)
            del self.active_responses[response.response_id]
            
            if self.logger:
                self.logger.log_info(f"防御响应执行完成: {response.response_id}, 状态: {response.status.value}")
            
            return response.status in [ResponseStatus.COMPLETED, ResponseStatus.PARTIAL_SUCCESS]
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("执行防御响应失败", e)
            
            # 更新失败状态
            response.status = ResponseStatus.FAILED
            response.completed_at = datetime.now()
            if response.response_id in self.active_responses:
                del self.active_responses[response.response_id]
            self.response_history.append(response)
            
            return False
    
    async def _execute_action(self, action: ResponseAction, response: DefenseResponse) -> bool:
        """执行单个响应动作"""
        try:
            if action == ResponseAction.LOG_EVENT:
                return await self._log_event_action(response)
            elif action == ResponseAction.BLOCK_IP:
                return await self._block_ip_action(response)
            elif action == ResponseAction.ALERT_ADMIN:
                return await self._alert_admin_action(response)
            elif action == ResponseAction.RATE_LIMIT:
                return await self._rate_limit_action(response)
            elif action == ResponseAction.ISOLATE_HOST:
                return await self._isolate_host_action(response)
            elif action == ResponseAction.INCREASE_MONITORING:
                return await self._increase_monitoring_action(response)
            elif action == ResponseAction.DEEP_PACKET_INSPECTION:
                return await self._deep_packet_inspection_action(response)
            elif action == ResponseAction.BACKUP_EVIDENCE:
                return await self._backup_evidence_action(response)
            else:
                if self.logger:
                    self.logger.log_warning(f"未知的响应动作: {action.value}")
                return False
                
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"执行响应动作失败: {action.value}", e)
            return False
    
    async def _log_event_action(self, response: DefenseResponse) -> bool:
        """记录事件动作"""
        if self.logger:
            self.logger.log_info(f"执行日志记录动作: {response.response_id}")
        return True
    
    async def _block_ip_action(self, response: DefenseResponse) -> bool:
        """阻止IP动作"""
        if self.logger:
            self.logger.log_info(f"执行IP阻止动作: {response.response_id}")
        # 这里应该实现实际的IP阻止逻辑
        return True
    
    async def _alert_admin_action(self, response: DefenseResponse) -> bool:
        """管理员告警动作"""
        if self.logger:
            self.logger.log_info(f"执行管理员告警动作: {response.response_id}")
        # 这里应该实现实际的告警逻辑
        return True
    
    async def _rate_limit_action(self, response: DefenseResponse) -> bool:
        """速率限制动作"""
        if self.logger:
            self.logger.log_info(f"执行速率限制动作: {response.response_id}")
        # 这里应该实现实际的速率限制逻辑
        return True
    
    async def _isolate_host_action(self, response: DefenseResponse) -> bool:
        """主机隔离动作"""
        if self.logger:
            self.logger.log_info(f"执行主机隔离动作: {response.response_id}")
        # 这里应该实现实际的主机隔离逻辑
        return True
    
    async def _increase_monitoring_action(self, response: DefenseResponse) -> bool:
        """增强监控动作"""
        if self.logger:
            self.logger.log_info(f"执行增强监控动作: {response.response_id}")
        # 这里应该实现实际的监控增强逻辑
        return True
    
    async def _deep_packet_inspection_action(self, response: DefenseResponse) -> bool:
        """深度包检测动作"""
        if self.logger:
            self.logger.log_info(f"执行深度包检测动作: {response.response_id}")
        # 这里应该实现实际的深度包检测逻辑
        return True
    
    async def _backup_evidence_action(self, response: DefenseResponse) -> bool:
        """备份证据动作"""
        if self.logger:
            self.logger.log_info(f"执行证据备份动作: {response.response_id}")
        # 这里应该实现实际的证据备份逻辑
        return True
    
    def get_active_responses(self) -> List[DefenseResponse]:
        """获取活跃响应列表"""
        return list(self.active_responses.values())
    
    def get_response_history(self, limit: int = 100) -> List[DefenseResponse]:
        """获取响应历史"""
        return self.response_history[-limit:]
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """获取响应统计信息"""
        total_responses = len(self.response_history)
        if total_responses == 0:
            return {"total_responses": 0}
        
        # 统计成功率
        successful_responses = sum(1 for r in self.response_history if r.status == ResponseStatus.COMPLETED)
        success_rate = successful_responses / total_responses
        
        # 统计响应时间
        response_times = []
        for response in self.response_history:
            if response.started_at and response.completed_at:
                duration = (response.completed_at - response.started_at).total_seconds()
                response_times.append(duration)
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            "total_responses": total_responses,
            "successful_responses": successful_responses,
            "success_rate": success_rate,
            "average_response_time": avg_response_time,
            "active_responses": len(self.active_responses)
        }