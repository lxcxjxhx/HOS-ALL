"""
集成主程序 - 统一入口点，集成所有核心模块
"""

import asyncio
import signal
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from core.logging_system import LoggingSystem
from core.health_monitor import HealthMonitor
from core.error_recovery import ErrorRecoverySystem
from config.manager import ConfigManager
from ai.assistant import AIAssistant
from attack.scanner import AttackSimulator
from defense.simulator import DefenseSimulator
from ctf.solver import CTFSolver
from security.compliance_monitor import ComplianceMonitor
from security.audit_logger import AuditLogger
from ui.cli import CLIFramework
from ui.progress import ProgressIndicator
from core.exceptions import CybersecurityPlatformError


class IntegratedCybersecurityPlatform:
    """集成网络安全平台主类"""
    
    def __init__(self):
        self.logger = None
        self.config_manager = None
        self.health_monitor = None
        self.error_recovery = None
        self.ai_assistant = None
        self.attack_simulator = None
        self.defense_simulator = None
        self.ctf_solver = None
        self.compliance_monitor = None
        self.audit_logger = None
        self.cli_framework = None
        
        self._shutdown_event = asyncio.Event()
        self._components = {}
        self._startup_time = None
        
    async def initialize(self) -> bool:
        """初始化所有组件"""
        try:
            print("🚀 正在初始化AI增强网络安全平台...")
            self._startup_time = datetime.now()
            
            # 1. 初始化日志系统
            print("📝 初始化日志系统...")
            self.logger = LoggingSystem()
            await self.logger.initialize()
            self._components['logger'] = self.logger
            
            # 2. 初始化配置管理器
            print("⚙️  初始化配置管理器...")
            self.config_manager = ConfigManager(logger=self.logger)
            await self.config_manager.initialize()
            self._components['config_manager'] = self.config_manager
            
            # 3. 初始化健康监控器
            print("💓 初始化健康监控器...")
            self.health_monitor = HealthMonitor(logger=self.logger)
            await self.health_monitor.initialize()
            self._components['health_monitor'] = self.health_monitor
            
            # 4. 初始化错误恢复系统
            print("🔧 初始化错误恢复系统...")
            self.error_recovery = ErrorRecoverySystem(logger=self.logger)
            await self.error_recovery.initialize()
            self._components['error_recovery'] = self.error_recovery
            
            # 5. 初始化审计日志器
            print("📋 初始化审计日志器...")
            self.audit_logger = AuditLogger(logger=self.logger)
            await self.audit_logger.initialize()
            self._components['audit_logger'] = self.audit_logger
            
            # 6. 初始化合规监控器
            print("🛡️  初始化合规监控器...")
            self.compliance_monitor = ComplianceMonitor(
                config_manager=self.config_manager,
                audit_logger=self.audit_logger,
                logger=self.logger
            )
            await self.compliance_monitor.initialize()
            self._components['compliance_monitor'] = self.compliance_monitor
            
            # 7. 初始化AI助手
            print("🤖 初始化AI助手...")
            self.ai_assistant = AIAssistant(
                config_manager=self.config_manager,
                logger=self.logger
            )
            await self.ai_assistant.initialize()
            self._components['ai_assistant'] = self.ai_assistant
            
            # 8. 初始化攻击模拟器
            print("⚔️  初始化攻击模拟器...")
            self.attack_simulator = AttackSimulator(
                ai_assistant=self.ai_assistant,
                config_manager=self.config_manager,
                logger=self.logger
            )
            await self.attack_simulator.initialize()
            self._components['attack_simulator'] = self.attack_simulator
            
            # 9. 初始化防御系统
            print("🛡️  初始化防御系统...")
            self.defense_simulator = DefenseSimulator(
                ai_assistant=self.ai_assistant,
                config_manager=self.config_manager,
                logger=self.logger
            )
            await self.defense_simulator.initialize()
            self._components['defense_simulator'] = self.defense_simulator
            
            # 10. 初始化CTF解题器
            print("🏆 初始化CTF解题器...")
            self.ctf_solver = CTFSolver(
                ai_assistant=self.ai_assistant,
                config_manager=self.config_manager,
                logger=self.logger
            )
            await self.ctf_solver.initialize()
            self._components['ctf_solver'] = self.ctf_solver
            
            # 11. 初始化CLI框架
            print("💻 初始化命令行界面...")
            self.cli_framework = CLIFramework(
                config_manager=self.config_manager,
                ai_assistant=self.ai_assistant,
                attack_simulator=self.attack_simulator,
                defense_simulator=self.defense_simulator,
                ctf_solver=self.ctf_solver,
                health_monitor=self.health_monitor,
                logger=self.logger
            )
            await self.cli_framework.initialize()
            self._components['cli_framework'] = self.cli_framework
            
            # 设置信号处理
            self._setup_signal_handlers()
            
            # 记录初始化完成
            startup_duration = (datetime.now() - self._startup_time).total_seconds()
            print(f"✅ 平台初始化完成，耗时 {startup_duration:.2f} 秒")
            
            if self.logger:
                self.logger.log_info("AI增强网络安全平台初始化完成", {
                    "startup_duration": startup_duration,
                    "components_count": len(self._components)
                })
            
            return True
            
        except Exception as e:
            print(f"❌ 平台初始化失败: {str(e)}")
            if self.logger:
                self.logger.log_error("平台初始化失败", e)
            return False
    
    async def start(self) -> None:
        """启动所有组件"""
        try:
            print("🚀 启动所有组件...")
            
            # 启动核心组件
            core_components = [
                'health_monitor', 'error_recovery', 'audit_logger', 
                'compliance_monitor', 'ai_assistant'
            ]
            
            for component_name in core_components:
                component = self._components.get(component_name)
                if component:
                    print(f"▶️  启动 {component_name}...")
                    await component.start()
            
            # 启动功能组件
            functional_components = [
                'attack_simulator', 'defense_simulator', 'ctf_solver'
            ]
            
            for component_name in functional_components:
                component = self._components.get(component_name)
                if component:
                    print(f"▶️  启动 {component_name}...")
                    await component.start()
            
            print("✅ 所有组件启动完成")
            
            if self.logger:
                self.logger.log_info("所有组件启动完成")
            
        except Exception as e:
            print(f"❌ 组件启动失败: {str(e)}")
            if self.logger:
                self.logger.log_error("组件启动失败", e)
            raise
    
    async def run(self) -> None:
        """运行主程序"""
        try:
            # 显示启动信息
            self._display_startup_info()
            
            # 运行CLI界面
            if self.cli_framework:
                await self.cli_framework.run_interactive()
            else:
                # 如果CLI未初始化，等待关闭信号
                await self._shutdown_event.wait()
                
        except KeyboardInterrupt:
            print("\n🛑 收到中断信号，正在关闭...")
        except Exception as e:
            print(f"❌ 运行时错误: {str(e)}")
            if self.logger:
                self.logger.log_error("运行时错误", e)
        finally:
            await self.shutdown()
    
    async def shutdown(self) -> None:
        """关闭所有组件"""
        try:
            print("🛑 正在关闭所有组件...")
            
            # 按相反顺序关闭组件
            shutdown_order = [
                'cli_framework', 'ctf_solver', 'defense_simulator', 
                'attack_simulator', 'ai_assistant', 'compliance_monitor',
                'audit_logger', 'error_recovery', 'health_monitor'
            ]
            
            for component_name in shutdown_order:
                component = self._components.get(component_name)
                if component:
                    try:
                        print(f"⏹️  关闭 {component_name}...")
                        await component.stop()
                    except Exception as e:
                        print(f"⚠️  关闭 {component_name} 时出错: {str(e)}")
            
            # 最后关闭日志系统
            if self.logger:
                self.logger.log_info("AI增强网络安全平台关闭完成")
                await self.logger.stop()
            
            print("✅ 平台关闭完成")
            
        except Exception as e:
            print(f"❌ 关闭过程中出错: {str(e)}")
    
    def _setup_signal_handlers(self) -> None:
        """设置信号处理器"""
        def signal_handler(signum, frame):
            print(f"\n🛑 收到信号 {signum}，正在关闭...")
            self._shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _display_startup_info(self) -> None:
        """显示启动信息"""
        print("\n" + "="*60)
        print("🔐 AI增强网络安全平台")
        print("="*60)
        print(f"📅 启动时间: {self._startup_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔧 组件数量: {len(self._components)}")
        
        # 显示健康状态
        if self.health_monitor:
            health_status = self.health_monitor.get_health_status()
            status_emoji = {
                "healthy": "✅",
                "warning": "⚠️",
                "critical": "❌",
                "unknown": "❓"
            }
            print(f"💓 系统状态: {status_emoji.get(health_status.value, '❓')} {health_status.value.upper()}")
        
        print("="*60)
        print("📖 使用说明:")
        print("  • 输入 'help' 查看帮助信息")
        print("  • 输入 'status' 查看系统状态")
        print("  • 输入 'quit' 或 Ctrl+C 退出程序")
        print("="*60 + "\n")
    
    def get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        info = {
            "platform_name": "AI增强网络安全平台",
            "startup_time": self._startup_time.isoformat() if self._startup_time else None,
            "uptime": (datetime.now() - self._startup_time).total_seconds() if self._startup_time else 0,
            "components": list(self._components.keys()),
            "component_count": len(self._components)
        }
        
        # 添加健康状态
        if self.health_monitor:
            info["health_status"] = self.health_monitor.get_health_status().value
            info["system_metrics"] = self.health_monitor.get_current_metrics()
        
        # 添加配置信息
        if self.config_manager:
            info["config_status"] = "loaded"
        
        return info
    
    async def execute_health_check(self) -> Dict[str, Any]:
        """执行健康检查"""
        if not self.health_monitor:
            return {"error": "健康监控器未初始化"}
        
        return self.health_monitor.get_health_report()
    
    async def get_component_status(self) -> Dict[str, Any]:
        """获取组件状态"""
        status = {}
        
        for name, component in self._components.items():
            try:
                if hasattr(component, 'get_status'):
                    status[name] = component.get_status()
                else:
                    status[name] = {"status": "unknown"}
            except Exception as e:
                status[name] = {"status": "error", "error": str(e)}
        
        return status


async def main():
    """主函数"""
    platform = IntegratedCybersecurityPlatform()
    
    try:
        # 初始化平台
        if not await platform.initialize():
            print("❌ 平台初始化失败，退出程序")
            return 1
        
        # 启动所有组件
        await platform.start()
        
        # 运行主程序
        await platform.run()
        
        return 0
        
    except Exception as e:
        print(f"❌ 程序运行异常: {str(e)}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"❌ 程序异常退出: {str(e)}")
        sys.exit(1)