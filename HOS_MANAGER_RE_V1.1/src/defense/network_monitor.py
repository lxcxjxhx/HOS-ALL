"""
网络监控器 - 实现网络流量捕获和分析功能
"""

import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
import ipaddress
import socket

from .models import NetworkPacket, NetworkStatistics, ThreatEvent, ThreatType, DefenseSession
from core.base import BaseComponent
from core.interfaces import ILogger, ThreatLevel
from core.exceptions import CybersecurityPlatformError

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkMonitorError(CybersecurityPlatformError):
    """网络监控器异常"""
    pass


class NetworkMonitor(BaseComponent):
    """网络监控器"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.scapy_available = SCAPY_AVAILABLE
        self.monitoring_sessions: Dict[str, Dict[str, Any]] = {}
        self.packet_handlers: Dict[str, Callable] = {}
        
        # 监控配置
        self.max_packet_buffer = 10000
        self.statistics_interval = 60  # 统计间隔（秒）
        self.cleanup_interval = 3600  # 清理间隔（秒）
        
        # 线程管理
        self._monitoring_threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        
        # 数据缓存
        self._packet_buffers: Dict[str, deque] = {}
        self._statistics_cache: Dict[str, NetworkStatistics] = {}
        
    async def _initialize_component(self) -> None:
        """初始化网络监控器"""
        if not self.scapy_available:
            if self.logger:
                self.logger.log_warning("Scapy不可用，网络监控功能受限")
        
        # 启动清理任务
        asyncio.create_task(self._cleanup_loop())
        
        if self.logger:
            self.logger.log_info(f"网络监控器初始化完成，Scapy状态: {'可用' if self.scapy_available else '不可用'}")
    
    async def _cleanup_component(self) -> None:
        """清理网络监控器"""
        # 停止所有监控会话
        for session_id in list(self.monitoring_sessions.keys()):
            await self.stop_monitoring(session_id)
        
        if self.logger:
            self.logger.log_info("网络监控器已清理")
    
    async def start_monitoring(self, session: DefenseSession, 
                             interface: str = None,
                             packet_filter: str = None) -> bool:
        """开始网络监控"""
        if not self.scapy_available:
            raise NetworkMonitorError("Scapy不可用，无法进行网络监控")
        
        session_id = session.session_id
        
        if session_id in self.monitoring_sessions:
            raise NetworkMonitorError(f"会话 {session_id} 已在监控中")
        
        # 验证网络接口
        if interface and interface not in self._get_available_interfaces():
            raise NetworkMonitorError(f"网络接口 {interface} 不可用")
        
        # 设置监控配置
        monitoring_config = {
            "session": session,
            "interface": interface,
            "packet_filter": packet_filter or self._build_default_filter(session.network_range),
            "start_time": datetime.now(),
            "packet_count": 0,
            "last_activity": datetime.now()
        }
        
        # 初始化数据结构
        self.monitoring_sessions[session_id] = monitoring_config
        self._packet_buffers[session_id] = deque(maxlen=self.max_packet_buffer)
        self._statistics_cache[session_id] = NetworkStatistics()
        self._stop_events[session_id] = threading.Event()
        
        # 启动监控线程
        monitor_thread = threading.Thread(
            target=self._monitoring_worker,
            args=(session_id,),
            daemon=True
        )
        
        self._monitoring_threads[session_id] = monitor_thread
        monitor_thread.start()
        
        if self.logger:
            self.logger.log_info(f"开始监控会话 {session_id}，接口: {interface or '默认'}")
        
        return True
    
    async def stop_monitoring(self, session_id: str) -> bool:
        """停止网络监控"""
        if session_id not in self.monitoring_sessions:
            return False
        
        # 设置停止事件
        if session_id in self._stop_events:
            self._stop_events[session_id].set()
        
        # 等待监控线程结束
        if session_id in self._monitoring_threads:
            thread = self._monitoring_threads[session_id]
            thread.join(timeout=5)  # 最多等待5秒
            
            if thread.is_alive():
                if self.logger:
                    self.logger.log_warning(f"监控线程 {session_id} 未能正常停止")
        
        # 清理资源
        self.monitoring_sessions.pop(session_id, None)
        self._monitoring_threads.pop(session_id, None)
        self._stop_events.pop(session_id, None)
        self._packet_buffers.pop(session_id, None)
        self._statistics_cache.pop(session_id, None)
        
        if self.logger:
            self.logger.log_info(f"停止监控会话 {session_id}")
        
        return True
    
    def get_monitoring_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取监控状态"""
        if session_id not in self.monitoring_sessions:
            return None
        
        config = self.monitoring_sessions[session_id]
        stats = self._statistics_cache.get(session_id)
        
        return {
            "session_id": session_id,
            "interface": config["interface"],
            "start_time": config["start_time"].isoformat(),
            "packet_count": config["packet_count"],
            "last_activity": config["last_activity"].isoformat(),
            "is_active": session_id in self._monitoring_threads and 
                        self._monitoring_threads[session_id].is_alive(),
            "statistics": {
                "total_packets": stats.total_packets if stats else 0,
                "total_bytes": stats.total_bytes if stats else 0,
                "unique_src_ips": stats.unique_src_ips if stats else 0,
                "unique_dst_ips": stats.unique_dst_ips if stats else 0
            }
        }
    
    def get_recent_packets(self, session_id: str, count: int = 100) -> List[NetworkPacket]:
        """获取最近的数据包"""
        if session_id not in self._packet_buffers:
            return []
        
        buffer = self._packet_buffers[session_id]
        return list(buffer)[-count:]
    
    def get_network_statistics(self, session_id: str) -> Optional[NetworkStatistics]:
        """获取网络统计信息"""
        return self._statistics_cache.get(session_id)
    
    def register_packet_handler(self, session_id: str, handler: Callable[[NetworkPacket], None]) -> None:
        """注册数据包处理器"""
        self.packet_handlers[session_id] = handler
    
    def unregister_packet_handler(self, session_id: str) -> None:
        """注销数据包处理器"""
        self.packet_handlers.pop(session_id, None)
    
    def _monitoring_worker(self, session_id: str) -> None:
        """监控工作线程"""
        try:
            config = self.monitoring_sessions[session_id]
            stop_event = self._stop_events[session_id]
            
            # 设置数据包处理函数
            def packet_callback(packet):
                if stop_event.is_set():
                    return
                
                try:
                    network_packet = self._parse_packet(packet)
                    if network_packet:
                        self._process_packet(session_id, network_packet)
                except Exception as e:
                    if self.logger:
                        self.logger.log_error(f"处理数据包失败: {session_id}", e)
            
            # 开始捕获数据包
            if self.logger:
                self.logger.log_info(f"开始捕获数据包: {session_id}")
            
            sniff(
                iface=config["interface"],
                filter=config["packet_filter"],
                prn=packet_callback,
                stop_filter=lambda x: stop_event.is_set(),
                timeout=1  # 1秒超时，允许检查停止事件
            )
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"监控线程异常: {session_id}", e)
        finally:
            if self.logger:
                self.logger.log_info(f"监控线程结束: {session_id}")
    
    def _parse_packet(self, packet) -> Optional[NetworkPacket]:
        """解析数据包"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            # 基本信息
            network_packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=0,
                dst_port=0,
                protocol="IP",
                packet_size=len(packet)
            )
            
            # 解析传输层协议
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                network_packet.src_port = tcp_layer.sport
                network_packet.dst_port = tcp_layer.dport
                network_packet.protocol = "TCP"
                network_packet.flags = str(tcp_layer.flags)
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                network_packet.src_port = udp_layer.sport
                network_packet.dst_port = udp_layer.dport
                network_packet.protocol = "UDP"
                
            elif packet.haslayer(ICMP):
                network_packet.protocol = "ICMP"
            
            # 获取载荷预览
            if hasattr(packet, 'load') and packet.load:
                try:
                    network_packet.payload_preview = packet.load[:100].decode('utf-8', errors='ignore')
                except:
                    network_packet.payload_preview = str(packet.load[:100])
            
            # 保存原始数据（可选）
            network_packet.raw_data = bytes(packet)
            
            return network_packet
            
        except Exception as e:
            if self.logger:
                self.logger.log_error("解析数据包失败", e)
            return None
    
    def _process_packet(self, session_id: str, packet: NetworkPacket) -> None:
        """处理数据包"""
        # 添加到缓冲区
        if session_id in self._packet_buffers:
            self._packet_buffers[session_id].append(packet)
        
        # 更新统计信息
        self._update_statistics(session_id, packet)
        
        # 更新会话活动时间
        if session_id in self.monitoring_sessions:
            self.monitoring_sessions[session_id]["packet_count"] += 1
            self.monitoring_sessions[session_id]["last_activity"] = datetime.now()
        
        # 调用注册的处理器
        if session_id in self.packet_handlers:
            try:
                self.packet_handlers[session_id](packet)
            except Exception as e:
                if self.logger:
                    self.logger.log_error(f"数据包处理器异常: {session_id}", e)
    
    def _update_statistics(self, session_id: str, packet: NetworkPacket) -> None:
        """更新统计信息"""
        if session_id not in self._statistics_cache:
            return
        
        stats = self._statistics_cache[session_id]
        
        # 更新基本统计
        stats.total_packets += 1
        stats.total_bytes += packet.packet_size
        
        # 更新协议统计
        if packet.protocol == "TCP":
            stats.tcp_packets += 1
        elif packet.protocol == "UDP":
            stats.udp_packets += 1
        elif packet.protocol == "ICMP":
            stats.icmp_packets += 1
        
        # 更新IP统计（简化实现）
        # 在实际应用中，这里应该使用更高效的数据结构
        
        stats.timestamp = datetime.now()
    
    def _build_default_filter(self, network_range: str) -> str:
        """构建默认的数据包过滤器"""
        if not network_range:
            return ""
        
        try:
            # 验证网络范围格式
            network = ipaddress.ip_network(network_range, strict=False)
            return f"net {network_range}"
        except ValueError:
            # 如果不是有效的网络范围，返回空过滤器
            return ""
    
    def _get_available_interfaces(self) -> List[str]:
        """获取可用的网络接口"""
        if not self.scapy_available:
            return []
        
        try:
            return get_if_list()
        except Exception:
            return []
    
    async def _cleanup_loop(self) -> None:
        """清理循环任务"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.logger:
                    self.logger.log_error("清理任务异常", e)
    
    async def _cleanup_old_data(self) -> None:
        """清理旧数据"""
        current_time = datetime.now()
        cleanup_threshold = timedelta(hours=24)  # 清理24小时前的数据
        
        for session_id in list(self._packet_buffers.keys()):
            if session_id not in self.monitoring_sessions:
                continue
            
            config = self.monitoring_sessions[session_id]
            if current_time - config["last_activity"] > cleanup_threshold:
                # 清理不活跃的会话数据
                buffer = self._packet_buffers[session_id]
                # 只保留最近1000个数据包
                if len(buffer) > 1000:
                    # 清理旧数据包
                    while len(buffer) > 1000:
                        buffer.popleft()
        
        if self.logger:
            self.logger.log_debug("完成数据清理")
    
    def get_monitor_info(self) -> Dict[str, Any]:
        """获取监控器信息"""
        return {
            "scapy_available": self.scapy_available,
            "active_sessions": len(self.monitoring_sessions),
            "available_interfaces": self._get_available_interfaces(),
            "max_packet_buffer": self.max_packet_buffer,
            "statistics_interval": self.statistics_interval
        }