"""
端口扫描器 - 实现各种类型的网络端口扫描功能
"""

import asyncio
import socket
import subprocess
import json
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

from .models import ScanResult, ScanType, PortInfo
from core.base import BaseComponent
from core.interfaces import ILogger
from core.exceptions import CybersecurityPlatformError


class ScannerError(CybersecurityPlatformError):
    """扫描器异常"""
    pass


class PortScanner(BaseComponent):
    """端口扫描器"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.max_concurrent_scans = 10
        self.default_timeout = 5
        self.nmap_available = False
        self.executor = None
    
    async def _initialize_component(self) -> None:
        """初始化扫描器"""
        # 检查nmap是否可用
        self.nmap_available = await self._check_nmap_availability()
        
        # 创建线程池
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_scans)
        
        if self.logger:
            nmap_status = "可用" if self.nmap_available else "不可用"
            self.logger.log_info(f"端口扫描器初始化完成，nmap状态: {nmap_status}")
    
    async def _cleanup_component(self) -> None:
        """清理扫描器"""
        if self.executor:
            self.executor.shutdown(wait=True)
        
        if self.logger:
            self.logger.log_info("端口扫描器已清理")
    
    async def scan_ports(self, target: str, ports: List[int], 
                        scan_type: ScanType = ScanType.TCP_CONNECT,
                        timeout: int = None) -> ScanResult:
        """执行端口扫描"""
        if not target:
            raise ScannerError("目标地址不能为空")
        
        if not ports:
            raise ScannerError("端口列表不能为空")
        
        # 验证目标地址
        if not self._validate_target(target):
            raise ScannerError(f"无效的目标地址: {target}")
        
        # 创建扫描结果对象
        scan_result = ScanResult(
            target=target,
            scan_type=scan_type,
            start_time=datetime.now()
        )
        
        timeout = timeout or self.default_timeout
        
        try:
            if self.logger:
                self.logger.log_info(f"开始扫描 {target}，端口: {len(ports)} 个，类型: {scan_type.value}")
            
            # 根据扫描类型选择扫描方法
            if scan_type == ScanType.TCP_CONNECT:
                await self._tcp_connect_scan(scan_result, ports, timeout)
            elif scan_type == ScanType.SYN_STEALTH and self.nmap_available:
                await self._nmap_syn_scan(scan_result, ports, timeout)
            elif scan_type == ScanType.UDP_SCAN and self.nmap_available:
                await self._nmap_udp_scan(scan_result, ports, timeout)
            elif scan_type == ScanType.VERSION_DETECTION and self.nmap_available:
                await self._nmap_version_scan(scan_result, ports, timeout)
            elif scan_type == ScanType.OS_FINGERPRINT and self.nmap_available:
                await self._nmap_os_scan(scan_result, ports, timeout)
            else:
                # 如果nmap不可用，回退到TCP连接扫描
                if scan_type != ScanType.TCP_CONNECT:
                    if self.logger:
                        self.logger.log_warning(f"nmap不可用，回退到TCP连接扫描")
                await self._tcp_connect_scan(scan_result, ports, timeout)
            
            scan_result.end_time = datetime.now()
            scan_result.duration = (scan_result.end_time - scan_result.start_time).total_seconds()
            scan_result.success = True
            
            if self.logger:
                self.logger.log_info(f"扫描完成，发现 {len(scan_result.open_ports)} 个开放端口")
            
        except Exception as e:
            scan_result.end_time = datetime.now()
            scan_result.duration = (scan_result.end_time - scan_result.start_time).total_seconds()
            scan_result.success = False
            scan_result.error_message = str(e)
            
            if self.logger:
                self.logger.log_error(f"扫描失败: {target}", e)
            
            raise ScannerError(f"扫描失败: {str(e)}")
        
        return scan_result
    
    async def quick_scan(self, target: str, common_ports: bool = True) -> ScanResult:
        """快速扫描常用端口"""
        if common_ports:
            # 常用端口列表
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
                1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
            ]
        else:
            # 扫描前1000个端口
            ports = list(range(1, 1001))
        
        return await self.scan_ports(target, ports, ScanType.TCP_CONNECT)
    
    async def full_scan(self, target: str) -> ScanResult:
        """全端口扫描"""
        ports = list(range(1, 65536))
        return await self.scan_ports(target, ports, ScanType.TCP_CONNECT)
    
    async def _tcp_connect_scan(self, scan_result: ScanResult, ports: List[int], timeout: int) -> None:
        """TCP连接扫描"""
        semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        
        async def scan_port(port: int) -> Optional[PortInfo]:
            async with semaphore:
                try:
                    # 创建连接
                    future = asyncio.open_connection(scan_result.target, port)
                    reader, writer = await asyncio.wait_for(future, timeout=timeout)
                    
                    # 尝试获取banner
                    banner = None
                    try:
                        writer.write(b'\r\n')
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=1)
                        if data:
                            banner = data.decode('utf-8', errors='ignore').strip()
                    except:
                        pass
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    # 尝试识别服务
                    service = self._identify_service(port, banner)
                    
                    return PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=service,
                        banner=banner
                    )
                    
                except asyncio.TimeoutError:
                    scan_result.filtered_ports.append(port)
                    return None
                except ConnectionRefusedError:
                    scan_result.closed_ports.append(port)
                    return None
                except Exception:
                    scan_result.filtered_ports.append(port)
                    return None
        
        # 并发扫描所有端口
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        for result in results:
            if isinstance(result, PortInfo):
                scan_result.open_ports.append(result)
    
    async def _nmap_syn_scan(self, scan_result: ScanResult, ports: List[int], timeout: int) -> None:
        """使用nmap进行SYN隐蔽扫描"""
        port_range = self._format_port_range(ports)
        
        cmd = [
            "nmap", "-sS", "-Pn", "--host-timeout", f"{timeout}s",
            "-p", port_range, "-oX", "-", scan_result.target
        ]
        
        await self._run_nmap_command(cmd, scan_result)
    
    async def _nmap_udp_scan(self, scan_result: ScanResult, ports: List[int], timeout: int) -> None:
        """使用nmap进行UDP扫描"""
        port_range = self._format_port_range(ports)
        
        cmd = [
            "nmap", "-sU", "-Pn", "--host-timeout", f"{timeout}s",
            "-p", port_range, "-oX", "-", scan_result.target
        ]
        
        await self._run_nmap_command(cmd, scan_result)
    
    async def _nmap_version_scan(self, scan_result: ScanResult, ports: List[int], timeout: int) -> None:
        """使用nmap进行版本检测扫描"""
        port_range = self._format_port_range(ports)
        
        cmd = [
            "nmap", "-sV", "-Pn", "--host-timeout", f"{timeout}s",
            "-p", port_range, "-oX", "-", scan_result.target
        ]
        
        await self._run_nmap_command(cmd, scan_result)
    
    async def _nmap_os_scan(self, scan_result: ScanResult, ports: List[int], timeout: int) -> None:
        """使用nmap进行操作系统指纹识别"""
        port_range = self._format_port_range(ports)
        
        cmd = [
            "nmap", "-O", "-Pn", "--host-timeout", f"{timeout}s",
            "-p", port_range, "-oX", "-", scan_result.target
        ]
        
        await self._run_nmap_command(cmd, scan_result)
    
    async def _run_nmap_command(self, cmd: List[str], scan_result: ScanResult) -> None:
        """运行nmap命令并解析结果"""
        try:
            # 在线程池中运行nmap命令
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                self._execute_nmap_command,
                cmd
            )
            
            if result["returncode"] != 0:
                raise ScannerError(f"nmap执行失败: {result['stderr']}")
            
            # 解析XML输出
            self._parse_nmap_xml(result["stdout"], scan_result)
            
            # 保存原始输出
            scan_result.raw_output = result["stdout"]
            
        except Exception as e:
            raise ScannerError(f"nmap扫描失败: {str(e)}")
    
    def _execute_nmap_command(self, cmd: List[str]) -> Dict[str, Any]:
        """在线程中执行nmap命令"""
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            return {
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr
            }
            
        except subprocess.TimeoutExpired:
            raise ScannerError("nmap命令执行超时")
        except FileNotFoundError:
            raise ScannerError("nmap命令未找到，请确保已安装nmap")
    
    def _parse_nmap_xml(self, xml_output: str, scan_result: ScanResult) -> None:
        """解析nmap XML输出"""
        try:
            root = ET.fromstring(xml_output)
            
            # 解析主机信息
            host = root.find("host")
            if host is None:
                return
            
            # 解析端口信息
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_info = self._parse_port_element(port_elem)
                    if port_info:
                        if port_info.state == "open":
                            scan_result.open_ports.append(port_info)
                        elif port_info.state == "closed":
                            scan_result.closed_ports.append(port_info.port)
                        elif port_info.state == "filtered":
                            scan_result.filtered_ports.append(port_info.port)
            
            # 解析操作系统信息
            os_elem = host.find("os")
            if os_elem is not None:
                scan_result.os_info = self._parse_os_element(os_elem)
                
        except ET.ParseError as e:
            if self.logger:
                self.logger.log_warning(f"解析nmap XML输出失败: {str(e)}")
    
    def _parse_port_element(self, port_elem) -> Optional[PortInfo]:
        """解析端口XML元素"""
        try:
            port_id = int(port_elem.get("portid"))
            protocol = port_elem.get("protocol", "tcp")
            
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"
            
            service_elem = port_elem.find("service")
            service = None
            version = None
            
            if service_elem is not None:
                service = service_elem.get("name")
                product = service_elem.get("product", "")
                version_info = service_elem.get("version", "")
                if product or version_info:
                    version = f"{product} {version_info}".strip()
            
            return PortInfo(
                port=port_id,
                protocol=protocol,
                state=state,
                service=service,
                version=version
            )
            
        except (ValueError, AttributeError):
            return None
    
    def _parse_os_element(self, os_elem) -> Dict[str, Any]:
        """解析操作系统XML元素"""
        os_info = {}
        
        # 解析OS匹配
        osmatch_elems = os_elem.findall("osmatch")
        if osmatch_elems:
            matches = []
            for osmatch in osmatch_elems:
                match_info = {
                    "name": osmatch.get("name"),
                    "accuracy": int(osmatch.get("accuracy", 0))
                }
                matches.append(match_info)
            
            os_info["matches"] = matches
            # 取准确度最高的作为最可能的OS
            if matches:
                best_match = max(matches, key=lambda x: x["accuracy"])
                os_info["most_likely"] = best_match["name"]
        
        return os_info
    
    def _format_port_range(self, ports: List[int]) -> str:
        """格式化端口范围为nmap格式"""
        if not ports:
            return ""
        
        # 对端口排序
        sorted_ports = sorted(set(ports))
        
        # 如果端口数量较少，直接列出
        if len(sorted_ports) <= 20:
            return ",".join(map(str, sorted_ports))
        
        # 否则尝试压缩为范围
        ranges = []
        start = sorted_ports[0]
        end = start
        
        for port in sorted_ports[1:]:
            if port == end + 1:
                end = port
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = end = port
        
        # 添加最后一个范围
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
        
        return ",".join(ranges)
    
    def _identify_service(self, port: int, banner: Optional[str] = None) -> Optional[str]:
        """根据端口号和banner识别服务"""
        # 常见端口服务映射
        common_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1723: "pptp",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            9200: "elasticsearch",
            27017: "mongodb"
        }
        
        service = common_services.get(port)
        
        # 如果有banner，尝试从中提取更准确的服务信息
        if banner and service:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service = "ssh"
            elif "http" in banner_lower or "html" in banner_lower:
                service = "http"
            elif "ftp" in banner_lower:
                service = "ftp"
            elif "smtp" in banner_lower:
                service = "smtp"
        
        return service
    
    def _validate_target(self, target: str) -> bool:
        """验证目标地址是否有效"""
        try:
            # 尝试解析IP地址
            socket.inet_aton(target)
            return True
        except socket.error:
            pass
        
        try:
            # 尝试解析域名
            socket.gethostbyname(target)
            return True
        except socket.error:
            return False
    
    async def _check_nmap_availability(self) -> bool:
        """检查nmap是否可用"""
        try:
            process = await asyncio.create_subprocess_exec(
                "nmap", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return process.returncode == 0
            
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """获取扫描器信息"""
        return {
            "nmap_available": self.nmap_available,
            "max_concurrent_scans": self.max_concurrent_scans,
            "default_timeout": self.default_timeout,
            "supported_scan_types": [st.value for st in ScanType]
        }


class AttackSimulator(BaseComponent):
    """攻击模拟器 - 执行各种渗透测试和攻击模拟"""
    
    def __init__(self, logger: Optional[ILogger] = None):
        super().__init__(logger)
        self.port_scanner = PortScanner(logger)
        self.active_sessions: Dict[str, Dict] = {}
    
    async def create_session(self, session_name: str, target: str, ports: List[int]) -> str:
        """创建攻击会话"""
        session_id = f"attack_{int(time.time())}_{session_name}"
        
        self.active_sessions[session_id] = {
            "session_name": session_name,
            "target": target,
            "ports": ports,
            "status": "created",
            "created_at": datetime.now(),
            "scan_results": {},
            "vulnerabilities": [],
            "attack_log": []
        }
        
        if self.logger:
            self.logger.log_info(f"创建攻击会话: {session_id}，目标: {target}")
        
        return session_id
    
    async def port_scan(self, target: str, ports: List[int], scan_type: str) -> Dict:
        """执行端口扫描"""
        try:
            scan_type_enum = ScanType(scan_type)
            result = await self.port_scanner.scan_ports(target, ports, scan_type_enum)
            
            # 转换为字典格式返回
            return {
                "target": result.target,
                "scan_type": result.scan_type.value,
                "open_ports": [{
                    "port": port.port,
                    "service": port.service,
                    "banner": port.banner,
                    "version": port.version
                } for port in result.open_ports],
                "closed_ports": result.closed_ports,
                "filtered_ports": result.filtered_ports,
                "duration": result.duration,
                "success": result.success
            }
            
        except ValueError:
            raise ScannerError(f"不支持的扫描类型: {scan_type}")
        except Exception as e:
            raise ScannerError(f"端口扫描失败: {str(e)}")
    
    async def vulnerability_scan(self, target: str, scan_results: Dict) -> Dict:
        """执行漏洞扫描"""
        # 这里可以集成漏洞扫描逻辑
        # 暂时返回模拟数据
        vulnerabilities = []
        
        # 模拟一些常见漏洞
        open_ports = scan_results.get("open_ports", [])
        for port_info in open_ports:
            port = port_info.get("port")
            service = port_info.get("service", "")
            
            # 根据端口和服务类型模拟漏洞
            if port == 22 and service == "ssh":
                vulnerabilities.append({
                    "type": "weak_ssh_config",
                    "severity": "medium",
                    "description": "SSH服务可能存在弱配置",
                    "port": port
                })
            elif port == 80 and service == "http":
                vulnerabilities.append({
                    "type": "potential_web_vuln", 
                    "severity": "high",
                    "description": "Web服务可能存在安全漏洞",
                    "port": port
                })
        
        return {
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "scan_time": datetime.now().isoformat()
        }
    
    async def generate_payload(self, vulnerability: Dict) -> str:
        """生成攻击载荷"""
        vuln_type = vulnerability.get("type", "")
        port = vulnerability.get("port")
        
        # 根据漏洞类型生成相应的攻击载荷
        if "ssh" in vuln_type:
            return f"ssh exploit payload for port {port}"
        elif "web" in vuln_type or "http" in vuln_type:
            return f"web attack payload for port {port}"
        else:
            return f"generic exploit for {vuln_type} on port {port}"
    
    async def execute_attack(self, session_id: str, payload: str) -> Dict:
        """执行攻击"""
        if session_id not in self.active_sessions:
            raise ScannerError(f"会话不存在: {session_id}")
        
        session = self.active_sessions[session_id]
        
        # 模拟攻击执行
        attack_result = {
            "session_id": session_id,
            "payload": payload,
            "executed_at": datetime.now(),
            "success": True,
            "result": "攻击模拟执行完成",
            "details": {
                "vulnerability_exploited": "simulated_vuln",
                "access_gained": "simulated_access",
                "persistence_established": False
            }
        }
        
        # 记录攻击日志
        session["attack_log"].append(attack_result)
        session["status"] = "attack_executed"
        
        if self.logger:
            self.logger.log_info(f"执行攻击: {session_id}，载荷: {payload}")
        
        return attack_result
    
    async def get_session_status(self, session_id: str) -> Dict:
        """获取会话状态"""
        if session_id not in self.active_sessions:
            raise ScannerError(f"会话不存在: {session_id}")
        
        return self.active_sessions[session_id]
    
    async def stop_attack(self, session_id: str) -> bool:
        """停止攻击"""
        if session_id not in self.active_sessions:
            raise ScannerError(f"会话不存在: {session_id}")
        
        session = self.active_sessions[session_id]
        session["status"] = "stopped"
        session["stopped_at"] = datetime.now()
        
        if self.logger:
            self.logger.log_info(f"停止攻击会话: {session_id}")
        
        return True