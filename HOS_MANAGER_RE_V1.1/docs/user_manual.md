# AI增强网络安全平台 - 用户手册

## 目录
1. [快速开始](#快速开始)
2. [系统概述](#系统概述)
3. [AI助手功能](#ai助手功能)
4. [攻击模拟器](#攻击模拟器)
5. [防御系统](#防御系统)
6. [CTF解题器](#ctf解题器)
7. [配置管理](#配置管理)
8. [安全与合规](#安全与合规)
9. [故障排除](#故障排除)
10. [最佳实践](#最佳实践)

## 快速开始

### 启动系统
```bash
# 激活虚拟环境
source venv/bin/activate  # Linux/macOS
# 或
venv\Scripts\activate     # Windows

# 启动集成平台
python src/integrated_main.py

# 或启动CLI版本
python src/main_cli.py
```

### 首次使用
1. **接受使用条款**: 系统启动时会显示使用条款，必须接受才能继续
2. **配置检查**: 系统会检查配置文件是否存在和有效
3. **选择功能**: 从主菜单选择要使用的功能模块

### 基本命令
```
help          - 显示帮助信息
status        - 查看系统状态
config        - 配置管理
ai            - AI助手功能
attack        - 攻击模拟器
defense       - 防御系统
ctf           - CTF解题器
quit/exit     - 退出系统
```

## 系统概述

### 架构组件
- **AI助手**: 提供智能分析和建议
- **攻击模拟器**: 执行渗透测试和漏洞扫描
- **防御系统**: 监控威胁和自动响应
- **CTF解题器**: 自动化解决CTF挑战
- **配置管理**: 统一管理系统配置
- **安全控制**: 确保合规使用

### 系统状态监控
```bash
# 查看系统状态
status

# 查看健康报告
health

# 查看组件状态
components

# 查看性能指标
metrics
```

## AI助手功能

### 支持的AI提供商
- **DeepSeek**: 高性能中文AI模型
- **OpenAI**: GPT系列模型
- **Claude**: Anthropic的AI助手
- **Gemini**: Google的AI模型
- **Ollama**: 本地部署的开源模型

### 基本使用
```bash
# 进入AI助手模式
ai

# 威胁分析
ai analyze-threat --scan-results scan_results.json

# 生成攻击载荷
ai generate-payload --vulnerability vuln_info.json

# 防御建议
ai defense-advice --threat-info threat.json

# CTF分析
ai analyze-ctf --challenge challenge.txt
```

### 提供商切换
```bash
# 查看可用提供商
ai providers

# 切换提供商
ai switch --provider openai

# 测试提供商连接
ai test --provider deepseek
```

### 高级功能
```bash
# 批量分析
ai batch-analyze --input-dir scans/ --output results.json

# 自定义提示
ai custom --prompt "分析这个网络流量" --data traffic.pcap

# 历史记录
ai history --limit 10
```

## 攻击模拟器

### 创建攻击会话
```bash
# 进入攻击模拟器
attack

# 创建新会话
attack create-session --name "test_scan" --target 192.168.1.100

# 列出活跃会话
attack list-sessions

# 查看会话详情
attack session-info --session-id <session_id>
```

### 端口扫描
```bash
# TCP连接扫描
attack port-scan --target 192.168.1.100 --ports 1-1000 --type tcp_connect

# SYN隐蔽扫描
attack port-scan --target 192.168.1.100 --ports 22,80,443 --type syn_scan

# UDP扫描
attack port-scan --target 192.168.1.100 --ports 53,161,123 --type udp_scan

# 服务版本检测
attack service-scan --target 192.168.1.100 --ports 22,80,443
```

### 漏洞扫描
```bash
# 基于端口扫描结果进行漏洞扫描
attack vuln-scan --session-id <session_id>

# 指定漏洞类型
attack vuln-scan --target 192.168.1.100 --types web,ssh,ftp

# 生成攻击载荷
attack generate-payload --vulnerability <vuln_id>
```

### 攻击执行
```bash
# 执行攻击载荷
attack execute --session-id <session_id> --payload <payload_id>

# 批量攻击
attack batch-execute --session-id <session_id> --payloads payload_list.json

# 停止攻击
attack stop --session-id <session_id>
```

### 结果导出
```bash
# 导出扫描结果
attack export --session-id <session_id> --format json --output results.json

# 生成报告
attack report --session-id <session_id> --template detailed --output report.html
```

## 防御系统

### 启动监控
```bash
# 进入防御系统
defense

# 创建防御会话
defense create-session --name "network_monitor" --network 192.168.1.0/24

# 启动监控
defense start-monitoring --session-id <session_id>

# 查看监控状态
defense monitoring-status
```

### 威胁检测
```bash
# 查看检测到的威胁
defense list-threats --session-id <session_id>

# 威胁详情
defense threat-info --threat-id <threat_id>

# 威胁统计
defense threat-stats --time-range 24h
```

### 防御响应
```bash
# 生成防御建议
defense generate-response --threat-id <threat_id>

# 执行防御措施
defense execute-response --response-id <response_id>

# 查看响应历史
defense response-history --session-id <session_id>
```

### 安全事件管理
```bash
# 查看安全事件
defense list-events --session-id <session_id> --severity high

# 事件详情
defense event-info --event-id <event_id>

# 导出事件日志
defense export-events --session-id <session_id> --format csv --output events.csv
```

## CTF解题器

### 挑战分析
```bash
# 进入CTF解题器
ctf

# 分析挑战
ctf analyze --challenge challenge.txt

# 指定挑战类型
ctf analyze --challenge challenge.txt --type web

# 批量分析
ctf batch-analyze --input-dir challenges/ --output analysis.json
```

### 自动解题
```bash
# 自动解题
ctf solve --challenge challenge.txt

# 指定解题工具
ctf solve --challenge challenge.txt --tools "burp,sqlmap"

# 交互式解题
ctf solve-interactive --challenge challenge.txt
```

### 支持的挑战类型

#### Web安全
```bash
# SQL注入检测
ctf solve --challenge web_challenge.txt --type web --focus sqli

# XSS检测
ctf solve --challenge web_challenge.txt --type web --focus xss

# 文件上传漏洞
ctf solve --challenge web_challenge.txt --type web --focus upload
```

#### 密码学
```bash
# 古典密码
ctf solve --challenge crypto_challenge.txt --type crypto --method classical

# 现代加密
ctf solve --challenge crypto_challenge.txt --type crypto --method modern

# 哈希破解
ctf solve --challenge crypto_challenge.txt --type crypto --method hash
```

#### 逆向工程
```bash
# 静态分析
ctf solve --challenge binary_challenge --type reverse --method static

# 动态调试
ctf solve --challenge binary_challenge --type reverse --method dynamic
```

#### 取证分析
```bash
# 文件恢复
ctf solve --challenge forensics_challenge --type forensics --method recovery

# 隐写术
ctf solve --challenge image.png --type forensics --method steganography
```

### 工具管理
```bash
# 列出可用工具
ctf list-tools

# 安装工具
ctf install-tool --name burpsuite

# 工具配置
ctf configure-tool --name sqlmap --config config.json
```

## 配置管理

### 查看配置
```bash
# 查看当前配置
config show

# 查看特定配置项
config show --section ai_providers

# 验证配置
config validate
```

### 修改配置
```bash
# 设置AI提供商
config set ai_providers.default deepseek

# 设置API密钥
config set ai_providers.openai.api_key "your-api-key"

# 设置网络配置
config set network.max_scan_threads 20
```

### 配置备份和恢复
```bash
# 备份配置
config backup --output config_backup.json

# 恢复配置
config restore --input config_backup.json

# 重置为默认配置
config reset --confirm
```

### 加密配置
```bash
# 加密敏感数据
config encrypt --key encryption_key

# 解密配置
config decrypt --key encryption_key

# 生成新的加密密钥
config generate-key
```

## 安全与合规

### 使用条款
- 仅用于授权的安全测试
- 不得用于恶意攻击
- 遵守当地法律法规
- 保护目标系统和数据

### 安全检查
```bash
# 检查目标授权
security check-authorization --target 192.168.1.100

# 合规性检查
security compliance-check --operation port_scan

# 查看安全警告
security list-warnings
```

### 审计日志
```bash
# 查看审计日志
security audit-log --time-range 24h

# 导出审计日志
security export-audit --format json --output audit.json

# 审计统计
security audit-stats --user current
```

## 故障排除

### 常见问题

#### 连接问题
```bash
# 测试网络连接
network test-connection --target 8.8.8.8

# 检查防火墙
network check-firewall

# 诊断网络问题
network diagnose --target 192.168.1.100
```

#### AI服务问题
```bash
# 测试AI提供商
ai test --provider openai

# 检查API密钥
ai validate-key --provider deepseek

# 查看API使用情况
ai usage-stats --provider all
```

#### 权限问题
```bash
# 检查系统权限
system check-permissions

# 提升权限（需要管理员）
system elevate-privileges

# 权限诊断
system diagnose-permissions
```

### 日志分析
```bash
# 查看错误日志
logs show --level error --tail 50

# 搜索日志
logs search --query "connection failed" --time-range 1h

# 导出日志
logs export --level all --output system.log
```

### 系统诊断
```bash
# 完整系统诊断
diagnose --full

# 组件诊断
diagnose --component ai_assistant

# 性能诊断
diagnose --performance
```

## 最佳实践

### 安全使用
1. **授权确认**: 始终确保有明确的测试授权
2. **范围限制**: 限制扫描和攻击的网络范围
3. **时间控制**: 避免在业务高峰期进行测试
4. **数据保护**: 妥善处理测试过程中的敏感数据

### 性能优化
1. **并发控制**: 根据网络环境调整并发数
2. **超时设置**: 合理设置扫描和连接超时
3. **资源监控**: 定期检查系统资源使用情况
4. **缓存利用**: 启用结果缓存提高效率

### 配置建议
1. **定期备份**: 定期备份重要配置和数据
2. **密钥轮换**: 定期更换API密钥和加密密钥
3. **日志管理**: 配置合适的日志级别和保留策略
4. **更新维护**: 定期更新系统和依赖包

### 学习建议
1. **从简单开始**: 先熟悉基本功能再使用高级特性
2. **实验环境**: 在隔离的实验环境中练习
3. **文档学习**: 仔细阅读相关技术文档
4. **社区交流**: 参与安全社区讨论和学习

## 支持和帮助

### 获取帮助
```bash
# 系统帮助
help

# 模块帮助
attack help
defense help
ctf help

# 命令帮助
attack port-scan --help
```

### 联系支持
- **GitHub Issues**: 报告bug和功能请求
- **文档**: 查看在线文档和FAQ
- **社区**: 参与用户社区讨论

### 贡献代码
欢迎提交Pull Request来改进系统：
1. Fork项目仓库
2. 创建功能分支
3. 提交代码更改
4. 创建Pull Request

---

**重要提醒**: 本工具仅用于授权的安全测试和教育目的。使用前请确保遵守相关法律法规，并获得适当的授权。