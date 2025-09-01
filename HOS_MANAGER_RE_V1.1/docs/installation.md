# 安装和配置指南

## 系统要求

### 最低系统要求
- **操作系统**: Windows 10/11, macOS 10.15+, Ubuntu 18.04+
- **Python版本**: Python 3.8 或更高版本
- **内存**: 最少 4GB RAM (推荐 8GB+)
- **存储空间**: 至少 2GB 可用空间
- **网络**: 互联网连接（用于AI API调用）

### 权限要求
- **管理员权限**: 某些网络扫描功能需要管理员权限
- **防火墙配置**: 可能需要配置防火墙允许网络扫描

## 安装步骤

### 1. 环境准备

#### 安装Python
确保系统已安装Python 3.8+：

```bash
# 检查Python版本
python --version
# 或
python3 --version
```

如果未安装Python，请从 [python.org](https://www.python.org/downloads/) 下载安装。

#### 安装Git（可选）
如果需要从源码安装：
```bash
# Windows (使用Chocolatey)
choco install git

# macOS (使用Homebrew)
brew install git

# Ubuntu/Debian
sudo apt-get install git
```

### 2. 获取项目代码

#### 方式一：从Git仓库克隆
```bash
git clone https://github.com/cybersecurity-platform/ai-cybersecurity-platform.git
cd ai-cybersecurity-platform
```

#### 方式二：下载压缩包
1. 从GitHub下载项目压缩包
2. 解压到目标目录
3. 进入项目目录

### 3. 创建虚拟环境

强烈建议使用虚拟环境来隔离项目依赖：

```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 4. 安装依赖包

```bash
# 升级pip
pip install --upgrade pip

# 安装项目依赖
pip install -r requirements.txt

# 或者使用开发模式安装（包含开发工具）
pip install -e .[dev]
```

### 5. 配置系统

#### 复制配置模板
```bash
cp config/config_template.json config/config.json
```

#### 编辑配置文件
使用文本编辑器打开 `config/config.json` 并配置以下内容：

```json
{
  "ai_providers": {
    "default": "deepseek",
    "deepseek": {
      "api_key": "your-deepseek-api-key-here",
      "base_url": "https://api.deepseek.com",
      "model": "deepseek-chat"
    }
  },
  "security": {
    "encryption_key": "your-32-character-encryption-key",
    "max_concurrent_sessions": 5,
    "session_timeout": 3600,
    "enable_audit_log": true
  }
}
```

### 6. 验证安装

运行系统诊断检查：
```bash
python -m src.main_cli
# 在CLI中运行: diagnose
```

或者运行测试套件：
```bash
pytest tests/ -v
```

## 配置详解

### AI提供商配置

#### DeepSeek配置
```json
"deepseek": {
  "api_key": "sk-xxxxxxxxxxxxxxxx",
  "base_url": "https://api.deepseek.com",
  "model": "deepseek-chat"
}
```

#### OpenAI配置
```json
"openai": {
  "api_key": "sk-xxxxxxxxxxxxxxxx",
  "base_url": "https://api.openai.com/v1",
  "model": "gpt-4"
}
```

#### Claude配置
```json
"claude": {
  "api_key": "sk-ant-xxxxxxxxxxxxxxxx",
  "base_url": "https://api.anthropic.com",
  "model": "claude-3-sonnet-20240229"
}
```

#### 本地Ollama配置
```json
"ollama": {
  "base_url": "http://localhost:11434",
  "model": "llama2"
}
```

### 安全配置

#### 生成加密密钥
```python
# 生成32字符加密密钥
import secrets
import string

alphabet = string.ascii_letters + string.digits
key = ''.join(secrets.choice(alphabet) for i in range(32))
print(key)
```

#### 网络安全配置
```json
"network": {
  "default_scan_timeout": 30,
  "max_scan_threads": 10,
  "allowed_networks": ["192.168.1.0/24"],
  "blocked_networks": ["127.0.0.0/8", "10.0.0.0/8"]
}
```

### 日志配置
```json
"logging": {
  "level": "INFO",
  "file": "logs/cybersecurity_platform.log",
  "max_size": "10MB",
  "backup_count": 5
}
```

## 常见安装问题

### Python版本问题
**问题**: `python: command not found`
**解决**: 
- Windows: 确保Python已添加到PATH环境变量
- macOS/Linux: 尝试使用 `python3` 命令

### 权限问题
**问题**: 网络扫描功能无法使用
**解决**: 
- Windows: 以管理员身份运行命令提示符
- Linux/macOS: 使用 `sudo` 运行程序

### 依赖安装失败
**问题**: `pip install` 失败
**解决**: 
```bash
# 升级pip
pip install --upgrade pip

# 使用国内镜像源
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 单独安装失败的包
pip install package_name --no-cache-dir
```

### 网络连接问题
**问题**: AI API调用失败
**解决**: 
- 检查网络连接
- 验证API密钥是否正确
- 检查防火墙设置
- 尝试使用代理

## 下一步

安装完成后，请参考：
- [用户手册](user_manual.md) - 了解如何使用系统
- [安全指南](security_guidelines.md) - 确保合规使用
- [故障排除](troubleshooting.md) - 解决常见问题