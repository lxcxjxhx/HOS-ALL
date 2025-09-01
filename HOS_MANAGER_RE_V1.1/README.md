# AI网络安全平台

一个集成AI助手的综合性网络安全工具平台，提供攻击模拟、防御监控和CTF解题功能。

## 功能特性

### 🤖 AI助手集成
- 支持多种AI提供商（DeepSeek、OpenAI、Claude、Gemini、Ollama）
- 智能攻击载荷生成
- AI驱动的防御响应
- 自动化CTF解题分析

### ⚔️ 攻击模拟
- 多种端口扫描技术
- 漏洞识别和分析
- 自动化攻击载荷生成
- 会话管理和并行执行

### 🛡️ 防御系统
- 实时网络监控
- 威胁检测和分类
- 智能防御响应
- 安全事件记录

### 🏆 CTF解题器
- 多种挑战类型支持
- AI驱动的解题分析
- 自动化解题流程
- 工具集成和管理

## 安装说明

### 环境要求
- Python 3.8+
- 管理员权限（用于网络操作）

### 安装步骤

1. 克隆项目
```bash
git clone https://github.com/cybersecurity-platform/ai-cybersecurity-platform.git
cd ai-cybersecurity-platform
```

2. 创建虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 配置系统
```bash
cp config/config_template.json config/config.json
# 编辑config.json文件，填入API密钥等配置信息
```

## 使用说明

### 基本使用
```bash
python -m src.main
```

### 配置AI提供商
在`config/config.json`中配置您的AI提供商API密钥：

```json
{
  "ai_providers": {
    "default": "deepseek",
    "deepseek": {
      "api_key": "your-deepseek-api-key",
      "model": "deepseek-chat"
    }
  }
}
```

### 安全注意事项

⚠️ **重要警告**
- 本工具仅用于授权的安全测试和教育目的
- 请勿在未经授权的系统上使用
- 使用前请确保遵守当地法律法规
- 建议在隔离的测试环境中使用

## 开发说明

### 项目结构
```
src/
├── core/           # 核心接口和基础类
├── ai/             # AI提供商集成
├── attack/         # 攻击模拟模块
├── defense/        # 防御系统模块
├── ctf/            # CTF解题模块
├── config/         # 配置管理
└── ui/             # 用户界面

tests/              # 测试文件
config/             # 配置文件
docs/               # 文档
```

### 运行测试
```bash
pytest tests/ -v --cov=src
```

### 代码格式化
```bash
black src/ tests/
flake8 src/ tests/
```

## 许可证

本项目采用MIT许可证 - 详见 [LICENSE](LICENSE) 文件

## 贡献指南

欢迎提交Issue和Pull Request！请确保：
1. 代码符合项目规范
2. 添加适当的测试
3. 更新相关文档

## 支持

如有问题或建议，请：
1. 查看[文档](docs/)
2. 提交[Issue](https://github.com/cybersecurity-platform/ai-cybersecurity-platform/issues)
3. 联系开发团队