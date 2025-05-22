import requests

class AIQueryModule:
    def __init__(self, app):
        self.app = app
        self.model = self.app.config_manager.get_config().get("model", "grok")
        self.api_key = self.app.config_manager.get_config().get("api_key", "")
        self.api_endpoint = self.app.config_manager.get_config().get("api_endpoint", "https://api.x.ai/v1")
        self.enabled_tools = self.app.config_manager.get_config().get("enabled_tools", [])

    def update_api_config(self, api_key, api_endpoint):
        self.api_key = api_key
        self.api_endpoint = api_endpoint
        self.app.log_event("CONFIG_UPDATE", f"API配置更新：端点={api_endpoint}")

    def update_enabled_tools(self, enabled_tools):
        self.enabled_tools = enabled_tools
        self.app.log_event("CONFIG_UPDATE", f"启用工具更新：{', '.join(enabled_tools)}")

    def process_query(self, query):
        try:
            if "rag" in query.lower():
                response = self.app.doc_processor.rag_query(query)
            else:
                response = self.call_grok_api(query)
            self.app.log_event("COMMAND_EXEC", f"AI查询已处理：{query}")
            return response
        except Exception as e:
            self.app.log_event("CLI_ERROR", f"AI查询失败：{str(e)}")
            return f"处理查询错误：{str(e)}"

    def process_security_query(self, query):
        try:
            # Use RAG for context
            rag_response = self.app.doc_processor.rag_query(query)
            # Check if query involves a tool
            tool_used = None
            for tool in self.enabled_tools:
                if tool.lower() in query.lower():
                    tool_used = tool
                    break
            if tool_used:
                tool_response = f"使用工具 {tool_used} 分析：模拟运行 {tool_used} 针对查询 '{query}'"
                self.app.log_event("TOOL_EXEC", f"工具 {tool_used} 用于查询：{query}")
            else:
                tool_response = "未使用特定工具"
            # Combine with simulated Grok response
            grok_response = self.call_grok_api(
                f"信息安全问题：{query}\n文档上下文：{rag_response}\n工具状态：{tool_response}"
            )
            response = f"RAG上下文：\n{rag_response}\n\n工具使用：\n{tool_response}\n\nGrok回答：\n{grok_response}"
            self.app.log_event("COMMAND_EXEC", f"信息安全查询已处理：{query}")
            return response
        except Exception as e:
            self.app.log_event("CLI_ERROR", f"信息安全查询失败：{str(e)}")
            return f"信息安全查询错误：{str(e)}"

    def call_grok_api(self, query):
        if self.api_key and self.api_endpoint:
            try:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                response = requests.post(
                    f"{self.api_endpoint}/grok/query",
                    json={"query": query, "model": self.model},
                    headers=headers,
                    timeout=10
                )
                response.raise_for_status()
                return response.json().get("response", f"AI响应：使用模型 {self.model} 处理查询 '{query}'")
            except requests.RequestException as e:
                return f"API错误：{str(e)}"
        return f"根据提供的上下文，'{query}' 的回答是：这是模拟的Grok响应，针对您的信息安全问题。"
