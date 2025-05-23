class AIQueryModule:
    def __init__(self, app):
        self.app = app
        self.enabled_tools = []
        self.api_key = ""
        self.api_endpoint = "https://api.x.ai/v1"

    def update_api_config(self, api_key, api_endpoint):
        self.api_key = api_key
        self.api_endpoint = api_endpoint
        self.app.log_event("CONFIG_UPDATE", "AI API配置已更新")

    def update_enabled_tools(self, tools):
        self.enabled_tools = tools
        self.app.log_event("CONFIG_UPDATE", f"启用工具：{', '.join(tools)}")

    def process_security_query(self, query):
        try:
            if "nmap" in query.lower() and "nmap" in self.enabled_tools:
                return "使用工具 nmap 进行网络扫描，示例：nmap -sP 192.168.1.0/24"
            elif "sql" in query.lower() and "sqlmap" in self.enabled_tools:
                return "使用工具 sqlmap 检测SQL注入，示例：sqlmap -u http://example.com"
            rag_response = self.app.doc_processor.rag_query(query)
            tools_hint = f"可用工具：{', '.join(self.enabled_tools)}" if self.enabled_tools else "无可用工具"
            return f"{rag_response}\n{tools_hint}"
        except Exception as e:
            self.app.log_event("QUERY_ERROR", f"查询处理失败：{str(e)}")
            return f"查询错误：{str(e)}"
