import requests
import json

class AIQueryModule:
    def __init__(self, app):
        self.app = app
        self.enabled_tools = []
        self.api_key = ""
        self.api_endpoint = "http://localhost:8000"

    def update_api_config(self, api_key, api_endpoint):
        self.api_key = api_key
        self.api_endpoint = api_endpoint
        self.app.log_event("CONFIG_UPDATE", "AI API配置已更新")

    def update_enabled_tools(self, tools):
        self.enabled_tools = tools
        self.app.log_event("CONFIG_UPDATE", f"启用工具：{', '.join(tools)}")

    def process_security_query(self, query):
        try:
            # Prepare headers with API key if provided
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            # Prepare payload for FASTAPI /generate endpoint
            payload = {
                "prompt": f"Security query: {query}. Available tools: {', '.join(self.enabled_tools) if self.enabled_tools else 'none'}.",
                "max_tokens": 512,
                "temperature": 0.7
            }

            # Make API request to FASTAPI /generate endpoint
            response = requests.post(
                f"{self.api_endpoint}/generate",
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()

            # Parse response
            result = response.json()
            api_response = result.get("response", "No response from API")

            # Incorporate RAG and tools
            rag_response = self.app.doc_processor.rag_query(query)
            tools_hint = f"可用工具：{', '.join(self.enabled_tools)}" if self.enabled_tools else "无可用工具"
            return f"{api_response}\nRAG结果：{rag_response}\n{tools_hint}"

        except requests.exceptions.RequestException as e:
            self.app.log_event("QUERY_ERROR", f"API请求失败：{str(e)}")
            return f"API错误：{str(e)}"
        except Exception as e:
            self.app.log_event("QUERY_ERROR", f"查询处理失败：{str(e)}")
            return f"查询错误：{str(e)}"
