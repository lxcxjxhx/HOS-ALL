import yaml
import os

class ConfigManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f) or {}
                return config
        except FileNotFoundError:
            return {
                "model": "grok",
                "doc_path": "/home/lxcxjxhx/PROJECT/INTEL-SE/docs",
                "api_key": "",
                "api_endpoint": "https://api.x.ai/v1",
                "tabs": {},
                "enabled_tools": []
            }
        except Exception as e:
            print(f"加载配置错误：{e}")
            return {}

    def save_config(self, config):
        try:
            current_config = self.load_config()
            current_config.update(config)
            with open(self.config_path, "w") as f:
                yaml.dump(current_config, f, allow_unicode=True)
            os.chmod(self.config_path, 0o664)
            self.config = current_config
        except Exception as e:
            print(f"保存配置错误：{e}")

    def get_config(self):
        return self.config
