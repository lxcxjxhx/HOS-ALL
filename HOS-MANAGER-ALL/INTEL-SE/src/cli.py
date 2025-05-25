import subprocess

class CLIHandler:
    def __init__(self, app):
        self.app = app
        self.available_tools = []

    def update_available_tools(self, tools):
        self.available_tools = tools
        self.app.log_event("CLI_UPDATE", f"可用工具更新：{', '.join(tools)}")

    def execute_command(self, command):
        if not command:
            return
        try:
            if command.split()[0] in self.available_tools:
                tool_path = f"/home/lxcxjxhx/PROJECT/INTEL-SE/tools/bin/{command.split()[0]}"
                process = subprocess.Popen(f"cd {tool_path} && {command}", shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            else:
                process = subprocess.Popen(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate(timeout=10)
            output = stdout + stderr
            self.app.log_event("COMMAND_EXEC", f"命令执行：{command}")
            return output
        except subprocess.TimeoutExpired:
            process.kill()
            self.app.log_event("CLI_ERROR", f"命令超时：{command}")
            return f"错误：命令 '{command}' 超时"
        except Exception as e:
            self.app.log_event("CLI_ERROR", f"命令失败：{str(e)}")
            return f"错误：{str(e)}"
