#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import os
import platform
import yaml
import subprocess
from datetime import datetime

from src.gui import AttackSessionTab
from src.cli import CLIHandler
from src.attack import AttackModule
from src.ai_query import AIQueryModule
from src.doc_processor import DocProcessor
from src.config_manager import ConfigManager

class AttackSimulationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI攻防模拟系统")
        self.root.geometry("1000x700")
        try:
            self.config_manager = ConfigManager("/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml")
            self.tab_configs = {}
            self.setup_styles()
            self.setup_layout()
            self.cli_handler = CLIHandler(self)
            self.attack_module = AttackModule(self)
            self.ai_query_module = AIQueryModule(self)
            self.doc_processor = DocProcessor(self)
            self.cmd_panel_visible = False
            self.ai_panel_visible = False
            self.log_event("CLI_INIT", "应用已初始化")
        except Exception as e:
            self.log_event("INIT_ERROR", f"应用初始化失败：{str(e)}")
            messagebox.showerror("初始化错误", f"无法启动应用：{str(e)}")
            raise

    def setup_styles(self):
        self.bg_color = "#4B5EAA"
        self.fg_color = "#D8D8D8"
        self.text_color = "#000000"
        self.terminal_bg = "#000000"
        self.terminal_fg = "#FFFFFF"
        self.font = ("Noto Sans CJK SC", 11)
        self.mono_font = ("Noto Sans Mono CJK SC" if platform.system() == "Linux" else "Consolas", 12)

        style = ttk.Style()
        style.configure("TNotebook", background=self.bg_color)
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, foreground=self.text_color, font=self.font)
        style.configure("TButton", background=self.fg_color, foreground=self.text_color, font=self.font)
        style.configure("TEntry", fieldbackground=self.fg_color, foreground=self.text_color, font=self.mono_font)
        style.configure("Compact.TButton", padding=(5, 2))

    def setup_layout(self):
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill="x", padx=10, pady=10)
        ttk.Label(header_frame, text="AI攻防模拟系统", font=("Noto Sans CJK SC", 16, "bold")).pack()

        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(button_frame, text="新建会话", command=self.add_session, style="Compact.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="AI API配置", command=self.configure_api, style="Compact.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="RAG文档仓库配置", command=self.configure_rag_docs, style="Compact.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="信息安全工具下载配置", command=self.configure_security_tools, style="Compact.TButton").pack(side="left", padx=5)

        main_container = ttk.Frame(self.root)
        main_container.pack(fill="both", expand=True)

        self.ai_container = ttk.Frame(main_container, width=30)
        self.ai_container.pack(side="right", fill="y")
        self.ai_container.pack_propagate(False)
        self.ai_button_canvas = tk.Canvas(self.ai_container, width=30, height=700, bg=self.fg_color, highlightthickness=0)
        self.ai_button_canvas.pack(side="right", fill="y")
        self.ai_button_canvas.create_text(15, 350, text="信息安全AI", font=self.font, fill=self.text_color, angle=90)
        self.ai_button_canvas.bind("<Button-1>", self.on_ai_button_click)
        self.ai_panel = ttk.Frame(self.ai_container, width=333, style="TFrame")  # 1/3 of 1000px
        self.ai_panel.pack_propagate(False)
        ttk.Label(self.ai_panel, text="信息安全AI咨询", font=("Noto Sans CJK SC", 10, "bold")).pack(pady=5)
        self.ai_input = ttk.Entry(self.ai_panel, font=self.mono_font)
        self.ai_input.pack(fill="x", padx=5, pady=5)
        self.ai_input.bind("<Return>", self.process_security_query)
        self.ai_output = tk.Text(self.ai_panel, height=20, font=self.mono_font, bg=self.fg_color, fg=self.text_color, wrap="word")
        self.ai_output.pack(fill="both", expand=True, padx=5, pady=5)
        self.ai_output.config(state="disabled")
        ai_scrollbar = ttk.Scrollbar(self.ai_panel, orient="vertical", command=self.ai_output.yview)
        ai_scrollbar.pack(side="right", fill="y")
        self.ai_output.config(yscrollcommand=ai_scrollbar.set)

        self.content_frame = ttk.Frame(main_container)
        self.content_frame.pack(side="left", fill="both", expand=True, padx=10)
        self.notebook = ttk.Notebook(self.content_frame)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.bind("<Button-3>", self.show_tab_context_menu)
        self.add_session()

        self.cmd_container = ttk.Frame(self.root)
        self.cmd_container.pack(side="bottom", fill="x")
        self.cmd_button = ttk.Button(self.cmd_container, text="↑ 命令行", command=self.toggle_cmd_panel)
        self.cmd_button.pack(fill="x")
        self.cmd_panel = ttk.Frame(self.cmd_container, height=233)
        self.cmd_panel.pack_propagate(False)
        ttk.Label(self.cmd_panel, text="本地命令行").pack(anchor="w", padx=5)
        self.cmd_input = ttk.Entry(self.cmd_panel, font=self.mono_font)
        self.cmd_input.pack(fill="x", padx=5, pady=2)
        self.cmd_input.bind("<Return>", self.execute_local_command)
        self.cmd_output = tk.Text(self.cmd_panel, height=10, font=self.mono_font, bg=self.terminal_bg, fg=self.terminal_fg)
        self.cmd_output.pack(fill="x", padx=5, pady=2)
        self.cmd_output.config(state="disabled")

    def on_ai_button_click(self, event):
        self.log_event("GUI_DEBUG", f"AI button clicked at ({event.x}, {event.y})")
        self.toggle_ai_panel()

    def toggle_cmd_panel(self):
        self.log_event("GUI_DEBUG", f"Toggle command panel, current state: {self.cmd_panel_visible}")
        if self.cmd_panel_visible:
            self.cmd_panel.pack_forget()
            self.cmd_button.configure(text="↑ 命令行")
        else:
            self.cmd_panel.pack(side="bottom", fill="x")
            self.cmd_button.configure(text="↓ 命令行")
        self.cmd_panel_visible = not self.cmd_panel_visible
        self.log_event("GUI_EVENT", f"命令行面板{'显示' if self.cmd_panel_visible else '隐藏'}")

    def toggle_ai_panel(self):
        self.log_event("GUI_DEBUG", f"Toggle AI panel, current state: {self.ai_panel_visible}")
        try:
            if self.ai_panel_visible:
                self.ai_panel.pack_forget()
                self.ai_button_canvas.configure(bg=self.fg_color)
                self.ai_container.configure(width=30)
                self.content_frame.pack_configure(expand=True)
            else:
                self.ai_container.configure(width=363)  # 30 + 333
                self.ai_panel.pack(side="right", fill="y", before=self.ai_button_canvas)
                self.ai_button_canvas.configure(bg="#A0A0A0")
                self.content_frame.pack_configure(expand=True)
            self.ai_panel_visible = not self.ai_panel_visible
            self.log_event("GUI_EVENT", f"AI面板{'显示' if self.ai_panel_visible else '隐藏'}")
            self.root.update()  # Force layout update
        except Exception as e:
            self.log_event("GUI_ERROR", f"AI面板切换失败：{str(e)}")
            messagebox.showerror("错误", f"无法切换AI面板：{str(e)}")

    def show_tab_context_menu(self, event):
        tab_index = self.notebook.index(f"@{event.x},{event.y}")
        if tab_index >= 0:
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="关闭会话", command=lambda: self.close_tab(tab_index))
            menu.post(event.x_root, event.y_root)

    def add_session(self):
        session = AttackSessionTab(self.notebook, self)
        tab_id = self.notebook.index("end") + 1
        tab_name = f"攻防会话 {tab_id}"
        self.notebook.add(session.frame, text=tab_name)
        self.tab_configs[tab_id] = {"ip": "", "port": ""}
        self.config_manager.save_config({"tabs": self.tab_configs})
        self.log_event("TAB_CREATED", f"新建会话：{tab_name}")

    def close_tab(self, tab_index):
        if self.notebook.index("end") <= 1:
            messagebox.showwarning("警告", "无法关闭最后一个会话")
            return
        tab_id = tab_index + 1
        self.notebook.forget(tab_index)
        if tab_id in self.tab_configs:
            del self.tab_configs[tab_id]
            self.config_manager.save_config({"tabs": self.tab_configs})
        self.log_event("TAB_CLOSED", f"会话 {tab_id} 已关闭")
        new_configs = {}
        for i, tab in enumerate(self.notebook.tabs(), 1):
            old_id = int(self.notebook.tab(tab, "text").split()[-1])
            new_configs[i] = self.tab_configs.get(old_id, {"ip": "", "port": ""})
            self.notebook.tab(tab, text=f"攻防会话 {i}")
        self.tab_configs = new_configs
        self.config_manager.save_config({"tabs": self.tab_configs})

    def configure_api(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("AI API配置")
        dialog.geometry("300x200")
        ttk.Label(dialog, text="API密钥：").pack(pady=5)
        api_key_entry = ttk.Entry(dialog, show="*")
        api_key_entry.pack(pady=5)
        ttk.Label(dialog, text="API端点：").pack(pady=5)
        api_endpoint_entry = ttk.Entry(dialog)
        api_endpoint_entry.pack(pady=5)
        config = self.config_manager.get_config()
        api_key_entry.insert(0, config.get("api_key", ""))
        api_endpoint_entry.insert(0, config.get("api_endpoint", "https://api.x.ai/v1"))
        def save_api_config():
            config["api_key"] = api_key_entry.get()
            config["api_endpoint"] = api_endpoint_entry.get()
            self.config_manager.save_config(config)
            self.ai_query_module.update_api_config(config["api_key"], config["api_endpoint"])
            self.log_event("CONFIG_UPDATE", "AI API配置已更新")
            dialog.destroy()
        ttk.Button(dialog, text="保存", command=save_api_config).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()

    def configure_rag_docs(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("RAG文档仓库配置")
        dialog.geometry("400x200")
        ttk.Label(dialog, text="文档仓库路径：").pack(pady=5)
        doc_path_entry = ttk.Entry(dialog)
        doc_path_entry.pack(pady=5, fill="x", padx=10)
        config = self.config_manager.get_config()
        doc_path_entry.insert(0, config.get("doc_path", "/home/lxcxjxhx/PROJECT/INTEL-SE/docs"))
        def save_doc_config():
            doc_path = doc_path_entry.get()
            if os.path.isdir(doc_path):
                config["doc_path"] = doc_path
                self.config_manager.save_config(config)
                self.doc_processor.update_doc_path(doc_path)
                self.log_event("CONFIG_UPDATE", f"RAG文档仓库路径更新为：{doc_path}")
                dialog.destroy()
            else:
                messagebox.showerror("错误", "无效的目录路径")
        ttk.Button(dialog, text="保存", command=save_doc_config).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()

    def configure_security_tools(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("信息安全工具下载配置")
        dialog.geometry("500x400")
        ttk.Label(dialog, text="选择要下载的工具：").pack(pady=5)
        tools_frame = ttk.Frame(dialog)
        tools_frame.pack(fill="both", padx=10, pady=5)
        available_tools = [
            {"name": "nmap", "url": "https://nmap.org/dist/nmap-7.94.tar.bz2"},
            {"name": "metasploit", "url": "https://github.com/rapid7/metasploit-framework/archive/refs/heads/master.zip"},
            {"name": "sqlmap", "url": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip"}
        ]
        tool_vars = {}
        config = self.config_manager.get_config()
        enabled_tools = config.get("enabled_tools", [])
        for tool in available_tools:
            var = tk.BooleanVar(value=tool["name"] in enabled_tools)
            tool_vars[tool["name"]] = var
            ttk.Checkbutton(tools_frame, text=tool["name"], variable=var).pack(anchor="w", padx=5, pady=2)
        def download_and_configure():
            selected_tools = [name for name, var in tool_vars.items() if var.get()]
            enabled_tools = []
            tools_dir = "/home/lxcxjxhx/PROJECT/INTEL-SE/tools"
            os.makedirs(tools_dir, exist_ok=True)
            os.chmod(tools_dir, 0o775)
            for tool in available_tools:
                if tool["name"] in selected_tools:
                    tool_path = os.path.join(tools_dir, tool["name"])
                    os.makedirs(tool_path, exist_ok=True)
                    with open(os.path.join(tool_path, "installed.txt"), "w") as f:
                        f.write(f"Simulated install of {tool['name']}\n")
                    os.chmod(tool_path, 0o775)
                    enabled_tools.append(tool["name"])
                    self.log_event("TOOL_DOWNLOAD", f"工具 {tool['name']} 已下载（模拟）")
            config["enabled_tools"] = enabled_tools
            self.config_manager.save_config(config)
            self.ai_query_module.update_enabled_tools(enabled_tools)
            self.log_event("CONFIG_UPDATE", f"启用工具：{', '.join(enabled_tools)}")
            dialog.destroy()
        ttk.Button(dialog, text="下载并配置", command=download_and_configure).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()

    def process_security_query(self, event):
        query = self.ai_input.get()
        if query:
            try:
                response = self.ai_query_module.process_security_query(query)
                self.ai_output.config(state="normal")
                self.ai_output.insert("end", f"问：{query}\n答：{response}\n\n")
                self.ai_output.yview("end")
                self.ai_output.config(state="disabled")
                self.ai_input.delete(0, "end")
                self.log_event("COMMAND_EXEC", f"信息安全查询：{query}")
            except Exception as e:
                self.log_event("QUERY_ERROR", f"信息安全查询失败：{str(e)}")
                self.ai_output.config(state="normal")
                self.ai_output.insert("end", f"错误：{str(e)}\n")
                self.ai_output.config(state="disabled")

    def execute_local_command(self, event):
        command = self.cmd_input.get().strip()
        if command:
            blocked_commands = ["sh", "bash", "zsh", "fish", "tcsh"]
            if command.split()[0] in blocked_commands:
                self.cmd_output.config(state="normal")
                self.cmd_output.insert("end", f"错误：不支持交互式壳 '{command}'\n")
                self.cmd_output.config(state="disabled")
                self.log_event("CLI_ERROR", f"阻止交互式命令：{command}")
                self.cmd_input.delete(0, "end")
                return
            try:
                process = subprocess.Popen(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                stdout, stderr = process.communicate(timeout=10)
                output = stdout + stderr
                self.cmd_output.config(state="normal")
                self.cmd_output.insert("end", f"$ {command}\n{output}\n")
                self.cmd_output.yview("end")
                self.cmd_output.config(state="disabled")
                self.cmd_input.delete(0, "end")
                self.log_event("COMMAND_EXEC", f"本地命令执行：{command}")
            except subprocess.TimeoutExpired:
                process.kill()
                self.cmd_output.config(state="normal")
                self.cmd_output.insert("end", f"错误：命令 '{command}' 超时\n")
                self.cmd_output.config(state="disabled")
                self.log_event("CLI_ERROR", f"命令超时：{command}")
            except Exception as e:
                self.cmd_output.config(state="normal")
                self.cmd_output.insert("end", f"错误：{str(e)}\n")
                self.cmd_output.config(state="disabled")
                self.log_event("CLI_ERROR", f"本地命令失败：{str(e)}")
            self.cmd_input.delete(0, "end")

    def log_event(self, event_type, message):
        log_path = "/home/lxcxjxhx/PROJECT/INTEL-SE/logs/attack_logs.log"
        try:
            with open(log_path, "a") as f:
                f.write(f"[{datetime.now()}] {event_type}: {message}\n")
            os.chmod(log_path, 0o664)
        except Exception as e:
            print(f"日志错误：{e}")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/logs", exist_ok=True)
    os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/config", exist_ok=True)
    os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/docs", exist_ok=True)
    os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/cache", exist_ok=True)
    os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/tools", exist_ok=True)
    settings_path = "/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml"
    if not os.path.exists(settings_path):
        with open(settings_path, "w") as f:
            yaml.dump({
                "model": "grok",
                "doc_path": "/home/lxcxjxhx/PROJECT/INTEL-SE/docs",
                "api_key": "",
                "api_endpoint": "https://api.x.ai/v1",
                "tabs": {},
                "enabled_tools": []
            }, f, allow_unicode=True)
        os.chmod(settings_path, 0o664)
    root = tk.Tk()
    app = AttackSimulationApp(root)
    app.run()
