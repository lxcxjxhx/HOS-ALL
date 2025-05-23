#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import os
import platform
import yaml
import subprocess
from datetime import datetime
import requests
import zipfile
import tarfile
import shutil

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
        self.ai_panel = ttk.Frame(self.ai_container, width=333, style="TFrame")
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
                self.ai_container.configure(width=363)
                self.ai_panel.pack(side="right", fill="y", before=self.ai_button_canvas)
                self.ai_button_canvas.configure(bg="#A0A0A0")
                self.content_frame.pack_configure(expand=True)
            self.ai_panel_visible = not self.ai_panel_visible
            self.log_event("GUI_EVENT", f"AI面板{'显示' if self.ai_panel_visible else '隐藏'}")
            self.root.update()
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
        dialog.geometry("600x500")
        ttk.Label(dialog, text="管理安全工具", font=("Noto Sans CJK SC", 12, "bold")).pack(pady=10)

        notebook = ttk.Notebook(dialog)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Application Market Tab
        market_frame = ttk.Frame(notebook)
        notebook.add(market_frame, text="应用市场")

        market_canvas = tk.Canvas(market_frame)
        market_scrollbar = ttk.Scrollbar(market_frame, orient="vertical", command=market_canvas.yview)
        market_scrollable_frame = ttk.Frame(market_canvas)

        market_scrollable_frame.bind(
            "<Configure>",
            lambda e: market_canvas.configure(scrollregion=market_canvas.bbox("all"))
        )
        market_canvas.create_window((0, 0), window=market_scrollable_frame, anchor="nw")
        market_canvas.configure(yscrollcommand=market_scrollbar.set)
        market_canvas.pack(side="left", fill="both", expand=True)
        market_scrollbar.pack(side="right", fill="y")

        tools_list = [
            {"name": "nmap", "desc": "网络探测和安全审计工具", "url": "https://nmap.org/dist/nmap-7.94.tar.bz2"},
            {"name": "metasploit", "desc": "渗透测试框架", "url": "https://github.com/rapid7/metasploit-framework/archive/refs/heads/master.zip"},
            {"name": "wireshark", "desc": "网络协议分析器", "url": "https://2.na.dl.wireshark.org/src/wireshark-4.4.0.tar.xz"},
            {"name": "sqlmap", "desc": "SQL注入和数据库接管工具", "url": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip"},
            {"name": "burp-suite", "desc": "Web漏洞扫描器（社区版）", "url": "https://portswigger.net/burp/releases/download?type=jar"},
            {"name": "aircrack-ng", "desc": "Wi-Fi安全审计套件", "url": "https://download.aircrack-ng.org/aircrack-ng-1.7.tar.gz"},
            {"name": "john", "desc": "密码破解工具", "url": "https://www.openwall.com/john/k/john-1.9.0-jumbo-1.tar.xz"},
            {"name": "hydra", "desc": "密码暴力破解工具", "url": "https://github.com/vanhauser-thc/thc-hydra/archive/refs/heads/master.zip"},
            {"name": "nikto", "desc": "Web服务器漏洞扫描器", "url": "https://github.com/sullo/nikto/archive/refs/heads/master.zip"},
            {"name": "openvas", "desc": "漏洞扫描器", "url": "https://github.com/greenbone/openvas-scanner/archive/refs/heads/main.zip"},
            {"name": "kismet", "desc": "无线网络探测器和嗅探器", "url": "https://www.kismetwireless.net/files/kismet-2023-09-R1.tar.gz"},
            {"name": "snort", "desc": "网络入侵检测系统", "url": "https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz"},
            {"name": "tcpdump", "desc": "网络数据包分析器", "url": "https://www.tcpdump.org/release/tcpdump-4.99.4.tar.gz"},
            {"name": "hashcat", "desc": "高级密码恢复工具", "url": "https://hashcat.net/files/hashcat-6.2.6.tar.gz"},
            {"name": "cain", "desc": "Windows密码恢复工具", "url": "http://www.oxid.it/downloads/cain_4_9_56.zip"},
            {"name": "ettercap", "desc": "中间人攻击工具", "url": "https://github.com/Ettercap/ettercap/archive/refs/heads/master.zip"},
        ]

        progress_frame = ttk.Frame(market_frame)
        progress_frame.pack(fill="x", padx=5, pady=5)
        progress_bar = ttk.Progressbar(progress_frame, mode="determinate")
        progress_bar.pack(fill="x", padx=5)
        progress_label = ttk.Label(progress_frame, text="下载进度：0%")
        progress_label.pack()

        for tool in tools_list:
            tool_frame = ttk.Frame(market_scrollable_frame)
            tool_frame.pack(fill="x", padx=5, pady=2)
            ttk.Label(tool_frame, text=f"{tool['name']}: {tool['desc']}").pack(side="left")
            ttk.Button(tool_frame, text="下载", command=lambda t=tool: self.download_tool(t['name'], t['url'], update_tool_list, progress_bar, progress_label)).pack(side="right")

        # Manual Download Tab
        manual_frame = ttk.LabelFrame(notebook, text="手动下载")
        notebook.add(manual_frame, text="手动下载")

        ttk.Label(manual_frame, text="工具名称：").pack(anchor="w", padx=5, pady=2)
        tool_name_entry = ttk.Entry(manual_frame)
        tool_name_entry.pack(fill="x", padx=5, pady=2)
        ttk.Label(manual_frame, text="下载链接：").pack(anchor="w", padx=5, pady=2)
        tool_url_entry = ttk.Entry(manual_frame)
        tool_url_entry.pack(fill="x", padx=5, pady=2)

        manual_progress_frame = ttk.Frame(manual_frame)
        manual_progress_frame.pack(fill="x", padx=5, pady=5)
        manual_progress_bar = ttk.Progressbar(manual_progress_frame, mode="determinate")
        manual_progress_bar.pack(fill="x", padx=5)
        manual_progress_label = ttk.Label(manual_progress_frame, text="下载进度：0%")
        manual_progress_label.pack()

        def manual_download():
            tool_name = tool_name_entry.get().strip()
            tool_url = tool_url_entry.get().strip()
            if not tool_name or not tool_url:
                messagebox.showerror("错误", "请填写工具名称和下载链接")
                return
            self.download_tool(tool_name, tool_url, update_tool_list, manual_progress_bar, manual_progress_label)
            tool_name_entry.delete(0, "end")
            tool_url_entry.delete(0, "end")

        ttk.Button(manual_frame, text="下载并安装", command=manual_download).pack(pady=10)

        # Installed Tools Section
        tools_frame = ttk.LabelFrame(dialog, text="已安装工具")
        tools_frame.pack(fill="both", expand=True, padx=10, pady=5)
        tools_canvas = tk.Canvas(tools_frame)
        tools_scrollbar = ttk.Scrollbar(tools_frame, orient="vertical", command=tools_canvas.yview)
        tools_scrollable_frame = ttk.Frame(tools_canvas)

        tools_scrollable_frame.bind(
            "<Configure>",
            lambda e: tools_canvas.configure(scrollregion=tools_canvas.bbox("all"))
        )
        tools_canvas.create_window((0, 0), window=tools_scrollable_frame, anchor="nw")
        tools_canvas.configure(yscrollcommand=tools_scrollbar.set)
        tools_canvas.pack(side="left", fill="both", expand=True)
        tools_scrollbar.pack(side="right", fill="y")

        def update_tool_list():
            for widget in tools_scrollable_frame.winfo_children():
                widget.destroy()
            tools_dir = "/home/lxcxjxhx/PROJECT/INTEL-SE/tools/bin"
            if os.path.exists(tools_dir):
                for tool_name in os.listdir(tools_dir):
                    tool_path = os.path.join(tools_dir, tool_name)
                    if os.path.isdir(tool_path) and os.path.exists(os.path.join(tool_path, "installed.txt")):
                        tool_frame = ttk.Frame(tools_scrollable_frame)
                        tool_frame.pack(fill="x", padx=5, pady=2)
                        ttk.Label(tool_frame, text=f"工具: {tool_name} (路径: {tool_path})").pack(side="left")
                        ttk.Button(tool_frame, text="打开文件夹", command=lambda p=tool_path: self.open_tool_folder(p)).pack(side="right", padx=5)
                        ttk.Button(tool_frame, text="引用工具", command=lambda n=tool_name: self.reference_tool(n)).pack(side="right", padx=5)
            else:
                ttk.Label(tools_scrollable_frame, text="暂无已安装工具").pack(anchor="w", padx=5, pady=2)

        def open_tools_folder():
            tools_dir = "/home/lxcxjxhx/PROJECT/INTEL-SE/tools"
            try:
                subprocess.run(["xdg-open", tools_dir], check=True)
                self.log_event("GUI_EVENT", f"打开工具目录：{tools_dir}")
            except Exception as e:
                self.log_event("GUI_ERROR", f"无法打开工具目录：{str(e)}")
                messagebox.showerror("错误", f"无法打开目录：{str(e)}")

        ttk.Button(dialog, text="打开工具目录", command=open_tools_folder).pack(pady=10)

        update_tool_list()
        dialog.transient(self.root)
        dialog.grab_set()

    def download_tool(self, tool_name, tool_url, update_callback, progress_bar, progress_label):
        try:
            tools_dir = "/home/lxcxjxhx/PROJECT/INTEL-SE/tools"
            tool_bin_dir = os.path.join(tools_dir, "bin", tool_name)
            os.makedirs(tool_bin_dir, exist_ok=True)
            os.chmod(tool_bin_dir, 0o775)
            response = requests.get(tool_url, stream=True)
            if response.status_code != 200:
                raise Exception(f"下载失败，状态码：{response.status_code}")
            file_name = tool_url.split("/")[-1]
            file_path = os.path.join(tool_bin_dir, file_name)
            total_size = int(response.headers.get("content-length", 0))
            downloaded_size = 0
            progress_bar["maximum"] = total_size
            progress_bar["value"] = 0
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        progress_bar["value"] = downloaded_size
                        percentage = (downloaded_size / total_size * 100) if total_size > 0 else 0
                        progress_label["text"] = f"下载进度：{percentage:.1f}%"
                        self.root.update()
            os.chmod(file_path, 0o664)
            if file_name.endswith(".zip"):
                with zipfile.ZipFile(file_path, "r") as zip_ref:
                    zip_ref.extractall(tool_bin_dir)
                os.remove(file_path)
            elif file_name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
                with tarfile.open(file_path, "r:*") as tar_ref:
                    tar_ref.extractall(tool_bin_dir)
                os.remove(file_path)
            with open(os.path.join(tool_bin_dir, "installed.txt"), "w") as f:
                f.write(f"Installed {tool_name} from {tool_url} at {datetime.now()}\n")
            config = self.config_manager.get_config()
            enabled_tools = config.get("enabled_tools", [])
            if tool_name not in enabled_tools:
                enabled_tools.append(tool_name)
                config["enabled_tools"] = enabled_tools
                self.config_manager.save_config(config)
                self.ai_query_module.update_enabled_tools(enabled_tools)
            self.log_event("TOOL_DOWNLOAD", f"工具 {tool_name} 下载并安装到 {tool_bin_dir}")
            messagebox.showinfo("成功", f"工具 {tool_name} 已下载并安装")
            progress_bar["value"] = 0
            progress_label["text"] = "下载进度：0%"
            update_callback()
        except Exception as e:
            self.log_event("TOOL_ERROR", f"工具 {tool_name} 下载失败：{str(e)}")
            messagebox.showerror("错误", f"下载工具失败：{str(e)}")
            progress_bar["value"] = 0
            progress_label["text"] = "下载进度：0%"

    def open_tool_folder(self, tool_path):
        try:
            subprocess.run(["xdg-open", tool_path], check=True)
            self.log_event("GUI_EVENT", f"打开工具目录：{tool_path}")
        except Exception as e:
            self.log_event("GUI_ERROR", f"无法打开工具目录：{str(e)}")
            messagebox.showerror("错误", f"无法打开目录：{str(e)}")

    def reference_tool(self, tool_name):
        try:
            config = self.config_manager.get_config()
            referenced_tools = config.get("referenced_tools", [])
            if tool_name not in referenced_tools:
                referenced_tools.append(tool_name)
                config["referenced_tools"] = referenced_tools
                self.config_manager.save_config(config)
                self.ai_query_module.update_enabled_tools(referenced_tools)
                self.cli_handler.update_available_tools(referenced_tools)
                self.log_event("TOOL_REFERENCE", f"工具 {tool_name} 已引用")
                messagebox.showinfo("成功", f"工具 {tool_name} 已引用，可在AI面板或命令行中使用")
        except Exception as e:
            self.log_event("TOOL_ERROR", f"引用工具 {tool_name} 失败：{str(e)}")
            messagebox.showerror("错误", f"引用工具失败：{str(e)}")

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
    try:
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/logs", exist_ok=True)
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/config", exist_ok=True)
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/docs", exist_ok=True)
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/cache", exist_ok=True)
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/tools/bin", exist_ok=True)
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/tools/config", exist_ok=True)
        os.makedirs("/home/lxcxjxhx/PROJECT/INTEL-SE/tools/logs", exist_ok=True)
        os.chmod("/home/lxcxjxhx/PROJECT/INTEL-SE/tools", 0o775)
        os.chmod("/home/lxcxjxhx/PROJECT/INTEL-SE/tools/bin", 0o775)
        os.chmod("/home/lxcxjxhx/PROJECT/INTEL-SE/tools/config", 0o775)
        os.chmod("/home/lxcxjxhx/PROJECT/INTEL-SE/tools/logs", 0o775)
    except Exception as e:
        print(f"目录创建失败：{str(e)}")
        exit(1)

    settings_path = "/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml"
    if not os.path.exists(settings_path):
        try:
            with open(settings_path, "w") as f:
                yaml.dump({
                    "model": "grok",
                    "doc_path": "/home/lxcxjxhx/PROJECT/INTEL-SE/docs",
                    "api_key": "",
                    "api_endpoint": "https://api.x.ai/v1",
                    "tabs": {},
                    "enabled_tools": [],
                    "referenced_tools": []
                }, f, allow_unicode=True)
            os.chmod(settings_path, 0o664)
        except Exception as e:
            print(f"配置文件创建失败：{str(e)}")
            exit(1)

    root = tk.Tk()
    app = AttackSimulationApp(root)
    app.run()
