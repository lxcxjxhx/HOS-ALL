import tkinter as tk
from tkinter import ttk
import re

class AttackSessionTab:
    def __init__(self, notebook, app):
        self.app = app
        self.notebook = notebook
        self.frame = ttk.Frame(notebook)
        self.tab_id = notebook.index("end") + 1
        self.setup_widgets()

    def setup_widgets(self):
        # Output area (read-only)
        self.output = tk.Text(self.frame, height=20, font=self.app.mono_font, bg=self.app.fg_color, fg=self.app.text_color)
        self.output.pack(fill="both", expand=True, padx=5, pady=5)
        self.output.config(state="disabled")
        
        # Command input
        self.input = ttk.Entry(self.frame, font=self.app.mono_font)
        self.input.pack(fill="x", padx=5, pady=5)
        self.input.bind("<Return>", self.process_command)
        
        # IP and Port configuration
        config_frame = ttk.Frame(self.frame)
        config_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(config_frame, text="目标IP或范围：").pack(side="left", padx=5)
        self.ip_entry = ttk.Entry(config_frame, width=20)
        self.ip_entry.pack(side="left", padx=5)
        self.ip_entry.bind("<FocusOut>", self.save_config)
        ttk.Label(config_frame, text="端口或范围：").pack(side="left", padx=5)
        self.port_entry = ttk.Entry(config_frame, width=10)
        self.port_entry.pack(side="left", padx=5)
        self.port_entry.bind("<FocusOut>", self.save_config)
        ttk.Button(config_frame, text="运行攻击", command=self.run_attack).pack(side="left", padx=5)
        # Load saved config
        config = self.app.config_manager.get_config()
        saved_config = config.get("tabs", {}).get(str(self.tab_id), {})
        self.ip_entry.insert(0, saved_config.get("ip", ""))
        self.port_entry.insert(0, saved_config.get("port", ""))

    def process_command(self, event):
        command = self.input.get()
        self.app.cli_handler.execute_command(command, self)
        self.input.delete(0, "end")

    def run_attack(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not self.validate_ip(ip):
            self.output.config(state="normal")
            self.output.insert("end", "错误：无效的IP或IP范围\n")
            self.output.config(state="disabled")
            return
        if not self.validate_port(port):
            self.output.config(state="normal")
            self.output.insert("end", "错误：无效的端口或端口范围\n")
            self.output.config(state="disabled")
            return
        self.save_config(None)
        self.app.attack_module.run_attack(ip, port, self)

    def save_config(self, event):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        valid = True
        if ip and not self.validate_ip(ip):
            self.output.config(state="normal")
            self.output.insert("end", "错误：无效的IP或IP范围\n")
            self.output.config(state="disabled")
            valid = False
        if port and not self.validate_port(port):
            self.output.config(state="normal")
            self.output.insert("end", "错误：无效的端口或端口范围\n")
            self.output.config(state="disabled")
            valid = False
        if valid:
            self.app.tab_configs[self.tab_id] = {"ip": ip, "port": port}
            self.app.config_manager.save_config({"tabs": self.app.tab_configs})
            self.app.log_event("CONFIG_UPDATE", f"会话 {self.tab_id} 配置更新：IP={ip}, 端口={port}")

    def validate_ip(self, ip):
        if not ip:
            return True
        single_ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        range_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"
        return bool(re.match(single_ip_pattern, ip) or re.match(range_pattern, ip))

    def validate_port(self, port):
        if not port:
            return True
        single_port_pattern = r"^\d{1,5}$"
        range_pattern = r"^\d{1,5}-\d{1,5}$"
        if re.match(single_port_pattern, port):
            try:
                return 0 <= int(port) <= 65535
            except ValueError:
                return False
        if re.match(range_pattern, port):
            try:
                start, end = map(int, port.split("-"))
                return 0 <= start <= end <= 65535
            except ValueError:
                return False
        return False
