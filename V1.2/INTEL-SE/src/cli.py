import shlex
import subprocess
from datetime import datetime

class CLIHandler:
    def __init__(self, app):
        self.app = app
        self.safe_mode = False  # Safe mode disabled by default
        self.blacklist = ["rm", "sudo", "dd", "mkfs", "reboot", "halt", "|", "&"]  # Blacklist for reference

    def execute_command(self, command, tab):
        """Process and execute commands entered in the GUI."""
        try:
            if not command.strip():
                return

            # Log the command execution
            self.app.log_event("COMMAND_EXEC", f"Command: {command}")

            # Parse command
            args = shlex.split(command)
            cmd = args[0].lower()

            # Check for blacklisted commands only if safe mode is enabled
            if self.safe_mode and cmd in self.blacklist:
                self.display_output(tab, f"Error: Command '{cmd}' is prohibited in safe mode\n")
                self.app.log_event("CLI_ERROR", f"Prohibited command: {command}")
                return

            # Handle built-in commands
            if cmd == "generate_payload":
                if len(args) < 3:
                    self.display_output(tab, "Usage: generate_payload <url> <vuln_type>\n")
                    return
                self.app.attack_module.generate_payload(args[1], args[2], tab)
            elif cmd == "process_docs":
                self.app.doc_processor.process_docs(tab)
            elif cmd == "run_attack":
                ip = tab.ip_entry.get()
                if not ip:
                    self.display_output(tab, "Error: No target IP specified\n")
                    return
                self.app.attack_module.run_attack(ip, tab)
            else:
                # Execute shell command
                self.execute_shell_command(args, tab)

        except Exception as e:
            self.display_output(tab, f"Error executing command: {str(e)}\n")
            self.app.log_event("CLI_ERROR", f"Command execution failed: {command} - {str(e)}")

    def execute_shell_command(self, args, tab):
        """Execute shell commands and display output."""
        try:
            # Execute command (no restrictions in non-safe mode)
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            output = result.stdout or result.stderr
            self.display_output(tab, output + "\n")
            self.app.log_event("COMMAND_EXEC", f"Shell command output: {output}")

        except subprocess.TimeoutExpired:
            self.display_output(tab, "Error: Command execution timed out\n")
            self.app.log_event("CLI_ERROR", "Command timed out")
        except Exception as e:
            self.display_output(tab, f"Error executing shell command: {str(e)}\n")
            self.app.log_event("CLI_ERROR", f"Shell command failed: {str(e)}")

    def display_output(self, tab, message):
        """Display text in the tab's output area."""
        tab.output.config(state="normal")
        tab.output.insert("end", message)
        tab.output.config(state="disabled")
        tab.output.see("end")
