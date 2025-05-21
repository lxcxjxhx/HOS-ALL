package com.intelse.cli;

import com.intelse.attack.AttackManager;
import com.intelse.doc.DocumentProcessor;

public class CommandExecutor {
    private final SafeShell safeShell;
    private final AttackManager attackManager;
    private final DocumentProcessor docProcessor;

    public CommandExecutor() {
        this.safeShell = new SafeShell();
        this.attackManager = new AttackManager();
        this.docProcessor = new DocumentProcessor();
    }

    public String execute(String command) throws Exception {
        String[] parts = command.split("\\s+");
        if (parts.length == 0) {
            return "Empty command";
        }

        String cmd = parts[0].toLowerCase();
        switch (cmd) {
            case "generate_payload":
                if (parts.length < 3) {
                    return "Usage: generate_payload <url> <vuln_type>";
                }
                return attackManager.generatePayload(parts[1], parts[2]);
            case "process_docs":
                return docProcessor.processDocuments();
            case "run_attack":
                return attackManager.runAttack();
            default:
                return safeShell.executeShellCommand(command);
        }
    }
}
