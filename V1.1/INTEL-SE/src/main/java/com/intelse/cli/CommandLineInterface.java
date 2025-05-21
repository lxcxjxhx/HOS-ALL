package com.intelse.cli;

import com.intelse.gui.AttackSessionTab;
import com.intelse.log.LogManager;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

public class CommandLineInterface {
    private final AttackSessionTab tab;
    private final CommandExecutor executor;
    private final List<String> commandHistory;
    private int historyIndex;

    public CommandLineInterface(AttackSessionTab tab) {
        this.tab = tab;
        this.executor = new CommandExecutor();
        this.commandHistory = new ArrayList<>();
        this.historyIndex = -1;

        // Add key listener for command input
        tab.getCommandInput().addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    e.consume();
                    String command = tab.getCommandInput().getText().trim();
                    if (!command.isEmpty()) {
                        processCommand(command);
                        commandHistory.add(command);
                        historyIndex = commandHistory.size();
                        tab.getCommandInput().setText("");
                    }
                } else if (e.getKeyCode() == KeyEvent.VK_UP) {
                    if (historyIndex > 0) {
                        historyIndex--;
                        tab.getCommandInput().setText(commandHistory.get(historyIndex));
                    }
                } else if (e.getKeyCode() == KeyEvent.VK_DOWN) {
                    if (historyIndex < commandHistory.size() - 1) {
                        historyIndex++;
                        tab.getCommandInput().setText(commandHistory.get(historyIndex));
                    } else {
                        historyIndex = commandHistory.size();
                        tab.getCommandInput().setText("");
                    }
                }
            }
        });

        // Log initialization
        LogManager.logEvent("CLI_INIT", "Command Line Interface initialized");
    }

    private void processCommand(String command) {
        try {
            String output = executor.execute(command);
            tab.getResultView().append(output + "\n");
            LogManager.logEvent("COMMAND_EXEC", "Command executed: " + command);
        } catch (Exception e) {
            String error = "Error executing command: " + e.getMessage();
            tab.getResultView().append(error + "\n");
            LogManager.logEvent("CLI_ERROR", error);
        }
    }

    public JTextArea getResultView() {
        return tab.getResultView();
    }
}
