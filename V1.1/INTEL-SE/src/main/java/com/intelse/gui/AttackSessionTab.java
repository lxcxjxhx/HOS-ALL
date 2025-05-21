package com.intelse.gui;

import com.intelse.cli.CommandLineInterface;

import javax.swing.*;
import java.awt.*;

public class AttackSessionTab extends JPanel {
    private JTextArea resultView;
    private JTextArea commandInput;
    private CommandLineInterface cli;

    public AttackSessionTab() {
        setLayout(new BorderLayout());

        // Result View (read-only, 300px min height)
        resultView = new JTextArea();
        resultView.setEditable(false);
        resultView.setFont(new Font(ThemeConfig.MONOSPACE_FONT, Font.PLAIN, ThemeConfig.FONT_SIZE));
        JScrollPane resultScroll = new JScrollPane(resultView);
        resultScroll.setPreferredSize(new Dimension(0, 300));
        add(resultScroll, BorderLayout.CENTER);

        // Command Input (editable, 200px min height)
        commandInput = new JTextArea();
        commandInput.setFont(new Font(ThemeConfig.MONOSPACE_FONT, Font.PLAIN, ThemeConfig.FONT_SIZE));
        commandInput.setText("Available commands: generate_payload, process_docs, run_attack, or any shell command");
        JScrollPane inputScroll = new JScrollPane(commandInput);
        inputScroll.setPreferredSize(new Dimension(0, 200));
        add(inputScroll, BorderLayout.SOUTH);

        // Initialize CLI
        cli = new CommandLineInterface(this);
    }

    public JTextArea getResultView() {
        return resultView;
    }

    public JTextArea getCommandInput() {
        return commandInput;
    }
}
