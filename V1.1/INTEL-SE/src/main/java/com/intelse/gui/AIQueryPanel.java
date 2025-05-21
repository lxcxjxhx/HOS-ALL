package com.intelse.gui;

import javax.swing.*;
import java.awt.*;

public class AIQueryPanel extends JPanel {
    private JTextArea queryInput;
    private JTextArea queryOutput;

    public AIQueryPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(250, 0));
        setBackground(new Color(0xD8D8D8));

        // Query Input (150px)
        queryInput = new JTextArea();
        queryInput.setFont(new Font("Inter", Font.PLAIN, 12));
        JScrollPane inputScroll = new JScrollPane(queryInput);
        inputScroll.setPreferredSize(new Dimension(0, 150));
        add(inputScroll, BorderLayout.NORTH);

        // Query Output (400px)
        queryOutput = new JTextArea();
        queryOutput.setEditable(false);
        queryOutput.setFont(new Font("Inter", Font.PLAIN, 12));
        JScrollPane outputScroll = new JScrollPane(queryOutput);
        outputScroll.setPreferredSize(new Dimension(0, 400));
        add(outputScroll, BorderLayout.CENTER);
    }
}
