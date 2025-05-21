package com.intelse.gui;

import javax.swing.*;
import java.awt.*;

public class MainWindow extends JFrame {
    private static final String TITLE = "AI Attack Simulator";
    private static final int WIDTH = 1000;
    private static final int HEIGHT = 800;

    public MainWindow() {
        setTitle(TITLE);
        setSize(WIDTH, HEIGHT);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Initialize layout
        setLayout(new BorderLayout());

        // Header Bar
        JPanel headerBar = new JPanel();
        headerBar.setBackground(new Color(0x4B5EAA));
        JLabel titleLabel = new JLabel(TITLE);
        titleLabel.setForeground(Color.BLACK);
        headerBar.add(titleLabel);
        add(headerBar, BorderLayout.NORTH);

        // Sidebar (80px wide)
        JPanel sidebar = new JPanel();
        sidebar.setBackground(new Color(0xD8D8D8));
        sidebar.setPreferredSize(new Dimension(80, HEIGHT));
        add(sidebar, BorderLayout.WEST);

        // Tabbed Pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Attack Session 1", new AttackSessionTab());
        add(tabbedPane, BorderLayout.CENTER);

        // AI Query Panel (250px wide, collapsible)
        AIQueryPanel aiPanel = new AIQueryPanel();
        add(aiPanel, BorderLayout.EAST);
    }
}
