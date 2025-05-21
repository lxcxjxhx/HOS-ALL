package com.intelse.gui;

import java.awt.*;

public class ThemeConfig {
    public static final Color BACKGROUND_COLOR = new Color(0x4B5EAA);
    public static final Color CONTENT_COLOR = new Color(0xD8D8D8);
    public static final Color FONT_COLOR = Color.BLACK;
    public static final String FONT_NAME = "Inter";
    public static final String MONOSPACE_FONT = System.getProperty("os.name").toLowerCase().contains("linux") ? "Monospace" : "Consolas";
    public static final int FONT_SIZE = 12;
}
