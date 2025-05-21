package com.intelse.config;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission; // Added import
import java.util.HashMap;
import java.util.Map;
import java.util.Set; // Added import
import java.util.HashSet; // Added import

public class ConfigManager {
    private static final String CONFIG_PATH = "/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml";
    private static ConfigManager instance;
    private Map<String, Object> config;

    private ConfigManager() {
        loadConfig();
    }

    public static ConfigManager getInstance() {
        if (instance == null) {
            instance = new ConfigManager();
        }
        return instance;
    }

    private void loadConfig() {
        try {
            File file = new File(CONFIG_PATH);
            if (!file.exists()) {
                config = new HashMap<>();
                config.put("docDir", "/home/lxcxjxhx/PROJECT/INTEL-SE/docs");
                config.put("aiModel", "deepseek");
                config.put("targetIp", "");
                saveConfig();
            } else {
                try (FileInputStream fis = new FileInputStream(file)) {
                    config = new Yaml().load(fis);
                }
            }
        } catch (Exception e) {
            config = new HashMap<>();
        }
    }

    private void saveConfig() {
        try (FileWriter writer = new FileWriter(CONFIG_PATH)) {
            new Yaml().dump(config, writer);
            // Set permissions only on POSIX systems
            if (System.getProperty("os.name").toLowerCase().contains("linux")) {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                perms.add(PosixFilePermission.GROUP_READ);
                perms.add(PosixFilePermission.GROUP_WRITE);
                perms.add(PosixFilePermission.OTHERS_READ);
                Files.setPosixFilePermissions(Paths.get(CONFIG_PATH), perms);
            }
        } catch (Exception e) {
            System.err.println("Config write error: " + e.getMessage());
        }
    }

    public String getDocDir() {
        return (String) config.getOrDefault("docDir", "/home/lxcxjxhx/PROJECT/INTEL-SE/docs");
    }

    public String getAIModel() {
        return (String) config.getOrDefault("aiModel", "deepseek");
    }

    public String getTargetIp() {
        return (String) config.getOrDefault("targetIp", "");
    }

    public void setTargetIp(String ip) {
        config.put("targetIp", ip);
        saveConfig();
    }
}
